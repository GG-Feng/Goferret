"""
Clone repositories listed in vuln_analysis.json.
Each repo is cloned with --mirror to get a complete bare copy (all branches, tags, commits).
Usage:
    python download_repos.py --limit 10
    python download_repos.py --workers 4
    python download_repos.py --limit 10 --workers 4 --output-dir repos
    python download_repos.py                       # clone all, single process

Resumable: already-cloned repos are skipped. Ctrl+C is handled gracefully.
"""

import json
import os
import subprocess
import argparse
import time
import sys
import shutil
import signal
import hashlib
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed


def load_repos(json_path="vuln_analysis.json"):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["repos"]


def is_valid_bare_repo(path):
    """Check if path is a valid bare git repo (has HEAD file)."""
    return os.path.isfile(os.path.join(path, "HEAD"))


def build_path_map(repos, dest_dir):
    """Pre-compute local paths for ALL repos upfront, resolving collisions.

    Returns dict: github_url -> (display_name, repo_path)
    """
    path_map = {}
    # Track (owner_lower, repo_lower) to detect collisions
    assigned = {}

    for repo_info in repos:
        github_url = repo_info["github_url"]
        if "github.com" not in github_url:
            continue
        parts = github_url.rstrip("/").split("/")[-2:]
        if len(parts) < 2:
            continue
        owner, repo = parts

        key = (owner.lower(), repo.lower())
        if key in assigned:
            h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
            repo = f"{repo}_{h}"

        assigned[key] = True
        display = f"{owner}/{repo}"
        repo_path = os.path.join(dest_dir, owner, repo)
        path_map[github_url] = (display, repo_path)

    return path_map


# Shared across processes via module-level global
_template_dir = ""


def _init_worker(template_dir):
    global _template_dir
    _template_dir = template_dir


RETRYABLE_ERRORS = [
    "server closed abruptly",
    "curl 56",
    "RPC failed",
    "connection timed out",
    "Could not resolve host",
    "early EOF",
    "fetch-pack",
]

AUTH_ERRORS = [
    "Authentication failed",
    "could not read Username",
    "could not read Password",
    "terminal prompts disabled",
    "Access denied",
    "403",
    "requires authentication",
]


def is_retryable(error_msg):
    return any(e in error_msg for e in RETRYABLE_ERRORS)


def is_auth_error(error_msg):
    return any(e in error_msg for e in AUTH_ERRORS)


def clone_repo(github_url, repo_path, retries=3):
    """Clone a repo as a bare mirror (complete copy with all objects)."""
    display = "/".join(repo_path.replace("\\", "/").split("/")[-2:])

    if os.path.exists(repo_path):
        if is_valid_bare_repo(repo_path):
            return display, "skipped", 0
        shutil.rmtree(repo_path, ignore_errors=True)

    os.makedirs(os.path.dirname(repo_path), exist_ok=True)

    cmd = ["git", "clone", "--mirror", github_url, repo_path]
    if _template_dir:
        cmd.insert(3, f"--template={_template_dir}")

    start = time.time()
    for attempt in range(1, retries + 1):
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            elapsed = time.time() - start
            return display, "ok", elapsed
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else ""
            if is_auth_error(stderr):
                elapsed = time.time() - start
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path, ignore_errors=True)
                return display, "auth_required", elapsed
            if attempt < retries and is_retryable(stderr):
                print(f"    [RETRY {attempt}/{retries}] {display}: {stderr[:120]}")
                if os.path.exists(repo_path):
                    shutil.rmtree(repo_path, ignore_errors=True)
                time.sleep(3 * attempt)  # 3s, 6s, 9s backoff
                continue
            elapsed = time.time() - start
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path, ignore_errors=True)
            return display, f"failed: {stderr[:200]}", elapsed


def _worker_sequential(task):
    """Worker for sequential mode."""
    github_url, repo_path = task
    return clone_repo(github_url, repo_path)


def _worker_parallel(task):
    """Worker for parallel mode — uses global template dir."""
    github_url, repo_path = task
    return clone_repo(github_url, repo_path)


def get_dir_size_mb(path):
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total / (1024 * 1024)


def print_summary(results, overall_start):
    overall_elapsed = time.time() - overall_start
    print()
    print("=" * 60)
    print(f"{'Interrupted!' if interrupted[0] else 'Done.'} Total time: {overall_elapsed:.1f}s")
    print(f"  Cloned:  {len(results['ok'])}")
    print(f"  Skipped: {len(results['skipped'])}")
    print(f"  Auth:    {len(results['auth_required'])}")
    print(f"  Failed:  {len(results['failed'])}")
    if results["auth_required"]:
        print("\nAuth-required repos (skipped):")
        for r in results["auth_required"]:
            print(f"  - {r['name']}: {r['url']}")
    if results["failed"]:
        print("\nFailed repos:")
        for r in results["failed"]:
            print(f"  - {r['name']}: {r['url']}")


interrupted = [False]


def _signal_handler(sig, frame):
    print("\n[INTERRUPT] Ctrl+C received, stopping after current task finishes...")
    interrupted[0] = True


def main():
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Clone repos from vuln_analysis.json")
    parser.add_argument("--limit", type=int, default=None, help="Number of repos to clone (default: all)")
    parser.add_argument("--workers", type=int, default=1, help="Number of parallel workers (default: 1)")
    parser.add_argument("--output-dir", type=str, default="repos", help="Output directory (default: repos)")
    parser.add_argument("--json", type=str, default="vuln_analysis.json", help="Path to vuln_analysis.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Create an empty template directory to avoid Windows fsmonitor-watchman errors
    template_dir = os.path.join(tempfile.gettempdir(), "git_clone_empty_template")
    os.makedirs(template_dir, exist_ok=True)

    repos = load_repos(args.json)
    total = len(repos)
    limit = total if args.limit is None else min(args.limit, total)
    target_repos = repos[:limit]

    # Pre-compute ALL paths upfront (no race conditions)
    path_map = build_path_map(target_repos, args.output_dir)

    collisions = [url for url, (d, _) in path_map.items() if "_" in d.split("/")[-1] and any(c.isalpha() for c in d.split("/")[-1].split("_")[-1])]
    if collisions:
        print(f"Note: {len(collisions)} repos renamed due to Windows name collisions:")
        for url in collisions:
            display, _ = path_map[url]
            print(f"  {url.split('/')[-1]} -> {display}")

    print(f"Total repos in JSON: {total}")
    print(f"Will process: {limit}")
    print(f"Workers:      {args.workers}")
    print(f"Output dir:   {os.path.abspath(args.output_dir)}")
    print()

    results = {"ok": [], "failed": [], "skipped": [], "auth_required": []}
    overall_start = time.time()

    # Build task list with pre-computed paths
    tasks = []
    for repo_info in target_repos:
        url = repo_info["github_url"]
        _, repo_path = path_map[url]
        tasks.append((url, repo_path))

    if args.workers <= 1:
        # Sequential
        global _template_dir
        _template_dir = template_dir

        for i, (url, repo_path) in enumerate(tasks):
            if interrupted[0]:
                print(f"[SKIP] Remaining {limit - i} repos skipped due to interrupt.")
                break

            display, _ = path_map[url]
            print(f"[{i+1}/{limit}] {display}")

            name, status, elapsed = clone_repo(url, repo_path)

            if status == "ok":
                size_mb = get_dir_size_mb(repo_path)
                print(f"  [DONE] {name} ({size_mb:.1f} MB, {elapsed:.1f}s)")
                results["ok"].append({"name": name, "url": url, "elapsed": elapsed})
            elif status == "skipped":
                print(f"  [SKIP] {name} already exists")
                results["skipped"].append({"name": name, "url": url})
            elif status == "auth_required":
                print(f"  [AUTH] {name} requires authentication, skipping")
                results["auth_required"].append({"name": name, "url": url})
            else:
                print(f"  [FAIL] {name}: {status}")
                results["failed"].append({"name": name, "url": url, "error": status})
    else:
        # Parallel
        with ProcessPoolExecutor(
            max_workers=args.workers,
            initializer=_init_worker,
            initargs=(template_dir,),
        ) as executor:
            futures = {executor.submit(_worker_parallel, t): i for i, t in enumerate(tasks)}

            try:
                for future in as_completed(futures):
                    i = futures[future]
                    url = tasks[i][0]
                    name, status, elapsed = future.result()

                    if status == "ok":
                        repo_path = tasks[i][1]
                        size_mb = get_dir_size_mb(repo_path)
                        print(f"[{i+1}/{limit}] [DONE] {name} ({size_mb:.1f} MB, {elapsed:.1f}s)")
                        results["ok"].append({"name": name, "url": url, "elapsed": elapsed})
                    elif status == "skipped":
                        print(f"[{i+1}/{limit}] [SKIP] {name}")
                        results["skipped"].append({"name": name, "url": url})
                    elif status == "auth_required":
                        print(f"[{i+1}/{limit}] [AUTH] {name} requires authentication, skipping")
                        results["auth_required"].append({"name": name, "url": url})
                    else:
                        print(f"[{i+1}/{limit}] [FAIL] {name}: {status}")
                        results["failed"].append({"name": name, "url": url, "error": status})

                    if interrupted[0]:
                        break
            except KeyboardInterrupt:
                interrupted[0] = True
                print("\n[INTERRUPT] Waiting for in-flight clones to finish...")
                executor.shutdown(wait=True, cancel_futures=True)

    print_summary(results, overall_start)

    if interrupted[0]:
        print("\nRe-run the same command to resume — already-cloned repos will be skipped.")


if __name__ == "__main__":
    main()
