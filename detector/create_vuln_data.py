"""
Create per-vuln snapshots in vuln_data/ from vuln_infos/ and cloned repos.

For each vulnerability (GO-XXXX-XXXX), creates:
  vuln_data/GO-XXXX-XXXX/
    vuln.json          - copied from vuln/GO-XXXX-XXXX.json
    vulnerable/        - source snapshot at vulnerable commit
    patch/             - source snapshot at patch commit (if has_patch)
    patch.diff         - diff between vulnerable and patch (if has_patch)

Resumable: skips already-completed vuln directories.
Ctrl+C safe: handles graceful interruption.

Usage:
    python create_vuln_data.py
    python create_vuln_data.py --workers 4
    python create_vuln_data.py --limit 10 --workers 2
"""

import json
import os
import shutil
import subprocess
import argparse
import signal
import sys
import hashlib
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

# ── globals ──────────────────────────────────────────────────────────

interrupted = False


def _signal_handler(sig, frame):
    global interrupted
    if interrupted:
        print("\n[FORCE EXIT]")
        sys.exit(1)
    interrupted = True
    print("\n[INTERRUPT] Ctrl+C received, stopping after current tasks...")


# ── path helpers ─────────────────────────────────────────────────────

def build_path_map(vuln_info_files, repos_dir):
    """Build github_url -> bare repo path mapping.

    Mirrors the collision-aware logic from download_repos.py so we find
    the correct directory even for renamed repos.
    """
    path_map = {}
    assigned = {}

    for info in vuln_info_files:
        github_url = info["github_url"]
        parts = github_url.rstrip("/").split("/")[-2:]
        if len(parts) < 2:
            continue
        owner, repo = parts

        key = (owner.lower(), repo.lower())
        if key in assigned:
            h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
            repo = f"{repo}_{h}"

        assigned[key] = True
        repo_path = os.path.join(repos_dir, owner, repo)
        path_map[github_url] = repo_path

    return path_map


def find_repo_path(github_url, path_map, repos_dir):
    """Look up repo path, with fallback scanning for hash-suffixed dirs."""
    repo_path = path_map.get(github_url)
    if repo_path and os.path.isdir(repo_path):
        return repo_path

    parts = github_url.rstrip("/").split("/")[-2:]
    owner, repo = parts
    owner_dir = os.path.join(repos_dir, owner)

    if os.path.isdir(owner_dir):
        # Exact match
        exact = os.path.join(owner_dir, repo)
        if os.path.isdir(exact):
            return exact
        # Scan for hash-suffixed match
        h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
        expected = f"{repo}_{h}"
        if expected in os.listdir(owner_dir):
            return os.path.join(owner_dir, expected)

    return repo_path  # may not exist


def is_completed(vuln_dir, has_patch):
    """Check if a vuln directory already has all expected outputs."""
    if not os.path.isdir(vuln_dir):
        return False
    if not os.path.isfile(os.path.join(vuln_dir, "vuln.json")):
        return False
    if not os.path.isdir(os.path.join(vuln_dir, "vulnerable")):
        return False
    if has_patch:
        if not os.path.isdir(os.path.join(vuln_dir, "patch")):
            return False
        if not os.path.isfile(os.path.join(vuln_dir, "patch.diff")):
            return False
    return True


# ── git operations on bare repos ─────────────────────────────────────

def git_archive(git_dir, commit, dest_dir):
    """Extract source tree at a commit into dest_dir.

    Streams git archive to a temp zip file on disk, then extracts
    file-by-file to avoid loading everything into memory at once.
    """
    import zipfile
    import tempfile

    os.makedirs(dest_dir, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    try:
        with open(tmp_fd, "wb") as tmp_f:
            proc = subprocess.Popen(
                ["git", "--git-dir", git_dir, "archive", "--format=zip", commit],
                stdout=tmp_f, stderr=subprocess.PIPE,
            )
            _, stderr = proc.communicate(timeout=600)
            if proc.returncode != 0:
                return False, stderr.decode("utf-8", errors="replace")[:200]

        # Extract members one at a time to keep memory usage low
        with zipfile.ZipFile(tmp_path) as zf:
            for member in zf.infolist():
                # Skip entries that would exceed path length limits on Windows
                try:
                    zf.extract(member, dest_dir)
                except (OSError, zipfile.BadZipFile):
                    pass
    except Exception as e:
        return False, f"archive failed: {e}"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return True, None


def git_diff(git_dir, vuln_commit, patch_commit, dest_file):
    """Save diff between two commits to a file (streamed to disk)."""
    try:
        with open(dest_file, "wb") as f:
            proc = subprocess.Popen(
                ["git", "--git-dir", git_dir, "diff", vuln_commit, patch_commit],
                stdout=f, stderr=subprocess.PIPE,
            )
            _, stderr = proc.communicate(timeout=300)
            if proc.returncode != 0:
                if os.path.isfile(dest_file):
                    os.remove(dest_file)
                return False, stderr.decode("utf-8", errors="replace")[:200]
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        if os.path.isfile(dest_file):
            os.remove(dest_file)
        return False, "diff timed out after 300s"
    return True, None


def git_resolve_head(git_dir):
    """Resolve HEAD to a commit SHA."""
    result = subprocess.run(
        ["git", "--git-dir", git_dir, "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def commit_exists(git_dir, commit):
    """Check if a commit exists in the repo."""
    result = subprocess.run(
        ["git", "--git-dir", git_dir, "cat-file", "-t", commit],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0 and "commit" in result.stdout


# ── worker ───────────────────────────────────────────────────────────

def process_vuln(task):
    """Process a single vulnerability. Returns (go_id, status, message)."""
    go_id, has_patch, patch_commit, vulnerable_commit, repo_git_dir, vuln_json_src, output_base = task

    vuln_dir = os.path.join(output_base, go_id)

    # Skip if already completed (resume support)
    if is_completed(vuln_dir, has_patch):
        return go_id, "skipped", None

    os.makedirs(vuln_dir, exist_ok=True)

    # Copy vuln.json
    vuln_json_dst = os.path.join(vuln_dir, "vuln.json")
    if not os.path.isfile(vuln_json_dst):
        if os.path.isfile(vuln_json_src):
            shutil.copy2(vuln_json_src, vuln_json_dst)
        else:
            return go_id, "warn", "vuln.json source not found"

    # Resolve "latest" to actual commit
    if vulnerable_commit == "latest":
        vulnerable_commit = git_resolve_head(repo_git_dir)
        if not vulnerable_commit:
            return go_id, "failed", "cannot resolve HEAD"

    # Validate commits exist
    if not commit_exists(repo_git_dir, vulnerable_commit):
        return go_id, "failed", f"vulnerable commit {vulnerable_commit[:12]} not in repo"

    if has_patch and patch_commit:
        if not commit_exists(repo_git_dir, patch_commit):
            return go_id, "failed", f"patch commit {patch_commit[:12]} not in repo"

    # Extract vulnerable snapshot
    vuln_snap_dir = os.path.join(vuln_dir, "vulnerable")
    if not os.path.isdir(vuln_snap_dir) or not os.listdir(vuln_snap_dir):
        ok, err = git_archive(repo_git_dir, vulnerable_commit, vuln_snap_dir)
        if not ok:
            shutil.rmtree(vuln_snap_dir, ignore_errors=True)
            return go_id, "failed", f"vulnerable archive: {err}"

    if has_patch and patch_commit:
        # Extract patch snapshot
        patch_snap_dir = os.path.join(vuln_dir, "patch")
        if not os.path.isdir(patch_snap_dir) or not os.listdir(patch_snap_dir):
            ok, err = git_archive(repo_git_dir, patch_commit, patch_snap_dir)
            if not ok:
                shutil.rmtree(patch_snap_dir, ignore_errors=True)
                return go_id, "failed", f"patch archive: {err}"

        # Save diff
        diff_file = os.path.join(vuln_dir, "patch.diff")
        if not os.path.isfile(diff_file) or os.path.getsize(diff_file) == 0:
            ok, err = git_diff(repo_git_dir, vulnerable_commit, patch_commit, diff_file)
            if not ok:
                if os.path.isfile(diff_file):
                    os.remove(diff_file)
                return go_id, "failed", f"diff: {err}"

    return go_id, "ok", None


# ── main ─────────────────────────────────────────────────────────────

def main():
    global interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Create per-vuln snapshot directories")
    parser.add_argument("--vuln-infos-dir", default="vuln_infos", help="Dir with per-repo vuln JSONs")
    parser.add_argument("--repos-dir", default="repos", help="Dir with cloned bare repos")
    parser.add_argument("--vuln-dir", default="vuln", help="Dir with raw vuln JSONs")
    parser.add_argument("--output-dir", default="vuln_data", help="Output directory")
    parser.add_argument("--workers", type=int, default=1, help="Parallel workers (default: 1)")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process (for testing)")
    args = parser.parse_args()

    # Load all vuln_info files
    vuln_info_path = os.path.join(args.vuln_infos_dir)
    all_vulns = []
    for fname in os.listdir(vuln_info_path):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(vuln_info_path, fname), "r", encoding="utf-8") as f:
            info = json.load(f)
        all_vulns.append(info)

    # Build path map for repo lookup
    path_map = build_path_map(all_vulns, args.repos_dir)

    # Build task list
    tasks = []
    skipped_no_repo = 0
    skipped_no_commit = 0

    for info in all_vulns:
        github_url = info["github_url"]
        repo_git_dir = find_repo_path(github_url, path_map, args.repos_dir)

        if not os.path.isdir(repo_git_dir):
            skipped_no_repo += len(info["vulns"])
            continue

        for v in info["vulns"]:
            go_id = v["go_id"]
            has_patch = v["has_patch"]
            patch_commit = v.get("patch_commit")
            vulnerable_commit = v.get("vulnerable_commit")

            # Skip if vulnerable_commit is None (parent not resolved)
            if not vulnerable_commit:
                skipped_no_commit += 1
                continue

            vuln_json_src = os.path.join(args.vuln_dir, f"{go_id}.json")
            tasks.append((go_id, has_patch, patch_commit, vulnerable_commit,
                          repo_git_dir, vuln_json_src, args.output_dir))

    if args.limit:
        tasks = tasks[:args.limit]

    print(f"Total tasks: {len(tasks)}")
    if skipped_no_repo:
        print(f"  Skipped (repo not cloned): {skipped_no_repo}")
    if skipped_no_commit:
        print(f"  Skipped (no vulnerable commit): {skipped_no_commit}")
    print(f"Workers: {args.workers}")
    print(f"Output:  {os.path.abspath(args.output_dir)}")
    print()

    os.makedirs(args.output_dir, exist_ok=True)

    # Count already completed (resume check)
    already_done = sum(1 for t in tasks if is_completed(
        os.path.join(args.output_dir, t[0]), t[1]))
    if already_done:
        print(f"Already completed (will skip): {already_done}")

    results = {"ok": [], "skipped": [], "failed": [], "warn": []}
    overall_start = time.time()

    if args.workers <= 1:
        # Sequential
        for i, task in enumerate(tasks):
            if interrupted:
                print(f"\n[INTERRUPT] Stopping. {len(tasks) - i} tasks remaining.")
                break
            go_id, status, msg = process_vuln(task)
            if status == "ok":
                print(f"[{i+1}/{len(tasks)}] {go_id} done")
            elif status == "skipped":
                pass  # silent for resumed
            else:
                print(f"[{i+1}/{len(tasks)}] {go_id} {status}: {msg}")
            results[status].append(go_id)
    else:
        # Parallel
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_vuln, t): t for t in tasks}
            done_count = 0
            try:
                for future in as_completed(futures):
                    if interrupted:
                        break
                    go_id, status, msg = future.result()
                    done_count += 1
                    if status == "ok":
                        print(f"[{done_count}/{len(tasks)}] {go_id} done")
                    elif status != "skipped":
                        print(f"[{done_count}/{len(tasks)}] {go_id} {status}: {msg}")
                    results[status].append(go_id)
            except KeyboardInterrupt:
                interrupted = True
                print("\n[INTERRUPT] Waiting for in-flight tasks...")
                executor.shutdown(wait=True, cancel_futures=True)

    elapsed = time.time() - overall_start
    print()
    print("=" * 50)
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {elapsed:.1f}s")
    print(f"  Completed:  {len(results['ok'])}")
    print(f"  Skipped:    {len(results['skipped'])}")
    print(f"  Warnings:   {len(results['warn'])}")
    print(f"  Failed:     {len(results['failed'])}")
    if results["failed"]:
        print("\nFailed:")
        # Re-read failures from results - we stored go_ids, find messages
        for gid in results["failed"][:20]:
            print(f"  - {gid}")
        if len(results["failed"]) > 20:
            print(f"  ... and {len(results['failed']) - 20} more")

    if interrupted:
        print("\nRe-run the same command to resume — completed vulns will be skipped.")


if __name__ == "__main__":
    main()
