"""
Enrich vuln_analysis.json by looking up the parent (vulnerable) commit
for each patch commit using locally cloned mirror repos.

Usage:
    python enrich_commits.py
    python enrich_commits.py --repos-dir repos
    python enrich_commits.py --repos-dir repos --json vuln_analysis.json
"""

import json
import os
import subprocess
import sys
import hashlib
import argparse
import shutil


def build_path_map(repos, dest_dir):
    """Same collision-aware path logic as download_repos.py."""
    path_map = {}
    assigned = {}

    for repo_info in repos:
        github_url = repo_info["github_url"]
        parts = github_url.rstrip("/").split("/")[-2:]
        owner, repo = parts

        key = (owner.lower(), repo.lower())
        if key in assigned:
            h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
            repo = f"{repo}_{h}"

        assigned[key] = True
        repo_path = os.path.join(dest_dir, owner, repo)
        path_map[github_url] = repo_path

    return path_map


def find_repo_path(repo_info, path_map):
    """Look up pre-computed path, or scan disk for hash-suffixed fallback."""
    github_url = repo_info["github_url"]

    # Primary: exact path from build_path_map
    repo_path = path_map.get(github_url)
    if repo_path and os.path.isdir(repo_path):
        return repo_path

    # Fallback: scan owner dir for hash-suffixed match (for repos cloned by older script versions)
    parts = github_url.rstrip("/").split("/")[-2:]
    owner, repo = parts
    owner_dir = os.path.join(os.path.dirname(path_map.get(github_url, "")), owner) if repo_path else ""

    if sys.platform == "win32" and owner_dir and os.path.isdir(owner_dir):
        h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
        expected = f"{repo}_{h}"
        if expected in os.listdir(owner_dir):
            return os.path.join(owner_dir, expected)

    return repo_path or os.path.join("repos", *parts)


def get_parent_commit(repo_path, commit):
    """Get the parent commit of a given commit using git log in a bare repo."""
    result = subprocess.run(
        ["git", "-C", repo_path, "log", "--format=%P", "-1", commit],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return None
    parents = result.stdout.strip().split()
    # Return first parent (mainline); for merge commits there could be multiple
    return parents[0] if parents else None


def main():
    parser = argparse.ArgumentParser(description="Enrich vuln_analysis.json with vulnerable commit info")
    parser.add_argument("--repos-dir", type=str, default="repos", help="Directory containing cloned mirror repos")
    parser.add_argument("--json", type=str, default="vuln_analysis.json", help="Path to vuln_analysis.json")
    parser.add_argument("--output", type=str, default=None, help="Output file (default: overwrite input)")
    args = parser.parse_args()

    output_path = args.output or args.json

    with open(args.json, "r", encoding="utf-8") as f:
        data = json.load(f)

    repos = data["repos"]
    total_patches = sum(len(r.get("patch_commits", [])) for r in repos)
    print(f"Repos: {len(repos)}, Total patch commits: {total_patches}")

    # Pre-compute all paths with collision resolution
    path_map = build_path_map(repos, args.repos_dir)

    repos_missing = 0
    parents_found = 0
    parents_failed = 0

    for i, repo_info in enumerate(repos):
        repo_path = find_repo_path(repo_info, path_map)
        patch_commits = repo_info.get("patch_commits", [])

        if not patch_commits:
            continue

        if not os.path.isdir(repo_path):
            repos_missing += 1
            for pc in patch_commits:
                pc["vulnerable_commit"] = None
                pc["error"] = "repo not cloned"
            continue

        print(f"[{i+1}/{len(repos)}] {repo_info['repo']} ({len(patch_commits)} patches)")

        for pc in patch_commits:
            commit = pc["commit"]
            parent = get_parent_commit(repo_path, commit)
            if parent:
                pc["vulnerable_commit"] = parent
                parents_found += 1
            else:
                pc["vulnerable_commit"] = None
                pc["error"] = "parent not found"
                parents_failed += 1

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 50)
    print(f"Parents found:   {parents_found}")
    print(f"Parents failed:  {parents_failed}")
    print(f"Repos missing:   {repos_missing}")
    print(f"Output: {os.path.abspath(output_path)}")


if __name__ == "__main__":
    main()
