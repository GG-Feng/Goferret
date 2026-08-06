"""
Generate per-repo vulnerability info JSON files from vuln_infos.json.

Each output file contains all vulns for one repo, with go_id, aliases,
patch_commit, and vulnerable_commit resolved.

Usage:
    python generate_vuln_infos.py
    python generate_vuln_infos.py --json vuln_infos.json --output-dir vuln_infos
"""

import json
import os
import hashlib
import argparse
from collections import defaultdict


def build_safe_filename(github_url):
    """Convert github URL to a safe filename, handling collisions."""
    parts = github_url.rstrip("/").split("/")[-2:]
    return "_".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Generate per-repo vuln info JSONs")
    parser.add_argument("--json", type=str, default="vuln_infos.json", help="Input JSON file")
    parser.add_argument("--output-dir", type=str, default="vuln_infos", help="Output directory")
    args = parser.parse_args()

    with open(args.json, "r", encoding="utf-8") as f:
        data = json.load(f)

    repos = data["repos"]
    vulnerabilities = data["vulnerabilities"]

    # Build go_id -> vulnerability lookup
    vulns_by_id = {v["go_id"]: v for v in vulnerabilities}

    # Group vulnerabilities by repo (case-insensitive key)
    vulns_by_repo = defaultdict(list)
    for v in vulnerabilities:
        vulns_by_repo[v["repo"].lower()].append(v)

    # Build patch_commit -> vulnerable_commit lookup per repo (case-insensitive key)
    # Merge ALL duplicate entries' patch_commits and latest_version_vuln_ids
    repo_commit_map = {}
    repo_latest_ids = {}
    for repo_entry in repos:
        repo_key = repo_entry["repo"].lower()
        if repo_key not in repo_commit_map:
            repo_commit_map[repo_key] = {}
            repo_latest_ids[repo_key] = []
        for pc in repo_entry.get("patch_commits", []):
            repo_commit_map[repo_key][pc["commit"]] = pc.get("vulnerable_commit")
        repo_latest_ids[repo_key].extend(repo_entry.get("latest_version_vuln_ids", []))

    os.makedirs(args.output_dir, exist_ok=True)

    # Track filenames for collision detection and deduplicate repos
    used_filenames = {}
    seen_repos = set()
    total_vulns = 0
    total_files = 0

    for repo_entry in repos:
        repo_name = repo_entry["repo"]
        repo_key = repo_name.lower()
        if repo_key in seen_repos:
            continue
        seen_repos.add(repo_key)
        repo_name = repo_entry["repo"]
        github_url = repo_entry["github_url"]
        commit_map = repo_commit_map[repo_key]
        vulns = vulns_by_repo.get(repo_key, [])

        # Also include vulns from latest_version_vuln_ids whose repo field
        # is a module name (e.g. "syscall", "net") rather than a github path
        collected_go_ids = {v["go_id"] for v in vulns}
        for gid in repo_latest_ids.get(repo_key, []):
            if gid not in collected_go_ids and gid in vulns_by_id:
                vulns.append(vulns_by_id[gid])
                collected_go_ids.add(gid)

        if not vulns:
            continue

        # Build output vulns list
        output_vulns = []
        patched = 0
        unpatched = 0

        for v in vulns:
            entry = {
                "go_id": v["go_id"],
                "aliases": v.get("aliases", []),
            }

            if v["has_patch"] and v["patch_commit"]:
                entry["has_patch"] = True
                entry["patch_commit"] = v["patch_commit"]
                entry["vulnerable_commit"] = commit_map.get(v["patch_commit"])
                patched += 1
            else:
                entry["has_patch"] = False
                entry["patch_commit"] = None
                entry["vulnerable_commit"] = "latest"
                unpatched += 1

            output_vulns.append(entry)

        output = {
            "repo": repo_name,
            "github_url": github_url,
            "vulns": output_vulns,
            "summary": {
                "total_vulns": len(output_vulns),
                "patched": patched,
                "unpatched": unpatched,
            },
        }

        # Resolve filename with collision handling
        base_name = build_safe_filename(github_url)
        if base_name in used_filenames:
            h = hashlib.sha256(github_url.encode()).hexdigest()[:8]
            base_name = f"{base_name}_{h}"
        used_filenames[base_name] = True

        out_path = os.path.join(args.output_dir, f"{base_name}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        total_vulns += len(output_vulns)
        total_files += 1

    print(f"Generated {total_files} files in {args.output_dir}/")
    print(f"Total vulns across all files: {total_vulns}")


if __name__ == "__main__":
    main()
