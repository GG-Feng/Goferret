import json
import os
import re
from collections import defaultdict, OrderedDict

VULN_DIR = r"E:\go_vuln_detect\vuln"
OUTPUT_FILE = r"E:\go_vuln_detect\vuln_analysis.json"


def find_patch_commit(references):
    for ref in references:
        m = re.search(r'github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})', ref)
        if m:
            repo = "github.com/" + m.group(1)
            commit = m.group(2)
            return repo, commit, ref
    for ref in references:
        m = re.search(r'go\.googlesource\.com/[^/]+/\+/([0-9a-f]{7,40})', ref)
        if m:
            commit = m.group(1)
            return "github.com/golang/go", commit, ref
    return None, None, None


def resolve_repo(module_path, patch_repo):
    if patch_repo:
        return patch_repo
    if module_path.startswith("github.com/"):
        parts = module_path.split("/")
        if len(parts) >= 3:
            return "/".join(parts[:3])
        return module_path
    if "/" in module_path and not module_path.startswith("github.com/"):
        return "github.com/golang/go"
    return module_path


def main():
    vulns = []
    has_patch_count = 0
    no_patch_count = 0
    skipped_count = 0

    repo_commits = defaultdict(lambda: {"patch_commits": set(), "latest_only_vulns": []})

    for fname in sorted(os.listdir(VULN_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(VULN_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "error" in data and "affects" not in data:
            skipped_count += 1
            continue

        go_id = data.get("go_id", "")
        affects = data.get("affects", [])
        references = data.get("references", [])
        aliases = data.get("aliases", [])
        description = data.get("description", "")

        module_path = affects[0].get("path", "") if affects else ""
        go_versions = affects[0].get("go_versions", "") if affects else ""

        patch_repo, patch_commit, patch_url = find_patch_commit(references)

        repo = resolve_repo(module_path, patch_repo)

        if patch_commit:
            has_patch_count += 1
            repo_commits[repo]["patch_commits"].add(patch_commit)
            vuln_entry = {
                "go_id": go_id,
                "aliases": aliases,
                "repo": repo,
                "module_path": module_path,
                "has_patch": True,
                "patch_commit": patch_commit,
                "patch_url": patch_url,
                "go_versions": go_versions,
                "description": description,
                "snapshots_needed": 2,
                "snapshot_type": "patch_commit_and_parent",
                "note": "patch_commit is the fix; its git parent^ is the vulnerable version"
            }
        else:
            no_patch_count += 1
            repo_commits[repo]["latest_only_vulns"].append(go_id)
            vuln_entry = {
                "go_id": go_id,
                "aliases": aliases,
                "repo": repo,
                "module_path": module_path,
                "has_patch": False,
                "patch_commit": None,
                "patch_url": None,
                "go_versions": go_versions,
                "description": description,
                "snapshots_needed": 1,
                "snapshot_type": "latest_version",
                "note": "no patch commit in references, download latest version"
            }

        vulns.append(vuln_entry)

    unique_patch_commits = set()
    for rv in repo_commits.values():
        unique_patch_commits.update(rv["patch_commits"])

    repos_with_latest = sum(1 for v in repo_commits.values() if v["latest_only_vulns"])
    total_snapshots = len(unique_patch_commits) * 2 + repos_with_latest

    repos_output = []
    for repo in sorted(repo_commits.keys()):
        info = repo_commits[repo]
        patch_list = sorted(info["patch_commits"])
        need_latest = len(info["latest_only_vulns"]) > 0

        repo_vulns_list = [v for v in vulns if v["repo"] == repo]
        patched_vulns = [v for v in repo_vulns_list if v["has_patch"]]
        unpatched_vulns = [v for v in repo_vulns_list if not v["has_patch"]]

        downloads = len(patch_list) * 2
        if need_latest:
            downloads += 1

        entry = OrderedDict()
        entry["repo"] = repo
        entry["github_url"] = f"https://{repo}" if repo.startswith("github.com/") else repo
        entry["vuln_count"] = len(repo_vulns_list)
        entry["patched_vulns"] = len(patched_vulns)
        entry["unpatched_vulns"] = len(unpatched_vulns)
        entry["total_snapshots_needed"] = downloads

        entry["patch_commits"] = [
            {
                "commit": c,
                "meaning": "patch_commit = fix (after); parent^ = vulnerable (before)"
            }
            for c in patch_list
        ]
        entry["need_latest_version"] = need_latest
        if need_latest:
            entry["latest_version_vuln_ids"] = info["latest_only_vulns"]

        repos_output.append(entry)

    result = OrderedDict()
    result["summary"] = OrderedDict()
    result["summary"]["total_vulns"] = len(vulns)
    result["summary"]["skipped_error_files"] = skipped_count
    result["summary"]["unique_repos"] = len(repo_commits)
    result["summary"]["vulns_with_patch"] = has_patch_count
    result["summary"]["vulns_without_patch"] = no_patch_count
    result["summary"]["unique_patch_commits"] = len(unique_patch_commits)
    result["summary"]["repos_needing_latest"] = repos_with_latest
    result["summary"]["total_snapshots_needed"] = total_snapshots
    result["summary"]["breakdown"] = OrderedDict()
    result["summary"]["breakdown"]["patch_commit_snapshots_fix"] = len(unique_patch_commits)
    result["summary"]["breakdown"]["patch_parent_snapshots_vulnerable"] = len(unique_patch_commits)
    result["summary"]["breakdown"]["latest_version_snapshots"] = repos_with_latest

    result["repos"] = repos_output
    result["vulnerabilities"] = vulns

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"=== Vuln Analysis ===")
    print(f"Skipped (error files):    {skipped_count}")
    print(f"Valid vulns:              {len(vulns)}")
    print(f"Unique repos:             {len(repo_commits)}")
    print(f"Vulns with patch:         {has_patch_count}")
    print(f"Vulns without patch:      {no_patch_count}")
    print(f"Unique patch commits:     {len(unique_patch_commits)}")
    print(f"Repos needing latest:     {repos_with_latest}")
    print(f"---")
    print(f"Snapshots to download:")
    print(f"  patch commit (fix):     {len(unique_patch_commits)}")
    print(f"  parent commit (vuln):   {len(unique_patch_commits)}")
    print(f"  latest version:         {repos_with_latest}")
    print(f"  TOTAL:                  {total_snapshots}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
