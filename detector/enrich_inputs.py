"""
Enrich vulnerability inputs with Go AST analysis results.

Reads vuln_data/ directories, extracts call chains and stdlib signals
via the Go AST analyzer, and produces enriched inputs for classification.

Usage:
    python enrich_inputs.py --all
    python enrich_inputs.py --all --limit 10
    python enrich_inputs.py GO-2020-0019
"""

import json
import os
import re
import sys
import argparse

from prepare_input import parse_diff_info, strip_test_hunks, extract_func_context
from go_ast_analysis import analyze_go_source


def extract_full_func_source(vulnerable_dir, fpath, func_name):
    """Extract the complete source of a function from a Go file."""
    source_path = os.path.join(vulnerable_dir, fpath)
    if not os.path.isfile(source_path):
        return None

    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None

    func_name_escaped = re.escape(func_name)
    patterns = [
        re.compile(r'^func\s+\(.*?\)\s+' + func_name_escaped + r'\s*\('),
        re.compile(r'^func\s+' + func_name_escaped + r'\s*\('),
    ]

    for pattern in patterns:
        for i, line in enumerate(lines):
            if pattern.search(line):
                # Find the end of the function by matching braces
                depth = 0
                start = i
                for j in range(i, len(lines)):
                    depth += lines[j].count('{') - lines[j].count('}')
                    if depth == 0 and j > i:
                        return ''.join(lines[start:j + 1]).rstrip()
                return ''.join(lines[start:]).rstrip()

    return None


def extract_func_names_from_hunks(hunks):
    """Extract function names from diff hunk headers."""
    names = []
    seen = set()
    for (fpath, line_no, func_header) in hunks:
        if not func_header:
            continue
        func_match = re.match(r'func\s+(?:\(.*?\)\s+)?(\w+)\s*\(', func_header)
        if func_match:
            name = func_match.group(1)
            key = (fpath, name)
            if key not in seen:
                seen.add(key)
                names.append(name)
    return names


def enrich_one(vuln_data_dir, go_id):
    """Prepare enriched input for a single vulnerability."""
    vuln_dir = os.path.join(vuln_data_dir, go_id)

    diff_path = os.path.join(vuln_dir, 'patch.diff')
    vuln_json_path = os.path.join(vuln_dir, 'vuln.json')
    vulnerable_dir = os.path.join(vuln_dir, 'vulnerable')

    if not os.path.isfile(diff_path):
        return None, "no patch.diff"
    if not os.path.isfile(vuln_json_path):
        return None, "no vuln.json"

    # Read vuln metadata
    try:
        with open(vuln_json_path, 'r', encoding='utf-8') as f:
            vuln = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "invalid vuln.json"

    if 'error' in vuln and 'affects' not in vuln:
        return None, "vuln has error, no affects data"

    # Read diff
    try:
        with open(diff_path, 'r', encoding='utf-8', errors='replace') as f:
            diff_text = f.read()
    except Exception:
        return None, "cannot read patch.diff"

    # Parse diff
    changed_files, hunks = parse_diff_info(diff_text)
    hunks = strip_test_hunks(hunks)

    # Extract function names from hunks
    func_names = extract_func_names_from_hunks(hunks)

    # Extract full function sources
    func_sources = []
    seen = set()
    for (fpath, line_no, func_header) in hunks:
        if not func_header:
            continue
        func_match = re.match(r'func\s+(?:\(.*?\)\s+)?(\w+)\s*\(', func_header)
        if not func_match:
            continue
        name = func_match.group(1)
        key = (fpath, name)
        if key in seen:
            continue
        seen.add(key)

        source = extract_full_func_source(vulnerable_dir, fpath, name)
        if source:
            func_sources.append({
                "file": fpath,
                "function": name,
                "source": source,
            })

    # Run Go AST analysis on vulnerable/ directory
    go_files = [f for f in changed_files if f.endswith('.go') and not f.endswith('_test.go')]
    ast_result = analyze_go_source(
        vulnerable_dir,
        changed_files=go_files if go_files else None,
        focus_functions=func_names if func_names else None,
    )

    # Build enriched input
    result = {
        "go_id": vuln.get("go_id", go_id),
        "description": vuln.get("description", ""),
        "aliases": vuln.get("aliases", []),
        "module_path": vuln["affects"][0]["path"] if vuln.get("affects") else "",
        "affected_symbols": vuln["affects"][0].get("symbols", []) if vuln.get("affects") else [],
        "go_versions": vuln["affects"][0].get("go_versions", "") if vuln.get("affects") else "",
        "changed_files": [f for f in changed_files if not f.endswith('_test.go')],
        "changed_functions": [
            {"file": f, "function": h} for (f, _, h) in hunks if h
        ],
        "func_sources": func_sources,
        "patch_diff": diff_text,
        "ast_analysis": ast_result,
    }

    return result, None


def main():
    parser = argparse.ArgumentParser(description="Enrich vuln inputs with AST analysis")
    parser.add_argument("go_id", nargs="?", help="Single GO-ID to process")
    parser.add_argument("--all", action="store_true", help="Process all vulns with patches")
    parser.add_argument("--vuln-data-dir", default="vuln_data", help="vuln_data directory")
    parser.add_argument("--output-dir", default="enriched_inputs", help="Output directory")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process")
    parser.add_argument("--force", action="store_true", help="Overwrite existing outputs")
    args = parser.parse_args()

    if not args.all and not args.go_id:
        parser.error("Specify a GO-ID or use --all")

    os.makedirs(args.output_dir, exist_ok=True)

    if args.go_id:
        result, err = enrich_one(args.vuln_data_dir, args.go_id)
        if err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(1)
        out_path = os.path.join(args.output_dir, f"{args.go_id}.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"Written: {out_path}")
        return

    # --all mode
    entries = sorted(os.listdir(args.vuln_data_dir))
    if args.limit:
        entries = entries[:args.limit]

    total = len(entries)
    ok = 0
    skipped = 0
    failed = 0

    for i, go_id in enumerate(entries):
        vuln_dir = os.path.join(args.vuln_data_dir, go_id)
        if not os.path.isdir(vuln_dir):
            continue

        out_path = os.path.join(args.output_dir, f"{go_id}.json")
        if os.path.isfile(out_path) and not args.force:
            skipped += 1
            continue

        result, err = enrich_one(args.vuln_data_dir, go_id)
        if result is None:
            skipped += 1
            continue

        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            ok += 1
        except Exception as e:
            print(f"  [{go_id}] Write error: {e}", file=sys.stderr)
            failed += 1

        if (ok + skipped + failed) % 50 == 0:
            print(f"  Progress: {ok} ok, {skipped} skipped, {i+1}/{total}")

    print(f"\nDone: {ok} enriched, {skipped} skipped, {failed} failed")
    print(f"Output: {os.path.abspath(args.output_dir)}")


if __name__ == "__main__":
    main()
