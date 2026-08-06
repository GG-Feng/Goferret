"""
Preprocess vuln_data into structured input for the functional domain classifier.

For each vulnerability with a patch, extracts:
  - vuln.json metadata
  - patch.diff (raw)
  - changed function signatures + context from vulnerable/ source

Usage:
    python prepare_input.py GO-2020-0019
    python prepare_input.py --all
    python prepare_input.py --all --output-dir prepared_inputs
    python prepare_input.py --all --limit 10
"""

import json
import os
import re
import argparse
import sys


def parse_diff_info(diff_text):
    """Parse a unified diff to extract changed files and hunk locations."""
    files = []
    current_file = None
    hunks = []  # (file, start_line, func_header)

    for line in diff_text.splitlines():
        # New file
        m = re.match(r'^diff --git a/(.*?) b/(.*?)$', line)
        if m:
            current_file = m.group(2)
            if current_file.endswith('_test.go') or not current_file.endswith('.go'):
                current_file = None
                continue
            files.append(current_file)
            continue

        if current_file is None:
            continue

        # Hunk header: @@ -old_start,count +new_start,count @@ func_header
        m = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)', line)
        if m:
            new_start = int(m.group(1))
            func_header = m.group(2).strip()
            hunks.append((current_file, new_start, func_header))

    return files, hunks


def extract_func_context(source_path, func_name, context_lines=25):
    """Extract function signature + first N lines from a Go source file.

    Works for both standalone functions (func Foo(...)) and methods
    (func (r *Type) Foo(...)).
    """
    if not os.path.isfile(source_path):
        return None

    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None

    # Build pattern to find the function/method
    # func_name could be "advanceFrame" or "(c *Conn) advanceFrame"
    func_name_clean = re.escape(func_name)

    # Try method: func (receiver) Name(
    # Try function: func Name(
    # Try type: type Name struct/interface
    patterns = [
        re.compile(r'^func\s+\(.*?\)\s+' + func_name_clean + r'\s*\('),
        re.compile(r'^func\s+' + func_name_clean + r'\s*\('),
        re.compile(r'^type\s+' + func_name_clean + r'\s+'),
    ]

    for pattern in patterns:
        for i, line in enumerate(lines):
            if pattern.search(line):
                # Extract from this line, up to context_lines
                start = i
                end = min(i + context_lines, len(lines))
                snippet = ''.join(lines[start:end])
                return snippet.rstrip()

    return None


def extract_hunk_context(source_path, line_no, context_lines=15):
    """Fallback: extract lines around a hunk location."""
    if not os.path.isfile(source_path):
        return None

    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None

    # line_no is 1-based from the diff (new file side)
    idx = line_no - 1
    start = max(0, idx - 3)
    end = min(len(lines), idx + context_lines)
    return ''.join(lines[start:end]).rstrip()


def strip_test_hunks(hunks):
    """Remove hunks from _test.go files — they don't help classification."""
    seen = set()
    filtered = []
    for (fpath, line_no, header) in hunks:
        if fpath.endswith('_test.go'):
            continue
        key = (fpath, header)
        if key in seen:
            continue
        seen.add(key)
        filtered.append((fpath, line_no, header))
    return filtered


def prepare_one(vuln_data_dir, go_id):
    """Prepare structured input for a single vulnerability."""
    vuln_dir = os.path.join(vuln_data_dir, go_id)

    # Check it has a patch
    diff_path = os.path.join(vuln_dir, 'patch.diff')
    vuln_json_path = os.path.join(vuln_dir, 'vuln.json')
    vulnerable_dir = os.path.join(vuln_dir, 'vulnerable')

    if not os.path.isfile(diff_path):
        return None, "no patch.diff"
    if not os.path.isfile(vuln_json_path):
        return None, "no vuln.json"

    # Read inputs
    with open(vuln_json_path, 'r', encoding='utf-8') as f:
        vuln = json.load(f)

    with open(diff_path, 'r', encoding='utf-8', errors='replace') as f:
        diff_text = f.read()

    if 'error' in vuln and 'affects' not in vuln:
        return None, "vuln has error, no affects data"

    # Parse diff
    changed_files, hunks = parse_diff_info(diff_text)
    hunks = strip_test_hunks(hunks)

    # Extract function contexts from vulnerable/ source
    func_contexts = []
    seen_funcs = set()

    for (fpath, line_no, func_header) in hunks:
        if not func_header:
            continue

        # Extract function name from hunk header
        # Examples: "func (c *Conn) advanceFrame() (int, error)"
        #           "type Conn struct"
        #           "func newConn(...)"
        func_match = re.match(r'func\s+(?:\(.*?\)\s+)?(\w+)\s*\(', func_header)
        type_match = re.match(r'type\s+(\w+)\s+', func_header)

        name = None
        if func_match:
            name = func_match.group(1)
        elif type_match:
            name = type_match.group(1)

        if not name:
            continue

        ctx_key = (fpath, name)
        if ctx_key in seen_funcs:
            continue
        seen_funcs.add(ctx_key)

        source_path = os.path.join(vulnerable_dir, fpath)
        ctx = extract_func_context(source_path, name)
        if ctx:
            func_contexts.append({
                "file": fpath,
                "function": func_header,
                "source_context": ctx,
            })
        else:
            # Fallback: just extract lines around the hunk
            ctx = extract_hunk_context(source_path, line_no)
            if ctx:
                func_contexts.append({
                    "file": fpath,
                    "function": func_header,
                    "source_context": ctx,
                })

    # Build output
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
        "func_source_contexts": func_contexts,
        "patch_diff": diff_text,
    }

    return result, None


def main():
    parser = argparse.ArgumentParser(description="Prepare structured input for vuln classifier")
    parser.add_argument("go_id", nargs="?", help="Single GO-ID to process (e.g. GO-2020-0019)")
    parser.add_argument("--all", action="store_true", help="Process all vulns with patches")
    parser.add_argument("--vuln-data-dir", default="vuln_data", help="vuln_data directory")
    parser.add_argument("--output-dir", default="prepared_inputs", help="Output directory")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process")
    parser.add_argument("--stdout", action="store_true", help="Print one result to stdout (for single go_id)")
    args = parser.parse_args()

    if not args.all and not args.go_id:
        parser.error("Specify a GO-ID or use --all")

    if args.go_id:
        result, err = prepare_one(args.vuln_data_dir, args.go_id)
        if err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(1)
        if args.stdout:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            os.makedirs(args.output_dir, exist_ok=True)
            out_path = os.path.join(args.output_dir, f"{args.go_id}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"Written: {out_path}")
        return

    # --all mode
    os.makedirs(args.output_dir, exist_ok=True)

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

        result, err = prepare_one(args.vuln_data_dir, go_id)
        if result is None:
            skipped += 1
            continue

        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        ok += 1

        if (ok + skipped + failed) % 100 == 0:
            print(f"  Progress: {ok} ok, {skipped} skipped, {i+1}/{total}")

    print(f"\nDone: {ok} prepared, {skipped} skipped (no patch)")
    print(f"Output: {os.path.abspath(args.output_dir)}")


if __name__ == "__main__":
    main()
