"""
Re-enrich enriched inputs with AST analysis for entries missing call_chains or data_flow.

The original enrich_inputs.py passes --focus-funcs to the ast_analyzer, but the
extracted function names often don't match actual Go function names (method name
parsing issues), resulting in null call_chains for ~83% of vulns.

This script re-runs the ast_analyzer WITHOUT --focus-funcs for those entries,
improving structured data coverage.

Usage:
    python re_enrich_ast.py
    python re_enrich_ast.py --limit 20
    python re_enrich_ast.py --force
    python re_enrich_ast.py --workers 4
"""

import json
import os
import sys
import argparse
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from go_ast_analysis import analyze_go_source


def needs_re_enrichment(enriched):
    """Check if an enriched input needs AST re-analysis."""
    ast = enriched.get('ast_analysis', {})
    if not ast:
        return True
    if ast.get('call_chains') is None:
        return True
    if ast.get('data_flow_indicators') is None:
        return True
    return False


def re_enrich_one(vuln_data_dir, go_id, enriched):
    """Re-run AST analysis for a single vulnerability and merge results."""
    vuln_dir = os.path.join(vuln_data_dir, go_id)
    vulnerable_dir = os.path.join(vuln_dir, 'vulnerable')

    if not os.path.isdir(vulnerable_dir):
        return None, "no vulnerable/ directory"

    # Get changed Go files (non-test) for focus
    changed_files = enriched.get('changed_files', [])
    go_files = [f for f in changed_files if f.endswith('.go') and not f.endswith('_test.go')]

    # Re-run AST analysis WITHOUT focus_functions
    new_ast = analyze_go_source(
        vulnerable_dir,
        changed_files=go_files if go_files else None,
        focus_functions=None,
    )

    # Check if we actually got better results
    old_ast = enriched.get('ast_analysis', {})
    old_had_chains = old_ast.get('call_chains') is not None
    old_had_flow = old_ast.get('data_flow_indicators') is not None
    new_has_chains = new_ast.get('call_chains') is not None and len(new_ast.get('call_chains', []) or []) > 0
    new_has_flow = new_ast.get('data_flow_indicators') is not None and len(new_ast.get('data_flow_indicators', []) or []) > 0

    if not new_has_chains and not new_has_flow:
        # No improvement - keep old data if it had any
        if old_had_chains or old_had_flow:
            return None, "no improvement over existing data"
        return None, "AST analysis returned no structured data"

    # Merge: prefer new data, but keep old data for fields where new is empty
    merged = new_ast

    # If new call_chains is empty but old had data, keep old
    if not new_has_chains and old_had_chains:
        merged['call_chains'] = old_ast.get('call_chains')

    # If new data_flow is empty but old had data, keep old
    if not new_has_flow and old_had_flow:
        merged['data_flow_indicators'] = old_ast.get('data_flow_indicators')

    enriched['ast_analysis'] = merged

    chain_count = len(merged.get('call_chains') or [])
    flow_count = len(merged.get('data_flow_indicators') or [])
    return enriched, f"chains={chain_count}, flows={flow_count}"


interrupted = False


def _signal_handler(sig, frame):
    global interrupted
    if interrupted:
        print("\n[FORCE EXIT]")
        sys.exit(1)
    interrupted = True
    print("\n[INTERRUPT] Stopping after current items...")


def main():
    global interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Re-enrich AST data for vulns missing call_chains/data_flow")
    parser.add_argument("--vuln-data-dir", default="vuln_data", help="vuln_data directory")
    parser.add_argument("--input-dir", default="enriched_inputs", help="enriched_inputs directory")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process")
    parser.add_argument("--force", action="store_true", help="Re-analyze all vulns, even those with data")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent workers")
    args = parser.parse_args()

    # Scan for vulns needing re-enrichment
    pending = []
    for f in sorted(os.listdir(args.input_dir)):
        if not f.endswith('.json'):
            continue
        go_id = f.replace('.json', '')

        with open(os.path.join(args.input_dir, f), encoding='utf-8') as fh:
            enriched = json.load(fh)

        if args.force or needs_re_enrichment(enriched):
            pending.append(go_id)

    if args.limit:
        pending = pending[:args.limit]

    print(f"Vulns needing re-enrichment: {len(pending)}")
    print(f"Workers: {args.workers}")
    print()

    if not pending:
        print("Nothing to do.")
        return

    results = {'ok': 0, 'no_change': 0, 'failed': 0}
    overall_start = time.time()

    def process(go_id):
        input_path = os.path.join(args.input_dir, f"{go_id}.json")
        with open(input_path, encoding='utf-8') as f:
            enriched = json.load(f)
        return go_id, *re_enrich_one(args.vuln_data_dir, go_id, enriched)

    if args.workers <= 1:
        for i, go_id in enumerate(pending):
            if interrupted:
                print(f"\n[INTERRUPT] {len(pending) - i} remaining.")
                break

            gid, updated, msg = process(go_id)
            if updated:
                out_path = os.path.join(args.input_dir, f"{gid}.json")
                with open(out_path, 'w', encoding='utf-8') as f:
                    json.dump(updated, f, indent=2, ensure_ascii=False)
                print(f"[{i+1}/{len(pending)}] {gid} -> {msg}")
                results['ok'] += 1
            else:
                print(f"[{i+1}/{len(pending)}] {gid} SKIP: {msg}")
                results['no_change'] += 1
    else:
        def process_and_save(go_id):
            gid, updated, msg = process(go_id)
            if updated:
                out_path = os.path.join(args.input_dir, f"{gid}.json")
                with open(out_path, 'w', encoding='utf-8') as f:
                    json.dump(updated, f, indent=2, ensure_ascii=False)
            return gid, updated, msg

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(process_and_save, gid): gid for gid in pending}
            done_count = 0
            for future in as_completed(futures):
                if interrupted:
                    break
                done_count += 1
                gid, updated, msg = future.result()
                if updated:
                    print(f"[{done_count}/{len(pending)}] {gid} -> {msg}")
                    results['ok'] += 1
                else:
                    print(f"[{done_count}/{len(pending)}] {gid} SKIP: {msg}")
                    results['no_change'] += 1

    elapsed = time.time() - overall_start
    print()
    print("=" * 50)
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {elapsed:.1f}s")
    print(f"  Updated:    {results['ok']}")
    print(f"  No change:  {results['no_change']}")


if __name__ == "__main__":
    main()
