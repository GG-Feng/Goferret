"""Mine AST pattern-table expansion candidates from the vuln dataset.

Streams:
  A. vuln_db.json template api_indicators (APIs already proven vuln-relevant)
  B. enriched_inputs func_sources + patch_diff removed lines: selector calls
     executed by the vulnerable code itself (test files excluded)
  C. behavior_chains MISSING-step evidence.apis (APIs the patch introduced =
     the strongest sanitizer-table signal)

Tables currently in ast_analyzer/main.go are parsed from source; any API the
existing substring matcher would already type is subtracted, so everything in
the output is a genuine table gap.

Output is split into:
  stdlib    — first component is a Go stdlib package: can enter the general
              substring tables directly
  framework — receiver-style methods (c.QueryParam, ...): need import-gated
              matching, review separately

Also writes the full ranked list to pattern_candidates.json.

Usage: python mine_pattern_candidates.py [--top 15] [--min-count 3]
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding='utf-8')

ROOT = os.path.dirname(os.path.abspath(__file__))

CALL_RE = re.compile(r'([A-Za-z_][\w.]*)\s*\(')
DIFF_FILE_RE = re.compile(r'^\+\+\+ b/(.+)$')

STDLIB_PKGS = {
    'os', 'io', 'ioutil', 'fmt', 'net', 'http', 'https', 'strings', 'strconv',
    'path', 'filepath', 'bytes', 'bufio', 'json', 'xml', 'yaml', 'binary',
    'time', 'regexp', 'exec', 'sql', 'template', 'url', 'crypto', 'errors',
    'context', 'log', 'math', 'sort', 'sync', 'atomic', 'base64', 'hex',
    'cipher', 'rsa', 'ecdsa', 'ed25519', 'hmac', 'subtle', 'x509', 'tls',
    'mail', 'textproto', 'httputil', 'multipart', 'zip', 'tar', 'gzip',
    'zlib', 'flate', 'lzw', 'bzip2', 'rand', 'unsafe', 'reflect', 'asn1',
    'cgi', 'fcgi', 'pprof', 'trace', 'websocket',
}

# receiver names that mark test/assert scaffolding, never anchor candidates
TEST_RECEIVERS = {'t', 'assert', 'require', 'gomock', 'ctrl', 'tester',
                  'test', 'mock', 'mocks', 'suite', 'b', 'tb'}

NOISE = {
    'fmt.Errorf', 'fmt.Sprintf', 'errors.New', 'fmt.Println', 'fmt.Print',
    'fmt.Fprintln', 'log.Printf', 'log.Println', 'log.Print',
    'errors.Is', 'errors.As', 'context.Background', 'time.Now',
    'context.WithValue', 'testing.T', 'make', 'new', 'append', 'len', 'cap',
    'panic', 'unsafe.Pointer',
}


def parse_main_tables():
    """Parse sourcePatterns/sinkPatterns/sanitizerPatterns from main.go."""
    src = open(os.path.join(ROOT, 'ast_analyzer', 'main.go'), encoding='utf-8').read()
    tables = {}
    for name in ('source', 'sink', 'sanitizer'):
        m = re.search(r'var ' + name + r'Patterns = \[\]struct \{[^}]*\}\{(.*?)\n\}',
                      src, re.DOTALL)
        entries = re.findall(r'\{"([^"]+)",\s*"([^"]+)"\}', m.group(1))
        tables[name] = entries
    return tables


def covered_by(api, tables):
    """Simulate the analyzer's substring matcher: does any pattern already
    type this call? Patterns with '(' match `api(`; bare patterns match api."""
    call_text = api + '('
    for entries in tables.values():
        for pattern, _typ in entries:
            if pattern.endswith('('):
                if pattern in call_text:
                    return True
            elif pattern in api:
                return True
    return False


def normalize_call(expr):
    """Keep the last two dotted components ('json.Marshal', 'c.QueryParam');
    drop single-component calls and empty components."""
    if '.' not in expr:
        return None
    parts = [p for p in expr.split('.') if p]
    if len(parts) < 2:
        return None
    return '.'.join(parts[-2:])


def bucket_of(api):
    if api in NOISE or api.split('.')[0] in TEST_RECEIVERS:
        return None
    first = api.split('.')[0]
    return 'stdlib' if first in STDLIB_PKGS else 'framework'


def extract_calls(text):
    out = set()
    for m in CALL_RE.finditer(text):
        norm = normalize_call(m.group(1))
        if norm:
            out.add(norm)
    return out


def category_of(behavior):
    chain = behavior.get('behavior_chain') or {}
    for step in chain.get('steps') or []:
        if str(step.get('action', '')).startswith('MISSING:'):
            return step.get('missing_step_category', 'unknown')
    return 'unknown'


def missing_step_apis(behavior):
    chain = behavior.get('behavior_chain') or {}
    for step in chain.get('steps') or []:
        if str(step.get('action', '')).startswith('MISSING:'):
            ev = step.get('evidence') or {}
            return set(ev.get('apis') or [])
    return set()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--top', type=int, default=15)
    parser.add_argument('--min-count', type=int, default=3)
    args = parser.parse_args()

    tables = parse_main_tables()
    n_patterns = sum(len(v) for v in tables.values())
    print(f"Parsed {n_patterns} patterns from main.go "
          f"(source {len(tables['source'])}, sink {len(tables['sink'])}, "
          f"sanitizer {len(tables['sanitizer'])})")

    candidates = {}   # api -> record
    n_records = 0

    def add(api, stream, category):
        bucket = bucket_of(api)
        if bucket is None:
            return
        rec = candidates.setdefault(api, {
            'bucket': bucket, 'count': 0,
            'categories': Counter(), 'streams': Counter(),
        })
        rec['count'] += 1
        rec['categories'][category] += 1
        rec['streams'][stream] += 1

    # Stream A: vuln_db api_indicators
    db = json.load(open(os.path.join(ROOT, 'vuln_db.json'), encoding='utf-8'))
    for tpl in (db.get('templates') or {}).values():
        cat = tpl.get('missing_step_category', 'unknown')
        for api in tpl.get('api_indicators') or []:
            api = api.strip()
            if '.' in api:
                add(api, 'db_indicators', cat)

    # Streams B + C over the dataset
    behaviors = {}
    for p in glob.glob(os.path.join(ROOT, 'behavior_chains', '*.json')):
        d = json.load(open(p, encoding='utf-8'))
        behaviors[d.get('go_id')] = d

    for p in glob.glob(os.path.join(ROOT, 'enriched_inputs', '*.json')):
        d = json.load(open(p, encoding='utf-8'))
        beh = behaviors.get(d.get('go_id')) or {}
        cat = category_of(beh) if beh else 'unknown'
        n_records += 1

        # B1: vulnerable function source (non-test files only)
        for fs in d.get('func_sources') or []:
            if str(fs.get('file', '')).endswith('_test.go'):
                continue
            for api in extract_calls(fs.get('source') or ''):
                add(api, 'vuln_code', cat)

        # B2: lines the patch removed (= the vulnerable code), test files skipped
        cur_file = ''
        for line in (d.get('patch_diff') or '').splitlines():
            fm = DIFF_FILE_RE.match(line)
            if fm:
                cur_file = fm.group(1)
                continue
            if line.startswith('-') and not line.startswith('---'):
                if cur_file.endswith('_test.go'):
                    continue
                for api in extract_calls(line):
                    add(api, 'patch_removed', cat)

        # C: APIs the patch introduced per the MISSING step
        for api in missing_step_apis(beh):
            api = api.strip()
            if '.' in api:
                add(api, 'patch_missing_step', cat)

    # subtract anything the existing matcher already covers
    dropped = sorted(a for a in candidates if covered_by(a, tables))
    for api in dropped:
        del candidates[api]

    ubiquity_cutoff = max(1, int(n_records * 0.15))
    rows = []
    for api, rec in candidates.items():
        rows.append({
            'api': api,
            'bucket': rec['bucket'],
            'count': rec['count'],
            'categories': dict(rec['categories'].most_common()),
            'streams': dict(rec['streams']),
            'ubiquitous': rec['count'] > ubiquity_cutoff,
        })
    rows.sort(key=lambda r: -r['count'])

    with open(os.path.join(ROOT, 'pattern_candidates.json'), 'w', encoding='utf-8') as f:
        json.dump({
            'records_scanned': n_records,
            'existing_patterns': {k: len(v) for k, v in tables.items()},
            'already_covered_dropped': len(dropped),
            'candidates': rows,
        }, f, indent=2, ensure_ascii=False)

    print(f"Scanned {n_records} records -> {len(rows)} uncovered candidates "
          f"({len(dropped)} dropped as already covered)\n")

    for bucket in ('stdlib', 'framework'):
        subset = [r for r in rows if r['bucket'] == bucket]
        print(f"########## {bucket} ({len(subset)}) ##########")
        by_cat = defaultdict(list)
        for r in subset:
            dom = r['categories'] and max(r['categories'], key=r['categories'].get)
            by_cat[dom or 'unknown'].append(r)
        for cat in sorted(by_cat, key=lambda c: -max(r['count'] for r in by_cat[c])):
            entries = [r for r in by_cat[cat] if r['count'] >= args.min_count]
            if not entries:
                continue
            print(f"== {cat} ==")
            for r in entries[:args.top]:
                flag = ' [ubiquitous]' if r['ubiquitous'] else ''
                stm = '/'.join(f"{k}:{v}" for k, v in sorted(r['streams'].items()))
                print(f"  {r['count']:4d}  {r['api']}{flag}  ({stm})")
        print()

    print("Full list: pattern_candidates.json")


if __name__ == '__main__':
    main()
