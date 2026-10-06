"""Regression: v3 with --rules v2 must reproduce v2's report.json exactly.

Both versions run the full detect pipeline on the same target with the LLM replaced by a
deterministic stub (extraction facts derived from the numbered source lines), so any
difference comes from the code, not from the model. Volatile fields (timestamps,
durations, paths, project id) are removed before comparison.

    python tests/regression_v2_equivalence.py --v2 <v2 worktree> --v3 <v3 tree> --target <go project> [--rules v2]
"""
import argparse, json, os, re, subprocess, sys, tempfile

RUNNER = r'''
import json, re, sys, os
tool, target, out, rules = sys.argv[1:5]
sys.path.insert(0, tool); os.chdir(tool)
import detect_vulns as dv
def stub(api_cfg, system_prompt, user_content, retries=3, max_tokens=8192):
    dv._record_usage({'usage': {'prompt_tokens': len(user_content), 'completion_tokens': 10}})
    if '入口判定器' in system_prompt:
        return [], None
    if '函数角色判定器' in system_prompt:
        roles = ['resource_access', 'validator', 'protocol_handler', 'none']
        return [{'function': k, 'role': roles[sum(map(ord, k)) % 4]}
                for k in re.findall(r'^- (\S+?)(?: 接收者类型|$)', user_content, re.M)], None
    if '行为链对齐器' in system_prompt:
        # deterministic stub: align every step to the first three numbered lines, missing step absent
        lines = [int(m) for m in re.findall(r'^(\d+)\| .*\(', user_content, re.M)][1:] or [1]
        ids = [int(m) for m in re.findall(r'^- step (\d+): .*?(?<!\[MISSING\]) —', user_content, re.M)]
        miss = re.search(r'^- step (\d+): .*\[MISSING\]', user_content, re.M)
        return {'aligned': True, 'segment': [min(ids or [1]), max(ids or [1])], 'steps': [{'step_id': i, 'line': lines[min(k, len(lines) - 1)]} for k, i in enumerate(ids)],
                'missing_step': {'step_id': int(miss.group(1)) if miss else 0, 'status': 'absent', 'note': 'stub'}}, None
    if 'active_domains' in system_prompt:
        return {'active_domains': [{'domain': 'NetworkRequestAndProtocolHandling', 'confidence': 0.8, 'evidence': 'stub'},
                                   {'domain': 'PathHandlingAndFilesystemAccess', 'confidence': 0.6, 'evidence': 'stub'}]}, None
    items = []
    for block in re.split(r'【待提取函数 \d+/\d+】', user_content)[1:]:
        lines = [int(m) for m in re.findall(r'^(\d+)\| ', block, re.M)]
        fn = re.search(r'- 函数: (\S+)', block).group(1)
        h = sum(map(ord, fn))
        lo, hi = (lines[0], lines[-1]) if lines else (1, 1)
        mid = (lo + hi) // 2
        items.append({'function': fn, 'purpose': f'stub {fn}', 'external_entry': {'kind': 'internal'},
                      'semantic_inputs': [{'origin': ['network', 'file', 'cli', 'internal'][h % 4], 'desc': 'in', 'line': lo + 1}],
                      'semantic_sinks': [{'kind': ['http_response', 'file_write', 'log', 'sql'][h % 4], 'desc': 'out', 'line': hi - 1}],
                      'observed_checks': ([{'category': 'input_sanitization', 'desc': 'chk', 'line': mid}] if h % 3 == 0 else [])})
    return items, None
dv.call_llm = stub
dv.load_env = lambda: {'LLM_API_KEY': 'stub', 'LLM_BASE_URL': 'http://stub', 'LLM_MODEL': 'stub-model'}
argv = ['detect_vulns.py', '--target', target, '--db', os.path.join(tool, 'vuln_db.json'), '--output', out,
        '--max-functions', '0', '--batch-size', '1', '--confidence-threshold', '0.5']
if rules: argv += ['--rules', rules]
sys.argv = argv
dv.main()
'''
VOLATILE = {'project_id', 'target', 'timestamp', 'total_duration'}

def run(tool, target, rules):
    out = tempfile.mktemp(suffix='.json')
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
        f.write(RUNNER)
    # v2 binds templates by iterating a set: ties depend on the hash seed, so the seed is
    # fixed to compare code paths rather than hash randomisation (see DESIGN_v3.md, F1).
    env = dict(os.environ, PYTHONHASHSEED='0')
    r = subprocess.run([sys.executable, f.name, tool, target, out, rules], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit(f'run failed for {tool}:\n{r.stderr[-2000:]}')
    rep = json.load(open(out))
    for k in VOLATILE:
        rep['scan_info'].pop(k, None)
    return rep

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--v2', required=True); ap.add_argument('--v3', required=True)
    ap.add_argument('--target', required=True); ap.add_argument('--rules', default='v2')
    a = ap.parse_args()
    r2, r3 = run(a.v2, a.target, ''), run(a.v3, a.target, a.rules)
    same = json.dumps(r2, sort_keys=True, ensure_ascii=False) == json.dumps(r3, sort_keys=True, ensure_ascii=False)
    print(json.dumps({'target': a.target, 'rules': a.rules, 'identical': same,
                      'v2_findings': len(r2['findings']), 'v3_findings': len(r3['findings']),
                      'v3_by_rule': r3['summary'].get('by_rule')}, ensure_ascii=False))
    if not same and a.rules == 'v2':
        for k in sorted(set(r2) | set(r3)):
            if json.dumps(r2.get(k), sort_keys=True) != json.dumps(r3.get(k), sort_keys=True):
                print('  differs:', k)
        sys.exit(1)

if __name__ == '__main__':
    main()
