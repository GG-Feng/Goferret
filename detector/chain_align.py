"""
v5.2 X4: template-guided behaviour-chain alignment for control-flow / protocol / lifecycle
vulnerability classes (the classes the data-flow rules cannot express).

Idea: those vulnerabilities have no dangerous sink; they are a legitimate sequence of steps
with one step that should have been there. The knowledge base holds such sequences (one
per past vulnerability, plus a few CWE-sourced generic chains). Instead of guessing
"authorization is missing here", the LLM is asked to ALIGN a candidate function to a chain
template step by step and to say whether the MISSING step is executed; a local rule then
decides.

Pipeline (after semantic extraction; needs the entry triage seeds / taint facts):
  1. candidates: externally reachable functions (X1 seeds, AST handlers, any parameter the
     taint engine reaches from an external origin) with at least one call/comparison line;
  1b. role (LLM, detect_role.md, signature + callee names only, batched): what kind of
     security decision the function makes; ROLE_CATEGORIES routes it to chain categories,
     role 'none' drops it. (Measured on the dev set: lexical API overlap alone ranked the
     truth functions at or below the median of 400-1500 reachable functions, so it cannot
     be the filter; it only orders chains inside the routed categories.)
  2. retrieval: per candidate, within its routed categories, the best real chain and the
     best generic chain by IDF-weighted token overlap (camelCase-split function name,
     callees, parameter types vs. chain summary / step text / evidence APIs);
  3. alignment (LLM, detect_align.md) per (function, chain);
  4. decision: report iff entry and exit steps aligned, >= MIN_ALIGNED of steps aligned,
     missing step 'absent' (not 'unknown'), and the aligned lines fall on AST call/comparison
     lines (F4 corroboration). Category = the chain's missing_step_category.
  5. sibling consistency (R5 generalised): among candidates aligned to the same chain in one
     file, an 'absent' beside 'present' peers is boosted.

CLI:
    python chain_align.py --selftest
"""

import json
import os
import re
import sys

MIN_ALIGNED = 0.6
TOP_K = 2
WEAK_CATEGORIES = {'access_control', 'identity_verification', 'origin_validation',
                   'protocol_validation', 'error_handling', 'state_synchronization', 'input_sanitization'}
_HERE = os.path.dirname(os.path.abspath(__file__))

# v5.2b A: each role has one primary category (real chains are searched only there) and
# its canonical generic chains (behavior_chains_generic/ was written for these roles).
ROLE_PRIMARY = {
    'resource_access': 'access_control', 'authorization': 'access_control',
    'authentication': 'identity_verification', 'trusted_forwarding': 'identity_verification',
    'validator': 'input_sanitization', 'redirect_origin': 'origin_validation',
    'protocol_handler': 'protocol_validation', 'state_mutation': 'state_synchronization',
}
ROLE_GENERIC = {
    'resource_access': ('GEN-CWE639-1',), 'authorization': ('GEN-CWE862-1', 'GEN-CWE863-1'),
    'authentication': ('GEN-CWE306-1',), 'trusted_forwarding': ('GEN-CWE290-1',),
    'validator': ('GEN-CWE20-VALIDATE-1',), 'redirect_origin': ('GEN-CWE601-1', 'GEN-CWE352-1'),
    'protocol_handler': ('GEN-CWE20-PROTO-1',), 'state_mutation': ('GEN-CWE362-1',),
}
MIN_SEGMENT_STEPS = 2

# v5.2 (kept for reference / ablation): role -> all categories it was aligned against
ROLE_CATEGORIES = {
    'resource_access': ('access_control',),
    'authorization': ('access_control',),
    'authentication': ('identity_verification',),
    'trusted_forwarding': ('identity_verification',),
    'validator': ('input_sanitization', 'origin_validation', 'protocol_validation'),
    'redirect_origin': ('origin_validation',),
    'protocol_handler': ('protocol_validation', 'error_handling', 'state_synchronization'),
    'state_mutation': ('state_synchronization',),
}


def load_chains(dirs=None):
    """[chain dict] from behavior_chains/ and behavior_chains_generic/ (non data_flow only)."""
    dirs = dirs or [os.path.join(_HERE, 'behavior_chains'), os.path.join(_HERE, 'behavior_chains_generic')]
    out = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith('.json'):
                continue
            try:
                c = json.load(open(os.path.join(d, fn), encoding='utf-8'))
            except (OSError, ValueError):
                continue
            bc = c.get('behavior_chain') or {}
            steps = bc.get('steps') or []
            miss = [s for s in steps if s.get('is_missing_step')]
            if len(miss) != 1 or len(steps) < 2 or bc.get('chain_type') == 'data_flow':
                continue
            cat = miss[0].get('missing_step_category')
            if cat not in WEAK_CATEGORIES:
                continue
            apis = set()
            actions = set()
            for s in steps:
                for a in (s.get('evidence') or {}).get('apis') or []:
                    apis.add(a.split('(')[0].strip())
                if not s.get('is_missing_step'):
                    actions.add(s.get('action') or '')
            bag = _tokens(bc.get('summary') or '') | _tokens((c.get('vulnerability_pattern') or {}).get('pattern_name', ''))
            for s in steps:
                bag |= _tokens(s.get('action') or '') | _tokens(s.get('description') or '')
            for a in apis:
                bag |= _tokens(a)
            out.append({'id': c.get('go_id'), 'domain': c.get('primary_domain'), 'generic': bool(c.get('generic')),
                        'bag': bag,
                        'chain_type': bc.get('chain_type'), 'category': cat, 'steps': steps,
                        'summary': bc.get('summary') or '', 'apis': apis, 'actions': actions,
                        'pattern': (c.get('vulnerability_pattern') or {}).get('pattern_name', ''),
                        'missing_id': miss[0].get('step_id'),
                        'entry_id': (bc.get('entry_point') or {}).get('step_id', steps[0]['step_id']),
                        'exit_id': (bc.get('exit_point') or {}).get('step_id', steps[-1]['step_id'])})
    return out


_STOP = {'the', 'and', 'for', 'with', 'from', 'into', 'that', 'this', 'are', 'via', 'its', 'not', 'without',
         'before', 'after', 'when', 'then', 'which', 'each', 'using', 'use', 'get', 'set', 'new', 'err', 'error'}


def _tokens(s):
    """Lower-cased word tokens; camelCase / PascalCase / acronyms split (FindSourceByID -> find, source, by, id)."""
    parts = re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+', s or '')
    return {t.lower() for t in parts if len(t) > 2 and t.lower() not in _STOP}


def idf(chains):
    import math
    df = {}
    for ch in chains:
        for t in ch['bag']:
            df[t] = df.get(t, 0) + 1
    n = max(1, len(chains))
    return {t: math.log((n + 1) / (c + 0.5)) for t, c in df.items()}


def retrieve_for_role(chains, role, func_text, active_domains=(), weights=None):
    """v5.2b: best real chain in the role's PRIMARY category + best of the role's canonical
    generic chains (<= TOP_K). func_text: function name, callee names and parameter types."""
    cat, generics = ROLE_PRIMARY.get(role), ROLE_GENERIC.get(role, ())
    if not cat:
        return []
    weights = weights or {}
    ftoks = _tokens(func_text)
    best = {True: None, False: None}
    for ch in chains:
        if ch['generic'] and ch['id'] not in generics:
            continue
        if not ch['generic'] and ch['category'] != cat:
            continue
        sc = sum(weights.get(t, 1.0) for t in ftoks & ch['bag']) + (0.5 if ch['domain'] in (active_domains or ()) else 0)
        cur = best[ch['generic']]
        if cur is None or sc > cur[0] or (sc == cur[0] and ch['id'] < cur[1]['id']):
            best[ch['generic']] = (sc, ch)
    out = [b[1] for b in (best[False], best[True]) if b]
    return out[:TOP_K]


def retrieve(chains, callees, imports, active_domains, k=TOP_K):
    """Top-k chains for one function. callees: set of callee names (bare, pkg.Func);
    imports: set of import paths of the file; active_domains: project domains."""
    ctoks = set()
    for c in callees:
        ctoks |= _tokens(c)
    itoks = set()
    for i in imports:
        itoks |= _tokens(i.split('/')[-1])
    scored = []
    for ch in chains:
        api_hit = sum(1 for a in ch['apis'] if a and (a in callees or a.split('.')[-1] in callees))
        act_hit = len(ctoks & set().union(*(_tokens(a) for a in ch['actions'])) if ch['actions'] else set())
        score = 3 * api_hit + act_hit + (2 if ch['domain'] in (active_domains or []) else 0) + (1 if ch['generic'] else 0)
        if score > 0:
            scored.append((score, ch['generic'], ch['id'], ch))
    scored.sort(key=lambda x: (-x[0], not x[1], x[2]))
    # at most one non-generic and the best generic, so the general knowledge always competes
    out, seen_generic = [], False
    for s, g, _id, ch in scored:
        if g and seen_generic:
            continue
        out.append(ch)
        seen_generic = seen_generic or g
        if len(out) >= k:
            break
    return out


def build_message(func_key, numbered_source, callee_snippets, chain):
    parts = [f"【待对齐函数】{func_key}", "源码（每行前的 N| 是文件中的绝对行号）:", numbered_source]
    if callee_snippets:
        parts.append("【被调函数】")
        parts += callee_snippets
    parts.append(f"【行为链模板】{chain['id']}（{chain['category']}，{chain['chain_type']}）")
    parts.append(f"摘要：{chain['summary']}")
    for s in chain['steps']:
        tag = ' [MISSING]' if s.get('is_missing_step') else ''
        parts.append(f"- step {s['step_id']}: {s.get('action')}{tag} — {s.get('description', '')}")
    return '\n'.join(parts)


def decide(alignment, chain, check_lines, func_line_range):
    """-> fact dict or None. v5.2b segment rule over the LLM's alignment.

    The function implements a contiguous segment [i, j] of the chain (a chain spans several
    functions; a validator or a response builder is one piece of it). Report iff the segment
    touches the missing step's position (contains it or a neighbouring step), >= 2 and
    >= MIN_ALIGNED of the segment's non-missing steps land on AST call/comparison lines, and
    the missing step is judged absent ('unknown' never reports)."""
    if not isinstance(alignment, dict) or not alignment.get('aligned'):
        return None
    seg = alignment.get('segment')
    if not (isinstance(seg, (list, tuple)) and len(seg) == 2 and all(isinstance(x, int) for x in seg)):
        return None
    s_lo, s_hi = sorted(seg)
    m = chain['missing_id']
    if not (s_lo <= m + 1 and s_hi >= m - 1):
        return None
    steps = {s.get('step_id'): s for s in (alignment.get('steps') or []) if isinstance(s, dict)}
    lo, hi = func_line_range
    cls = set(check_lines or [])

    def ok_line(l):
        return isinstance(l, int) and lo <= l <= hi and (not cls or any(x in cls for x in (l - 1, l, l + 1)))
    in_seg = [s for s in chain['steps'] if not s.get('is_missing_step') and s_lo <= s['step_id'] <= s_hi]
    aligned = [s for s in in_seg if ok_line((steps.get(s['step_id']) or {}).get('line'))]
    if len(aligned) < MIN_SEGMENT_STEPS or len(aligned) / len(in_seg) < MIN_ALIGNED:
        return None
    ms = alignment.get('missing_step') or {}
    if ms.get('status') != 'absent':
        return None
    lines = sorted((steps[s['step_id']]['line'] for s in aligned))
    src_line, snk_line = lines[0], lines[-1]
    if snk_line == src_line:
        snk_line = min(hi, src_line + 1)
    return {'category': chain['category'], 'template': chain['id'], 'generic': chain['generic'],
            'pattern': chain['pattern'], 'aligned_ratio': round(len(aligned) / len(in_seg), 2),
            'segment': [s_lo, s_hi],
            'source': {'line': src_line, 'type': 'param_external', 'desc': f"行为链片段起点（模板 {chain['id']}）",
                       'provenance': 'chain_align', 'path': []},
            'sink': {'line': snk_line, 'type': 'chain_exit',
                     'desc': f"行为链片段终点；缺失 {chain['category']}：{ms.get('note', '')[:60]}"},
            'note': ms.get('note', '')}


def gate_generic(facts_by_func):
    """v5.2b C: a fact from a generic chain is kept only with extra evidence — a sibling in the
    same file aligned to the same template performs the step (peers_present), or the same
    function also has a fact from a real advisory chain. Returns (kept, suppressed)."""
    kept, suppressed = {}, {}
    for key, facts in facts_by_func.items():
        real = any(not f.get('generic') for f in facts)
        for f in facts:
            ok = (not f.get('generic')) or f.get('peers_present') or real
            (kept if ok else suppressed).setdefault(key, []).append(f)
    return kept, suppressed


def sibling_boost(facts_by_func, alignments_by_func):
    """Mark facts whose siblings (same file, same template) have the missing step present."""
    present = {}
    for key, als in alignments_by_func.items():
        for tpl, al in als:
            if (al.get('missing_step') or {}).get('status') == 'present':
                present.setdefault((key.rsplit(':', 1)[0], tpl), 0)
                present[(key.rsplit(':', 1)[0], tpl)] += 1
    for key, facts in facts_by_func.items():
        for f in facts:
            n = present.get((key.rsplit(':', 1)[0], f['template']), 0)
            f['peers_present'] = n
    return facts_by_func


def _selftest():
    failures = []
    chains = load_chains([os.path.join(_HERE, 'behavior_chains_generic')])
    if len(chains) < 10:
        failures.append(f'generic chains loaded: {len(chains)}')
    idor = next((c for c in chains if c['id'] == 'GEN-CWE639-1'), None)
    if not idor:
        failures.append('GEN-CWE639-1 missing')
    else:
        top = retrieve(chains, {'FindByID', 'store.Get'}, {'net/http'}, ['AuthenticationAndAuthorization'])
        if not top or top[0]['category'] != 'access_control':
            failures.append(f'retrieval should rank an access_control chain first: {[c["id"] for c in top]}')
        good = {'aligned': True, 'segment': [1, 5], 'steps': [{'step_id': 1, 'line': 10}, {'step_id': 2, 'line': 12}, {'step_id': 3, 'line': 15}, {'step_id': 5, 'line': 20}],
                'missing_step': {'step_id': 4, 'status': 'absent', 'note': '无归属比较'}}
        f = decide(good, idor, [10, 12, 15, 20], (9, 22))
        if not f or f['category'] != 'access_control' or (f['source']['line'], f['sink']['line']) != (10, 20):
            failures.append(f'decide should report: {f}')
        if decide({**good, 'missing_step': {'step_id': 4, 'status': 'unknown'}}, idor, [10, 12, 15, 20], (9, 22)):
            failures.append('unknown must not report')
        if decide({**good, 'missing_step': {'step_id': 4, 'status': 'present', 'line': 17}}, idor, [10, 12, 15, 17, 20], (9, 22)):
            failures.append('present must not report')
        if decide(good, idor, [30, 31], (9, 22)):
            failures.append('aligned lines off any call/comparison line must not count')
        weak = {**good, 'steps': [{'step_id': 1, 'line': 10}, {'step_id': 5, 'line': 20}]}
        if decide(weak, idor, [10, 20], (9, 22)):
            failures.append('two of four steps is below MIN_ALIGNED')
        # segment: a callee implementing steps 3..5 around the missing step 4 reports
        seg = {'aligned': True, 'segment': [3, 5], 'steps': [{'step_id': 3, 'line': 15}, {'step_id': 5, 'line': 20}],
               'missing_step': {'step_id': 4, 'status': 'absent'}}
        if not decide(seg, idor, [15, 20], (9, 22)):
            failures.append('segment 3..5 around missing step 4 should report')
        far = {**seg, 'segment': [1, 2], 'steps': [{'step_id': 1, 'line': 10}, {'step_id': 2, 'line': 12}]}
        if decide(far, idor, [10, 12], (9, 22)):
            failures.append('segment 1..2 does not touch missing step 4')
        if decide({**seg, 'segment': [4, 5], 'steps': [{'step_id': 5, 'line': 20}]}, idor, [20], (9, 22)):
            failures.append('a single aligned step is below MIN_SEGMENT_STEPS')
        if decide({k: v for k, v in seg.items() if k != 'segment'}, idor, [15, 20], (9, 22)):
            failures.append('no segment, no report')
        g = {'f': [{'generic': True, 'peers_present': 0}], 'g': [{'generic': True, 'peers_present': 1}],
             'h': [{'generic': True}, {'generic': False}]}
        kept, sup = gate_generic(g)
        if sorted(kept) != ['g', 'h'] or sorted(sup) != ['f']:
            failures.append(f'gate_generic: kept {sorted(kept)} suppressed {sorted(sup)}')
    if _tokens('FindSourceByID') != {'find', 'source'} or 'jwt' not in _tokens('EncodeJWTToken'):
        failures.append(f"camelCase tokens: {_tokens('FindSourceByID')} {_tokens('EncodeJWTToken')}")
    if chains:
        got = retrieve_for_role(chains, 'resource_access', 'FindSourceByID sourceRepo.FetchSourceByID projectID string',
                                weights=idf(chains))
        if not got or any(c['category'] != 'access_control' for c in got) or not any(c['generic'] for c in got):
            failures.append(f"role retrieval: {[(c['id'], c['category']) for c in got]}")
        v = retrieve_for_role(chains, 'validator', 'validateWebsiteURL url.Parse strings.HasPrefix string')
        if [c['id'] for c in v if c['generic']] != ['GEN-CWE20-VALIDATE-1']:
            failures.append(f"validator must get the canonical generic chain: {[c['id'] for c in v]}")
        if retrieve_for_role(chains, 'none', 'x'):
            failures.append('role none must retrieve nothing')
    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for m in failures:
            print(f"  - {m}")
        return 1
    print("SELFTEST PASSED: generic chains load, retrieval ranks by category/API, decide (report / unknown / present / "
          "off-line / under-aligned), camelCase tokens, role-routed retrieval, segment rule, generic gate")
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(__doc__)
