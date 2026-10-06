"""
v3 R3: validator contract (pure Python, deterministic).

A validator-named function (validate*/valid*/check*/verify*/sanitize*/is*Valid|Allowed|Safe)
whose parameters are externally reachable (R2 taint) is checked against the purpose
its callers put it to:

  purpose from the caller: the caller passes the validator's result (vret:L) or the
      validated argument (varg:L) to a sink -> redirect / path / encoding / input
      (validator_rules.json maps sink types to purposes);
  purpose from names (on by default in detect_vulns; --no-r3-infer-purpose): no sink found, but a tainted
      parameter is named like a URL -> url_field (reported as purpose_inferred).

The validator is reported when none of the purpose's strong patterns occurs among
its calls/comparisons (ast_analyzer check_facts). A weak pattern, if present, is the
span's end line; otherwise the function's closing line is.

Qualification: check*/valid*/is* names must return bool or error as the last result
(these verbs are also used for non-validating helpers); validate*/verify*/sanitize*
names qualify with any result type.

CLI:
    python validator_contract.py --selftest
"""

import json
import os
import re
import sys

import param_taint

VALIDATOR_RE = re.compile(r'^(?i:validate|valid|check|verify|sanitize)|^(?:is|Is)[A-Z].*(?:Valid|Allowed|Safe)')
STRONG_VERB_RE = re.compile(r'^(?i:validate|verify|sanitize)')

_HERE = os.path.dirname(os.path.abspath(__file__))


def load_rules(path=None):
    with open(path or os.path.join(_HERE, 'validator_rules.json'), encoding='utf-8') as f:
        rules = json.load(f)['purposes']
    for p in rules.values():
        p['_strong'] = [re.compile(x['re']) for x in p.get('strong') or []]
        p['_weak'] = [re.compile(x['re']) for x in p.get('weak') or []]
    return rules


def qualifies(pf):
    name = param_taint._bare(pf['function'])
    if not VALIDATOR_RE.search(name):
        return False
    if STRONG_VERB_RE.search(name):
        return True
    results = pf.get('results') or []
    return bool(results) and results[-1] in ('bool', 'error')


def r3_facts(param_flows, modules=None, rules=None, max_hops=param_taint.MAX_HOPS,
             name_dispatch=True, infer_purpose=False, wire_types=None, extra_seeds=None):
    """-> {validator_key: [fact]} with fact = {category, purpose, inferred, source, sink, callers}."""
    rules = rules or load_rules()
    sink_purpose = {}
    for pname in sorted(rules):
        for st in rules[pname].get('sinks') or []:
            sink_purpose.setdefault(st, pname)
    tainted, idx = param_taint.propagate(param_flows, modules, max_hops, name_dispatch, wire_types, extra_seeds)

    # purposes per validator from its callers
    purposes = {}
    for ckey in sorted(idx.funcs):
        cpf = idx.funcs[ckey]
        for cs in cpf.get('call_sites') or []:
            if not VALIDATOR_RE.search(cs.get('name') or ''):
                continue
            marks = {f"vret:{cs['line']}", f"varg:{cs['line']}"}
            used = sorted({snk['type'] for snk in (cpf.get('taint_sinks') or [])
                           if marks & set(snk.get('roots') or []) and snk['type'] in sink_purpose})
            if not used:
                continue
            keys, _res = idx.resolve(ckey, cs, name_dispatch=name_dispatch)
            for vkey in keys:
                for st in used:
                    purposes.setdefault(vkey, {}).setdefault(sink_purpose[st], []).append(
                        f"{ckey}@L{cs['line']} → {st}")

    out = {}
    for vkey in sorted(idx.funcs):
        vpf = idx.funcs[vkey]
        if not qualifies(vpf):
            continue
        tparams = tainted.get(vkey) or {}
        if not tparams:
            continue  # not externally reachable
        found = dict(purposes.get(vkey) or {})
        inferred = False
        if not found and infer_purpose:
            for pname in sorted(rules):
                pat = rules[pname].get('inferred_from_names')
                if pat and any(re.search(pat, p.get('name') or '') for p in (vpf.get('params') or [])
                               if p['index'] in tparams):
                    found[pname] = ['parameter name']
                    inferred = True
        if not found:
            continue
        params = {p['index']: p for p in (vpf.get('params') or [])}
        best_i = min(tparams, key=lambda i: (param_taint._rank(tparams[i]), i))
        state = tparams[best_i]
        first = min((params[i].get('first_use') or 0 for i in tparams if params.get(i, {}).get('first_use')),
                    default=0)
        src_line = first or vpf.get('line', 1)
        facts_ = vpf.get('check_facts') or []
        for pname in sorted(found):
            rule = rules[pname]
            if any(rx.search(cf['text']) for cf in facts_ for rx in rule['_strong']):
                continue
            weak = next((cf for cf in sorted(facts_, key=lambda c: c['line'])
                         if any(rx.search(cf['text']) for rx in rule['_weak'])), None)
            sink_line = weak['line'] if weak and weak['line'] > src_line else (vpf.get('end_line') or src_line + 1)
            out.setdefault(vkey, []).append({
                'category': rule['category'], 'purpose': pname, 'inferred': inferred,
                'weak_check': weak['text'] if weak else '',
                'source': {'line': src_line, 'type': 'param_external',
                           'desc': f"参数 {params.get(best_i, {}).get('name', '')} 外部可达（{param_taint.provenance(state)}）",
                           'provenance': param_taint.provenance(state), 'path': state[2]},
                'sink': {'line': sink_line, 'type': 'validator_contract',
                         'desc': (f"弱校验 {weak['text'][:60]}" if weak else '函数内未见该用途的强校验')},
                'callers': sorted(found[pname])[:5],
            })
    return out


def callee_checks(param_flows, modules=None, rules=None, name_dispatch=True):
    """v5 X3: checks a function delegates to validator-named callees.

    For each call to a validator-named function whose body holds a STRONG pattern of some
    purpose (validator_rules.json), the caller gets a check of that purpose's category at
    the call line. This is the protection counterpart of R3: a span that routes its data
    through validate*/check*/sanitize* with a real check is protected across the call.
    -> {caller_key: [{'line', 'category', 'desc'}]}
    """
    rules = rules or load_rules()
    idx = param_taint._Index(param_flows, modules or [])
    strong_cats = {}   # validator key -> set of categories its strong patterns cover
    for vkey, vpf in idx.funcs.items():
        if not VALIDATOR_RE.search(param_taint._bare(vpf['function'])):
            continue
        facts_ = vpf.get('check_facts') or []
        cats = set()
        for pname, rule in rules.items():
            if any(rx.search(cf['text']) for cf in facts_ for rx in rule['_strong']):
                cats.add(rule['category'])
        if cats:
            strong_cats[vkey] = cats
    out = {}
    for ckey in sorted(idx.funcs):
        for cs in idx.funcs[ckey].get('call_sites') or []:
            if not VALIDATOR_RE.search(cs.get('name') or ''):
                continue
            keys, _res = idx.resolve(ckey, cs, name_dispatch=name_dispatch)
            cats = set()
            for k in keys:
                cats |= strong_cats.get(k, set())
            for cat in sorted(cats):
                out.setdefault(ckey, []).append({'line': cs['line'], 'category': cat,
                                                 'desc': f"调用 {cs.get('name')}（含 {cat} 强校验）"})
    return out


# ── Selftest ──────────────────────────────────────────────────────────

def _selftest():
    fx = os.path.join(_HERE, 'tests', 'fixtures', 'r3')
    sys.path.insert(0, _HERE)
    from go_ast_analysis import analyze_go_source
    flows = (analyze_go_source(fx) or {}).get('param_flows') or []
    failures = []
    if not flows:
        print('SELFTEST FAILED: no param_flows (binary stale?)')
        return 1
    mods = param_taint.load_modules(fx)
    got = r3_facts(flows, mods)
    summary = {k: sorted((f['purpose'], f['inferred']) for f in v) for k, v in got.items()}
    expect = {'redirect.go:validateRedirectTarget': [('redirect', False)]}
    if summary != expect:
        failures.append(f'default rules: expected {expect}, got {summary}')
    g = got.get('redirect.go:validateRedirectTarget', [{}])[0]
    if g and 'HasPrefix' not in g.get('weak_check', ''):
        failures.append(f"weak check should be the HasPrefix(\"/\"): {g.get('weak_check')}")
    got_i = r3_facts(flows, mods, infer_purpose=True)
    summary_i = {k: sorted((f['purpose'], f['inferred']) for f in v) for k, v in got_i.items()}
    if summary_i.get('url.go:validateHomepageURL') != [('url_field', True)]:
        failures.append(f'inferred URL purpose: {summary_i}')
    if 'url.go:validateStrictURL' in summary_i:
        failures.append('character-class rejection is a strong URL check')
    if 'redirect.go:validateStrictRedirect' in summary_i:
        failures.append('// prefix rejection is a strong redirect check')
    if 'redirect.go:checkNotEmpty' in summary_i:
        failures.append('check* returning string must not qualify')
    if 'redirect.go:validateInternal' in summary_i:
        failures.append('validator not reachable from external input must not be reported')
    if r3_facts(flows, mods) != got:
        failures.append('not deterministic')
    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for m in failures:
            print(f"  - {m}")
        return 1
    print("SELFTEST PASSED: redirect purpose via caller sink (weak), strong // rejection, "
          "inferred URL purpose (opt-in), strong char-class, check* qualification, reachability, determinism")
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(__doc__)
