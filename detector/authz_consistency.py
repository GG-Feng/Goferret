"""
v3.2 R5: inconsistent authorization across sibling handlers (CWE-862 / CWE-639).

Middleware often does authentication, so "no check in this handler" alone is not a
signal. The signal is inconsistency: among the handlers of one receiver type (same
package) that access data by an identifier taken from the request, most establish
the caller's identity or check authorization (principal_check), and some do not.

A group is judged when it has at least MIN_GROUP such handlers and at least
MIN_RATIO of them check; each non-checking handler in it is reported at its first
request-identified data access (category access_control).

Facts come from ast_analyzer param_flows: handler, principal_check, resource_access.

CLI:
    python authz_consistency.py --selftest
"""

import os
import sys

MIN_GROUP = 3
MIN_RATIO = 0.5


def r5_facts(param_flows, llm_principal=None):
    """-> {func_key: [fact]} with fact = {category, source, sink, peers}.

    llm_principal (v5.1): function keys where the LLM extraction observed an
    access_control / identity_verification check; counted like an AST principal check
    when the siblings are compared (a second pass after extraction).
    """
    llm_principal = llm_principal or set()

    def checked_(pf):
        return bool(pf.get('principal_check')) or f"{pf['file']}:{pf['function']}" in llm_principal

    groups = {}
    for pf in param_flows or []:
        if not (pf.get('handler') and pf.get('resource_access') and pf.get('recv_type')):
            continue
        # siblings: same receiver type in the same file (handlers of one resource
        # live together; other files of the same type may follow another authz scheme)
        g = (pf['file'], pf['recv_type'])
        groups.setdefault(g, []).append(pf)
    out = {}
    # v4.2: handler closures registered inline in one function are siblings of each other
    for pf in param_flows or []:
        chs = pf.get('closure_handlers') or []
        members = [c for c in chs if c.get('resource_access')]
        checked = [c for c in members if c.get('principal_check')]
        if len(members) < MIN_GROUP or len(checked) / len(members) < MIN_RATIO:
            continue
        key = f"{pf['file']}:{pf['function']}"
        for c in members:
            if c.get('principal_check'):
                continue
            acc = min(c['resource_access'], key=lambda a: a['line'])
            out.setdefault(key, []).append({
                'category': 'access_control',
                'source': {'line': c['line'], 'type': 'param_external',
                           'desc': f"L{c['line']} 注册的处理闭包（资源标识来自请求）",
                           'provenance': 'peer_inconsistency', 'path': []},
                'sink': {'line': acc['line'], 'type': 'resource_access',
                         'desc': f"按请求中的标识访问资源：{acc['text'][:60]}"},
                'peers': f"{len(checked)}/{len(members)} 个同函数内注册的处理闭包检查了调用者身份或权限",
                'checked_peers': [f"L{x['line']}" for x in checked][:5],
            })
    for g in sorted(groups):
        members = sorted(groups[g], key=lambda p: (p['file'], p['function']))
        checked = [p for p in members if checked_(p)]
        if len(members) < MIN_GROUP or len(checked) / len(members) < MIN_RATIO:
            continue
        for pf in members:
            if checked_(pf):
                continue
            acc = min(pf['resource_access'], key=lambda a: a['line'])
            key = f"{pf['file']}:{pf['function']}"
            out.setdefault(key, []).append({
                'category': 'access_control',
                'source': {'line': pf['line'], 'type': 'param_external',
                           'desc': '处理函数的请求参数（资源标识来自请求）', 'provenance': 'peer_inconsistency', 'path': []},
                'sink': {'line': acc['line'], 'type': 'resource_access',
                         'desc': f"按请求中的标识访问资源：{acc['text'][:60]}"},
                'peers': f"{len(checked)}/{len(members)} 个同类处理函数检查了调用者身份或权限",
                'checked_peers': sorted(p['function'] for p in checked)[:5],
            })
    return out


def _selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    fx = os.path.join(here, 'tests', 'fixtures', 'r5')
    sys.path.insert(0, here)
    from go_ast_analysis import analyze_go_source
    flows = (analyze_go_source(fx) or {}).get('param_flows') or []
    failures = []
    got = r5_facts(flows)
    if sorted(got) != ['handlers.go:Handler.GetDownloadURL', 'routes.go:Routes']:
        failures.append(f'expected GetDownloadURL and the inline closure in Routes, got {sorted(got)}')
    rt = got.get('routes.go:Routes') or []
    if [f['sink']['line'] for f in rt] != [22]:
        failures.append(f'inline closure without the check should be the one at L21-24: {[f["sink"]["line"] for f in rt]}')
    other = r5_facts([p for p in flows if p.get('recv_type') != 'Handler' and p['function'] != 'Routes'])
    if other:
        failures.append(f'group without checking peers must not be reported: {sorted(other)}')
    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for m in failures:
            print(f"  - {m}")
        return 1
    print("SELFTEST PASSED: inconsistent handler reported, checked peers and "
          "all-unchecked group (middleware auth) not reported, inline handler closures")
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(__doc__)
