"""
v3 R2: inter-procedural parameter taint (pure Python, deterministic).

Input is the analyzer's per-function `param_flows` (ast_analyzer/param_flow.go):
parameters, call sites whose arguments carry taint roots, handler references
passed to route registration, and dangerous sinks with the roots of their
arguments. This module resolves callees across packages, propagates taint to
callee parameters up to MAX_HOPS call edges from the external origin, and
returns, per function, the sinks that a tainted parameter reaches.

Roots (from the analyzer): param:i; entry / src (network input); wire (decoded data:
any / map[string]any parameters, values asserted from an interface); io (any other read
or decode from outside the process); cb (parameter of a function value that escaped);
call:L (result of a cross-package / unresolved call, resolved here).

Callee resolution:
  pkg.Func(...)   import path -> directory via go.mod module paths  (exact)
  recv.M(...)     recv is the enclosing method's receiver             (exact)
  f(...)          same-package function                               (exact)
  x.M(...)        receiver type unknown: every method named M with a
                  compatible arity in the module, at most
                  NAME_DISPATCH_MAX candidates                        (name_dispatch)

Provenance (v4): <origin>_<distance>[_dispatch] with origin net | wire | io | cb and
distance direct (origin inside the function) | entry (a parameter seeded at hop 0) |
1hop | nhop; "_dispatch" when an edge on the path was resolved by method name only.

CLI:
    python param_taint.py --selftest
"""

import os
import re
import sys

MAX_HOPS = 8        # hard cap; beyond SOFT_HOPS the confidence drops per hop (v4.2)
SOFT_HOPS = 4
NAME_DISPATCH_MAX = 5
EXTERNAL_ROOTS = ('entry', 'src')


def load_modules(target_dir):
    """[(module_path, rel_dir)] from every go.mod under target_dir, longest path first."""
    mods = []
    if not target_dir or not os.path.isdir(target_dir):
        return mods
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted(d for d in dirs if d not in ('vendor', 'testdata', '.git'))
        if 'go.mod' not in files:
            continue
        try:
            with open(os.path.join(root, 'go.mod'), encoding='utf-8', errors='replace') as f:
                for line in f:
                    m = re.match(r'^\s*module\s+(\S+)', line)
                    if m:
                        rel = os.path.relpath(root, target_dir).replace('\\', '/')
                        mods.append((m.group(1).strip('"'), '' if rel == '.' else rel))
                        break
        except OSError:
            continue
    mods.sort(key=lambda m: (-len(m[0]), m[0]))
    return mods


def import_to_dir(import_path, modules):
    for mod, rel in modules:
        if import_path == mod or import_path.startswith(mod + '/'):
            sub = import_path[len(mod):].lstrip('/')
            return '/'.join(p for p in (rel, sub) if p)
    return None


def _dir(path):
    d = os.path.dirname(path).replace('\\', '/')
    return d


def _bare(qname):
    return qname.rsplit('.', 1)[-1]


def _arity_ok(pf, nargs):
    n = len(pf.get('params') or [])
    if pf.get('variadic'):
        return nargs >= n - 1
    return nargs == n


class _Index:
    def __init__(self, param_flows, modules):
        self.modules = modules
        self.funcs = {}
        self.by_dir_name = {}
        self.methods_by_name = {}
        for pf in param_flows or []:
            key = f"{pf['file']}:{pf['function']}"
            self.funcs[key] = pf
            self.by_dir_name.setdefault((_dir(pf['file']), pf['function']), []).append(key)
            if pf.get('recv_type'):
                self.methods_by_name.setdefault(_bare(pf['function']), []).append(key)
        for v in self.by_dir_name.values():
            v.sort()
        for v in self.methods_by_name.values():
            v.sort()

    def resolve(self, caller_key, cs, check_arity=True, name_dispatch=True):
        """-> (sorted callee keys, resolution)"""
        caller = self.funcs[caller_key]
        cdir = _dir(caller['file'])
        name = cs.get('name') or ''
        nargs = cs.get('nargs', 0)
        ok = (lambda k: _arity_ok(self.funcs[k], nargs)) if check_arity else (lambda k: True)
        if cs.get('pkg'):
            d = import_to_dir(cs['pkg'], self.modules)
            if d is None:
                return [], None
            return [k for k in self.by_dir_name.get((d, name), []) if ok(k)], 'exact'
        recv = cs.get('recv')
        if recv == 'self' and caller.get('recv_type'):
            keys = [k for k in self.by_dir_name.get((cdir, f"{caller['recv_type']}.{name}"), []) if ok(k)]
            if keys:
                return keys, 'exact'
        if not recv:
            return [k for k in self.by_dir_name.get((cdir, name), []) if ok(k)], 'exact'
        if not name_dispatch:
            return [], None
        keys = [k for k in self.methods_by_name.get(name, []) if ok(k)]
        if not keys:
            return [], None
        if len(keys) <= NAME_DISPATCH_MAX:
            return keys, 'name_dispatch'
        # v4: many same-named methods with one identical parameter signature are the
        # implementations of one interface (a plugin / driver architecture); the call
        # may reach any of them. Differing signatures are coincidental names: give up.
        sigs = {tuple(p.get('type') for p in (self.funcs[k].get('params') or [])) for k in keys}
        if len(sigs) == 1:
            return keys, 'name_dispatch'
        return [], None


# ── v4 state model ────────────────────────────────────────────────────
#
# A taint state is (hops, dispatch, path, origin):
#   hops      call edges between the origin and the current function
#   dispatch  some edge on the path was resolved by method name only
#   path      human-readable edge list
#   origin    0 net (request / network read), 1 wire (decoded data: tagged struct,
#             any / map[string]any, value asserted from an interface), 2 io (any
#             other read or decode of data from outside the process), 3 cb
#             (parameter of a function value that escaped to other code)
# Ranking prefers a stronger origin, then exact resolution, then fewer hops.

ORIGIN = {'entry': 0, 'src': 0, 'wire': 1, 'io': 2, 'cb': 3}
ORIGIN_NAME = ('net', 'wire', 'io', 'cb', 'llm')   # llm (v5): parameter judged external by the entry triage
_SKIP_ROOTS = ('lim', 'body', 'decomp', 'resp')


def _rank(state):
    hops, dispatch, _path, origin = state
    return (origin, dispatch, hops)


def provenance(state, direct=False):
    hops, dispatch, _path, origin = state
    hop = 'direct' if direct and hops == 0 else ('entry' if hops == 0 else ('1hop' if hops == 1 else 'nhop'))
    return f"{ORIGIN_NAME[origin]}_{hop}" + ('_dispatch' if dispatch else '')


def _better(a, b):
    return b is None or _rank(a) < _rank(b)


class _Engine:
    """Fixed point over parameter states and return-value states of every function."""

    def __init__(self, idx, max_hops, name_dispatch, wire_types, extra_seeds=None):
        self.idx, self.max_hops, self.name_dispatch = idx, max_hops, name_dispatch
        self.wire_types = wire_types or set()
        self.extra_seeds = extra_seeds or {}   # v5: {func_key: [param index, ...]} judged external by the LLM triage
        self.tainted = {}   # key -> {param index -> state}
        self.ret = {}       # key -> state of the returned value
        self.ret_calls = {}
        self._res_cache = {}
        self._cs_cache = {}   # (key, line, own-params-ignored) -> state, valid within one round
        self._noparam = None  # function whose own parameters count as untainted (see run)
        for key, pf in idx.funcs.items():
            for cs in pf.get('ret_calls') or []:
                self.ret_calls.setdefault((key, cs['line']), []).append(cs)

    def resolve(self, key, cs):
        ck = (key, cs['line'], cs.get('name'), cs.get('pkg'), cs.get('recv'), cs.get('nargs'))
        if ck not in self._res_cache:
            self._res_cache[ck] = self.idx.resolve(key, cs, name_dispatch=self.name_dispatch)
        return self._res_cache[ck]

    def offer(self, key, i, state):
        cur = self.tainted.setdefault(key, {}).get(i)
        if _better(state, cur):
            self.tainted[key][i] = state
            return True
        return False

    def root_state(self, key, r, depth=0):
        if r in ORIGIN:
            return (0, False, [], ORIGIN[r])
        if r.startswith('param:'):
            if key == self._noparam:
                return None
            return self.tainted.get(key, {}).get(int(r[6:]))
        if r.startswith('call:') and depth < 4:
            return self.call_state(key, int(r[5:]), depth)
        return None

    def best_of(self, key, roots, depth=0):
        best = None
        for r in roots or []:
            st = self.root_state(key, r, depth)
            if st is not None and _better(st, best):
                best = st
        return best

    def call_state(self, key, line, depth):
        """State of the value returned by the call at `line`: the callee's own return
        origin, or (pass-through) the state of an argument the callee returns.
        Memoised per round; a call currently being evaluated (cycle) yields None."""
        ck = (key, line, key == self._noparam)
        if ck in self._cs_cache:
            return self._cs_cache[ck]
        self._cs_cache[ck] = None   # in progress: cycles see None
        best = self._call_state(key, line, depth)
        self._cs_cache[ck] = best
        return best

    def _call_state(self, key, line, depth):
        best = None
        for cs in self.ret_calls.get((key, line), []):
            keys, res = self.resolve(key, cs)
            if not keys:
                continue
            disp = res == 'name_dispatch'
            cands = []
            for t in keys:
                c = None
                rs = self.ret.get(t)
                if rs is not None:
                    c = rs
                pf = self.idx.funcs[t]
                args = {a['index']: a.get('roots') or [] for a in (cs.get('args') or [])}
                for i in pf.get('ret_params') or []:
                    if i in args:
                        st = self.best_of(key, args[i], depth + 1)
                        if st is not None and _better(st, c):
                            c = st
                cands.append(c)
            if disp:
                if any(c is None for c in cands):
                    continue
                c = max(cands, key=_rank)   # every candidate agrees; take the weakest claim
            else:
                c = min((c for c in cands if c is not None), key=_rank, default=None)
            if c is None or c[0] + 1 > self.max_hops:
                continue
            st = (c[0] + 1, c[1] or disp, c[2] + [f"{key}@L{line} ← {keys[0]}"], c[3])
            if _better(st, best):
                best = st
        return best

    def module_callees(self):
        """Functions that some module code calls (exact or by name)."""
        called = set()
        for key in sorted(self.idx.funcs):
            for cs in self.idx.funcs[key].get('callees') or []:
                keys, _res = self.idx.resolve(key, dict(cs, line=0), name_dispatch=self.name_dispatch)
                called.update(keys)
        return called

    def seed(self):
        # v5: parameters the signature-level LLM triage judged to carry external data
        for key in sorted(self.extra_seeds):
            if key in self.idx.funcs:
                for i in self.extra_seeds[key]:
                    self.offer(key, int(i), (0, False, [f"{key}: parameter {i} judged external by entry triage"], 4))
        called = self.module_callees()
        for key in sorted(self.idx.funcs):
            pf = self.idx.funcs[key]
            # parameters whose type is a wire struct of this module, on functions no
            # module code calls: the caller is a framework that decoded the value
            for p in (pf.get('params') or []) if key not in called else []:
                tb = p.get('type_base')
                if not tb or p.get('name') in (None, '_'):
                    continue
                d = import_to_dir(p['type_pkg'], self.idx.modules) if p.get('type_pkg') else _dir(pf['file'])
                if d is not None and (d, tb) in self.wire_types:
                    self.offer(key, p['index'], (0, False, [f"{key}: {p['name']} is {p.get('type')} (tagged struct)"], 1))
            # parameters of function values that escaped to other code
            for ref in pf.get('callback_refs') or []:
                targets, res = self.idx.resolve(key, ref, check_arity=False, name_dispatch=self.name_dispatch)
                for t in targets:
                    for p in self.idx.funcs[t].get('params') or []:
                        if p.get('name') in (None, '_') or p.get('type') in ('context.Context', 'http.ResponseWriter'):
                            continue
                        self.offer(t, p['index'], (0, res == 'name_dispatch',
                                                   [f"{key}@L{ref['line']} hands {t} to other code"], 3))

    def run(self):
        self.seed()
        for _round in range(self.max_hops + 4):
            changed = False
            self._cs_cache = {}
            for key in sorted(self.idx.funcs):
                pf = self.idx.funcs[key]
                # the function's own return state: origins and call chains only. What it
                # returns of its parameters is applied per call site (ret_params), never
                # summarised — otherwise one tainted caller would taint every caller.
                self._noparam = key
                rs = self.best_of(key, pf.get('return_roots'))
                self._noparam = None
                if rs is not None and _better(rs, self.ret.get(key)):
                    self.ret[key] = rs
                    changed = True
                for cs in pf.get('call_sites') or []:
                    callees = None
                    for arg in cs.get('args') or []:
                        best = self.best_of(key, arg.get('roots'))
                        if best is None or best[0] + 1 > self.max_hops:
                            continue
                        if callees is None:
                            callees = self.resolve(key, cs)
                        keys, res = callees
                        for t in keys:
                            if t == key:
                                continue
                            st = (best[0] + 1, best[1] or res == 'name_dispatch',
                                  best[2] + [f"{key}@L{cs['line']}"], best[3])
                            if self.offer(t, arg['index'], st):
                                changed = True
            if not changed:
                break
        return self.tainted


def propagate(param_flows, modules=None, max_hops=MAX_HOPS, name_dispatch=True, wire_types=None, extra_seeds=None):
    """-> ({func_key: {param_index: state}}, index). index.engine holds the return states."""
    idx = _Index(param_flows, modules or [])
    eng = _Engine(idx, max_hops, name_dispatch, wire_types, extra_seeds)
    tainted = eng.run()
    idx.engine = eng
    return tainted, idx


def tainted_sinks(param_flows, modules=None, max_hops=MAX_HOPS, name_dispatch=True, wire_types=None, extra_seeds=None, retain_protection=False):
    """-> {func_key: [ {sink, source} ]} sinks reached by externally originated data.

    source: {line, type: 'param_external', provenance, param, path}. The source line is
    the parameter's first use, or the function line when the taint arrives through a
    non-parameter root or the first use is not before the sink.
    """
    tainted, idx = propagate(param_flows, modules, max_hops, name_dispatch, wire_types, extra_seeds)
    eng = idx.engine
    out = {}
    for key in sorted(idx.funcs):
        pf = idx.funcs[key]
        params = {p['index']: p for p in (pf.get('params') or [])}
        for snk in pf.get('taint_sinks') or []:
            roots = list(snk.get('roots') or [])
            if snk.get('type') == 'unbounded_read':
                if 'lim' in roots and not retain_protection:
                    continue  # read through io.LimitReader / http.MaxBytesReader
                if 'body' in roots and 'decomp' in roots:
                    roots.append('src')  # decompressed HTTP body: decompression bomb (CWE-409)
            best, best_param = None, None
            for r in roots:
                if r in _SKIP_ROOTS or r.startswith(('varg:', 'vret:')):
                    continue
                st = eng.root_state(key, r)
                if st is None:
                    continue
                pi = int(r[6:]) if r.startswith('param:') else None
                if _better(st, best) or (best is not None and _rank(st) == _rank(best)
                                         and best_param is None and pi is not None):
                    best, best_param = st, pi
            if best is None:
                continue
            p = params.get(best_param) or {}
            first = p.get('first_use') or 0
            line = first if 0 < first < snk['line'] else pf.get('line', snk['line'])
            pname = p.get('name', '')
            prov = provenance(best, direct=best_param is None)
            out.setdefault(key, []).append({
                'sink': {'line': snk['line'], 'type': snk['type'], 'desc': snk.get('pattern', '')[:80]},
                'source': {'line': line, 'type': 'param_external',
                           'desc': (f"参数 {pname} 外部可达（{prov}）" if pname
                                    else f"外部输入（{prov}）"),
                           'provenance': prov, 'param': pname,
                           'path': best[2]},
            })
    return out


def wire_types_from(ast_result, prefix=''):
    """{(dir, TypeName)} from an analyzer result (or a list of WireType dicts)."""
    items = ast_result.get('wire_types') if isinstance(ast_result, dict) else ast_result
    out = set()
    for w in items or []:
        f = f"{prefix}/{w['file']}" if prefix else w['file']
        out.add((_dir(f), w['name']))
    return out


def sanitizers_by_func(param_flows):
    return {f"{pf['file']}:{pf['function']}": list(pf.get('sanitizers') or [])
            for pf in (param_flows or []) if pf.get('sanitizers')}


# ── Selftest ──────────────────────────────────────────────────────────

def _selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    fx = os.path.join(here, 'tests', 'fixtures', 'r2')
    failures = []
    try:
        sys.path.insert(0, here)
        from go_ast_analysis import analyze_go_source
    except ImportError as e:
        print(f'SELFTEST FAILED: {e}')
        return 1
    flows = []
    for sub in ('', 'store'):
        res = analyze_go_source(os.path.join(fx, sub) if sub else fx) or {}
        for pf in res.get('param_flows') or []:
            if sub:
                pf['file'] = f"{sub}/{pf['file']}"
            flows.append(pf)
    if not flows:
        print('SELFTEST FAILED: analyzer produced no param_flows (binary stale?)')
        return 1
    mods = load_modules(fx)
    if mods != [('example.com/r2fx', '')]:
        failures.append(f'module map: {mods}')
    if import_to_dir('example.com/r2fx/store', mods) != 'store':
        failures.append('import_to_dir')

    got = tainted_sinks(flows, mods)
    summary = {k: sorted((s['sink']['type'], s['source']['provenance']) for s in v) for k, v in got.items()}
    expect = {
        'store/store.go:Run': [('command_execution', 'net_1hop')],          # HandleRun -> store.Run
        'store/store.go:LdapClient.Lookup': [('query_exec', 'net_1hop_dispatch')],  # s.db.Lookup
        'types.go:openIt': [('file_read', 'cb_nhop')],                      # escaped closure -> validate -> openIt
        'handlers.go:onMsg': [('command_execution', 'cb_entry')],           # handed to api.Register
        'store/store.go:Repo.Find': [('sql_exec', 'net_1hop_dispatch')],    # string-built SQL
    }
    for k, v in expect.items():
        if summary.get(k) != v:
            failures.append(f'{k}: expected {v}, got {summary.get(k)}')
    for k in ('store/store.go:Repo.Delete', 'store/store.go:Repo.Rename'):
        if k in summary:
            failures.append(f'{k}: bind argument / same-named field must not be a tainted sink')
    if 'store/store.go:SafeClient.Lookup' in summary:
        failures.append('escaped value must not reach the sink (SafeClient.Lookup)')
    if summary.get('handlers.go:d5') != [('command_execution', 'net_nhop')]:
        failures.append(f'5-hop chain is reached under the soft limit (hard cap {MAX_HOPS}): {summary.get("handlers.go:d5")}')
    got4 = tainted_sinks(flows, mods, max_hops=4)
    if 'handlers.go:d5' in got4:
        failures.append('d5 must not be reached with max_hops=4')
    nd = tainted_sinks(flows, mods, name_dispatch=False)
    if 'store/store.go:LdapClient.Lookup' in nd:
        failures.append('name_dispatch=False must not dispatch')
    # multi-line sink: first use inside the call -> function line
    lk = got.get('store/store.go:LdapClient.Lookup', [{}])[0]
    fline = next(pf['line'] for pf in flows if pf['function'] == 'LdapClient.Lookup')
    if lk and lk['source']['line'] != fline:
        failures.append(f"source line should fall back to function line {fline}: {lk['source']['line']}")
    if tainted_sinks(flows, mods) != got:
        failures.append('not deterministic')

    # v3.1: network-only sources, return summaries, SSRF destination, R4 unbounded read
    fx4 = os.path.join(here, 'tests', 'fixtures', 'r4')
    flows4 = (analyze_go_source(fx4) or {}).get('param_flows') or []
    got4 = tainted_sinks(flows4, load_modules(fx4))
    s4 = {k: sorted((x['sink']['type'], x['source']['provenance']) for x in v) for k, v in got4.items()}
    exp4 = {'main.go:FetchGzip': [('unbounded_read', 'net_direct')],      # limit undone by gzip
            'main.go:NewClient': [('http_request', 'net_direct')],         # annotation via return value
            'main.go:Proxy': [('http_request', 'net_direct')]}             # query value as outbound URL
    if s4 != exp4:
        failures.append(f'v3.1 fixture: expected {exp4}, got {s4}')

    # v3.2: out-parameter decode, multi-result, cross-package return, URL path/authority,
    # string-built query, response write, safe Content-Type
    fx6 = os.path.join(here, 'tests', 'fixtures', 'r6')
    flows6 = []
    for sub in ('', 'proto'):
        for pf in (analyze_go_source(os.path.join(fx6, sub) if sub else fx6) or {}).get('param_flows') or []:
            if sub:
                pf['file'] = f"{sub}/{pf['file']}"
            flows6.append(pf)
    got6 = tainted_sinks(flows6, load_modules(fx6))
    s6 = {k: sorted(x['sink']['type'] for x in v) for k, v in got6.items()}
    exp6 = {'main.go:forward': ['url_path'], 'main.go:Lookup': ['query_built'], 'main.go:Echo': ['response_write']}
    if s6 != exp6:
        failures.append(f'v3.2 fixture: expected {exp6}, got {s6}')

    # v4: structural origins — tagged struct param, map[string]any param, type assertion,
    # escaped function value (FuncMap), file content (io), pass-through summaries,
    # os.Stdin excluded, plain internal helper not reported
    fx7 = os.path.join(here, 'tests', 'fixtures', 'r7')
    flows7, wt7 = [], set()
    for sub in ('', 'api'):
        res = analyze_go_source(os.path.join(fx7, sub) if sub else fx7) or {}
        for pf in res.get('param_flows') or []:
            if sub:
                pf['file'] = f"{sub}/{pf['file']}"
            flows7.append(pf)
        wt7 |= wire_types_from(res, sub)
    if ('api', 'ToolCall') not in wt7:
        failures.append(f'wire types: {wt7}')
    got7 = tainted_sinks(flows7, load_modules(fx7), wire_types=wt7)
    s7 = {k: sorted((x['sink']['type'], x['source']['provenance']) for x in v) for k, v in got7.items()}
    exp7 = {'main.go:Invoke': [('url_path', 'wire_entry')],            # tagged struct param, via pass-through
            'main.go:buildURL': [('url_path', 'wire_direct')],         # value asserted out of map[string]any
            'main.go:Parser.readFile': [('file_read', 'cb_entry')],    # method value in a FuncMap literal
            'main.go:loadSpec': [('file_read', 'io_direct')],          # path taken from a file's content
            'main.go:resolvePath': [('url_path', 'wire_direct')]}      # template output into a URL's path
    if s7 != exp7:
        failures.append(f'v4 fixture: expected {exp7}, got {s7}')
    # checkPassword asserts from its own `any` parameter: a projection of param:1, not new data
    for k in ('main.go:fromStdin', 'main.go:helper', 'main.go:Dispatch', 'main.go:checkPassword'):
        if k in s7:
            failures.append(f'{k} must not be reported')

    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for m in failures:
            print(f"  - {m}")
        return 1
    print("SELFTEST PASSED: module map, 1-hop pkg call, name dispatch, closure 2-hop, "
          "registered ref, string-built SQL, prepared stmt / field-name negatives, sanitizer kill, "
          "hop limit, dispatch switch, source line, determinism, v3.1 (gzip bomb, MaxBytesReader, stdin, "
          "annotation return summary -> Address, handler SSRF), v3.2 (decode out-param, 2nd result, "
          "cross-package return -> URL path, built query, response write, safe Content-Type), "
          "v4 (tagged struct, map[string]any, type assertion, escaped FuncMap value, file content, "
          "pass-through, stdin excluded)")
    return 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        sys.exit(_selftest())
    print(__doc__)
