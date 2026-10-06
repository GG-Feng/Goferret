#!/usr/bin/env python3
"""复现与验证 workflow v2

  python3 repro.py select   [--repos a/b,c/d] [--include 'file.go:Recv.Name[:category]']
  python3 repro.py evidence [--repos ...]
  python3 repro.py design   [--repos ...] [--regenerate]     # 唯一调用 LLM 的步骤；已冻结的单元跳过
  python3 repro.py run      [--repos ...]                    # 重放冻结测试（一次性断网容器）
  python3 repro.py judge    [--repos ...]                    # 纯规则判定
  python3 repro.py report   [--repos ...]                    # 每仓库一份维护者报告草稿 + summary.csv
  python3 repro.py all      [--repos ...]
  python3 repro.py check-stable [--repos ...]                # 再跑一遍 run+judge，逐单元比对
"""
import argparse, hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm, docker_run, judge as judge_mod, report as report_mod  # noqa: E402

SEV = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
SEV_NAME = {v: k for k, v in SEV.items()}


CONFIG_PATH = os.environ.get('REPRO_CONFIG', os.path.join(HERE, 'config.json'))


def cfg():
    return json.load(open(CONFIG_PATH, encoding='utf-8'))


def slug(repo):
    return repo.replace('/', '__')


def cases_root():
    return cfg().get('cases_root') or os.path.join(HERE, 'cases')


def case_dir(repo):
    return os.path.join(cases_root(), slug(repo))


def src_dir(c, repo):
    return os.path.join(c['src_root'], slug(repo))


def unit_id(function, category):
    return 'U' + hashlib.sha1(f'{function}|{category}'.encode()).hexdigest()[:8]


def split_function(key):
    file, _, q = key.rpartition(':')
    recv, _, name = q.rpartition('.')
    return file, recv, name


# 测试辅助/示例代码不进入验证：维护者不关心，且这类代码的"缺少校验"通常是有意为之
TEST_HELPER_DIRS = {'testing', 'testutil', 'testutils', 'testhelper', 'testhelpers', 'test', 'tests', 'e2e', 'integration',
                    'mock', 'mocks', 'fake', 'fakes', 'fixtures', 'testdata', 'examples', 'example'}
TEST_HELPER_FILE_RE = re.compile(r'(_test\.go$)|(^.*_mock.*\.go$)|(^mock_.*\.go$)|(^.*_fake.*\.go$)')


def is_test_helper(path):
    parts = path.replace('\\', '/').split('/')
    return any(d in TEST_HELPER_DIRS for d in parts[:-1]) or bool(TEST_HELPER_FILE_RE.match(parts[-1]))


def jload(p, default=None):
    return json.load(open(p, encoding='utf-8')) if os.path.exists(p) else default


def jdump(o, p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(o, open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)


def load_sel(repo):
    sel = jload(os.path.join(case_dir(repo), 'selected.json'))
    if not sel:
        sys.exit(f'{repo}: 先执行 select')
    return sel


# ---------------------------------------------------------------- 1 select
def cmd_select(c, repo, include=(), manual=()):
    rp = os.path.join(c['reports_root'], slug(repo), c['report_file'])
    raw = open(rp, 'rb').read()
    F = json.loads(raw)['findings']
    units = {}
    for i, f in enumerate(F):
        k = (f['function'], f['missing_step_category'])
        u = units.setdefault(k, dict(function=f['function'], category=f['missing_step_category'], findings=[],
                                     pattern_names=set(), template_ids=set(), severity_rank=9, confidence=0.0,
                                     source_lines=set(), sink_lines=set(), source_types=set(), included=False))
        u['findings'].append(i); u['pattern_names'].add(f['pattern_name']); u['template_ids'].add(f['template_id'])
        st = ((f.get('span') or {}).get('source') or {}).get('type')
        if st: u['source_types'].add(st)
        u['severity_rank'] = min(u['severity_rank'], SEV.get(f['severity'], 9))
        u['confidence'] = max(u['confidence'], float(f.get('confidence') or 0))
        sp = f.get('span') or {}
        for side, dst in (('source', 'source_lines'), ('sink', 'sink_lines')):
            ln = (sp.get(side) or {}).get('line')
            if ln: u[dst].add(int(ln))
    order = sorted(units.values(), key=lambda u: (u['severity_rank'], -u['confidence'], u['function'], min(u['template_ids'])))
    skipped = [u['function'] for u in order if is_test_helper(u['function'].rpartition(':')[0])]
    order = [u for u in order if not is_test_helper(u['function'].rpartition(':')[0])]
    selected = order[:c['per_repo']]
    for spec in include:
        fn, cat = (spec.rsplit(':', 1) if spec.count(':') >= 2 else (spec, None))
        for u in order:
            if u['function'] == fn and (cat is None or u['category'] == cat) and u not in selected:
                u['included'] = True; selected.append(u)
    # --manual 'file.go:Recv.Name:category'：检测器没报到的目标也造一个单元（无检测器主张），用于把"漏报"和"复现不了"分开衡量
    for spec in manual:
        body, _, desc = spec.partition('::')  # 'file.go:Recv.Name:category::一句话假设'
        fn, cat = body.rsplit(':', 1)
        if any(u['function'] == fn and u['category'] == cat for u in selected): continue
        selected.append(dict(function=fn, category=cat, findings=[], pattern_names=set(), template_ids={'manual'}, severity_rank=9,
                             confidence=0.0, source_lines=set(), sink_lines=set(), source_types=set(), included=True, manual=True,
                             manual_claim=desc.strip()))
    commit = subprocess.run(['git', '-C', src_dir(c, repo), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    out = []
    for u in selected:
        out.append(dict(unit_id=unit_id(u['function'], u['category']), function=u['function'], category=u['category'],
                        severity=SEV_NAME.get(u['severity_rank'], 'manual' if u.get('manual') else '?'), confidence=u['confidence'],
                        included=u['included'], manual=bool(u.get('manual')), manual_claim=u.get('manual_claim', ''),
                        findings=u['findings'], pattern_names=sorted(u['pattern_names']), template_ids=sorted(u['template_ids']),
                        source_lines=sorted(u['source_lines']), sink_lines=sorted(u['sink_lines']), source_types=sorted(u['source_types'])))
    # 不再入选的旧单元目录移到 _stale/，避免陈旧的 verdict.json 混进统计
    cd = case_dir(repo); keep = {u['unit_id'] for u in out}
    for name in os.listdir(cd) if os.path.isdir(cd) else []:
        if name.startswith('U') and name not in keep and os.path.isdir(os.path.join(cd, name)):
            os.makedirs(os.path.join(cd, '_stale'), exist_ok=True)
            os.replace(os.path.join(cd, name), os.path.join(cd, '_stale', name))
    jdump(dict(repo=repo, slug=slug(repo), commit=commit, report_sha256=hashlib.sha256(raw).hexdigest(),
               total_findings=len(F), total_units=len(units), per_repo=c['per_repo'], units=out,
               skipped_test_helper_units=sorted(set(skipped))),
          os.path.join(case_dir(repo), 'selected.json'))
    print(f'{repo}: {len(F)} findings → {len(units)} units（测试辅助路径跳过 {len(set(skipped))}）→ selected {len(out)}')


# ---------------------------------------------------------------- 2 evidence
def locate(lines, recv, name):
    if recv:
        pat = re.compile(r'^func\s*\(\s*\w*\s*\*?\s*' + re.escape(recv) + r'(\[[^\]]*\])?\s*\)\s*' + re.escape(name) + r'\s*[\[(]')
    else:
        pat = re.compile(r'^func\s+' + re.escape(name) + r'\s*[\[(]')
    for i, l in enumerate(lines):
        if pat.match(l):
            depth, opened = 0, False
            for j in range(i, len(lines)):
                if '{' in lines[j]: opened = True
                depth += lines[j].count('{') - lines[j].count('}')
                if opened and depth == 0:
                    return i + 1, j + 1
    return None


def module_of(src, file):
    d = os.path.dirname(file)
    while True:
        gm = os.path.join(src, d, 'go.mod')
        if os.path.exists(gm):
            m = re.search(r'^module\s+(\S+)', open(gm, encoding='utf-8').read(), re.M)
            return m.group(1), d
        if d in ('', '.'):
            return '', ''
        d = os.path.dirname(d)


def guards(c, src, file, name, line):
    p = subprocess.run([c['ast_analyzer'], '--dir', src, '--guards', file, '--guard-func', name, '--guard-line', str(line)],
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        return []
    return (json.loads(p.stdout) or {}).get('guards') or []


def callers(src, name, file):
    p = subprocess.run(['grep', '-rn', '--include=*.go', '--exclude=*_test.go', '--exclude-dir=vendor', '--exclude-dir=testdata',
                        '-F', name + '(', src], capture_output=True, text=True)
    out = []
    for l in p.stdout.splitlines():
        rel = l.replace(src + '/', '', 1)
        if re.search(r'\bfunc\b.*\b' + re.escape(name) + r'\s*\(', l):
            continue
        if re.search(r'\b' + re.escape(name) + r'\(', l):
            out.append(rel[:200])
    return sorted(out)[:12]


def claims(F, u):
    """检测器对该单元的主张（reasoning/evidence），去重，最多 3 条，每条截断。只是待验证假设。"""
    out, seen = [], set()
    if u.get('manual_claim'):
        out.append(f"- [manual] {u['manual_claim']}")
    for i in u['findings']:
        f = F[i]; key = (f.get('reasoning') or '')[:200]
        if key in seen: continue
        seen.add(key)
        out.append(f"- [{f.get('pattern_name')}] {(f.get('reasoning') or '')[:600]}\n  evidence: {(f.get('evidence') or '')[:200]}")
        if len(out) == 3: break
    return out


def cmd_evidence(c, repo):
    sel, src = load_sel(repo), src_dir(c, repo)
    F = json.load(open(os.path.join(c['reports_root'], slug(repo), c['report_file']), encoding='utf-8'))['findings']
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id']); os.makedirs(d, exist_ok=True)
        file, recv, name = split_function(u['function'])
        path = os.path.join(src, file)
        ev = dict(unit_id=u['unit_id'], function=u['function'], file=file, recv=recv, name=name, qname=(recv + '.' if recv else '') + name, located=False)
        if os.path.exists(path):
            lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
            loc = locate(lines, recv, name)
            if loc:
                s, e = loc
                module, mod_rel = module_of(src, file)
                pkg_rel = os.path.relpath(os.path.dirname(file) or '.', mod_rel or '.')
                pm = re.search(r'^package\s+(\w+)', '\n'.join(lines[:200]), re.M)
                target = max(u['sink_lines']) if u['sink_lines'] else 0
                ev.update(located=True, start=s, end=e, module=module, mod_rel=mod_rel, pkg_rel=pkg_rel,
                          import_path=(module + ('/' + pkg_rel if pkg_rel != '.' else '')), package=pm.group(1) if pm else '',
                          guards=guards(c, src, file, name, target), callers=callers(src, name, file),
                          source_lines=u['source_lines'], sink_lines=u['sink_lines'], category=u['category'])
                body = '\n'.join(f'{s + i:5d}  {l}' for i, l in enumerate(lines[s - 1:e]))
                txt = [f"unit: {u['unit_id']}", f"function: {u['function']}", f"category: {u['category']}",
                       f"module: {module}    import_path: {ev['import_path']}    package: {ev['package']}",
                       f"target: source lines {u['source_lines']} -> sink lines {u['sink_lines']}", '',
                       f'===== FUNCTION SOURCE ({file}, lines {s}-{e}) =====', body, '',
                       '===== GUARDS (early returns between entry and target line; file:line) =====']
                txt += [f"{file}:{g['line']}  returns {g.get('returns', '')}  cond: {g.get('condition', '')}  deps: {g.get('depends_on', [])}" for g in ev['guards']] or ['(none)']
                txt += ['', '===== CALLERS (sorted, up to 12) ====='] + (ev['callers'] or ['(none found)'])
                txt += ['', '===== CLAIM (detector output; a hypothesis to test, not evidence) ====='] + claims(F, u)
                open(os.path.join(d, 'evidence.txt'), 'w', encoding='utf-8').write('\n'.join(txt) + '\n')
        jdump(ev, os.path.join(d, 'evidence.json'))
        print(('OK  ' if ev['located'] else 'MISS'), repo, u['unit_id'], u['function'], f"{ev.get('start')}-{ev.get('end')}" if ev['located'] else '')


# ---------------------------------------------------------------- 3 design（唯一的 LLM 步骤）
GO_ENV = dict(os.environ, GOPROXY='off', GOTOOLCHAIN='local', GOWORK='off')


# 同包测试的 TestMain 依赖离线拿不到的基础设施（DB/外部服务），任何同包测试都会被它的 os.Exit 挡住
INFRA_RE = re.compile(r'InitDatabaseFromEnv|GetDatabaseFromEnv|POSTGRESQL_HOST|PrepareTestForMySQL|PrepareTestForPostgresSQL|'
                      r'test\.InitDatabase|dao\.PrepareTestData|redis\.Init|InitRedisFromEnv')


def package_needs_infra(src, mod_rel, pkg_rel):
    """目标包的 _test.go 里有 TestMain 且其（或它调用的 setup）触及数据库/外部服务 → 离线无法同包测试。返回触发的标记文本或 ''。"""
    d = os.path.join(src, mod_rel, pkg_rel)
    tests = [f for f in os.listdir(d) if f.endswith('_test.go')] if os.path.isdir(d) else []
    if not any('func TestMain' in open(os.path.join(d, f), encoding='utf-8', errors='replace').read() for f in tests):
        return ''
    for f in tests:
        txt = open(os.path.join(d, f), encoding='utf-8', errors='replace').read()
        m = INFRA_RE.search(txt)
        if m:
            return f'{f}: TestMain 依赖 {m.group(0)}（离线容器无此基础设施）'
    return ''


def go_doc(src, mod_rel, pkg_rel, symbol='.', cap=16000):
    p = subprocess.run(['go', 'doc', '-all', '-u', symbol], cwd=os.path.join(src, mod_rel, pkg_rel), capture_output=True, text=True,
                       env=GO_ENV, timeout=120)
    return p.stdout[:cap]


def symbol_docs(src, mod_rel, pkg_rel, compiler_output, test_code=''):
    """编译错误里提到的类型/符号，补上它们的 go doc，避免下一轮再猜字段名。
    `undefined: pkg.Sym` 这种，给出测试所导入的那个包的 go doc（LLM 常常编造别的包里的函数）。"""
    syms = set(re.findall(r'\(type \*?(\w+) has no field or method', compiler_output))
    syms |= set(re.findall(r'undefined: (\w+)\s*$', compiler_output, re.M))
    out = []
    for s in sorted(syms)[:6]:
        d = go_doc(src, mod_rel, pkg_rel, s, cap=3000)
        if d.strip(): out.append(f'===== go doc -u {s} =====\n{d}')
    pkgs = set(re.findall(r'undefined: (\w+)\.\w+', compiler_output))
    imports = re.findall(r'^\s*(?:(\w+)\s+)?"([\w./-]+)"', test_code, re.M)
    for p in sorted(pkgs)[:4]:
        path = next((ip for alias, ip in imports if alias == p or ip.rsplit('/', 1)[-1] == p), None)
        if not path: continue
        d = subprocess.run(['go', 'doc', '-all', '-u', path], cwd=os.path.join(src, mod_rel), capture_output=True, text=True, env=GO_ENV, timeout=120).stdout[:4000]
        if d.strip(): out.append(f'===== go doc -all -u {path}（导入包 {p} 实际提供的 API）=====\n{d}')
    return '\n\n'.join(out)


CALL_RE = re.compile(r'\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\(')
SKIP_IDENTS = {'if', 'for', 'switch', 'return', 'func', 'go', 'defer', 'make', 'len', 'append', 'string', 'byte', 'int', 'error',
               'errors.New', 'fmt.Errorf', 'fmt.Sprintf', 'log.Printf', 'context.Background'}


def body_idents(body):
    """目标函数体里调用的标识符：pkg.Func 形式和 recv.method 的方法名，用来找相关测试和被调函数。"""
    out = set()
    for m in CALL_RE.findall(body):
        if m in SKIP_IDENTS or len(m.split('.')[-1]) < 4: continue
        out.add(m.split('.')[-1] if not m[0].isupper() or '.' not in m else m)  # 'c.initiateBlobUpload' → 方法名；'config.AuthMode' 保留
        out.add(m.split('.')[-1])
    return out


def split_funcs(text):
    """按顶层 func 切片：返回 [(签名行, 片段)]"""
    parts = re.split(r'(?m)^(?=func )', text)
    return [(p.splitlines()[0][:120], p) for p in parts if p.startswith('func ')]


def related_test_snippets(src, mod_rel, pkg_rel, name, idents, limit=3, cap=3000):
    """模块内所有 _test.go 里引用了目标函数或其调用标识符的测试函数，按命中数排序；同文件的 TestMain/init 一并给出（初始化常在里面）。"""
    root, scored = os.path.join(src, mod_rel), []
    for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if d not in ('vendor', 'testdata', 'node_modules', '.git'))
        for f in sorted(fn):
            if not f.endswith('_test.go'): continue
            path = os.path.join(dp, f); text = open(path, encoding='utf-8', errors='replace').read()
            if name not in text and not any(i in text for i in idents): continue
            rel = os.path.relpath(path, root); same_pkg = os.path.relpath(dp, root) == pkg_rel
            setup = [p for s, p in split_funcs(text) if re.match(r'func (TestMain|init)\(', s)]
            for sig, chunk in split_funcs(text):
                sc = (5 if re.search(r'\b' + re.escape(name) + r'\(', chunk) else 0) + 2 * sum(1 for i in idents if i in chunk) + (3 if same_pkg else 0)
                if sc: scored.append((-sc, rel, sig, chunk[:cap], setup))
    scored.sort(key=lambda x: (x[0], x[1], x[2]))
    out, seen_setup = [], set()
    for _, rel, sig, chunk, setup in scored[:limit]:
        out.append(f'===== RELATED TEST {rel} =====\n{chunk}')
        for s in setup:
            if (rel, s[:80]) not in seen_setup:
                seen_setup.add((rel, s[:80])); out.append(f'===== SETUP IN {rel} =====\n{s[:cap]}')
    return out


def callee_sources(src, mod_rel, pkg_rel, idents, exclude, limit=4, cap=2500):
    """目标函数调用的同包函数/方法的源码（如 initiateBlobUpload），让设计者知道守卫背后期待什么交互。"""
    d = os.path.join(src, mod_rel, pkg_rel); out = []
    names = sorted(i.split('.')[-1] for i in idents if '.' not in i or i.split('.')[0][0].islower())
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('.go') or fn.endswith('_test.go'): continue
        lines = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read().splitlines()
        for n in names:
            if n == exclude or len(out) >= limit: continue
            loc = locate(lines, '', n) or next((locate(lines, r, n) for r in [m.group(1) for m in re.finditer(r'^func \(\s*\w*\s*\*?\s*(\w+)', '\n'.join(lines), re.M)] if locate(lines, r, n)), None)
            if loc:
                s, e = loc; out.append(f'===== CALLEE {fn}:{n} (lines {s}-{e}) =====\n' + '\n'.join(lines[s - 1:e])[:cap]); names.remove(n)
    return out


def example_tests(src, mod_rel, pkg_rel, file, name):
    d = os.path.join(src, mod_rel, pkg_rel); base = os.path.basename(file)[:-3]
    scored = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('_test.go'): continue
        t = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read()
        sc = (10 if fn.startswith(base) else 0) + (8 if name + '(' in t else 0) + (3 if 'httptest' in t else 0)
        scored.append((-sc, fn, t[:4000]))
    return [(fn, t) for _, fn, t in sorted(scored)[:2]]


def cmd_design(c, repo, regenerate=False):
    sel, src = load_sel(repo), src_dir(c, repo)
    system_tpl = open(os.path.join(HERE, 'prompts', 'design.md'), encoding='utf-8').read()
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id'])
        tp = os.path.join(d, 'experiment_test.go')
        ev = jload(os.path.join(d, 'evidence.json'), {})
        if not ev.get('located'):
            print('SKIP  ', repo, u['unit_id'], 'evidence missing'); continue
        test_name = f"TestRepro_{u['unit_id']}"
        infra = package_needs_infra(src, ev['mod_rel'], ev['pkg_rel'])
        if os.path.exists(tp) and not regenerate and not infra:
            print('FROZEN', repo, u['unit_id']); continue
        if infra:
            for fn in ('experiment_test.go', 'spec.json', 'test.sha256'):
                if os.path.exists(os.path.join(d, fn)): os.remove(os.path.join(d, fn))
            jdump([dict(round=0, package_needs_infra=infra)], os.path.join(d, 'design.log.json'))
            print('NOINFRA', repo, u['unit_id'], infra); continue
        # 先确认目标包本身能编译；不能编译的包写不出任何可运行的测试，不必浪费 LLM 轮次
        pre = docker_run.run_test(c, src, ev['mod_rel'], ev['pkg_rel'], '', None, '^$', c['test_timeout_sec'])
        if pre['build_failed']:
            for fn in ('experiment_test.go', 'spec.json', 'test.sha256'):
                if os.path.exists(os.path.join(d, fn)): os.remove(os.path.join(d, fn))
            jdump([dict(round=0, package_unbuildable=True, compiler=pre['output'][-3000:])], os.path.join(d, 'design.log.json'))
            print('NOPKG ', repo, u['unit_id'], ev['import_path']); continue
        system = system_tpl.replace('PACKAGE', ev['package']).replace('TEST_NAME', test_name).replace('MODULE', ev['module'])
        user = open(os.path.join(d, 'evidence.txt'), encoding='utf-8').read()
        user += '\n\n===== PACKAGE API (go doc -all -u) =====\n' + go_doc(src, ev['mod_rel'], ev['pkg_rel'])
        body_lines = open(os.path.join(src, ev['file']), encoding='utf-8', errors='replace').read().splitlines()[ev['start'] - 1:ev['end']]
        idents = body_idents('\n'.join(body_lines))
        for s in callee_sources(src, ev['mod_rel'], ev['pkg_rel'], idents, ev['name']):
            user += '\n\n' + s
        snippets = related_test_snippets(src, ev['mod_rel'], ev['pkg_rel'], ev['name'], idents)
        if snippets:
            user += '\n\n' + '\n\n'.join(snippets)
        else:
            for fn, t in example_tests(src, ev['mod_rel'], ev['pkg_rel'], ev['file'], ev['name']):
                user += f'\n\n===== EXISTING TEST {fn} =====\n{t}'
        log, code, spec = [], None, None
        for rnd in range(1, c['max_design_rounds'] + 1):
            content, meta = llm.chat(c['goferret_dir'], system, user, c['llm_max_tokens'])
            try:
                spec = llm.parse_json(content); code = spec.get('test_code') or ''
            except Exception as e:
                log.append(dict(round=rnd, cached=meta['cached'], error=f'JSON 解析失败: {e}')); user += '\n\n上一次输出不是合法 JSON，请只输出 JSON 对象。'; continue
            problems = []
            if not re.search(r'^package\s+' + re.escape(ev['package']) + r'\b', code, re.M): problems.append(f"包名必须是 {ev['package']}")
            if test_name not in code: problems.append(f'测试函数名必须是 {test_name}')
            r, setup_fail = None, None
            if not problems:
                # 直接跑正式测试：既检查编译，也检查前置条件有没有建好（benign 臂到不了目标行就要重试）
                r = docker_run.run_test(c, src, ev['mod_rel'], ev['pkg_rel'], f"repro_{u['unit_id']}_test.go", code, f'^{test_name}$', c['test_timeout_sec'])
                if r['build_failed']:
                    problems.append('编译失败')
                elif not r['timed_out']:
                    gl = {f"{ev['file']}:{g['line']}" for g in ev.get('guards', [])} | {f"{os.path.basename(ev['file'])}:{g['line']}" for g in ev.get('guards', [])}
                    verdict, rule, arms, _ = judge_mod.judge(r, gl, spec.get('bug_if'), ev.get('sink_lines') or [])
                    if rule in ('benign_not_reached', 'markers_missing'):
                        setup_fail = (rule, arms); problems.append('前置条件未建立' if rule == 'benign_not_reached' else '没有产生有效标记')
            log.append(dict(round=rnd, cached=meta['cached'], resp_model=meta['resp_model'], problems=problems, rc=r['rc'] if r else None,
                            compiler=(r['output'][-2000:] if r and r['build_failed'] else None)))
            if not problems:
                break
            detail = '\n'.join(problems)
            if r and r['build_failed']:
                detail += '\n\n编译器输出：\n' + r['output'][-4000:] + '\n\n' + symbol_docs(src, ev['mod_rel'], ev['pkg_rel'], r['output'], code)
            elif setup_fail:
                rule, arms = setup_fail
                seen = {a: (arms[a]['reached'], arms[a]['blocked_at'], arms[a]['result']) for a in arms}
                detail += (f'\n\n实际观察：{seen}\n（HTTP 4xx/5xx 一律视为未到达目标行，不管测试自己打了什么 REACHED）\n'
                           '\n这说明前置条件没有建立好，测的不是目标行为。请对照「守卫链」逐条满足：'
                           '凡是守卫依赖某个状态（缓存条目、文件、会话、权限），优先调用仓库里**真正创建该状态的函数**（POST/Create/Register 一类的 handler 或方法），'
                           '不要自己推导它内部用的 key/路径；它成功返回就说明状态对了。两臂各自独立建立状态。\n'
                           '被守卫拒绝时请打印 REACHED=no 和 BLOCKED_AT=文件:行号。\n\n测试输出末尾：\n' + r['output'][-2500:])
            user = user.split('\n\n===== 上一版')[0] + f'\n\n===== 上一版代码（在此基础上最小改动）=====\n```go\n{code}\n```\n\n===== 上一版的问题 =====\n{detail}\n\n修正后输出同样的 JSON。'
        if code is not None:
            open(tp, 'w', encoding='utf-8').write(code)
            open(os.path.join(d, 'test.sha256'), 'w').write(hashlib.sha256(code.encode()).hexdigest() + '\n')
            jdump(dict(test_name=test_name, what=spec.get('what'), category=spec.get('category'), bug_if=spec.get('bug_if'),
                       benign=spec.get('benign'), malicious=spec.get('malicious'),
                       expected_if_bug=spec.get('expected_if_bug'), expected_if_safe=spec.get('expected_if_safe'),
                       prompt_sha256=hashlib.sha256(system_tpl.encode()).hexdigest()[:12]), os.path.join(d, 'spec.json'))
        jdump(log, os.path.join(d, 'design.log.json'))
        print(('OK    ' if log and not log[-1].get('problems') else 'NOBLD '), repo, u['unit_id'], f'rounds={len(log)}')


# ---------------------------------------------------------------- 4 run
def cmd_run(c, repo, suffix=''):
    sel, src = load_sel(repo), src_dir(c, repo)
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id'])
        tp, ev, sp = os.path.join(d, 'experiment_test.go'), jload(os.path.join(d, 'evidence.json'), {}), jload(os.path.join(d, 'spec.json'), {})
        if not os.path.exists(tp) or not ev.get('located'):
            print('SKIP ', repo, u['unit_id']); continue
        code = open(tp, encoding='utf-8').read()
        r = docker_run.run_test(c, src, ev['mod_rel'], ev['pkg_rel'], f"repro_{u['unit_id']}_test.go", code, f"^{sp['test_name']}$", c['test_timeout_sec'])
        head = [f"image={r['image']}", f"command={r['cmd']}", f"test_sha256={hashlib.sha256(code.encode()).hexdigest()}",
                f"exit_code={r['rc']}", f"timed_out={r['timed_out']}", f"build_failed={r['build_failed']}", '===== OUTPUT =====']
        open(os.path.join(d, f'run{suffix}.log'), 'w', encoding='utf-8').write('\n'.join(head) + '\n' + r['output'])
        print(('OK   ' if r['rc'] == 0 else 'FAIL '), repo, u['unit_id'], f"rc={r['rc']}")


# ---------------------------------------------------------------- 5 judge
def parse_run_log(p):
    txt = open(p, encoding='utf-8', errors='replace').read()
    head, _, out = txt.partition('===== OUTPUT =====\n')
    kv = dict(l.split('=', 1) for l in head.splitlines() if '=' in l)
    return dict(output=out, rc=int(kv.get('exit_code', -1)), timed_out=kv.get('timed_out') == 'True',
                build_failed=kv.get('build_failed') == 'True', image=kv.get('image'), test_sha256=kv.get('test_sha256'))


def cmd_judge(c, repo, suffix=''):
    sel = load_sel(repo)
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id'])
        ev, rp = jload(os.path.join(d, 'evidence.json'), {}), os.path.join(d, f'run{suffix}.log')
        dl = jload(os.path.join(d, 'design.log.json'), [])
        if not ev.get('located'):
            v, rule, arms, lines, run = '未能复现', 'evidence_missing', {}, [], {}
        elif dl and dl[0].get('package_unbuildable'):
            v, rule, arms, lines, run = '未能复现', 'package_unbuildable', {}, [], {}
        elif dl and dl[0].get('package_needs_infra'):
            v, rule, arms, lines, run = '未能复现', 'package_needs_infra', {}, [], {}
        elif not os.path.exists(rp):
            v, rule, arms, lines, run = '未能复现', 'no_experiment', {}, [], {}
        else:
            run = parse_run_log(rp)
            gl = set()
            for g in ev.get('guards', []):
                gl.add(f"{ev['file']}:{g['line']}"); gl.add(f"{os.path.basename(ev['file'])}:{g['line']}")
            sp = jload(os.path.join(d, 'spec.json'), {})
            v, rule, arms, lines = judge_mod.judge(run, gl, sp.get('bug_if'), ev.get('sink_lines') or [])
        jdump(dict(unit_id=u['unit_id'], function=u['function'], category=u['category'], verdict=v, rule=rule, arms=arms,
                   marker_lines=lines, test_sha256=run.get('test_sha256'), image=run.get('image')), os.path.join(d, f'verdict{suffix}.json'))
        print(f'{v:5s} {rule:26s} {repo} {u["unit_id"]} {u["function"]}')


# ---------------------------------------------------------------- 6 report
def cmd_report(c, repo):
    sel = load_sel(repo); results = []
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id'])
        ev, sp, v = jload(os.path.join(d, 'evidence.json'), {}), jload(os.path.join(d, 'spec.json'), {}), jload(os.path.join(d, 'verdict.json'))
        if not v:
            continue
        if ev.get('located') and sp:
            open(os.path.join(d, 'repro.sh'), 'w', encoding='utf-8').write(report_mod.repro_sh(repo, sel['commit'], u, ev, sp['test_name']))
        results.append(dict(unit=u, ev=ev if ev.get('located') else None, spec=sp, verdict=v))
    md = report_mod.render_repo(repo, sel, results)
    open(os.path.join(case_dir(repo), f'report_{slug(repo)}.md'), 'w', encoding='utf-8').write(md)
    rows = report_mod.summary_csv(cases_root())
    print(f'{repo}: report written; summary rows={len(rows)}')


# ---------------------------------------------------------------- check-stable
def cmd_check_stable(c, repo):
    cmd_run(c, repo, suffix='.b'); cmd_judge(c, repo, suffix='.b')
    sel, diffs = load_sel(repo), []
    for u in sel['units']:
        d = os.path.join(case_dir(repo), u['unit_id'])
        a, b = jload(os.path.join(d, 'verdict.json'), {}), jload(os.path.join(d, 'verdict.b.json'), {})
        # 比对结论、规则和去掉易变 key 后的两臂观察值（marker_lines 原文可能含耗时，不参与比对）
        if (a.get('verdict'), a.get('rule'), a.get('arms')) != (b.get('verdict'), b.get('rule'), b.get('arms')):
            diffs.append((u['unit_id'], a.get('verdict'), a.get('rule'), b.get('verdict'), b.get('rule')))
    print(f'{repo}: {len(sel["units"])} units, {len(diffs)} differ between two runs')
    for x in diffs: print('  DIFF', *x)
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('step', choices=['select', 'evidence', 'design', 'run', 'judge', 'report', 'all', 'check-stable'])
    ap.add_argument('--repos', default='')
    ap.add_argument('--include', action='append', default=[])
    ap.add_argument('--manual', action='append', default=[], help="'file.go:Recv.Name:category'，检测器没报到的目标也造一个单元")
    ap.add_argument('--regenerate', action='store_true')
    a = ap.parse_args(); c = cfg()
    repos = [r for r in a.repos.split(',') if r] or c['repos']
    for repo in repos:
        if a.step in ('select', 'all'): cmd_select(c, repo, a.include, a.manual)
        if a.step in ('evidence', 'all'): cmd_evidence(c, repo)
        if a.step in ('design', 'all'): cmd_design(c, repo, a.regenerate)
        if a.step in ('run', 'all'): cmd_run(c, repo)
        if a.step in ('judge', 'all'): cmd_judge(c, repo)
        if a.step in ('report', 'all'): cmd_report(c, repo)
        if a.step == 'check-stable': cmd_check_stable(c, repo)


if __name__ == '__main__':
    main()
