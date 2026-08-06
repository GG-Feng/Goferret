"""
Detect vulnerabilities in a Go project using the behavior chain knowledge base.

Pipeline:
  1. AST scan of target project (local)
  2. Domain classification via LLM
  3. Pattern retrieval from vuln_db (local)
  4. Function prioritization (local scoring)
  5. Deep analysis per function via LLM

Usage:
    python detect_vulns.py --target /path/to/go/project
    python detect_vulns.py --target . --workers 3
    python detect_vulns.py --target . --max-functions 30
    python detect_vulns.py --target . --domains NetworkRequestAndProtocolHandling,InputParsingAndDeserialization
"""

import json
import os
import sys
import re
import time
import shutil
import argparse
import signal
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from go_ast_analysis import analyze_go_source


# ── config ────────────────────────────────────────────────────────────

def load_env():
    cfg = {}
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.isfile(env_path):
        print("Error: .env file not found", file=sys.stderr)
        sys.exit(1)
    with open(env_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                cfg[k.strip()] = v.strip()
    return cfg


# ── prompt loading ────────────────────────────────────────────────────

def load_prompt(filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path, encoding='utf-8') as f:
        return f.read()


# ── function source extraction ────────────────────────────────────────

def extract_func_sources(target_dir, functions):
    """Extract source code for given function definitions."""
    sources = []
    seen = set()

    for func_info in functions:
        fpath = func_info['file']
        name = func_info['name']
        key = (fpath, name)
        if key in seen:
            continue
        seen.add(key)

        source_path = os.path.join(target_dir, fpath)
        if not os.path.isfile(source_path):
            continue

        try:
            with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            continue

        name_escaped = re.escape(name)
        patterns = [
            re.compile(r'^func\s+\(.*?\)\s+' + name_escaped + r'\s*\('),
            re.compile(r'^func\s+' + name_escaped + r'\s*\('),
            re.compile(r'^var\s+' + name_escaped + r'\s*=\s*func\s*\('),
        ]

        for pattern in patterns:
            for i, line in enumerate(lines):
                if pattern.search(line):
                    depth = 0
                    start = i
                    for j in range(i, len(lines)):
                        depth += lines[j].count('{') - lines[j].count('}')
                        if depth == 0 and j > i:
                            src = ''.join(lines[start:j + 1]).rstrip()
                            sources.append({
                                'file': fpath,
                                'function': name,
                                'line': func_info.get('line', start + 1),
                                'source': src,
                            })
                            break
                    break

    return sources


# ── Stage 1: AST Scan ─────────────────────────────────────────────────

def stage_ast_scan(target_dir):
    print("[Stage 1/5] AST scan...")
    start = time.time()

    # Try full scan first
    result = analyze_go_source(target_dir, changed_files=None, focus_functions=None)

    # A5 fix: always also scan subdirectories and merge, keeping whichever covers more
    # functions. A root-only scan misses code in subpackages whenever the root dir has
    # its own .go files (e.g. nats-server has main.go at root but the bulk of the code
    # lives in server/ etc), which previously yielded only the few root-level functions.
    # The old code ran the subdir scan ONLY when the root scan was empty, so such
    # projects were badly under-covered (2 functions, 0 findings for nats-server).
    subdirs = _find_go_subdirs(target_dir)
    if subdirs:
        merged = _merge_subdir_results(target_dir, subdirs)
        if merged and len(merged.get('functions') or []) > len(result.get('functions') or []):
            print(f"  Merged {len(subdirs)} subdirectories for fuller coverage")
            result = merged

    elapsed = time.time() - start
    cc_count = len(result.get('call_chains') or [])
    df_count = len(result.get('data_flow_indicators') or [])
    func_count = len(result.get('functions') or [])
    print(f"  Done in {elapsed:.1f}s: {func_count} functions, {cc_count} call chains, {df_count} data flows")
    return result


def _find_go_subdirs(target_dir, max_depth=4):
    """Find subdirectories containing Go files."""
    # A7: raised max_depth 2->4 so deep monorepos (e.g. mattermost keeps its Go code under
    # server/channels/api4/ at depth 3+) get their core packages scanned, not just the shallow
    # config dirs. Also prune vendor/node_modules/.git/testdata so we don't waste time on — or
    # report findings in — third-party / test-fixture code.
    skip_dirs = {'vendor', 'node_modules', '.git', 'testdata', '.cache', 'dist'}
    go_dirs = set()
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        depth = root.replace(target_dir, '').count(os.sep)
        if depth > max_depth:
            dirs.clear()
            continue
        if any(f.endswith('.go') and not f.endswith('_test.go') for f in files):
            go_dirs.add(root)
    # Only keep leaf-ish directories (remove parents that contain other go_dirs)
    return list(go_dirs)


def _merge_subdir_results(target_dir, subdirs):
    """Analyze subdirectories separately and merge results."""
    merged = {
        'imports': {},
        'call_chains': [],
        'data_flow_indicators': [],
        'stdlib_signals': [],
        'concurrency_patterns': [],
        'functions': [],
        'parse_mode': 'parser',
    }
    seen_chains = set()
    seen_signals = set()

    for subdir in subdirs:
        rel = os.path.relpath(subdir, target_dir).replace('\\', '/')
        result = analyze_go_source(subdir, changed_files=None, focus_functions=None)

        # Adjust paths and merge
        for k, v in result.get('imports', {}).items():
            merged['imports'][f"{rel}/{k}" if rel != '.' else k] = v

        for cc in (result.get('call_chains') or []):
            key = f"{cc.get('root_file', '')}:{cc.get('root_function', '')}"
            if key not in seen_chains:
                seen_chains.add(key)
                if rel != '.':
                    cc['root_file'] = f"{rel}/{cc['root_file']}"
                merged['call_chains'].append(cc)

        for s in (result.get('stdlib_signals') or []):
            if s['package'] not in seen_signals:
                seen_signals.add(s['package'])
                merged['stdlib_signals'].append(s)

        for df in (result.get('data_flow_indicators') or []):
            if rel != '.':
                df['file'] = f"{rel}/{df['file']}"
            merged['data_flow_indicators'].append(df)

        for cp in (result.get('concurrency_patterns') or []):
            if rel != '.':
                cp['file'] = f"{rel}/{cp['file']}"
            merged['concurrency_patterns'].append(cp)

        for fd in (result.get('functions') or []):
            if rel != '.':
                fd['file'] = f"{rel}/{fd['file']}"
            merged['functions'].append(fd)

    if not merged['call_chains'] and not merged['data_flow_indicators']:
        return None
    return merged


# ── Stage 2: Domain Classification ────────────────────────────────────

def stage_domain_classification(api_cfg, ast_result):
    print("[Stage 2/5] Domain classification...")
    start = time.time()

    system_prompt = load_prompt('detect_domain.md')
    user_msg = _build_domain_message(ast_result)

    result, err = call_llm(api_cfg, system_prompt, user_msg)
    if err:
        print(f"  LLM error: {err}, falling back to stdlib signal inference")
        return _infer_domains_from_signals(ast_result), time.time() - start

    domains = result.get('active_domains', [])
    elapsed = time.time() - start
    print(f"  Done in {elapsed:.1f}s: {[d['domain'] for d in domains]}")
    return domains, elapsed


def _build_domain_message(ast_result):
    parts = []
    parts.append("【项目静态分析结果】")

    # Stdlib signals
    signals = ast_result.get('stdlib_signals', [])
    if signals:
        for s in signals:
            apis = ', '.join((s.get('apis') or [])[:5])
            parts.append(f"- 标准库信号: {s['package']}.{apis}")
            if s.get('domain_hints'):
                parts.append(f"  域提示: {', '.join(s['domain_hints'])}")

    # Imports summary
    imports = ast_result.get('imports', {})
    if imports:
        all_stdlib = set()
        all_third = set()
        for fi in imports.values():
            all_stdlib.update(fi.get('stdlib') or [])
            all_third.update(fi.get('third_party') or [])
        parts.append(f"\n- 标准库导入: {', '.join(sorted(all_stdlib)[:15])}")
        if all_third:
            parts.append(f"- 第三方导入: {', '.join(sorted(all_third)[:10])}")

    # Function summary (top 20 by call chain depth)
    chains = ast_result.get('call_chains') or []
    if chains:
        parts.append("\n- 关键函数调用链:")
        for cc in chains[:20]:
            calls = (cc.get('calls') or [])[:5]
            call_str = ' → '.join(c['callee'] for c in calls)
            parts.append(f"  {cc['root_function']} → {call_str}")

    return '\n'.join(parts)


def _infer_domains_from_signals(ast_result):
    """Fallback: infer domains purely from stdlib signals."""
    domain_map = defaultdict(float)
    for s in (ast_result.get('stdlib_signals') or []):
        for hint in (s.get('domain_hints') or []):
            domain_map[hint] += 1

    total = sum(domain_map.values()) or 1
    return [
        {'domain': d, 'confidence': min(1.0, c / total * 2), 'evidence': f'inferred from {int(c)} stdlib signals'}
        for d, c in sorted(domain_map.items(), key=lambda x: -x[1])
        if c / total >= 0.1
    ]


# ── Stage 3: Pattern Retrieval ────────────────────────────────────────

def stage_pattern_retrieval(vuln_db, active_domains, ast_result):
    print("[Stage 3/5] Pattern retrieval...")
    templates = vuln_db.get('templates', {})
    domain_index = vuln_db.get('domain_index', {})
    api_index = vuln_db.get('api_index', {})

    # Collect candidate template IDs from active domains
    candidate_ids = set()
    domain_conf = {}
    for d in active_domains:
        name = d['domain']
        domain_conf[name] = d.get('confidence', 0.5)
        for tpl_id in domain_index.get(name, []):
            candidate_ids.add(tpl_id)

    # Score each candidate by API overlap
    project_apis = set()
    for s in (ast_result.get('stdlib_signals') or []):
        for api in (s.get('apis') or []):
            project_apis.add(f"{s['package']}.{api}")

    scored = []
    for tpl_id in candidate_ids:
        tpl = templates.get(tpl_id)
        if not tpl:
            continue
        domain_score = domain_conf.get(tpl['domain'], 0)
        api_overlap = sum(1 for api in tpl.get('api_indicators', []) if api in project_apis)
        api_total = max(len(tpl.get('api_indicators', [])), 1)
        api_score = api_overlap / api_total if api_total > 0 else 0
        score = domain_score * 0.5 + api_score * 0.5
        scored.append((tpl_id, score, api_overlap))

    scored.sort(key=lambda x: -x[1])

    print(f"  {len(candidate_ids)} candidates, top scores: "
          f"{[(tpl_id, f'{s:.2f}') for tpl_id, s, _ in scored[:5]]}")
    return scored


# ── Stage 4: Function Prioritization ──────────────────────────────────

def stage_function_prioritization(ast_result, candidate_templates, vuln_db):
    print("[Stage 4/5] Function prioritization...")
    templates = vuln_db.get('templates', {})

    # Gather all API indicators from candidate templates
    template_apis = set()
    for tpl_id, _, _ in candidate_templates:
        tpl = templates.get(tpl_id)
        if tpl:
            template_apis.update(tpl.get('api_indicators', []))

    # Build data flow lookup
    data_flows = {}
    for df in (ast_result.get('data_flow_indicators') or []):
        key = f"{df.get('file', '')}:{df.get('function', '')}"
        data_flows[key] = df

    # Build call chain lookup
    call_chains = {}
    for cc in (ast_result.get('call_chains') or []):
        key = f"{cc.get('root_file', '')}:{cc.get('root_function', '')}"
        call_chains[key] = cc

    # Build import lookup per file
    imports_by_file = ast_result.get('imports', {})

    # Score each function
    scored_functions = []
    for func in (ast_result.get('functions') or []):
        # A6: skip auto-generated code (ORM/protobuf/mock). Generated boilerplate (e.g. GORM
        # .gen.go ScanByPage/FindByPage, *.pb.go) otherwise crowds out real business logic in
        # the top-N priority list, wasting the --max-functions budget on non-vuln-bearing code.
        # A8: also skip test suites and generated store-decorator layers (mattermost's
        # storetest/, timerlayer/opentracinglayer/retrylayer, Test*/Benchmark*/Fuzz* funcs),
        # which otherwise filled all 40 slots on mattermost (22x timerlayer.Get + Test*Store).
        _fpath = func['file'].lower()
        _fname = func['name']
        if any(m in _fpath for m in ('.gen.go', '_gen.go', '.pb.go', '_generated.go', 'zz_generated', '_mock.go',
                                     '_test.go', 'storetest', '/mocks/', 'mock_',
                                     'timerlayer', 'opentracinglayer', 'retrylayer')):
            continue
        if _fname.startswith('Test') or _fname.startswith('Benchmark') or _fname.startswith('Fuzz'):
            continue
        score = 0
        reasons = []
        key = f"{func['file']}:{func['name']}"

        # Has both source and sink
        df = data_flows.get(key, {})
        has_sources = bool(df and df.get('sources'))
        has_sinks = bool(df and df.get('sinks'))
        if has_sources and has_sinks:
            score += 3
            reasons.append('has data flow (source+sink)')
        elif has_sources or has_sinks:
            score += 1
            if has_sinks and df:
                sink_types = [s.get('type', '') for s in (df.get('sinks') or [])]
                if any(t in sink_types for t in ['string_format', 'write', 'command_execution', 'sql_query']):
                    score += 10
                    reasons.append(f'dangerous sink: {sink_types[0]}')

        # API matches template indicators
        cc = call_chains.get(key, {})
        if cc:
            for call in (cc.get('calls') or []):
                callee = call.get('callee', '')
                for tapi in template_apis:
                    if tapi in callee or callee in tapi:
                        score += 2
                        reasons.append(f'API match: {callee}')
                        break

        # HTTP handler
        if cc:
            for call in (cc.get('calls') or []):
                if 'http' in call.get('callee', '').lower() or 'Handle' in call.get('callee', ''):
                    score += 2
                    reasons.append('HTTP handler')
                    break

        # Risky stdlib
        # A4 fix: use `or []` so a null 'stdlib' value (not just a missing key) becomes an
        # empty list; otherwise `.get('stdlib', [])` returns None and `for pkg in ...` crashes
        # (TypeError: 'NoneType' object is not iterable) on projects where AST emits stdlib: null.
        file_imports = imports_by_file.get(func['file'], {})
        stdlib_list = (file_imports.get('stdlib') or []) if isinstance(file_imports, dict) else []
        risky = {'os/exec', 'database/sql', 'net/http', 'archive/zip', 'archive/tar',
                 'crypto/cipher', 'crypto/rsa', 'text/template', 'html/template'}
        for pkg in stdlib_list:
            if pkg in risky:
                score += 2
                reasons.append(f'uses {pkg}')
                break

        # Function name suggests security relevance
        name_lower = func['name'].lower()
        security_keywords = ['handle', 'process', 'parse', 'execute', 'write', 'read',
                             'serve', 'dispatch', 'validate', 'verify', 'auth', 'login',
                             'upload', 'download', 'import', 'export', 'create', 'delete']
        for kw in security_keywords:
            if kw in name_lower:
                score += 1
                reasons.append(f'name suggests: {kw}')
                break

        if score > 0:
            scored_functions.append({
                'function': func,
                'score': score,
                'reasons': reasons,
                'data_flow': df if has_sources or has_sinks else None,
                'call_chain': cc if cc else None,
            })

    scored_functions.sort(key=lambda x: -x['score'])
    print(f"  {len(scored_functions)} functions scored, top: "
          f"{[(f['function']['name'], f['score']) for f in scored_functions[:5]]}")
    return scored_functions


# ── Stage 5: Deep Analysis ───────────────────────────────────────────

def stage_deep_analysis(api_cfg, target_dir, scored_functions, candidate_templates, vuln_db, max_functions):
    print(f"[Stage 5/5] Deep analysis ({len(scored_functions)} functions)...")
    start = time.time()

    system_prompt = load_prompt('detect_analyze.md')
    templates = vuln_db.get('templates', {})
    full_records = vuln_db.get('full_records', {})

    # Prepare template summaries for LLM context — include ALL matched templates
    template_summaries = []
    seen_tpl_ids = set()
    for tpl_id, _, _ in candidate_templates:
        seen_tpl_ids.add(tpl_id)
        tpl = templates.get(tpl_id)
        if not tpl:
            continue
        examples = []
        for ex in tpl.get('top_examples', [])[:1]:
            gid = ex.get('go_id', '')
            rec = full_records.get(gid)
            if rec:
                examples.append(f"案例 {gid} ({ex.get('pattern_name', '')}): {rec.get('behavior_chain', {}).get('summary', '')[:80]}")
        template_summaries.append({
            'id': tpl_id,
            'domain': tpl['domain'],
            'category': tpl['missing_step_category'],
            'chain_type': tpl.get('chain_type', ''),
            'apis': tpl.get('api_indicators', [])[:3],
            'cwes': tpl.get('cwe_coverage', [])[:5],
            'patterns': tpl.get('pattern_names', [])[:5],
            'summary': tpl.get('summary', ''),
            'examples': examples,
        })

    # Analyze all scored functions
    targets = scored_functions

    # Extract function sources
    func_defs = [t['function'] for t in targets]
    func_sources = extract_func_sources(target_dir, func_defs)
    source_map = {(fs['file'], fs['function']): fs['source'] for fs in func_sources}

    findings = []
    analyzed = 0

    def analyze_function(target):
        func = target['function']
        key = (func['file'], func['name'])
        source = source_map.get(key, '')

        if not source:
            return None, f"{func['file']}:{func['name']}", "no source available"

        user_msg = _build_analysis_message(func, source, target, template_summaries)
        result, err = call_llm(api_cfg, system_prompt, user_msg, max_tokens=8192)

        if err:
            return None, f"{func['file']}:{func['name']}", err

        func_findings = result.get('findings', [])
        return result, f"{func['file']}:{func['name']}", func_findings

    for i, target in enumerate(targets):
        func = target['function']
        key = (func['file'], func['name'])
        source = source_map.get(key, '')

        if not source:
            continue

        user_msg = _build_analysis_message(func, source, target, template_summaries)
        result, err = call_llm(api_cfg, system_prompt, user_msg, max_tokens=8192)

        if err:
            print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} ERROR: {err}")
            continue

        func_findings = result.get('findings', [])
        analyzed += 1
        if func_findings:
            for f in func_findings:
                f['function'] = f"{func['file']}:{func['name']}"
            findings.extend(func_findings)
            print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} -> {len(func_findings)} finding(s)")
        else:
            print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} -> clean")

    elapsed = time.time() - start
    print(f"  Done in {elapsed:.1f}s: {analyzed} analyzed, {len(findings)} findings")
    return findings, analyzed, elapsed


def _build_analysis_message(func, source, target, template_summaries):
    parts = []

    parts.append("【待分析函数】")
    parts.append(f"- 文件: {func['file']}")
    parts.append(f"- 函数: {func['name']}")
    if func.get('receiver'):
        parts.append(f"- 接收者: {func['receiver']}")

    cc = target.get('call_chain')
    if cc:
        calls = (cc.get('calls') or [])[:8]
        call_str = ' → '.join(c['callee'] for c in calls)
        parts.append(f"- 调用链: {func['name']} → {call_str}")

    df = target.get('data_flow')
    has_dangerous_sink = False
    sink_hint = ''
    if df:
        srcs = ', '.join(f"{s['type']}({s['pattern']})" for s in (df.get('sources') or [])[:3])
        snks = ', '.join(f"{s['type']}({s['pattern']})" for s in (df.get('sinks') or [])[:3])
        if srcs:
            parts.append(f"- 数据源: [{srcs}]")
        if snks:
            parts.append(f"- 数据汇: [{snks}]")
            dangerous_types = {'string_format', 'write', 'command_execution', 'sql_query',
                              'file_write', 'html_injection', 'js_injection'}
            for s in (df.get('sinks') or []):
                if s.get('type') in dangerous_types:
                    has_dangerous_sink = True
                    sink_hint = f"该函数存在危险数据汇（{s['type']}），请重点检查数据从参数到该汇的路径上是否缺少安全步骤（如输入验证、输出编码、路径校验等）"
                    break

    # Truncate long source
    # A1 fix: raised 3000 -> 12000 so large functions (e.g. single-func files) are not cut
    # off mid-body, which previously dropped all vulnerabilities in the latter half.
    display_source = source
    if len(display_source) > 12000:
        display_source = display_source[:12000] + "\n// ... (truncated)"
    parts.append(f"\n- 源码:\n{display_source}")

    if has_dangerous_sink:
        parts.append(f"\n【分析提示】{sink_hint}")

    parts.append("\n【相关漏洞模板】")
    parts.append("以下模板仅供参考。你需要检查函数中是否缺少对应 category 的安全步骤，而不仅限于匹配模板中的已知 pattern 名称。")
    parts.append("即：只要函数的行为链中缺少了某个 category 定义的安全检查，就应报告，无论该漏洞是否在已知案例中出现过。")
    parts.append("")
    for tpl in template_summaries:
        parts.append(f"模板 {tpl['id']} (缺失步骤: {tpl['category']}):")
        if tpl['apis']:
            parts.append(f"  关注API: {', '.join(tpl['apis'])}")
        if tpl['examples']:
            parts.append(f"  参考案例: {tpl['examples'][0]}")
        parts.append("")

    return '\n'.join(parts)


# ── LLM call ──────────────────────────────────────────────────────────

import requests


def call_llm(api_cfg, system_prompt, user_content, retries=3, max_tokens=8192):
    url = api_cfg['ZHIPU_BASE_URL'] + '/chat/completions'
    headers = {
        'Authorization': 'Bearer ' + api_cfg['ZHIPUAI_API_KEY'],
        'Content-Type': 'application/json',
    }

    content = ''
    for attempt in range(retries):
        try:
            payload = {
                'model': api_cfg['ZHIPU_MODEL'],
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_content},
                ],
                'temperature': 0.1,
                'max_tokens': max_tokens,
            }

            r = requests.post(url, headers=headers, json=payload, timeout=300)

            if r.status_code == 429:
                wait = min(30, 5 * (attempt + 1))
                print(f"    [429 rate limited, waiting {wait}s]", flush=True)
                time.sleep(wait)
                continue

            if r.status_code != 200:
                return None, f"HTTP {r.status_code}: {r.text[:300]}"

            data = r.json()
            finish_reason = data['choices'][0].get('finish_reason', '')
            msg = data['choices'][0]['message']
            content = msg.get('content', '') or msg.get('reasoning_content', '') or ''

            if not content.strip():
                return None, f"empty response, finish_reason={finish_reason}"

            content = content.strip()
            if content.startswith('```'):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
                content = content.strip()

            # If truncated, retry with larger max_tokens
            if finish_reason == 'length' and attempt < retries - 1:
                max_tokens = min(max_tokens * 2, 32768)
                print(f"    [truncated, retrying with max_tokens={max_tokens}]", flush=True)
                time.sleep(2)
                continue

            result = json.loads(content)
            return result, None

        except json.JSONDecodeError as e:
            m = re.search(r'\{[\s\S]*\}', content)
            if m:
                try:
                    return json.loads(m.group()), None
                except json.JSONDecodeError:
                    pass
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None, f"JSON parse error: {e}"
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return None, "timeout"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None, str(e)

    return None, "max retries exceeded"


# ── main ──────────────────────────────────────────────────────────────

interrupted = False


def _signal_handler(sig, frame):
    global interrupted
    if interrupted:
        print("\n[FORCE EXIT]")
        sys.exit(1)
    interrupted = True
    print("\n[INTERRUPT] Stopping...")


def main():
    global interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Detect vulnerabilities in a Go project")
    parser.add_argument("--target", default=None, help="Target Go project directory")
    parser.add_argument("--git-url", default=None, help="GitHub repo URL to clone and analyze (e.g. https://github.com/gin-gonic/gin)")
    parser.add_argument("--git-ref", default=None, help="Git branch/tag/commit to checkout after clone (default: default branch)")
    parser.add_argument("--db", default="vuln_db.json", help="Vulnerability database file")
    parser.add_argument("--output", default=None, help="Override report output path (default: projects/<id>/report.json)")
    parser.add_argument("--no-copy", action="store_true", help="Skip copying source into project directory")
    parser.add_argument("--max-functions", type=int, default=0, help="Max functions to analyze (0=all)")
    parser.add_argument("--confidence-threshold", type=float, default=0.5, help="Min finding confidence")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent LLM requests")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between LLM calls")
    parser.add_argument("--domains", type=str, default=None, help="Manually specify domains (comma-separated)")
    args = parser.parse_args()

    if not args.target and not args.git_url:
        parser.error("Either --target or --git-url is required")
    if args.target and args.git_url:
        parser.error("Use --target or --git-url, not both")

    # Create project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_id = time.strftime('%Y%m%d_%H%M%S')
    project_dir = os.path.join(script_dir, 'projects', project_id)

    if args.output:
        report_path = os.path.abspath(args.output)
    else:
        os.makedirs(project_dir, exist_ok=True)
        report_path = os.path.join(project_dir, 'report.json')

    # Resolve target directory
    if args.git_url:
        # Clone from git URL
        source_dir = os.path.join(project_dir, 'source')
        print(f"Cloning {args.git_url} into {source_dir}...")
        clone_cmd = ['git', 'clone', '--depth', '1']
        if args.git_ref:
            clone_cmd.extend(['--branch', args.git_ref])
        clone_cmd.extend([args.git_url, source_dir])
        try:
            subprocess.run(clone_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else ""
            print(f"Error: git clone failed: {stderr}", file=sys.stderr)
            sys.exit(1)
        target_dir = source_dir
    else:
        target_dir = os.path.abspath(args.target)
        if not os.path.isdir(target_dir):
            print(f"Error: {target_dir} is not a directory", file=sys.stderr)
            sys.exit(1)

        # Copy source into project directory
        if not args.no_copy and not args.output:
            source_dir = os.path.join(project_dir, 'source')
            print(f"Copying source to {source_dir}...")
            shutil.copytree(target_dir, source_dir)
            target_dir = source_dir

    # Load API config
    cfg = load_env()
    for key in ('ZHIPUAI_API_KEY', 'ZHIPU_BASE_URL', 'ZHIPU_MODEL'):
        if key not in cfg or not cfg[key]:
            print(f"Error: {key} not set in .env", file=sys.stderr)
            sys.exit(1)

    # Load vulnerability database
    if not os.path.isfile(args.db):
        print(f"Error: {args.db} not found. Run build_vuln_db.py first.", file=sys.stderr)
        sys.exit(1)
    with open(args.db, encoding='utf-8') as f:
        vuln_db = json.load(f)
    print(f"Loaded vuln_db: {vuln_db['metadata']['total_templates']} templates, "
          f"{vuln_db['metadata']['total_records']} records\n")

    overall_start = time.time()

    # Stage 1: AST scan
    if interrupted:
        return
    ast_result = stage_ast_scan(target_dir)

    # Stage 2: Domain classification
    if interrupted:
        return
    if args.domains:
        domains = [{'domain': d.strip(), 'confidence': 1.0, 'evidence': 'manually specified'}
                    for d in args.domains.split(',')]
        print(f"[Stage 2/5] Domains (manual): {[d['domain'] for d in domains]}")
        domain_time = 0.0
    else:
        domains, domain_time = stage_domain_classification(cfg, ast_result)

    # Stage 3: Pattern retrieval
    if interrupted:
        return
    candidate_templates = stage_pattern_retrieval(vuln_db, domains, ast_result)

    # Stage 4: Function prioritization
    if interrupted:
        return
    scored_functions = stage_function_prioritization(ast_result, candidate_templates, vuln_db)

    # Ensure functions with dangerous data flow sinks are analyzed even if score is low
    dangerous_sinks = {'string_format', 'command_execution', 'sql_query', 'sql_exec',
                       'file_write', 'html_injection', 'js_injection', 'write'}
    data_flows = {}
    for df in (ast_result.get('data_flow_indicators') or []):
        data_flows[f"{df.get('file', '')}:{df.get('function', '')}"] = df

    scored_set = {(f['function']['file'], f['function']['name']) for f in scored_functions}
    for func in (ast_result.get('functions') or []):
        key = f"{func['file']}:{func['name']}"
        if (func['file'], func['name']) in scored_set:
            continue
        df = data_flows.get(key)
        if df:
            sinks = df.get('sinks') or []
            sink_types = [s.get('type', '') for s in sinks]
            if any(t in dangerous_sinks for t in sink_types):
                scored_functions.append({
                    'function': func,
                    'score': 15,
                    'reasons': [f'dangerous sink: {sink_types[0]} (data flow guarantee)'],
                    'data_flow': df,
                    'call_chain': None,
                })
                scored_set.add((func['file'], func['name']))

    scored_functions.sort(key=lambda x: -x['score'])

    # Stage 5: Deep analysis
    if interrupted:
        return
    max_funcs = args.max_functions if args.max_functions > 0 else len(scored_functions)
    findings, analyzed_count, analysis_time = stage_deep_analysis(
        cfg, target_dir, scored_functions[:max_funcs], candidate_templates, vuln_db, max_funcs
    )

    # Filter by confidence threshold
    filtered = [f for f in findings if f.get('confidence', 0) >= args.confidence_threshold]

    # Generate report
    total_elapsed = time.time() - overall_start
    report = {
        'scan_info': {
            'project_id': project_id,
            'target': target_dir,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'model': cfg['ZHIPU_MODEL'],
            'total_functions': len(ast_result.get('functions') or []),
            'analyzed_functions': analyzed_count,
            'total_templates_matched': len(candidate_templates),
            'total_duration': round(total_elapsed, 1),
        },
        'project_domains': domains,
        'summary': {
            'total_findings': len(filtered),
            'by_severity': _count_by(filtered, 'severity'),
            'by_domain': _count_by(filtered, lambda f: _infer_domain_from_template(f, vuln_db)),
            'by_category': _count_by(filtered, 'missing_step_category'),
        },
        'findings': filtered,
        'function_scores': [
            {'function': f"{t['function']['file']}:{t['function']['name']}",
             'score': t['score'], 'reasons': t['reasons']}
            for t in scored_functions[:30]
        ],
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 50}")
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {total_elapsed:.1f}s")
    print(f"  Functions analyzed: {analyzed_count}")
    print(f"  Findings: {len(filtered)} (threshold: {args.confidence_threshold})")
    for f in filtered:
        print(f"    [{f.get('severity', '?').upper()}] {f.get('function', '?')}: "
              f"{f.get('pattern_name', '?')} (confidence: {f.get('confidence', 0):.2f})")
    print(f"\nProject: {project_dir}")
    print(f"Report: {os.path.abspath(report_path)}")


def _count_by(items, key):
    counts = defaultdict(int)
    for item in items:
        k = key(item) if callable(key) else item.get(key, 'unknown')
        counts[k] += 1
    return dict(counts)


def _infer_domain_from_template(finding, vuln_db):
    tpl_id = finding.get('template_id', '')
    tpl = vuln_db.get('templates', {}).get(tpl_id, {})
    return tpl.get('domain', 'unknown')


if __name__ == "__main__":
    main()
