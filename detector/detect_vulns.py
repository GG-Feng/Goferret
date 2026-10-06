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
from cvss import enrich_findings_with_cvss
from confidence import enrich_findings_with_confidence
from decide import build_findings
import param_taint
import validator_contract
import authz_consistency
import chain_align
from llm_config import resolve_llm


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
    resolve_llm(cfg)
    return cfg


# ── prompt loading ────────────────────────────────────────────────────

def load_prompt(filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path, encoding='utf-8') as f:
        return f.read()


# ── function source extraction ────────────────────────────────────────

def _qname(func):
    """Function key name: "Recv.Name" for methods (from the AST analyzer), else the bare name.

    Keys must include the receiver: two methods with the same name on different
    types in one file (String, Next, Resolve ...) would otherwise overwrite each other.
    """
    return func.get('qname') or func['name']


def extract_func_sources(target_dir, functions):
    """Extract source code for given function definitions."""
    sources = []
    seen = set()

    for func_info in functions:
        fpath = func_info['file']
        name = func_info['name']
        qname = _qname(func_info)
        key = (fpath, qname)
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
        recv = qname[:-len(name) - 1] if qname != name else ''
        patterns = [
            re.compile(r'^func\s+\([^)]*?\b' + re.escape(recv) + r'\b[^)]*\)\s+' + name_escaped + r'\s*[\[(]'),
        ] if recv else [
            re.compile(r'^func\s+\(.*?\)\s+' + name_escaped + r'\s*\('),
            re.compile(r'^func\s+' + name_escaped + r'\s*\('),
            re.compile(r'^var\s+' + name_escaped + r'\s*=\s*func\s*\('),
        ]

        for pattern in patterns:
            for i, line in enumerate(lines):
                if pattern.search(line):
                    depth = 0
                    # A multi-line signature keeps the body's opening brace off
                    # the `func` line, so depth is still 0 there; only treat
                    # depth 0 as the end once the body has actually opened.
                    opened = False
                    start = i
                    for j in range(i, len(lines)):
                        if '{' in lines[j]:
                            opened = True
                        depth += lines[j].count('{') - lines[j].count('}')
                        if opened and depth == 0:
                            src = ''.join(lines[start:j + 1]).rstrip()
                            sources.append({
                                'file': fpath,
                                'function': qname,
                                'line': func_info.get('line', start + 1),
                                'source': src,
                            })
                            break
                    break

    return sources


# ── Stage 1: AST Scan ─────────────────────────────────────────────────

def stage_ast_scan(target_dir, max_depth=4):
    print("[Stage 1/5] AST scan...")
    start = time.time()

    # Try full scan first
    result = analyze_go_source(target_dir, changed_files=None, focus_functions=None)

    # ParseDir only covers the root package; merge subdirectory packages so
    # multi-package repos (binding/, internal/, ...) are scanned at all.
    subdirs = _find_go_subdirs(target_dir, max_depth)
    if len(subdirs) > 1:
        print(f"  Merging {len(subdirs)} package directories...")
        merged = _merge_subdir_results(target_dir, subdirs)
        if merged:
            result = merged

    elapsed = time.time() - start
    cc_count = len(result.get('call_chains') or [])
    df_count = len(result.get('data_flow_indicators') or [])
    func_count = len(result.get('functions') or [])
    print(f"  Done in {elapsed:.1f}s: {func_count} functions, {cc_count} call chains, {df_count} data flows")
    return result


def _find_go_subdirs(target_dir, max_depth=4):
    """Find package directories containing Go files.

    vendor/ (dependency code, wrong finding locus) and testdata/ (ignored by
    the go tool) are pruned. max_depth=None (v3 rule F2) removes the depth limit.
    """
    go_dirs = set()
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ('vendor', 'testdata', '.git', 'node_modules')]
        depth = root.replace(target_dir, '').count(os.sep)
        if max_depth is not None and depth > max_depth:
            dirs.clear()
            continue
        if any(f.endswith('.go') and not f.endswith('_test.go') for f in files):
            go_dirs.add(root)
    # sorted: set iteration order varies by hash seed, which would make the
    # merged function order (and thus the report) non-reproducible
    return sorted(go_dirs)


def _merge_subdir_results(target_dir, subdirs):
    """Analyze subdirectories separately and merge results."""
    merged = {
        'imports': {},
        'call_chains': [],
        'data_flow_indicators': [],
        'stdlib_signals': [],
        'concurrency_patterns': [],
        'functions': [],
        'size_flows': [],
        'param_flows': [],
        'wire_types': [],
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
            if rel != '.':
                cc['root_file'] = f"{rel}/{cc['root_file']}"
            # Key on the repo-relative path: keying before the prefix made
            # main.go:main in two different subdirectories collide.
            key = f"{cc.get('root_file', '')}:{cc.get('root_function', '')}"
            if key not in seen_chains:
                seen_chains.add(key)
                merged['call_chains'].append(cc)

        for s in (result.get('stdlib_signals') or []):
            if s['package'] not in seen_signals:
                seen_signals.add(s['package'])
                merged['stdlib_signals'].append(s)

        for df in (result.get('data_flow_indicators') or []):
            if rel != '.':
                df['file'] = f"{rel}/{df['file']}"
            merged['data_flow_indicators'].append(df)

        for sf in (result.get('size_flows') or []):
            if rel != '.':
                sf['file'] = f"{rel}/{sf['file']}"
            merged['size_flows'].append(sf)

        for pf in (result.get('param_flows') or []):
            if rel != '.':
                pf['file'] = f"{rel}/{pf['file']}"
            merged['param_flows'].append(pf)

        for wt in (result.get('wire_types') or []):
            if rel != '.':
                wt['file'] = f"{rel}/{wt['file']}"
            merged['wire_types'].append(wt)

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

    result, err = call_llm(api_cfg, system_prompt, user_msg, max_tokens=1024)
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

def stage_pattern_retrieval(vuln_db, active_domains, ast_result, deterministic=False):
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

    # v3 F1: candidate_ids is a set, so equal scores kept hash-seed-dependent order and the
    # template bound to a finding (template_id / pattern_name / template_support) varied
    # between runs. With F1, ties are broken by template id.
    scored.sort(key=(lambda x: (-x[1], x[0])) if deterministic else (lambda x: -x[1]))

    print(f"  {len(candidate_ids)} candidates, top scores: "
          f"{[(tpl_id, f'{s:.2f}') for tpl_id, s, _ in scored[:5]]}")
    return scored


# ── Stage 4: Function Prioritization ──────────────────────────────────

def stage_entry_triage(api_cfg, ast_result, batch_size=40, workers=1):
    """v5 X1: signature-level entry judgement by the LLM (no function bodies).

    Returns {func_key: [external param indices]} for functions the model judges to be
    invoked from outside the program (framework handlers, protocol servers, k8s
    webhooks, plugin interfaces ...). Cheap: one call per `batch_size` signatures.
    """
    print("[Stage 4b] Entry triage (signatures only)...")
    start = time.time()
    system_prompt = load_prompt('detect_triage.md')
    pflows = ast_result.get('param_flows') or []
    imports = ast_result.get('imports') or {}
    items = []
    for pf in pflows:
        if not pf.get('params'):
            continue
        key = f"{pf['file']}:{pf['function']}"
        third = (imports.get(pf['file']) or {}).get('third_party') or []
        sig = ', '.join(f"{p['name']} {p['type']}" for p in pf['params'])
        recv = f" 接收者类型: {pf['recv_type']}" if pf.get('recv_type') else ''
        items.append((key, f"- {key}{recv}\n  参数: ({sig})\n  文件的第三方 import: {', '.join(third[:12]) or '无'}"))
    batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    seeds, judged = {}, 0

    def _one(batch):
        msg = "【待判定函数签名】\n" + '\n'.join(t for _, t in batch)
        return batch, call_llm(api_cfg, system_prompt, msg, max_tokens=4096)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for batch, (result, err) in ex.map(_one, batches):
            if err or not isinstance(result, list):
                continue
            by_fn = {r.get('function'): r for r in result if isinstance(r, dict)}
            for key, _ in batch:
                r = by_fn.get(key)
                if not r:
                    continue
                judged += 1
                if r.get('entry') and r.get('external_params'):
                    seeds[key] = [int(i) for i in r['external_params'] if isinstance(i, (int, float, str)) and str(i).isdigit()]
    print(f"  {len(items)} signatures in {len(batches)} call(s), {judged} judged, "
          f"{len(seeds)} entry function(s) with external parameters ({time.time() - start:.1f}s)")
    return seeds


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
        score = 0
        reasons = []
        key = f"{func['file']}:{_qname(func)}"

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
        file_imports = imports_by_file.get(func['file'], {})
        # Go marshals nil slices as null, so a present-but-null 'stdlib' key
        # defeats dict.get's default; fall through to [] with `or`.
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

# Measured on filebrowser@fe7efb2e: 77 gated functions cost 78 LLM calls.
# Used only to warn about the order of magnitude before a full run starts.
BASELINE_FUNCS = 77
BASELINE_CALLS = 78


def stage_semantic_extraction(api_cfg, target_dir, scored_functions, workers=1,
                              batch_size=1, flow_gate=False, max_funcs=0, allow_keys=None,
                              prompt_file='detect_extract.md', entry_seeds=None):
    """LLM extracts semantic facts only (detect_extract.md); no judgments.

    Cost control for full runs:
    - flow gate: a function whose AST data flow shows neither a source nor a
      sink cannot yield a span (the decision engine requires both), so it
      never reaches the LLM. This is the dominant cost lever: on a full repo
      most functions have no flow indicators at all.
    - requests run concurrently (--workers); 429 backoff is inside call_llm.
    - max_tokens starts at 2048 (extraction JSON is compact); call_llm
      auto-doubles it if a response ever truncates.
    """
    print(f"[Stage 5/5] Semantic extraction ({len(scored_functions)} scored functions)...")
    start = time.time()

    system_prompt = load_prompt(prompt_file)

    def _has_flow(target):
        df = target.get('data_flow') or {}
        return bool(df.get('sources') or df.get('sinks'))

    # Optional cost lever. A function whose AST data flow has neither a source
    # nor a sink cannot form a span, so on paper it can produce no finding —
    # but the decision stage merges AST facts with the LLM's semantic ones, and
    # the LLM does sometimes see inputs the pattern tables miss. Off by default
    # so that --max-functions 0 really means "everything"; pass --flow-gate to
    # trade that recall for roughly a third of the cost.
    gated = scored_functions
    skipped = 0
    if flow_gate:
        gated = [t for t in scored_functions if _has_flow(t)]
        skipped = len(scored_functions) - len(gated)
        print(f"  Flow gate: {skipped} function(s) without AST sources/sinks skipped "
              f"({len(gated)} remain)")
    # v4.1 G1: taint gate — only functions where a finding is possible under the
    # active rules (structural facts, or AST sources / sinks the span rule can
    # pair) reach the LLM; see taint_gate_keys()
    if allow_keys is not None:
        before = len(gated)
        gated = [t for t in gated if f"{t['function']['file']}:{_qname(t['function'])}" in allow_keys]
        skipped += before - len(gated)
        print(f"  Taint gate: {before - len(gated)} function(s) skipped ({len(gated)} remain)")

    # Truncate AFTER gating so the number means "functions actually analysed",
    # which is what the flag name promises and what analyzed_functions reports.
    targets = gated[:max_funcs] if max_funcs > 0 else gated
    if max_funcs > 0 and len(gated) > max_funcs:
        print(f"  Top-{max_funcs} by score ({len(gated) - max_funcs} lower-ranked skipped)")

    if not flow_gate and len(targets) > BASELINE_FUNCS:
        est = int(round(len(targets) * BASELINE_CALLS / BASELINE_FUNCS))
        print(f"  ⚠ Flow gate 未启用，将分析全部 {len(targets)} 个函数，"
              f"预计约 {est} 次 LLM 调用"
              f"（基线：{BASELINE_FUNCS} 个函数 / {BASELINE_CALLS} 次调用）。")
        print(f"    加 --flow-gate 可跳过无数据流函数；Ctrl+C 中止。")

    funnel = {'scored': len(scored_functions), 'gated_in': len(gated),
              'truncated': len(targets), **({'gate_skipped': skipped} if allow_keys is not None else {})}
    func_defs = [t['function'] for t in targets]
    func_sources = extract_func_sources(target_dir, func_defs)
    source_map = {(fs['file'], fs['function']): fs['source'] for fs in func_sources}
    line_map = {(fs['file'], fs['function']): fs.get('line', 1) for fs in func_sources}

    # Hybrid batching: paired functions (AST sees both source AND sink) are the
    # high-confidence ones whose check extraction matters most — extract them
    # one-per-call to avoid batch attention dilution. Single-sided functions
    # (source-only or sink-only) rely on the LLM to fill the other half, so
    # batch them to control cost.
    paired_queue = []
    side_queue = []
    for i, target in enumerate(targets):
        func = target['function']
        source = source_map.get((func['file'], _qname(func)), '')
        if not source:
            continue
        df = target.get('data_flow') or {}
        is_paired = bool(df.get('sources') and df.get('sinks'))
        item = (i, func, source, line_map.get((func['file'], _qname(func)), 1))
        if is_paired:
            paired_queue.append(item)
        else:
            side_queue.append(item)

    def _extract_batch(batch):
        user_msg = _build_batch_message(batch, entry_seeds)
        max_tk = 2048 * len(batch)
        return batch, call_llm(api_cfg, system_prompt, user_msg, max_tokens=max_tk)

    paired_batches = [[item] for item in paired_queue]
    side_batches = [side_queue[i:i + batch_size] for i in range(0, len(side_queue), batch_size)]
    batches = paired_batches + side_batches
    if paired_queue and side_queue:
        print(f"  Hybrid: {len(paired_queue)} paired single-call + "
              f"{len(side_queue)} single-sided batched at {batch_size}")
    if workers > 1 and len(batches) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_extract_batch, batches))
    else:
        results = [_extract_batch(b) for b in batches]

    extractions = {}
    errors = 0
    for batch, (result, err) in results:
        if err:
            for i, func, _source, _start in batch:
                errors += 1
                print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} ERROR: {err}")
            continue
        items = result if isinstance(result, list) else [result]
        for idx, (i, func, _source, _start) in enumerate(batch):
            key = f"{func['file']}:{_qname(func)}"
            if idx >= len(items) or not items[idx]:
                errors += 1
                print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} "
                      f"ERROR: batch item missing")
                continue
            extractions[key] = items[idx]
            n_in = len((items[idx].get('semantic_inputs') or []))
            n_out = len((items[idx].get('semantic_sinks') or []))
            n_chk = len((items[idx].get('observed_checks') or []))
            print(f"  [{i+1}/{len(targets)}] {func['file']}:{func['name']} -> "
                  f"{n_in} input(s), {n_out} sink(s), {n_chk} check(s)")

    elapsed = time.time() - start
    print(f"  Done in {elapsed:.1f}s: {len(extractions)} extracted, {errors} error(s)")
    funnel['extracted'] = len(extractions)
    return extractions, len(extractions), elapsed, source_map, line_map, funnel


def _build_batch_message(batch, entry_seeds=None):
    """Build one extraction message for a batch of functions.

    batch is a list of (i, func, source, start_line) tuples. Each function's
    source is prefixed with its absolute file line number so extracted facts
    share the AST channel's line space (merge_facts dedups on exact line).
    Full source is passed through untruncated — max_tokens bounds output only.
    """
    parts = []
    for k, (i, func, source, start_line) in enumerate(batch, 1):
        parts.append(f"【待提取函数 {k}/{len(batch)}】")
        parts.append(f"- 文件: {func['file']}")
        parts.append(f"- 函数: {func['name']}")
        if func.get('receiver'):
            parts.append(f"- 接收者: {func['receiver']}")
        key = f"{func['file']}:{_qname(func)}"
        if entry_seeds and key in entry_seeds:
            parts.append(f"- 入口判定：参数 {', '.join(str(i) for i in entry_seeds[key])} 携带外部数据（下标从 0 起，不计接收者）")
        numbered = '\n'.join(f"{start_line + ln}| {line}"
                             for ln, line in enumerate(source.split('\n')))
        parts.append(f"- 源码（每行前的 N| 是该行在文件中的绝对行号）:\n{numbered}")
        parts.append("")
    return '\n'.join(parts)


def stage_chain_alignment(api_cfg, target_dir, ast_result, entry_keys, active_domains, workers=1,
                          max_funcs=150, tainted_keys=(), chain_dirs=None, role_batch=40):
    """v5.2 X4: align externally reachable functions to behaviour-chain templates (chain_align.py).

    Candidates: functions the entry triage marked external, AST handlers, and every function
    the taint engine reaches from an external origin — each must hold at least one
    call/comparison line. A signature-level role pass (detect_role.md, batched) routes each
    candidate to chain categories (role 'none' drops it); within them the best real and the
    best generic chain are retrieved and the LLM aligns the function to each. The local rule
    (chain_align.decide) reports only a MISSING step judged absent on aligned code.

    Returns (facts_by_func, alignments_by_func, withheld_generic_facts, funnel).
    """
    print("[Stage 5b] Behaviour-chain alignment...")
    start = time.time()
    chains = chain_align.load_chains(chain_dirs)
    if not chains:
        print("  no chain templates available (behavior_chains/ missing?) — skipped")
        return {}, {}, {}, {'chains': 0}
    weights = chain_align.idf(chains)
    pflows = {f"{pf['file']}:{pf['function']}": pf for pf in (ast_result.get('param_flows') or [])}
    by_name = {}
    for func in (ast_result.get('functions') or []):
        by_name.setdefault(_qname(func).rsplit('.', 1)[-1], []).append(func)
    cands = [(key, pf) for key, pf in sorted(pflows.items())
             if (key in entry_keys or pf.get('handler') or key in tainted_keys)
             and pf.get('check_lines') and not pf['file'].endswith('_test.go')]

    # 1b. role pass: signature + callee names, no bodies
    role_prompt = load_prompt('detect_role.md')
    items = []
    for key, pf in cands:
        sig = ', '.join(f"{p['name']} {p['type']}" for p in (pf.get('params') or []))
        recv = f" 接收者类型: {pf['recv_type']}" if pf.get('recv_type') else ''
        res = f" 返回: ({', '.join(pf.get('results') or [])})" if pf.get('results') else ''
        calls = sorted({(f"{c['pkg'].rsplit('/', 1)[-1]}." if c.get('pkg') else '') + c['name']
                        for c in (pf.get('callees') or [])})
        items.append((key, f"- {key}{recv}\n  参数: ({sig}){res}\n  调用: {', '.join(calls[:25]) or '无'}"))
    role_batches = [items[i:i + role_batch] for i in range(0, len(items), role_batch)]

    def _roles(batch):
        return batch, call_llm(api_cfg, role_prompt, "【待判定函数】\n" + '\n'.join(t for _, t in batch), max_tokens=4096)

    roles = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for batch, (result, err) in ex.map(_roles, role_batches):
            if err or not isinstance(result, list):
                continue
            by_fn = {r.get('function'): r for r in result if isinstance(r, dict)}
            for key, _ in batch:
                role = (by_fn.get(key) or {}).get('role')
                if role in chain_align.ROLE_CATEGORIES:
                    roles[key] = role
    routed = [(key, pf) for key, pf in cands if key in roles]
    # entry functions first, then the rest; the cap bounds cost on large repos
    routed.sort(key=lambda kp: (kp[0] not in entry_keys, kp[0]))
    capped = 0
    if max_funcs > 0 and len(routed) > max_funcs:
        capped = len(routed) - max_funcs
        routed = routed[:max_funcs]
    print(f"  {len(cands)} reachable candidate(s), {len(role_batches)} role call(s), {len(roles)} with a security role"
          + (f", {capped} over the cap skipped" if capped else ''))

    system_prompt = load_prompt('detect_align.md')
    func_defs = [next((f for f in (ast_result.get('functions') or [])
                       if f['file'] == pf['file'] and _qname(f) == pf['function']), None) for _, pf in routed]
    sources = {(fs['file'], fs['function']): fs for fs in extract_func_sources(target_dir, [f for f in func_defs if f])}
    jobs = []
    for key, pf in routed:
        fs = sources.get((pf['file'], pf['function']))
        if not fs:
            continue
        text = ' '.join([pf['function']] + [c['name'] for c in (pf.get('callees') or [])] +
                        [p.get('type', '') for p in (pf.get('params') or [])])
        top = chain_align.retrieve_for_role(chains, roles[key], text, active_domains, weights)
        if not top:
            continue
        # short module callees (<= 30 lines) travel with the function so a check
        # delegated one hop down is visible to the aligner
        snippets = []
        for cs in (pf.get('callees') or []):
            if cs.get('pkg'):
                continue
            for f in by_name.get(cs['name'], [])[:2]:
                if os.path.dirname(f['file']) != os.path.dirname(pf['file']):
                    continue
                cf = extract_func_sources(target_dir, [f])
                if cf and cf[0]['source'].count('\n') <= 30:
                    snippets.append('\n'.join(f"{cf[0]['line'] + i}| {l}" for i, l in enumerate(cf[0]['source'].split('\n'))))
            if len(snippets) >= 6:
                break
        numbered = '\n'.join(f"{fs['line'] + i}| {l}" for i, l in enumerate(fs['source'].split('\n')))
        for ch in top:
            jobs.append((key, pf, fs, ch, chain_align.build_message(key, numbered, snippets, ch)))

    def _one(job):
        key, pf, fs, ch, msg = job
        return job, call_llm(api_cfg, system_prompt, msg, max_tokens=2048)

    if workers > 1 and len(jobs) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_one, jobs))
    else:
        results = [_one(j) for j in jobs]
    alignments, facts, errors = {}, {}, 0
    for (key, pf, fs, ch, _msg), (result, err) in results:
        if err or not isinstance(result, dict):
            errors += 1
            continue
        alignments.setdefault(key, []).append((ch['id'], result))
        end = pf.get('end_line') or (fs['line'] + fs['source'].count('\n'))
        fact = chain_align.decide(result, ch, pf.get('check_lines'), (fs['line'], end))
        if fact:
            facts.setdefault(key, []).append(fact)
            print(f"  {key} ~ {ch['id']} ({ch['category']}): missing step absent, "
                  f"{fact['aligned_ratio']:.0%} steps aligned")
    chain_align.sibling_boost(facts, alignments)
    # v5.2b C: generic-chain facts need a sibling that performs the step or a real-chain fact
    facts, suppressed = chain_align.gate_generic(facts)
    n_sup = sum(len(v) for v in suppressed.values())
    if n_sup:
        print(f"  generic gate: {n_sup} generic-chain fact(s) without sibling / real-chain support withheld")
    print(f"  {len(routed)} routed function(s), {len(jobs)} alignment call(s), {errors} error(s), "
          f"{sum(len(v) for v in facts.values())} fact(s) in {len(facts)} function(s) ({time.time() - start:.1f}s)")
    return facts, alignments, suppressed, {'chains': len(chains), 'candidates': len(cands), 'role_calls': len(role_batches),
                               'roles': dict(sorted(_count_roles(roles).items())), 'capped': capped,
                               'align_calls': len(jobs), 'errors': errors, 'generic_withheld': n_sup,
                               'facts': sum(len(v) for v in facts.values())}


def _count_roles(roles):
    out = {}
    for r in roles.values():
        out[r] = out.get(r, 0) + 1
    return out


# ── LLM call ──────────────────────────────────────────────────────────

import requests
import threading

LLM_USAGE = {'calls': 0, 'prompt_tokens': 0, 'completion_tokens': 0}
_USAGE_LOCK = threading.Lock()


def _record_usage(data):
    usage = (data or {}).get('usage') or {}
    with _USAGE_LOCK:
        LLM_USAGE['calls'] += 1
        LLM_USAGE['prompt_tokens'] += int(usage.get('prompt_tokens') or 0)
        LLM_USAGE['completion_tokens'] += int(usage.get('completion_tokens') or 0)


# 实验记录：每次 HTTP 请求追加一行到 LLM_CALL_LOG（仅日志，不影响任何返回值或流程）
LLM_CALL_LOG = None
_CALL_LOG_LOCK = threading.Lock()


def _log_call(call_id, attempt, req_model, status, outcome, data=None, max_tokens=None):
    if not LLM_CALL_LOG:
        return
    try:
        usage = (data or {}).get('usage') or {}
        choice = ((data or {}).get('choices') or [{}])[0]
        rec = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'call_id': call_id, 'attempt': attempt,
            'retried': attempt > 0, 'req_model': req_model, 'resp_model': (data or {}).get('model'),
            'status': status, 'outcome': outcome, 'finish_reason': choice.get('finish_reason'),
            'max_tokens': max_tokens,
            'prompt_tokens': usage.get('prompt_tokens'), 'completion_tokens': usage.get('completion_tokens'),
            'prompt_cache_hit_tokens': usage.get('prompt_cache_hit_tokens'),
            'prompt_cache_miss_tokens': usage.get('prompt_cache_miss_tokens'),
        }
        with _CALL_LOG_LOCK, open(LLM_CALL_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass


def call_llm(api_cfg, system_prompt, user_content, retries=3, max_tokens=8192):
    url = api_cfg['LLM_BASE_URL'] + '/chat/completions'
    headers = {
        'Authorization': 'Bearer ' + api_cfg['LLM_API_KEY'],
        'Content-Type': 'application/json',
    }

    content = ''
    call_id = '%x' % (time.time_ns() ^ threading.get_ident())
    for attempt in range(retries):
        try:
            payload = {
                'model': api_cfg['LLM_MODEL'],
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_content},
                ],
                'temperature': 0.1,
                'max_tokens': max_tokens,
                'thinking': {'type': 'disabled'},
            }

            r = requests.post(url, headers=headers, json=payload, timeout=300)

            if r.status_code == 429:
                _log_call(call_id, attempt, api_cfg['LLM_MODEL'], 429, 'rate_limited', max_tokens=max_tokens)
                wait = min(30, 5 * (attempt + 1))
                print(f"    [429 rate limited, waiting {wait}s]", flush=True)
                time.sleep(wait)
                continue

            if r.status_code != 200:
                _log_call(call_id, attempt, api_cfg['LLM_MODEL'], r.status_code, 'http_error', max_tokens=max_tokens)
                return None, f"HTTP {r.status_code}: {r.text[:300]}"

            data = r.json()
            _record_usage(data)
            _log_call(call_id, attempt, api_cfg['LLM_MODEL'], 200, 'response', data, max_tokens=max_tokens)
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
            _log_call(call_id, attempt, api_cfg['LLM_MODEL'], None, 'timeout', max_tokens=max_tokens)
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return None, "timeout"
        except Exception as e:
            _log_call(call_id, attempt, api_cfg['LLM_MODEL'], None, 'exception:' + type(e).__name__, max_tokens=max_tokens)
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None, str(e)

    return None, "max retries exceeded"


# ── main ──────────────────────────────────────────────────────────────

interrupted = False


def taint_gate_keys(level, ast_result, data_flows, r2_facts, r3_facts, r5_facts, f3, entry_keys=None):
    """v4.1 G1: the functions the LLM is asked about, from AST / taint facts alone.

    A function can only yield a finding if (structural rules) it has an R2/R3/R4/R5
    fact or an R1 size sink with a source, or (span rule) it has AST sources and a
    sink the span rule may pair. The LLM can add semantic facts to fill one side:
      level A: facts, or AST source AND pairable sink            (cheapest)
      level B: A, or any pairable AST sink (LLM may supply the source)
      level C: B, or any AST source (LLM may supply the sink)     (default)
    """
    from decide import F3_GENERIC_SINKS
    facts = set(r2_facts) | set(r3_facts) | set(r5_facts) | set(entry_keys or [])   # v5.1: judged entries always pass
    size = {f"{s.get('file', '')}:{s.get('function', '')}" for s in (ast_result.get('size_flows') or [])}
    keys = set()
    for func in (ast_result.get('functions') or []):
        k = f"{func['file']}:{_qname(func)}"
        df = data_flows.get(k) or {}
        src = bool(df.get('sources'))
        sink = any((not f3) or (x.get('type') not in F3_GENERIC_SINKS) for x in (df.get('sinks') or []))
        ok = k in facts or (k in size and src) or (src and sink)
        if level in ('B', 'C'):
            ok = ok or sink
        if level == 'C':
            ok = ok or src
        if ok:
            keys.add(k)
    return keys


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
    parser.add_argument("--db", default=None, help="Vulnerability database file (default: vuln_db.json)")
    parser.add_argument("--no-kb", action="store_true",
                        help="Ablation mode: remove the KB front-end chain entirely — skip domain "
                             "classification (no LLM call), do not load vuln_db.json / template "
                             "retrieval, drop the KB template-API +2 function bonus, and renormalize "
                             "confidence over code_evidence+ast_corroboration. AST tables, semantic "
                             "extraction prompt and decide.py stay untouched. Mutually exclusive "
                             "with --db and --domains")
    parser.add_argument("--output", default=None, help="Override report output path (default: projects/<id>/report.json)")
    parser.add_argument("--no-copy", action="store_true", help="Skip copying source into project directory")
    parser.add_argument("--max-functions", type=int, default=0,
                        help="Functions to analyze: 0 = all scored functions, "
                             "N = top N by score")
    parser.add_argument("--flow-gate", action="store_true",
                        help="Skip functions whose AST data flow has neither a source "
                             "nor a sink (cheaper, but may miss what only the LLM sees)")
    parser.add_argument("--confidence-threshold", type=float, default=0.5, help="Min finding confidence")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent semantic-extraction LLM requests")
    parser.add_argument("--batch-size", type=int, default=1, help="Functions per LLM extraction call (batching; default 1)")
    parser.add_argument("--domains", type=str, default=None, help="Manually specify domains (comma-separated)")
    parser.add_argument("--rules", default="v2,R1,R2,R3,R4,R5,F1,F2,F3,F4,G1,X1,X2,X3,X4",
                        help="v3 rule set, comma-separated: v2 (always on) and any of "
                             "R1 (size sinks), R2 (parameter taint across calls), "
                             "R3 (validator contract), R4 (unbounded read of external input), "
                             "R5 (inconsistent authorization across sibling handlers), "
                             "F1 (deterministic template binding), F2 (no package-depth limit), "
                             "F3 (no generic-sink / source-only span pairs), "
                             "F4 (LLM-reported checks must land on a call/comparison line), "
                             "G1 (taint gate: only functions that can yield a finding reach the LLM), "
                             "X1 (signature-level LLM entry triage seeds the taint engine), "
                             "X2 (v5 extraction prompt: shape-named sinks, triage-aware inputs), "
                             "X3 (checks inside validator callees on the path protect the span), "
                             "X4 (behaviour-chain alignment: entry functions are aligned by the LLM to "
                             "non-data-flow chain templates; a missing step judged absent is reported). "
                             "'--rules v2' reproduces v2 output exactly")
    parser.add_argument("--r2-max-hops", type=int, default=param_taint.MAX_HOPS,
                        help="R2: hard cap on call edges from the external origin (default 8; "
                             "chains longer than 4 lose confidence per extra edge)")
    parser.add_argument("--no-name-dispatch", action="store_true",
                        help="R2: do not resolve calls on receivers of unknown type by method name")
    parser.add_argument("--gate-level", choices=("A", "B", "C"), default="C",
                        help="G1 taint gate strictness (A cheapest, C default: any AST source or sink, "
                             "or a structural fact, admits the function)")
    parser.add_argument("--dump-extractions", action="store_true",
                        help="Also write <report dir>/extractions.json: the LLM's per-function facts "
                             "(inputs / sinks / checks), the AST data flow and the R2/R3/R5 facts, for "
                             "offline audits of where a chain broke on a known vulnerability")
    parser.add_argument("--align-max-funcs", type=int, default=150,
                        help="X4: at most this many role-routed functions are aligned to chain templates "
                             "(each costs up to %d LLM calls; entry functions first); 0 = no cap" % chain_align.TOP_K)
    parser.add_argument("--chain-dirs", default=None,
                        help="X4: comma-separated directories of behaviour-chain JSON files (default: "
                             "behavior_chains/ and behavior_chains_generic/ next to this script)")
    parser.add_argument("--no-r3-infer-purpose", dest="r3_infer_purpose", action="store_false",
                        help="R3: do not infer a validator's purpose from URL-like parameter names "
                             "when no caller sink fixes it (inference is on by default, confidence 0.4)")
    parser.add_argument("--source-only-findings", action="store_true",
                        help="Also report functions with attacker-controlled input but no sink "
                             "(catches trusted-header/unvalidated-length classes; widens results)")
    args = parser.parse_args()

    if not args.target and not args.git_url:
        parser.error("Either --target or --git-url is required")
    rules = tuple(dict.fromkeys(['v2'] + [r.strip() for r in args.rules.split(',') if r.strip()]))
    unknown = [r for r in rules if r not in ('v2', 'R1', 'R2', 'R3', 'R4', 'R5', 'F1', 'F2', 'F3', 'F4', 'G1', 'X1', 'X2', 'X3', 'X4')]
    if unknown:
        parser.error(f"unknown rule(s) in --rules: {unknown}")
    if args.target and args.git_url:
        parser.error("Use --target or --git-url, not both")
    if args.no_kb and args.db:
        parser.error("--no-kb removes the knowledge base entirely; --db is mutually exclusive")
    if args.no_kb and args.domains:
        parser.error("--no-kb removes the knowledge base entirely; --domains is mutually exclusive")

    # Create project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_id = time.strftime('%Y%m%d_%H%M%S')
    project_dir = os.path.join(script_dir, 'projects', project_id)

    if args.output:
        report_path = os.path.abspath(args.output)
    else:
        os.makedirs(project_dir, exist_ok=True)
        report_path = os.path.join(project_dir, 'report.json')
    global LLM_CALL_LOG
    LLM_CALL_LOG = os.path.join(os.path.dirname(report_path), 'llm_calls.jsonl')

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
    for key in ('LLM_API_KEY', 'LLM_BASE_URL', 'LLM_MODEL'):
        if key not in cfg or not cfg[key]:
            print(f"Error: {key} not set in .env", file=sys.stderr)
            sys.exit(1)

    # Load vulnerability database (skipped entirely in --no-kb ablation mode)
    if args.no_kb:
        vuln_db = {}
        print("KB ablation mode (--no-kb): domain classification, vuln_db loading and "
              "template retrieval are skipped; KB scoring bonus removed.\n")
    else:
        db_path = args.db or "vuln_db.json"
        if not os.path.isfile(db_path):
            print(f"Error: {db_path} not found. Run build_vuln_db.py first.", file=sys.stderr)
            sys.exit(1)
        with open(db_path, encoding='utf-8') as f:
            vuln_db = json.load(f)
        print(f"Loaded vuln_db: {vuln_db['metadata']['total_templates']} templates, "
              f"{vuln_db['metadata']['total_records']} records\n")

    overall_start = time.time()

    # Stage 1: AST scan
    if interrupted:
        return
    ast_result = stage_ast_scan(target_dir, max_depth=None if 'F2' in rules else 4)

    # Stage 2: Domain classification
    if interrupted:
        return
    if args.no_kb:
        domains = []
        domain_time = 0.0
        print("[Stage 2/5] Domain classification: skipped (--no-kb)")
    elif args.domains:
        domains = [{'domain': d.strip(), 'confidence': 1.0, 'evidence': 'manually specified'}
                    for d in args.domains.split(',')]
        print(f"[Stage 2/5] Domains (manual): {[d['domain'] for d in domains]}")
        domain_time = 0.0
    else:
        domains, domain_time = stage_domain_classification(cfg, ast_result)

    # Stage 3: Pattern retrieval
    if interrupted:
        return
    if args.no_kb:
        candidate_templates = []
        print("[Stage 3/5] Pattern retrieval: skipped (--no-kb)")
    else:
        candidate_templates = stage_pattern_retrieval(vuln_db, domains, ast_result,
                                                      deterministic='F1' in rules)

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

    scored_set = {(f['function']['file'], _qname(f['function'])) for f in scored_functions}
    for func in (ast_result.get('functions') or []):
        key = f"{func['file']}:{_qname(func)}"
        if (func['file'], _qname(func)) in scored_set:
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
                scored_set.add((func['file'], _qname(func)))

    # v5 X1: signature-level entry triage seeds the taint engine
    llm_seeds = {}
    if 'X1' in rules:
        llm_seeds = stage_entry_triage(cfg, ast_result, workers=args.workers)

    # v3 R2: parameter taint across calls; functions with a tainted dangerous sink
    # must reach semantic extraction (the decision needs their checks).
    # v3 R3: validator contract (reuses the R2 taint facts for reachability).
    r2_facts, r2_sanitizers, r3_facts, r5_facts = {}, {}, {}, {}
    if 'R2' in rules or 'R3' in rules or 'R4' in rules or 'R5' in rules:
        pflows = ast_result.get('param_flows') or []
        modules = param_taint.load_modules(target_dir)
        wire_types = param_taint.wire_types_from(ast_result)
        if 'R2' in rules or 'R4' in rules:
            r2_facts = param_taint.tainted_sinks(pflows, modules, max_hops=args.r2_max_hops,
                                                 name_dispatch=not args.no_name_dispatch,
                                                 wire_types=wire_types, extra_seeds=llm_seeds)
            r2_sanitizers = param_taint.sanitizers_by_func(pflows)
            print(f"  R2: {sum(len(v) for v in r2_facts.values())} tainted sink(s) in "
                  f"{len(r2_facts)} function(s)")
        if 'R3' in rules:
            r3_facts = validator_contract.r3_facts(pflows, modules, max_hops=args.r2_max_hops,
                                                   name_dispatch=not args.no_name_dispatch,
                                                   infer_purpose=args.r3_infer_purpose,
                                                   wire_types=wire_types, extra_seeds=llm_seeds)
            print(f"  R3: {sum(len(v) for v in r3_facts.values())} validator contract gap(s) in "
                  f"{len(r3_facts)} function(s)")
        if 'R5' in rules:
            r5_facts = authz_consistency.r5_facts(pflows)
            print(f"  R5: {len(r5_facts)} handler(s) without the authorization their siblings perform")
        added = 0
        for func in (ast_result.get('functions') or []):
            key = f"{func['file']}:{_qname(func)}"
            if (key in r2_facts or key in r3_facts or key in r5_facts) and \
                    (func['file'], _qname(func)) not in scored_set:
                scored_functions.append({
                    'function': func,
                    'score': 15,
                    'reasons': ['R2/R3: externally tainted parameter reaches a dangerous sink '
                                'or an incomplete validator'],
                    'data_flow': data_flows.get(key),
                    'call_chain': None,
                })
                scored_set.add((func['file'], _qname(func)))
                added += 1
        print(f"  R2/R3: {added} function(s) added to extraction")

    scored_functions.sort(key=lambda x: -x['score'])

    # Stage 5: Semantic extraction + local decision
    if interrupted:
        return
    df_by_func = {f"{t['function']['file']}:{_qname(t['function'])}": (t.get('data_flow') or {})
                  for t in scored_functions}
    gate_keys = None
    if 'G1' in rules:
        gate_keys = taint_gate_keys(args.gate_level, ast_result, data_flows, r2_facts, r3_facts, r5_facts,
                                    'F3' in rules, entry_keys=llm_seeds if 'X1' in rules else None)
    extractions, analyzed_count, analysis_time, source_map, line_map, funnel = \
        stage_semantic_extraction(
            cfg, target_dir, scored_functions, workers=args.workers,
            batch_size=args.batch_size, flow_gate=args.flow_gate,
            max_funcs=args.max_functions, allow_keys=gate_keys,
            prompt_file='detect_extract_v5.md' if 'X2' in rules else 'detect_extract.md',
            entry_seeds=llm_seeds if 'X2' in rules else None,
        )
    funnel['total'] = len(ast_result.get('functions') or [])
    # v5.1: R5 second pass — sibling handlers compared with LLM-observed authorization checks too
    if 'R5' in rules and 'X2' in rules:
        llm_principal = {k for k, e in (extractions or {}).items() if e and any(
            (c.get('category') in ('access_control', 'identity_verification')) for c in (e.get('observed_checks') or []))}
        r5_facts = authz_consistency.r5_facts(ast_result.get('param_flows') or [], llm_principal=llm_principal)
    # v5.2 X4: chain alignment for the classes without a dangerous sink
    x4_facts, x4_alignments, x4_withheld = {}, {}, {}
    if 'X4' in rules and not interrupted:
        x4_tainted, _ = param_taint.propagate(ast_result.get('param_flows') or [], param_taint.load_modules(target_dir),
                                              max_hops=args.r2_max_hops, name_dispatch=not args.no_name_dispatch,
                                              wire_types=param_taint.wire_types_from(ast_result), extra_seeds=llm_seeds)
        x4_reach = {k for k, v in x4_tainted.items() if v}
        x4_facts, x4_alignments, x4_withheld, funnel['align'] = stage_chain_alignment(
            cfg, target_dir, ast_result, set(llm_seeds), domains, workers=args.workers,
            max_funcs=args.align_max_funcs, tainted_keys=x4_reach,
            chain_dirs=args.chain_dirs.split(',') if args.chain_dirs else None)
    if args.dump_extractions:
        dump_path = os.path.join(os.path.dirname(report_path), 'extractions.json')
        with open(dump_path, 'w', encoding='utf-8') as f:
            json.dump({'extractions': extractions, 'data_flow': df_by_func,
                       'r2_facts': r2_facts, 'r3_facts': r3_facts, 'r5_facts': r5_facts,
                       'llm_entry_seeds': llm_seeds,
                       **({'x4_facts': x4_facts, 'x4_alignments': x4_alignments,
                           'x4_withheld': x4_withheld} if 'X4' in rules else {})},
                      f, ensure_ascii=False, indent=1, default=list)
        print(f"  Extractions dumped: {dump_path}")
    size_flows_by_func = {f"{sf.get('file', '')}:{sf.get('function', '')}": sf
                          for sf in (ast_result.get('size_flows') or [])}
    findings = build_findings(extractions, df_by_func, candidate_templates, vuln_db,
                              source_only=args.source_only_findings,
                              size_flows_by_func=size_flows_by_func, rules=rules,
                              r2_facts_by_func=r2_facts, r2_sanitizers_by_func=r2_sanitizers,
                              r3_facts_by_func=r3_facts, r5_facts_by_func=r5_facts,
                              check_lines_by_func={f"{pf['file']}:{pf['function']}": pf.get('check_lines') or []
                                                   for pf in (ast_result.get('param_flows') or [])}
                              if 'F4' in rules else None,
                              ext_checks_by_func=validator_contract.callee_checks(
                                  ast_result.get('param_flows') or [], param_taint.load_modules(target_dir),
                                  name_dispatch=not args.no_name_dispatch) if 'X3' in rules else None,
                              x4_facts_by_func=x4_facts if 'X4' in rules else None)
    print(f"  Decision: {len(findings)} finding(s) from local span rules")

    # CVSS scoring: metrics derived from AST facts + category defaults (no LLM input)
    enrich_findings_with_cvss(findings, df_by_func)
    if findings:
        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f['severity']] += 1
        dist = ' '.join(f"{s}:{sev_counts[s]}" for s in ('critical', 'high', 'medium', 'low') if sev_counts[s])
        print(f"  CVSS scored: {len(findings)} findings ({dist})")

    # Confidence scoring: weighted evidence model (citation / AST / template / LLM self)
    source_by_func = {f"{file}:{name}": src for (file, name), src in source_map.items()}
    # Evidence cites absolute file lines, so confidence needs each function's
    # start line to bound-check them against the right range.
    start_line_by_func = {f"{file}:{name}": ln for (file, name), ln in line_map.items()}
    enrich_findings_with_confidence(findings, df_by_func, source_by_func, vuln_db,
                                    start_line_by_func, no_kb=args.no_kb)
    if findings:
        lvl_counts = defaultdict(int)
        for f in findings:
            lvl_counts[f['confidence_level']] += 1
        dist = ' '.join(f"{l}:{lvl_counts[l]}" for l in ('confirmed', 'likely', 'tentative') if lvl_counts[l])
        print(f"  Confidence scored: {len(findings)} findings ({dist})")

    # Filter by confidence threshold
    filtered = [f for f in findings if f.get('confidence', 0) >= args.confidence_threshold]

    # Generate report
    total_elapsed = time.time() - overall_start
    report = {
        'scan_info': {
            'project_id': project_id,
            'target': target_dir,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'model': cfg['LLM_MODEL'],
            'total_functions': len(ast_result.get('functions') or []),
            'analyzed_functions': analyzed_count,
            'total_templates_matched': len(candidate_templates),
            'total_duration': round(total_elapsed, 1),
            'cvss': {'version': '3.1', 'severity_source': 'computed'},
            'confidence': {'model': ('evidence-weighted-v1-nokb-normalized' if args.no_kb
                                     else 'evidence-weighted-v1'),
                           'dimensions': ['code_evidence', 'ast_corroboration'] +
                                         ([] if args.no_kb else ['template_support'])},
            'llm_role': 'semantic_extraction',
            'decision_engine': 'local_rules_v1',
            'llm_usage': dict(LLM_USAGE),
            'filters': {
                'max_functions': args.max_functions,
                'flow_gate': args.flow_gate,
                'source_only_findings': args.source_only_findings,
                'no_kb': args.no_kb,
                **({'rules': list(rules)} if rules != ('v2',) else {}),
                **({'r2_max_hops': args.r2_max_hops, 'r2_name_dispatch': not args.no_name_dispatch}
                   if ('R2' in rules or 'R3' in rules or 'R4' in rules) else {}),
                **({'r3_infer_purpose': args.r3_infer_purpose} if 'R3' in rules else {}),
                **({'taint_gate_level': args.gate_level} if 'G1' in rules else {}),
                **({'align_max_funcs': args.align_max_funcs} if 'X4' in rules else {}),
            },
            'funnel': funnel,
        },
        'project_domains': domains,
        'summary': {
            'total_findings': len(filtered),
            'by_severity': _count_by(filtered, 'severity'),
            'by_confidence_level': _count_by(filtered, 'confidence_level'),
            'by_domain': _count_by(filtered, lambda f: _infer_domain_from_template(f, vuln_db)),
            'by_category': _count_by(filtered, 'missing_step_category'),
            **({'by_rule': _count_by(filtered, 'rule_id')} if rules != ('v2',) else {}),
            'score_summary': {
                'max': max((f['cvss_score'] for f in filtered), default=0.0),
                'mean': round(sum(f['cvss_score'] for f in filtered) / len(filtered), 1) if filtered else 0.0,
            },
        },
        'findings': filtered,
        'function_scores': [
            {'function': f"{t['function']['file']}:{_qname(t['function'])}",
             'score': t['score'], 'reasons': t['reasons']}
            for t in scored_functions[:30]
        ],
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 50}")
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {total_elapsed:.1f}s")
    print(f"  Functions analyzed: {analyzed_count}")
    print(f"  LLM usage: {LLM_USAGE['calls']} calls, "
          f"{LLM_USAGE['prompt_tokens']:,} prompt tokens, "
          f"{LLM_USAGE['completion_tokens']:,} completion tokens")
    print(f"  Findings: {len(filtered)} (threshold: {args.confidence_threshold})")
    for f in filtered:
        print(f"    [{f.get('severity', '?').upper()} {f.get('cvss_score', 0):.1f}] {f.get('function', '?')}: "
              f"{f.get('pattern_name', '?')} (confidence: {f.get('confidence', 0):.2f}/{f.get('confidence_level', '?')}) "
              f"{f.get('cvss_vector', '')}")
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
