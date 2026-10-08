"""
Deterministic decision engine for the detection pipeline.

The LLM only performs semantic fact extraction (detect_extract.md); whether
a finding exists is decided here by local span rules:

    report condition  =  source present  AND  sink present
                        AND  no category-matching check inside the span

Facts come from two channels and are merged before judging:
  - AST channel: data_flow_indicators (sources / sinks / sanitizers from
    pattern tables in ast_analyzer/main.go)
  - semantic channel: LLM extraction (semantic_inputs / semantic_sinks /
    observed_checks), mapped onto the same type space via KIND_HINTS

Everything downstream (pattern naming, evidence text, template binding) is
deterministic, so identical facts always produce an identical report.

CLI:
    python decide.py --selftest
"""

import sys

from confidence import CATEGORY_FLOW_HINTS

# ── Semantic fact mappings (LLM enums -> AST type space) ──────────────

ORIGIN_TO_SOURCE_TYPE = {
    'network': 'http_request',
    'file': 'read',
    'cli': 'scan',
    'env': 'read',
    # 'internal' origins are not attacker-controlled -> no source type
}

KIND_TO_SINK_TYPE = {
    'file_write': 'file_write',
    'file_read': 'file_read',
    'command': 'command_execution',
    'sql': 'sql_query',
    'http_response': 'write',
    'log': 'write',
    'network': 'http_request',
    'template': 'string_format',
}


# v5 X2: the extraction prompt detect_extract_v5.md names sinks by shape; these map onto
# the structural sink types so the span rule can pair them (V5_SINK_CATEGORY).
KIND_TO_SINK_TYPE_V5 = {
    **KIND_TO_SINK_TYPE,
    'query': 'sql_query', 'alloc': 'alloc_size', 'unbounded_read': 'unbounded_read',
    'url_path': 'url_path', 'redirect': 'redirect', 'response_html': 'response_write',
    'forward': 'forward',
}
V5_SINK_CATEGORY = {
    'alloc_size': ['resource_limit'], 'unbounded_read': ['resource_limit'],
    'url_path': ['path_validation'], 'redirect': ['origin_validation'],
    'response_write': ['output_encoding'], 'forward': ['identity_verification', 'input_sanitization'],
}


# ── Fact merging ──────────────────────────────────────────────────────

def merge_facts(extraction, data_flow, kind_map=None):
    """Merge semantic extraction facts with AST data flow facts.

    The AST channel is authoritative: when both channels report a fact at
    the same line, the AST type wins and the semantic fact only enriches
    the description. Semantic facts fill gaps (lines/types the pattern
    tables missed). Facts without a usable line are dropped.

    A semantic fact whose line drifts within +-2 lines of an AST fact of
    the same mapped type snaps onto the AST line, so LLM line drift and
    origin/kind flips near AST-covered lines cannot create phantom
    duplicate facts (a 'network' input at L534 and an AST http_request at
    L535 are one fact, not two).
    """
    extraction = extraction or {}
    data_flow = data_flow or {}

    SNAP_DISTANCE = 2

    def _snap(line, kind, kind_lines):
        cands = [al for al in kind_lines.get(kind, []) if abs(al - line) <= SNAP_DISTANCE]
        return min(cands, key=lambda al: (abs(al - line), al)) if cands else line

    def _merge(ast_items, sem_items, type_of):
        merged = {}
        ast_line_types = {}
        ast_type_lines = {}
        for s in (ast_items or []):
            if s.get('line') and s.get('type'):
                merged[(s['line'], s['type'])] = {'line': s['line'], 'type': s['type'], 'desc': ''}
                ast_line_types.setdefault(s['line'], s['type'])
                ast_type_lines.setdefault(s['type'], []).append(s['line'])
        for s in (sem_items or []):
            mtype = type_of(s)
            if not (mtype and s.get('line')):
                continue
            line = _snap(s['line'], mtype, ast_type_lines)
            key = (line, mtype)
            if key in merged:
                if s.get('desc'):
                    merged[key]['desc'] = s['desc']
            elif line in ast_line_types:
                continue  # AST already typed this line differently -> AST wins
            else:
                merged[key] = {'line': line, 'type': mtype, 'desc': s.get('desc', '')}
        return sorted(merged.values(), key=lambda x: x['line'])

    def _merge_checks(ast_items, sem_items):
        merged = {}
        ast_line_cats = {}
        ast_cat_lines = {}
        for s in (ast_items or []):
            if s.get('line') and s.get('category'):
                merged[(s['line'], s['category'])] = {'line': s['line'], 'category': s['category'], 'desc': '', 'ast': True}
                ast_line_cats.setdefault(s['line'], set()).add(s['category'])
                ast_cat_lines.setdefault(s['category'], []).append(s['line'])
        for s in (sem_items or []):
            if not (s.get('line') and s.get('category')):
                continue
            line = _snap(s['line'], s['category'], ast_cat_lines)
            key = (line, s['category'])
            if key in merged:
                if s.get('desc'):
                    merged[key]['desc'] = s['desc']
            else:
                merged[key] = {'line': line, 'category': s['category'], 'desc': s.get('desc', ''), 'ast': False}
        return sorted(merged.values(), key=lambda x: x['line'])

    sources = _merge(data_flow.get('sources'), extraction.get('semantic_inputs'),
                     lambda s: ORIGIN_TO_SOURCE_TYPE.get(str(s.get('origin', '')).lower()))
    kind_map = kind_map or KIND_TO_SINK_TYPE
    sinks = _merge(data_flow.get('sinks'), extraction.get('semantic_sinks'),
                   lambda s: kind_map.get(str(s.get('kind', '')).lower()))
    checks = _merge_checks(data_flow.get('sanitizers'), extraction.get('observed_checks'))

    return {'sources': sources, 'sinks': sinks, 'checks': checks}


# ── Span judgment ─────────────────────────────────────────────────────

def categories_for_pair(source_type, sink_type):
    """Categories whose flow hints hit this (source, sink) pair."""
    cats = []
    for cat, (src_hints, sink_hints) in CATEGORY_FLOW_HINTS.items():
        if not src_hints and not sink_hints:
            continue
        src_ok = source_type in src_hints
        sink_ok = sink_type in sink_hints
        if src_ok and (sink_ok or not sink_hints):
            cats.append(cat)
    return cats


def unprotected_categories(span_lo, span_hi, categories, checks):
    """Filter out categories protected by a check inside the span."""
    out = []
    for cat in categories:
        protected = any(c['category'] == cat and span_lo < c['line'] < span_hi
                        for c in checks)
        if not protected:
            out.append(cat)
    return out


# ── Finding construction ──────────────────────────────────────────────

def _pick_template(category, candidate_templates, templates):
    for tpl_id, _score, _api in candidate_templates or []:
        tpl = (templates or {}).get(tpl_id)
        if tpl and tpl.get('missing_step_category') == category:
            return tpl_id, tpl
    return '', {}


def _is_source_only(category):
    """Category keyed purely on the source side (no sink hints)."""
    _src_hints, sink_hints = CATEGORY_FLOW_HINTS[category]
    return not sink_hints


def _collapse(candidates):
    """Collapse (src, snk, cat) span candidates into reporting spans.

    Without this, N sources x M sinks multiply every category into N*M
    near-identical findings. Two rules:

    - sink-hint categories: one finding per (sink, category). The earliest
      source wins (the longest flow into that sink).
    - source-only categories: one finding per (function, category). The
      widest span wins (strongest claim: no check across the whole range).
    """
    best = {}
    for src, snk, cat in candidates:
        if _is_source_only(cat) and snk['type'] not in V5_SINK_CATEGORY:
            key = (cat, None)
            rank = (-abs(snk['line'] - src['line']), src['line'], snk['line'])
        else:
            key = (cat, snk['line'])
            rank = (src['line'], snk['line'])
        if key not in best or rank < best[key][0]:
            best[key] = (rank, src, snk, cat)
    order = sorted(best, key=lambda k: (k[0], k[1] or 0))
    return [best[k][1:] for k in order]


SOURCE_ONLY_CATEGORIES = tuple(
    c for c, (sh, kh) in CATEGORY_FLOW_HINTS.items() if sh and not kh)


def source_only_categories(sources, checks):
    """Categories a sink-less function can still be missing.

    Some vulnerability classes have no dangerous operation to point at: the
    flaw is that attacker-controlled input is trusted as-is — a forged auth
    header believed to be an identity, a length field used without bounds.
    Those categories declare empty sink hints, so a (source, sink) pair can
    never form and the function is dropped before any category is considered.
    Here the source alone carries the finding, and a matching check anywhere
    in the function protects it.
    """
    types = set(s['type'] for s in sources)
    out = []
    for cat in SOURCE_ONLY_CATEGORIES:
        src_hints, _ = CATEGORY_FLOW_HINTS[cat]
        if not (types & src_hints):
            continue
        if any(c['category'] == cat for c in checks):
            continue
        out.append(cat)
    return sorted(out)


# ── v3 R1: attacker-controlled size (allocation length / index) ─────

R1_SOURCE_TYPES = {'http_request', 'http_body', 'read_message', 'network_read', 'network_accept',
                   'read', 'read_all', 'scan', 'buffered_read', 'json_decode', 'xml_decode',
                   'binary_read', 'io_copy'}
R1_SINK_CATEGORY = {'alloc_size': 'resource_limit', 'index_access': 'bounds_check'}
R1_PROTECTING = {'resource_limit', 'bounds_check'}


def r1_candidates(sources, checks, size_flow):
    """(src, sink, category) triples for rule R1.

    A size sink (AST: a numerically parsed value used as make() length or as an
    index) preceded by an external source is reported unless a range check on the
    same variable (AST) or a bounds_check/resource_limit check (either channel)
    sits between the source and the sink.
    """
    out = []
    size_flow = size_flow or {}
    range_checks = size_flow.get('range_checks') or []
    for snk in size_flow.get('size_sinks') or []:
        cat = R1_SINK_CATEGORY.get(snk.get('type'))
        if not cat:
            continue
        srcs = [s for s in sources if s['type'] in R1_SOURCE_TYPES and s['line'] < snk['line']]
        if not srcs:
            continue
        src = min(srcs, key=lambda x: x['line'])
        lo, hi = src['line'], snk['line']
        guarded = any(rc.get('var') == snk.get('var') and lo <= rc['line'] < hi for rc in range_checks) or \
            any(c['category'] in R1_PROTECTING and lo < c['line'] < hi for c in checks)
        if guarded:
            continue
        sink = {'line': snk['line'], 'type': snk['type'],
                'desc': f"{snk.get('var', '')} → {str(snk.get('pattern', ''))[:60]}"}
        out.append((src, sink, cat))
    # one finding per (category, sink line)
    seen, uniq = set(), []
    for src, sink, cat in sorted(out, key=lambda t: (t[1]['line'], t[2])):
        if (cat, sink['line']) not in seen:
            seen.add((cat, sink['line'])); uniq.append((src, sink, cat))
    return uniq


# ── v3 R2: externally reachable parameters into dangerous sinks ──────

R2_SINK_CATEGORY = {
    'command_execution': 'input_sanitization', 'sql_query': 'input_sanitization',
    'sql_exec': 'input_sanitization', 'query_exec': 'output_encoding',
    'file_read': 'path_validation', 'file_write': 'path_validation',
    'html_injection': 'output_encoding', 'js_injection': 'output_encoding',
    'redirect': 'origin_validation', 'alloc_size': 'resource_limit',
    'http_request': 'input_sanitization',   # v3.1: attacker-chosen outbound destination (SSRF)
    'unbounded_read': 'resource_limit',     # v3.1 R4: read of external input without a size bound
    'url_path': 'path_validation',          # v3.2: external input in the path of an outbound URL
    'query_built': 'input_sanitization',    # v3.2: string-built query (any query language, CWE-943)
    'response_write': 'output_encoding',    # v3.2: external input written to an HTML-capable response
}


def r2_candidates(r2_facts, checks, r2_sanitizers=None, size_flow=None, retain_all=False):
    """(src, sink, category) triples for rule R2.

    r2_facts come from param_taint.tainted_sinks: a sink whose arguments are reached
    by an externally tainted parameter (taint is already cut at R2 sanitizers such as
    ldap.EscapeFilter). A same-category check (AST sanitizer, R2 sanitizer, or
    LLM-observed check) in [source line, sink line) protects the flow.
    """
    out = []
    all_checks = list(checks or []) + list(r2_sanitizers or [])
    for fact in r2_facts or []:
        snk, src = fact['sink'], fact['source']
        cat = R2_SINK_CATEGORY.get(snk.get('type'))
        if not cat:
            continue
        lo, hi = src['line'], snk['line']
        # R4: only a reader limit bounds a read, and the AST already cut those
        # (io.LimitReader / http.MaxBytesReader); a Content-Length or size check the
        # LLM reports does not (the header is attacker-set, and compressed size says
        # nothing about the decompressed stream)
        if snk.get('type') != 'unbounded_read' and \
                any(c.get('category') == cat and lo <= c.get('line', 0) < hi for c in all_checks):
            continue
        # v4.3: an allocation length is bounded by a relational check on the parsed value
        # (the R1 range check) just as well as by a resource_limit check
        if snk.get('type') == 'alloc_size' and \
                any(lo <= rc.get('line', 0) < hi for rc in ((size_flow or {}).get('range_checks') or [])):
            continue
        out.append((src, snk, cat))
    if retain_all:
        return out
    # one finding per category: the earliest reached sink (one missing check upstream)
    seen, uniq = set(), []
    for src, snk, cat in sorted(out, key=lambda t: (t[1]['line'], t[2], t[0]['line'])):
        if cat not in seen:
            seen.add(cat); uniq.append((src, snk, cat))
    return uniq


# v4 F3: generic sinks and source-only categories. In exp2's blind review, every
# span finding paired with fmt.Sprintf / .Write (0/25) or carried by a source-only
# category (0/10) was judged false; they were 62% of all alerts. fmt.Sprintf is a
# propagation step, not an operation; a write is dangerous only as a structural
# sink (response_write, R2), and access control only as R5.
F3_GENERIC_SINKS = {'write', 'string_format'}


def build_findings(extraction_by_func, data_flow_by_func, candidate_templates,
                   vuln_db, source_only=False, size_flows_by_func=None, rules=('v2',),
                   r2_facts_by_func=None, r2_sanitizers_by_func=None, r3_facts_by_func=None,
                   r5_facts_by_func=None, check_lines_by_func=None, ext_checks_by_func=None,
                   x4_facts_by_func=None, retain_protection=False):
    """Turn merged facts into deterministic findings.

    extraction_by_func: {func_key: extraction dict or None}
    data_flow_by_func:  {func_key: AST data_flow dict or {}}
    source_only: also emit findings for functions that have sources but no
        sink (see source_only_categories); off by default because it widens
        the candidate set considerably.
    size_flows_by_func / rules (v3): with 'R1' in rules, size sinks from the AST
        are paired with external sources (r1_candidates). With rules == ('v2',)
        the output is identical to v2 (no rule_id field is added).
    r2_facts_by_func / r2_sanitizers_by_func (v3): with 'R2' in rules, sinks reached by
        externally tainted parameters (param_taint.tainted_sinks) become findings unless
        protected or already reported by the v2 span rule for the same (category, sink).
    r3_facts_by_func (v3): with 'R3' in rules, validator-contract facts
        (validator_contract.r3_facts) become findings on the validator itself.
    """
    templates = (vuln_db or {}).get('templates') or {}
    findings = []
    v3 = any(r != 'v2' for r in rules)
    f3 = 'F3' in rules
    f4 = 'F4' in rules
    x2 = 'X2' in rules
    ext_checks_by_func = ext_checks_by_func or {}   # X3: checks performed by validator callees on the path
    check_lines_by_func = check_lines_by_func or {}
    size_flows_by_func = size_flows_by_func or {}
    r2_facts_by_func = r2_facts_by_func or {}
    r2_sanitizers_by_func = r2_sanitizers_by_func or {}
    r3_facts_by_func = r3_facts_by_func or {}
    r5_facts_by_func = r5_facts_by_func or {}
    x4_facts_by_func = x4_facts_by_func or {}   # X4: chain_align.decide facts (already rule-checked)

    keys = set(extraction_by_func) | set(data_flow_by_func) | set(x4_facts_by_func)
    original_sizes = size_flows_by_func
    original_sanitizers = r2_sanitizers_by_func
    if retain_protection:
        keys |= set(r2_facts_by_func) | set(r3_facts_by_func) | set(r5_facts_by_func) | set(size_flows_by_func)
        size_flows_by_func = {k: dict(v, range_checks=[]) for k, v in size_flows_by_func.items()}
        r2_sanitizers_by_func = {}
    protections = {}
    for func_key in sorted(keys):
        extraction = extraction_by_func.get(func_key)
        if extraction is None and retain_protection:
            extraction = {}
        if extraction is None:
            continue  # no semantic extraction (LLM failed or skipped) -> no facts
        facts = merge_facts(extraction, data_flow_by_func.get(func_key), KIND_TO_SINK_TYPE_V5 if x2 else None)
        sources, sinks, checks = facts['sources'], facts['sinks'], facts['checks']
        for c in ext_checks_by_func.get(func_key) or []:
            checks.append({'line': c['line'], 'category': c['category'], 'desc': c.get('desc', ''), 'ast': True})
        checks.sort(key=lambda c: c['line'])
        if retain_protection:
            protections[func_key] = (list(checks)
                + list((original_sizes.get(func_key) or {}).get('range_checks') or [])
                + list(original_sanitizers.get(func_key) or []))
            checks = []
        if f4:
            # F4 (v4.2): a check the LLM reports counts only where the AST has a call or a
            # comparison within a line of it — an invented or misplaced check must not
            # protect a span. Without the function's line facts nothing is dropped.
            cl = check_lines_by_func.get(func_key)
            if cl:
                cls = set(cl)
                checks = [c for c in checks if c.get('ast') or
                          any(l in cls for l in (c['line'] - 1, c['line'], c['line'] + 1))]
        purpose = str(extraction.get('purpose') or '').strip()
        if ('R2' in rules or 'R4' in rules) and func_key in r2_facts_by_func:
            facts_ = [x for x in r2_facts_by_func[func_key]
                      if ('R4' in rules if x['sink'].get('type') == 'unbounded_read' else 'R2' in rules)]
            for src, snk, cat in r2_candidates(facts_, checks, r2_sanitizers_by_func.get(func_key),
                                               size_flows_by_func.get(func_key), retain_all=retain_protection):
                f = _make_finding(func_key, src, snk, cat, purpose, candidate_templates, templates)
                f['rule_id'] = 'R4' if snk.get('type') == 'unbounded_read' else 'R2'
                f['source_provenance'] = src.get('provenance', '')
                f['taint_path'] = list(src.get('path') or [])
                findings.append(f)
        if 'R3' in rules and func_key in r3_facts_by_func:
            for fact in r3_facts_by_func[func_key]:
                f = _make_finding(func_key, fact['source'], fact['sink'], fact['category'],
                                  purpose, candidate_templates, templates)
                via = '参数名推断' if fact.get('inferred') else '调用方 ' + '；'.join(fact.get('callers') or [])
                weak = f"只有弱校验 `{fact['weak_check'][:80]}`" if fact.get('weak_check') else '未见该用途的强校验'
                f['reasoning'] = ((f"函数用途：{purpose}。" if purpose else '') +
                                  f"校验函数的参数外部可达（{fact['source'].get('provenance', '')}），"
                                  f"用途为 {fact['purpose']}（依据：{via}），函数内{weak}。")
                f['rule_id'] = 'R3'
                f['source_provenance'] = fact['source'].get('provenance', '')
                f['taint_path'] = list(fact['source'].get('path') or [])
                f['validator_purpose'] = fact['purpose']
                f['purpose_inferred'] = bool(fact.get('inferred'))
                findings.append(f)
        if 'R5' in rules and func_key in r5_facts_by_func:
            for fact in r5_facts_by_func[func_key]:
                f = _make_finding(func_key, fact['source'], fact['sink'], fact['category'],
                                  purpose, candidate_templates, templates)
                f['reasoning'] = ((f"函数用途：{purpose}。" if purpose else '') +
                                  f"处理函数按请求中的标识访问资源（L{fact['sink']['line']}），"
                                  f"但未检查调用者身份或权限；{fact['peers']}"
                                  f"（如 {', '.join(fact.get('checked_peers') or [])}）。")
                f['rule_id'] = 'R5'
                f['source_provenance'] = 'peer_inconsistency'
                findings.append(f)
        if 'X4' in rules and func_key in x4_facts_by_func:
            best_x4 = {}
            for fact in x4_facts_by_func[func_key]:   # one finding per category: best aligned, real chain on ties
                cur = best_x4.get(fact['category'])
                if cur is None or (fact['aligned_ratio'], not fact.get('generic'), fact.get('peers_present', 0)) > \
                        (cur['aligned_ratio'], not cur.get('generic'), cur.get('peers_present', 0)):
                    best_x4[fact['category']] = fact
            selected_x4 = x4_facts_by_func[func_key] if retain_protection else [best_x4[c] for c in sorted(best_x4)]
            for fact in selected_x4:
                f = _make_finding(func_key, fact['source'], fact['sink'], fact['category'],
                                  purpose, candidate_templates, templates)
                f['reasoning'] = ((f"函数用途：{purpose}。" if purpose else '') +
                                  f"函数行为与行为链模板 {fact['template']}（{fact['pattern'] or fact['category']}）"
                                  f"逐步对齐（{fact['aligned_ratio']:.0%} 步骤，L{fact['source']['line']}–"
                                  f"L{fact['sink']['line']}），模板要求的 {fact['category']} 步骤在本函数及其"
                                  f"直接被调函数中均未执行：{fact.get('note', '')}"
                                  + (f"；同文件 {fact['peers_present']} 个对齐到同一模板的函数执行了该步骤。"
                                     if fact.get('peers_present') else "。"))
                f['rule_id'] = 'X4'
                f['source_provenance'] = 'chain_align'
                # the KB match is the aligned chain itself, not a category-picked template
                f['template_id'] = fact['template']
                f['pattern_name'] = fact['pattern'] or f"{fact['category']}_chain"
                f['chain_template'] = fact['template']
                f['chain_generic'] = bool(fact.get('generic'))
                f['aligned_ratio'] = fact['aligned_ratio']
                f['peers_present'] = fact.get('peers_present', 0)
                findings.append(f)
        if not sources:
            continue
        if 'R1' in rules and func_key in size_flows_by_func:
            for src, snk, cat in r1_candidates(sources, checks, size_flows_by_func[func_key]):
                f = _make_finding(func_key, src, snk, cat, purpose, candidate_templates, templates)
                f['rule_id'] = 'R1'
                findings.append(f)
        if not sinks:
            if not source_only:
                continue
            first = min(sources, key=lambda s: s['line'])
            for cat in source_only_categories(sources, checks):
                synthetic = {'line': first['line'], 'type': 'no_sink',
                             'desc': '该函数内无危险操作；风险在于输入未经校验即被采信'}
                findings.append(_make_finding(func_key, first, synthetic, cat,
                                              purpose, candidate_templates,
                                              templates))
            continue
        candidates = []
        for src in sources:
            for snk in sinks:
                if snk['line'] == src['line']:
                    continue
                # a "sink" 1-2 lines BEFORE its source is line-counting drift
                # on the same statement, not a flow
                if snk['line'] < src['line'] and src['line'] - snk['line'] <= 2:
                    continue
                lo, hi = sorted((src['line'], snk['line']))
                if f3 and snk['type'] in F3_GENERIC_SINKS:
                    continue
                cats = categories_for_pair(src['type'], snk['type'])
                if x2 and snk['type'] in V5_SINK_CATEGORY:
                    cats = V5_SINK_CATEGORY[snk['type']]   # shape-named sinks pair by shape, not by hint table
                for cat in unprotected_categories(lo, hi, cats, checks):
                    if f3 and _is_source_only(cat) and snk['type'] not in V5_SINK_CATEGORY:
                        continue
                    candidates.append((src, snk, cat))
        for src, snk, cat in (candidates if retain_protection else _collapse(candidates)):
            findings.append(_make_finding(func_key, src, snk, cat,
                                          purpose, candidate_templates, templates))
    if retain_protection:
        for f in findings:
            f.setdefault('rule_id', 'v2_span')
            f['protection_hypotheses'] = protections.get(f['function'], [])
    if v3 and not retain_protection:
        for f in findings:
            f.setdefault('rule_id', 'v2_span')
        # R2 only adds flows the span rule missed
        v2_keys = {(f['function'], f['missing_step_category'], f['span']['sink']['line'])
                   for f in findings if f['rule_id'] == 'v2_span'}
        findings = [f for f in findings if f['rule_id'] not in ('R2', 'R4') or
                    (f['function'], f['missing_step_category'], f['span']['sink']['line']) not in v2_keys]
        # X4 only adds (function, category) pairs no data-flow / structural rule reported
        other = {(f['function'], f['missing_step_category']) for f in findings if f['rule_id'] != 'X4'}
        findings = [f for f in findings if f['rule_id'] != 'X4' or
                    (f['function'], f['missing_step_category']) not in other]
    findings.sort(key=lambda f: (f['function'], f['span']['source']['line'],
                                 f['span']['sink']['line'], f['missing_step_category']))
    return findings


def _make_finding(func_key, src, snk, category, purpose, candidate_templates, templates):
    tpl_id, tpl = _pick_template(category, candidate_templates, templates)
    if tpl and tpl.get('pattern_names'):
        pattern_name = tpl['pattern_names'][0]
    else:
        pattern_name = f"{category}_via_{snk['type']}"
    src_desc = src.get('desc') or src['type']
    snk_desc = snk.get('desc') or snk['type']
    reasoning = (f"数据从 L{src['line']}（{src_desc}）流向 L{snk['line']}（{snk_desc}），"
                 f"跨度内未观察到 {category} 类别的安全检查。")
    if purpose:
        reasoning = f"函数用途：{purpose}。" + reasoning
    if tpl and tpl.get('summary'):
        reasoning += f" 漏洞库同类模式：{tpl['summary']}"
    return {
        'function': func_key,
        'template_id': tpl_id,
        'pattern_name': pattern_name,
        'missing_step_category': category,
        'reasoning': reasoning,
        'evidence': f"L{src['line']} {src['type']} → L{snk['line']} {snk['type']}，"
                    f"跨度内无 {category} 检查",
        'span': {
            'source': {'line': src['line'], 'type': src['type'], 'desc': src.get('desc', '')},
            'sink': {'line': snk['line'], 'type': snk['type'], 'desc': snk.get('desc', '')},
        },
    }


# ── Selftest ──────────────────────────────────────────────────────────

def _selftest():
    failures = []

    # merge_facts: mapping, dedup, line requirement
    ext = {'purpose': '保存上传文件',
           'semantic_inputs': [{'origin': 'network', 'desc': 'filename 参数', 'line': 42}],
           'semantic_sinks': [{'kind': 'file_write', 'desc': 'os.Create', 'line': 88}],
           'observed_checks': [{'category': 'path_validation', 'desc': '无', 'line': 50}],
           'data_paths': []}
    df = {'sources': [{'line': 42, 'type': 'http_request', 'pattern': 'http.Request'}],
          'sinks': [{'line': 88, 'type': 'file_write', 'pattern': 'os.Create('}]}
    facts = merge_facts(ext, df)
    if len(facts['sources']) != 1 or facts['sources'][0]['type'] != 'http_request':
        failures.append(f'merge dedup source failed: {facts["sources"]}')
    if len(facts['sinks']) != 1 or facts['sinks'][0]['desc'] != 'os.Create':
        failures.append(f'merge sink desc failed: {facts["sinks"]}')
    # fact without line dropped
    facts2 = merge_facts({'semantic_sinks': [{'kind': 'sql', 'line': 0}]}, {})
    if facts2['sinks']:
        failures.append('lineless fact not dropped')
    # unknown origin ignored
    facts3 = merge_facts({'semantic_inputs': [{'origin': 'internal', 'line': 5}]}, {})
    if facts3['sources']:
        failures.append('internal origin should not create a source')

    # snap: semantic fact within +-2 lines of an AST fact of the same mapped
    # type merges onto the AST line; beyond that it stays a separate fact
    df_snap = {'sources': [{'line': 42, 'type': 'http_request'}],
               'sinks': [{'line': 88, 'type': 'file_write'}]}
    ext_snap = {'semantic_inputs': [{'origin': 'network', 'line': 41},
                                    {'origin': 'network', 'line': 20}],
                'semantic_sinks': [{'kind': 'file_write', 'line': 90}]}
    fs_ = merge_facts(ext_snap, df_snap)
    src_lines = [x['line'] for x in fs_['sources']]
    if src_lines != [20, 42]:
        failures.append(f'snap should fold L41 into AST L42: {src_lines}')
    snk_lines = [x['line'] for x in fs_['sinks']]
    if snk_lines != [88]:
        failures.append(f'snap should fold semantic sink L90 into AST L88: {snk_lines}')
    # check snap
    fs_ = merge_facts({'observed_checks': [{'category': 'path_validation', 'line': 52}]},
                      {'sanitizers': [{'line': 50, 'category': 'path_validation'}]})
    if [c['line'] for c in fs_['checks']] != [50]:
        failures.append(f'check snap failed: {fs_["checks"]}')

    # categories_for_pair
    cats = categories_for_pair('http_request', 'string_format')
    if 'output_encoding' not in cats or 'input_sanitization' not in cats:
        failures.append(f'pair categories wrong: {cats}')
    cats = categories_for_pair('http_request', 'file_write')
    if 'path_validation' not in cats:
        failures.append(f'path pair missing path_validation: {cats}')
    if 'bounds_check' in cats:
        failures.append('http_request should not hit bounds_check')

    # unprotected_categories / protection
    checks = [{'category': 'path_validation', 'line': 50}]
    out = unprotected_categories(42, 88, ['path_validation', 'output_encoding'], checks)
    if 'path_validation' in out or 'output_encoding' not in out:
        failures.append(f'protection filter wrong: {out}')
    out = unprotected_categories(42, 88, ['path_validation'],
                                 [{'category': 'path_validation', 'line': 90}])
    if 'path_validation' not in out:
        failures.append('check outside span should not protect')

    # build_findings end to end (unprotected)
    db = {'templates': {'tpl_p': {'missing_step_category': 'path_validation',
                                  'pattern_names': ['path_traversal'], 'summary': 's'}}}
    cands = [('tpl_x', 0.9, 3), ('tpl_p', 0.8, 1)]
    fs = build_findings({'ctx.go:save': ext}, {'ctx.go:save': df}, cands, db)
    # span 42-88 contains path_validation check at 50 -> protected; the
    # source-hint categories (empty sink hints) on http_request survive
    cats = [f['missing_step_category'] for f in fs]
    if cats != ['access_control', 'identity_verification', 'origin_validation']:
        failures.append(f'build_findings protected span: {cats}')
    if fs and fs[0]['template_id'] != '':
        failures.append(f'access_control should have no template: {fs[0]["template_id"]}')
    if fs and fs[0]['pattern_name'] != 'access_control_via_file_write':
        failures.append(f'fallback pattern naming wrong: {fs[0]["pattern_name"]}')
    if fs and fs[0]['span']['source']['line'] != 42 or fs[0]['span']['sink']['line'] != 88:
        failures.append(f'span fields wrong: {fs[0]["span"]}')

    # protection removed -> path_validation emitted with template binding
    ext2 = {**ext, 'observed_checks': []}
    fs = build_findings({'ctx.go:save': ext2}, {'ctx.go:save': df}, cands, db)
    cats = [f['missing_step_category'] for f in fs]
    if 'path_validation' not in cats:
        failures.append(f'path_validation missing without check: {cats}')
    pv = next(f for f in fs if f['missing_step_category'] == 'path_validation')
    if pv['template_id'] != 'tpl_p' or pv['pattern_name'] != 'path_traversal':
        failures.append(f'template binding wrong: {pv["template_id"]}/{pv["pattern_name"]}')
    if 'L42' not in pv['evidence'] or 'L88' not in pv['evidence']:
        failures.append(f'evidence missing line refs: {pv["evidence"]}')

    # deterministic ordering + dedup on same tuple
    fs1 = build_findings({'a:f': ext2}, {'a:f': df}, cands, db)
    fs2 = build_findings({'a:f': ext2}, {'a:f': df}, cands, db)
    if fs1 != fs2:
        failures.append('build_findings not deterministic')
    if len(fs) != len({(f['span']['source']['line'], f['span']['sink']['line'],
                        f['missing_step_category']) for f in fs}):
        failures.append('dedup key violated')

    # missing extraction -> no findings even with data flow
    fs = build_findings({'a:f': None}, {'a:f': df}, cands, db)
    if fs:
        failures.append('None extraction must yield no findings')

    # semantic-only facts (no AST data flow)
    fs = build_findings({'a:f': ext2}, {'a:f': {}}, cands, db)
    if not fs:
        failures.append('semantic-only facts should still produce spans')

    # collapse: 2 sources x 2 sinks must not multiply near-identical findings
    df_multi = {'sources': [{'line': 10, 'type': 'http_request'},
                            {'line': 42, 'type': 'http_request'}],
                'sinks': [{'line': 88, 'type': 'file_write'},
                          {'line': 120, 'type': 'file_write'}]}
    ext_multi = {**ext2, 'semantic_inputs': [], 'semantic_sinks': []}
    fs = build_findings({'a:f': ext_multi}, {'a:f': df_multi}, cands, db)
    cats = [f['missing_step_category'] for f in fs]
    # source-only cats: once per function; path_validation: once per sink
    # final sort is (src_line, sink_line, category): sink 88 first, then 120 group
    if cats != ['path_validation', 'access_control', 'identity_verification',
                'origin_validation', 'path_validation']:
        failures.append(f'collapse wrong categories: {cats}')
    if fs:
        so = next(f for f in fs if f['missing_step_category'] == 'access_control')
        if (so['span']['source']['line'], so['span']['sink']['line']) != (10, 120):
            failures.append(f'source-only should use widest span: {so["span"]}')
        pv = [f for f in fs if f['missing_step_category'] == 'path_validation']
        if {(f['span']['source']['line'], f['span']['sink']['line']) for f in pv} != {(10, 88), (10, 120)}:
            failures.append(f'sink-hint should use min source line: '
                            f'{[f["span"] for f in pv]}')

    # adjacent backward pair (sink 1-2 lines before source) is drift, not flow
    df_bwd = {'sources': [{'line': 943, 'type': 'http_request'}],
              'sinks': [{'line': 942, 'type': 'file_write'}]}
    fs = build_findings({'a:f': {'purpose': 'x', 'semantic_inputs': [],
                                 'semantic_sinks': [], 'observed_checks': []}},
                        {'a:f': df_bwd}, [], {})
    if fs:
        failures.append(f'adjacent backward span must not be a finding: {fs[0]["span"]}')
    df_bwd2 = {'sources': [{'line': 947, 'type': 'http_request'}],
               'sinks': [{'line': 941, 'type': 'file_write'}]}
    fs = build_findings({'a:f': {'purpose': 'x', 'semantic_inputs': [],
                                 'semantic_sinks': [], 'observed_checks': []}},
                        {'a:f': df_bwd2}, [], {})
    if not fs:
        failures.append('non-adjacent backward span should still be judged')

    # ── v3 R1 ────────────────────────────────────────────────────────
    ext_r1 = {'purpose': 'x', 'semantic_inputs': [{'origin': 'network', 'line': 109}],
              'semantic_sinks': [], 'observed_checks': []}
    sf = {'size_sinks': [{'line': 130, 'type': 'alloc_size', 'var': 'n', 'pattern': 'make([]string, n)'},
                         {'line': 136, 'type': 'index_access', 'var': 'i', 'pattern': 'p[i-1]'}],
          'range_checks': []}
    fs = build_findings({'c.go:Cookie': ext_r1}, {'c.go:Cookie': {}}, [], {},
                        size_flows_by_func={'c.go:Cookie': sf}, rules=('v2', 'R1'))
    got = sorted((f['missing_step_category'], f['span']['sink']['line'], f.get('rule_id')) for f in fs)
    if got != [('bounds_check', 136, 'R1'), ('resource_limit', 130, 'R1')]:
        failures.append(f'R1 unguarded size sinks: {got}')
    sf_g = {**sf, 'range_checks': [{'line': 128, 'var': 'n'}, {'line': 134, 'var': 'i'}]}
    fs = build_findings({'c.go:Cookie': ext_r1}, {'c.go:Cookie': {}}, [], {},
                        size_flows_by_func={'c.go:Cookie': sf_g}, rules=('v2', 'R1'))
    if fs:
        failures.append(f'R1 range-checked sinks must be protected: {[f["missing_step_category"] for f in fs]}')
    ext_chk = {**ext_r1, 'observed_checks': [{'category': 'resource_limit', 'line': 120}]}
    fs = build_findings({'c.go:Cookie': ext_chk}, {'c.go:Cookie': {}}, [], {},
                        size_flows_by_func={'c.go:Cookie': sf}, rules=('v2', 'R1'))
    if [f['span']['sink']['line'] for f in fs] != []:
        failures.append('R1: an LLM-observed resource_limit check inside the span must protect both sinks')
    fs = build_findings({'c.go:Cookie': ext_r1}, {'c.go:Cookie': {}}, [], {},
                        size_flows_by_func={'c.go:Cookie': sf}, rules=('v2',))
    if fs:
        failures.append('rules=v2 must ignore size flows')
    fs2 = build_findings({'a:f': ext2}, {'a:f': df}, cands, db)
    if any('rule_id' in f for f in fs2):
        failures.append('rules=v2 must not add rule_id')
    fs3 = build_findings({'a:f': ext2}, {'a:f': df}, cands, db, rules=('v2', 'R1'))
    if [ {k: v for k, v in f.items() if k != 'rule_id'} for f in fs3] != fs2 or any(f['rule_id'] != 'v2_span' for f in fs3):
        failures.append('v2 findings must be unchanged under R1 apart from rule_id')

    # ── v3 R2 ────────────────────────────────────────────────────────
    ext_r2 = {'purpose': 'x', 'semantic_inputs': [], 'semantic_sinks': [], 'observed_checks': []}
    fact = {'sink': {'line': 172, 'type': 'query_exec', 'desc': 'ldap.NewSearchRequest(...)'},
            'source': {'line': 169, 'type': 'param_external', 'desc': 'p', 'provenance': 'name_dispatch',
                       'path': ['a.go:Auth@L107']}}
    kw = dict(rules=('v2', 'R2'), r2_facts_by_func={'c.go:Client.GetUser': [fact]})
    fs = build_findings({'c.go:Client.GetUser': ext_r2}, {'c.go:Client.GetUser': {}}, [], {}, **kw)
    got = [(f['missing_step_category'], f['rule_id'], f['source_provenance'], f['taint_path']) for f in fs]
    if got != [('output_encoding', 'R2', 'name_dispatch', ['a.go:Auth@L107'])]:
        failures.append(f'R2 tainted query sink: {got}')
    fact2 = {**fact, 'sink': {**fact['sink'], 'line': 184}}
    fs = build_findings({'c.go:Client.GetUser': ext_r2}, {'c.go:Client.GetUser': {}}, [], {},
                        rules=('v2', 'R2'), r2_facts_by_func={'c.go:Client.GetUser': [fact2, fact]})
    if [f['span']['sink']['line'] for f in fs] != [172]:
        failures.append(f'R2 collapses to the earliest sink per category: {[f["span"]["sink"]["line"] for f in fs]}')
    fs = build_findings({'c.go:Client.GetUser': ext_r2}, {'c.go:Client.GetUser': {}}, [], {},
                        r2_sanitizers_by_func={'c.go:Client.GetUser': [{'line': 170, 'category': 'output_encoding'}]},
                        **kw)
    if fs:
        failures.append('R2: escape sanitizer inside the span must protect')
    ext_chk2 = {**ext_r2, 'observed_checks': [{'category': 'output_encoding', 'line': 169}]}
    fs = build_findings({'c.go:Client.GetUser': ext_chk2}, {'c.go:Client.GetUser': {}}, [], {}, **kw)
    if fs:
        failures.append('R2: LLM-observed check at the source line must protect')
    fs = build_findings({'c.go:Client.GetUser': None}, {'c.go:Client.GetUser': {}}, [], {}, **kw)
    if fs:
        failures.append('R2 requires a semantic extraction')
    fs = build_findings({'c.go:Client.GetUser': ext_r2}, {'c.go:Client.GetUser': {}}, [], {},
                        r2_facts_by_func={'c.go:Client.GetUser': [fact]})
    if fs:
        failures.append('rules=v2 must ignore R2 facts')
    # R4: an LLM-observed size check does not protect an unbounded read
    fact4 = {'sink': {'line': 202, 'type': 'unbounded_read', 'desc': 'io.ReadAll(bodyReader)'},
             'source': {'line': 162, 'type': 'param_external', 'desc': 'p', 'provenance': 'direct', 'path': []}}
    ext4 = {**ext_r2, 'observed_checks': [{'category': 'resource_limit', 'line': 168}]}
    fs = build_findings({'s.go:Execute': ext4}, {'s.go:Execute': {}}, [], {},
                        rules=('v2', 'R4'), r2_facts_by_func={'s.go:Execute': [fact4]})
    if [(f['rule_id'], f['missing_step_category']) for f in fs] != [('R4', 'resource_limit')]:
        failures.append(f'R4 must ignore LLM size checks: {[(f["rule_id"], f["missing_step_category"]) for f in fs]}')
    fs = build_findings({'s.go:Execute': ext4}, {'s.go:Execute': {}}, [], {},
                        rules=('v2', 'R2'), r2_facts_by_func={'s.go:Execute': [fact4]})
    if fs:
        failures.append('unbounded_read facts need R4 enabled')
    # F4: an LLM-reported check off any call/comparison line does not protect
    df_f4 = {'sources': [{'line': 42, 'type': 'http_request'}], 'sinks': [{'line': 88, 'type': 'file_write'}]}
    ext_f4 = {'purpose': 'x', 'semantic_inputs': [], 'semantic_sinks': [],
              'observed_checks': [{'category': 'path_validation', 'desc': '校验', 'line': 60}]}
    fs = build_findings({'a:f': ext_f4}, {'a:f': df_f4}, [], {}, rules=('v2', 'F4'),
                        check_lines_by_func={'a:f': [45, 70, 88]})
    if 'path_validation' not in [f['missing_step_category'] for f in fs]:
        failures.append('F4: a check on no call/comparison line must not protect')
    fs = build_findings({'a:f': ext_f4}, {'a:f': df_f4}, [], {}, rules=('v2', 'F4'),
                        check_lines_by_func={'a:f': [45, 61, 88]})
    if 'path_validation' in [f['missing_step_category'] for f in fs]:
        failures.append('F4: a check within one line of a call must protect')
    fs = build_findings({'a:f': ext_f4}, {'a:f': df_f4}, [], {}, rules=('v2', 'F4'))
    if 'path_validation' in [f['missing_step_category'] for f in fs]:
        failures.append('F4: without line facts the LLM check is kept')

    # F3: generic-sink pairs and source-only categories are dropped from the span rule,
    # and a structural R2 finding on the same key then survives the dedup
    df_f3 = {'sources': [{'line': 30, 'type': 'read_all'}],
             'sinks': [{'line': 107, 'type': 'write'}, {'line': 60, 'type': 'file_write'}]}
    fact_xss = {'sink': {'line': 107, 'type': 'response_write', 'desc': 'w.Write(body)'},
                'source': {'line': 30, 'type': 'param_external', 'desc': 'p', 'provenance': 'net_direct', 'path': []}}
    fs = build_findings({'e.go:echo': ext_r2}, {'e.go:echo': df_f3}, [], {}, rules=('v2', 'R2', 'F3'),
                        r2_facts_by_func={'e.go:echo': [fact_xss]})
    got = sorted((f['rule_id'], f['missing_step_category'], f['span']['sink']['line']) for f in fs)
    if got != [('R2', 'output_encoding', 107), ('v2_span', 'path_validation', 60)]:
        failures.append(f'F3: {got}')
    fs = build_findings({'e.go:echo': ext_r2}, {'e.go:echo': df_f3}, [], {}, rules=('v2', 'R2'),
                        r2_facts_by_func={'e.go:echo': [fact_xss]})
    if not any(f['rule_id'] == 'v2_span' and f['span']['sink']['line'] == 107 for f in fs):
        failures.append('without F3 the generic write pair must remain')

    # v4.3: R2 alloc_size honours R1 range checks
    fact_alloc = {'sink': {'line': 130, 'type': 'alloc_size', 'desc': 'make([]string, numParts)'},
                  'source': {'line': 103, 'type': 'param_external', 'desc': 'p', 'provenance': 'net_entry', 'path': []}}
    fs = build_findings({'c.go:Cookie': ext_r2}, {'c.go:Cookie': {}}, [], {}, rules=('v2', 'R2'),
                        r2_facts_by_func={'c.go:Cookie': [fact_alloc]},
                        size_flows_by_func={'c.go:Cookie': {'size_sinks': [], 'range_checks': [{'line': 110, 'var': 'numParts'}]}})
    if fs:
        failures.append('R2 alloc_size must be protected by an R1 range check in the span')

    # X2: shape-named LLM sinks pair by shape; X3: a validator callee's strong check protects
    ext_x2 = {'purpose': 'x', 'semantic_inputs': [{'origin': 'network', 'line': 20}],
              'semantic_sinks': [{'kind': 'alloc', 'line': 40}, {'kind': 'forward', 'line': 50}], 'observed_checks': []}
    fs = build_findings({'a:f': ext_x2}, {'a:f': {}}, [], {}, rules=('v2', 'F3', 'X2'))
    got = sorted((f['missing_step_category'], f['span']['sink']['type']) for f in fs)
    if got != [('identity_verification', 'forward'), ('input_sanitization', 'forward'), ('resource_limit', 'alloc_size')]:
        failures.append(f'X2 shaped sinks: {got}')
    fs = build_findings({'a:f': ext_x2}, {'a:f': {}}, [], {}, rules=('v2', 'F3'))
    if fs:
        failures.append('without X2 the v5 sink kinds are unknown and yield nothing')
    fs = build_findings({'a:f': ext_x2}, {'a:f': {}}, [], {}, rules=('v2', 'F3', 'X2', 'X3'),
                        ext_checks_by_func={'a:f': [{'line': 30, 'category': 'resource_limit', 'desc': 'validateSize'}]})
    if any(f['missing_step_category'] == 'resource_limit' for f in fs):
        failures.append('X3: a validator callee with a strong resource_limit check must protect')

    # R5: facts become access_control findings only with R5 enabled
    r5 = {'category': 'access_control', 'peers': '5/6', 'checked_peers': ['H.Get'],
          'source': {'line': 236, 'type': 'param_external', 'desc': 'p', 'provenance': 'peer_inconsistency', 'path': []},
          'sink': {'line': 237, 'type': 'resource_access', 'desc': 'x'}}
    fs = build_findings({'s.go:H.URL': ext_r2}, {'s.go:H.URL': {}}, [], {}, rules=('v2', 'R5'),
                        r5_facts_by_func={'s.go:H.URL': [r5]})
    if [(f['rule_id'], f['missing_step_category']) for f in fs] != [('R5', 'access_control')]:
        failures.append(f'R5 finding: {[(f["rule_id"], f["missing_step_category"]) for f in fs]}')
    if build_findings({'s.go:H.URL': ext_r2}, {'s.go:H.URL': {}}, [], {}, r5_facts_by_func={'s.go:H.URL': [r5]}):
        failures.append('rules=v2 must ignore R5 facts')
    # already reported by the v2 span rule for the same (category, sink) -> dropped
    df_dup = {'sources': [{'line': 150, 'type': 'http_request'}],
              'sinks': [{'line': 172, 'type': 'string_format'}]}
    fs = build_findings({'c.go:Client.GetUser': ext_r2}, {'c.go:Client.GetUser': df_dup}, [], {}, **kw)
    if [f['rule_id'] for f in fs if f['missing_step_category'] == 'output_encoding'] != ['v2_span']:
        failures.append(f'R2 must defer to v2_span on the same key: {[(f["rule_id"], f["missing_step_category"]) for f in fs]}')

    # ── v3 R3 ────────────────────────────────────────────────────────
    r3 = {'category': 'origin_validation', 'purpose': 'redirect', 'inferred': False,
          'weak_check': 'strings.HasPrefix(next, "/")', 'callers': ['h.go:Login@L34 → redirect'],
          'source': {'line': 10, 'type': 'param_external', 'desc': 'p', 'provenance': 'param_1hop', 'path': ['h.go:Login@L34']},
          'sink': {'line': 10, 'type': 'validator_contract', 'desc': 'weak'}}
    r3b = {**r3, 'sink': {**r3['sink'], 'line': 13}}
    fs = build_findings({'v.go:validateTarget': ext_r2}, {'v.go:validateTarget': {}}, [], {},
                        rules=('v2', 'R3'), r3_facts_by_func={'v.go:validateTarget': [r3b]})
    got = [(f['rule_id'], f['missing_step_category'], f['validator_purpose'], f['purpose_inferred']) for f in fs]
    if got != [('R3', 'origin_validation', 'redirect', False)] or 'HasPrefix' not in fs[0]['reasoning']:
        failures.append(f'R3 finding: {got}')
    fs = build_findings({'v.go:validateTarget': ext_r2}, {'v.go:validateTarget': {}}, [], {},
                        r3_facts_by_func={'v.go:validateTarget': [r3b]})
    if fs:
        failures.append('rules=v2 must ignore R3 facts')

    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for msg in failures:
            print(f"  - {msg}")
        return 1
    print("SELFTEST PASSED: 7 merge_facts (incl. 3 snap), 3 categories_for_pair, "
          "2 protection, 11 build_findings (merge/protect/template/order/dedup/"
          "semantic-only/collapse/backward-drift), 6 v3-R1, 7 v3-R2, 2 v3-R3, 2 v3.1-R4, 2 v3.2-R5, 2 v4-F3, 3 v4.2-F4, 1 v4.3-R2/R1, 3 v5-X2/X3")
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if args[0] == '--selftest':
        return _selftest()
    print(__doc__)
    return 1


if __name__ == '__main__':
    sys.exit(main())
