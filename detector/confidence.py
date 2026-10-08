"""
Evidence-weighted confidence scoring for detection findings.

Scoring model (deterministic; the LLM performs semantic extraction only
and never self-assesses):
  - This module computes the final confidence as a weighted sum over 3
    independently verifiable evidence dimensions:
      code_evidence     (0.45)  L<line> references in the finding's evidence
                                are checked against the function source
                                bounds; legacy free-text citations fall back
                                to whitespace-normalized substring matching
      ast_corroboration (0.35)  category-specific source/sink types present
                                in the function's AST data flow; a
                                category-matching sanitizer inside the flow
                                span marks the chain protected (0.1)
      template_support  (0.20)  template_id resolves and/or pattern_name is
                                a known pattern of that template
  - Each dimension reports score + provenance in `confidence_breakdown`.

Levels: confirmed (>=0.75) / likely (>=0.5) / tentative (<0.5).

CLI:
    python confidence.py --selftest
    python confidence.py --recalc projects/<id>/report.json [--write]
"""

import json
import os
import re
import sys

# ── Weights (must sum to 1.0) ─────────────────────────────────────────

WEIGHTS = {
    'code_evidence': 0.45,
    'ast_corroboration': 0.35,
    'template_support': 0.20,
}

CONFIDENCE_LEVELS = [(0.75, 'confirmed'), (0.5, 'likely'), (0.0, 'tentative')]

# ── Category -> relevant AST source/sink types (ast_analyzer/main.go) ─

ALL_SOURCE_TYPES = {'read', 'read_all', 'channel_recv', 'network_accept',
                    'read_message', 'network_read', 'http_request', 'http_body',
                    'buffered_read', 'json_decode', 'xml_decode', 'binary_read',
                    'scan', 'io_copy'}

CATEGORY_FLOW_HINTS = {
    'input_sanitization': (ALL_SOURCE_TYPES,
                           {'command_execution', 'sql_query', 'sql_exec',
                            'string_format', 'write', 'html_injection', 'js_injection'}),
    'output_encoding': (ALL_SOURCE_TYPES,
                        {'string_format', 'write', 'html_injection', 'js_injection'}),
    'path_validation': (ALL_SOURCE_TYPES, {'file_read', 'file_write'}),
    'bounds_check': ({'json_decode', 'xml_decode', 'binary_read', 'scan', 'read',
                      'read_all', 'buffered_read', 'io_copy', 'http_body'}, set()),
    'resource_limit': ({'json_decode', 'xml_decode', 'binary_read', 'scan', 'read_all',
                        'io_copy', 'http_body', 'network_accept', 'read_message'}, set()),
    'origin_validation': ({'http_request', 'http_body'}, set()),
    'access_control': ({'http_request', 'http_body', 'network_accept', 'read_message'}, set()),
    'identity_verification': ({'http_request', 'http_body', 'network_accept', 'read_message'}, set()),
    'cryptographic_verification': (set(), set()),
    'state_synchronization': ({'channel_recv'}, set()),
    'error_handling': (set(), set()),
    'protocol_validation': ({'network_read', 'network_accept', 'read_message',
                             'scan', 'binary_read'}, set()),
}


# ── Dimension 1: code evidence citation ───────────────────────────────

def _normalize_ws(s):
    return ' '.join(str(s).split())


def _extract_code_spans(evidence):
    """Pull candidate code fragments out of the evidence string.

    Backtick spans first (markdown convention), then double-quoted spans,
    then the whole string as a fallback when it looks like code.
    """
    text = str(evidence or '')
    spans = []
    i = 0
    while i < len(text):
        if text[i] == '`':
            j = text.find('`', i + 1)
            if j == -1:
                break
            spans.append(text[i + 1:j])
            i = j + 1
        else:
            i += 1
    j = 0
    while j < len(text):
        if text[j] == '"':
            k = text.find('"', j + 1)
            if k == -1:
                break
            span = text[j + 1:k]
            if len(span) >= 6:
                spans.append(span)
            j = k + 1
        else:
            j += 1
    spans = [s.strip() for s in spans if len(s.strip()) >= 6]
    if not spans:
        whole = text.strip()
        if len(whole) >= 6 and any(c in whole for c in '().={}<>'):
            spans.append(whole)
    return spans


def score_code_evidence(evidence, source, start_line=1):
    """Returns (score, provenance, detail).

    Constructed evidence (decide.py) carries `L<line>` references — verify
    them against the source bounds. Legacy free-text evidence falls back to
    code-span substring matching.

    `L<line>` refs are absolute file line numbers (extraction prompts number
    lines from the function's start line), so bounds are checked in that same
    absolute space. `start_line` is the function's first line in its file;
    it defaults to 1 for callers holding only a standalone snippet.
    """
    if source is None:
        return 0.5, 'source_unavailable', 'function source not provided'
    text = str(evidence or '').strip()
    if not text:
        return 0.0, 'no_evidence', 'empty evidence field'
    refs = [int(n) for n in re.findall(r'\bL(\d{1,5})\b', text)]
    if refs:
        lo = max(1, int(start_line or 1))
        hi = lo + str(source).count('\n')
        in_bounds = [n for n in refs if lo <= n <= hi]
        if len(in_bounds) == len(refs) and len(refs) >= 2:
            return 1.0, 'verified_citation', f'{len(refs)} line refs within source bounds ({lo}-{hi})'
        if in_bounds:
            return 0.4, 'unverified_citation', f'{len(in_bounds)}/{len(refs)} line refs in bounds ({lo}-{hi})'
        return 0.4, 'unverified_citation', f'all {len(refs)} line refs out of bounds ({lo}-{hi})'
    spans = _extract_code_spans(text)
    if not spans:
        return 0.4, 'unverified_citation', 'no code-like citation found'
    norm_source = _normalize_ws(source)
    matched = sum(1 for s in spans if _normalize_ws(s) and _normalize_ws(s) in norm_source)
    if matched:
        return 1.0, 'verified_citation', f'{matched}/{len(spans)} cited spans found in source'
    return 0.4, 'unverified_citation', f'{len(spans)} span(s) cited, none match source'


# ── Dimension 2: AST data-flow corroboration ──────────────────────────

def score_ast_corroboration(category, data_flow):
    """Returns (score, provenance, detail).

    Sanitizer protection (span approximation): a category-matching security
    check emitted by ast_analyzer that sits inside the function's flow span
    (between the outermost source and sink lines) marks the chain protected
    -> 0.1; present but outside the span -> capped at 0.5.
    """
    if not data_flow:
        return 0.5, 'no_data_flow', 'no AST data flow record for function'
    hints = CATEGORY_FLOW_HINTS.get(category)
    if hints is None or (not hints[0] and not hints[1]):
        return 0.5, 'no_ast_signal', f'category {category!r} has no AST signal definition'
    src_hints, sink_hints = hints
    sources = data_flow.get('sources') or []
    sinks = data_flow.get('sinks') or []
    src_types = {s.get('type') for s in sources if s.get('type')}
    sink_types = {s.get('type') for s in sinks if s.get('type')}
    src_hit = sorted(src_types & src_hints)
    sink_hit = sorted(sink_types & sink_hints)
    if src_hit and sink_hit:
        score, prov = 1.0, 'source_and_sink'
        detail = f'sources: {",".join(src_hit)}; sinks: {",".join(sink_hit)}'
    elif src_hit:
        score, prov = 0.7, 'source_only'
        detail = f'sources: {",".join(src_hit)}; no relevant sink'
    elif sink_hit:
        score, prov = 0.6, 'sink_only'
        detail = f'sinks: {",".join(sink_hit)}; no relevant source'
    else:
        score, prov = 0.2, 'no_match'
        detail = f'flow types (src={sorted(src_types)}, sink={sorted(sink_types)}) do not match category hints'

    relevant = [s for s in (data_flow.get('sanitizers') or [])
                if s.get('category') == category]
    if relevant:
        span_lines = [p.get('line') for p in sources + sinks if p.get('line')]
        on_path = [s for s in relevant
                   if s.get('line') and span_lines
                   and min(span_lines) < s['line'] < max(span_lines)]
        if on_path:
            first = on_path[0]
            return 0.1, 'sanitizer_on_path', (
                f"category check at line {first['line']} inside flow span "
                f"[{min(span_lines)}-{max(span_lines)}]: {str(first.get('pattern', ''))[:40]}")
        return min(score, 0.5), 'sanitizer_off_path', (
            f"category check present (line {relevant[0].get('line')}) but outside flow span; " + detail)
    return score, prov, detail + '; no category sanitizer in function'


# ── Dimension 3: vulnerability database template support ──────────────

def score_template_support(finding, vuln_db):
    """Returns (score, provenance, detail)."""
    templates = (vuln_db or {}).get('templates') or {}
    if finding.get('rule_id') == 'X4':
        # X4: the finding IS a step-level alignment to one chain; a generic (CWE-derived)
        # chain carries less project-specific evidence than a chain from a real advisory
        return (0.6 if finding.get('chain_generic') else 0.8), 'chain_template', \
            f"aligned to chain {finding.get('template_id')}" + (' (generic)' if finding.get('chain_generic') else '')
    if not templates:
        return 0.5, 'db_unavailable', 'vuln_db not provided or empty'
    tpl = templates.get(finding.get('template_id'))
    if not tpl:
        return 0.3, 'unresolved_template', f'template_id {finding.get("template_id")!r} not in db'
    pattern = finding.get('pattern_name') or ''
    known = pattern in (tpl.get('pattern_names') or [])
    score = 1.0 if known else 0.7
    prov = 'known_pattern' if known else 'novel_pattern'
    detail = (f'pattern {pattern!r} ' + ('in template pattern_names' if known else 'self-named')) + \
             f', {len(tpl.get("pattern_names") or [])} known, {tpl.get("example_count", 0)} examples'
    if tpl.get('missing_step_category') and tpl['missing_step_category'] != finding.get('missing_step_category'):
        if score > 0.5:
            score = 0.5
            prov = 'category_mismatch'
            detail += f'; template category {tpl["missing_step_category"]!r} != finding category'
    return score, prov, detail


# ── Aggregation ───────────────────────────────────────────────────────

def confidence_level(confidence):
    for threshold, name in CONFIDENCE_LEVELS:
        if confidence >= threshold:
            return name
    return 'tentative'


def score_ast_corroboration_r1(finding, data_flow):
    """v3 R1: the sink is an AST size sink by construction; corroboration depends on
    whether the source line is also an AST source (1.0) or semantic-only (0.7)."""
    src_line = ((finding.get('span') or {}).get('source') or {}).get('line')
    ast_src = {s.get('line') for s in ((data_flow or {}).get('sources') or [])}
    if src_line in ast_src:
        return 1.0, 'r1_ast_source_and_size_sink', f'AST source at L{src_line}; AST size sink'
    return 0.7, 'r1_semantic_source_and_size_sink', f'semantic source at L{src_line}; AST size sink'


# v4: score by origin class, then by how the taint travelled. Legacy v3 strings keep
# their old values.
R2_ORIGIN_SCORE = {'net': 0.7, 'wire': 0.6, 'io': 0.5, 'cb': 0.5, 'llm': 0.5}
R2_PROVENANCE_SCORE = {'direct': 0.7, 'param_entry': 0.7, 'param_1hop': 0.7, 'param_nhop': 0.6, 'name_dispatch': 0.5}


def score_ast_corroboration_r2(finding):
    """R2/R4: source and sink are both AST facts by construction (a sink whose arguments
    carry taint); corroboration reflects where the data came from and how it arrived."""
    prov = finding.get('source_provenance') or ''
    hops = len(finding.get('taint_path') or [])
    if prov in R2_PROVENANCE_SCORE:
        return R2_PROVENANCE_SCORE[prov], f'r2_{prov}', f'parameter taint via {prov} ({hops} call edge(s))'
    parts = prov.split('_')
    score = R2_ORIGIN_SCORE.get(parts[0], 0.5)
    if 'nhop' in parts:
        score -= 0.05
    if 'dispatch' in parts:
        score -= 0.1
    if hops > 4:                     # v4.2: long chains are not cut, they cost confidence
        score -= 0.05 * (hops - 4)
    score = round(max(0.3, score), 2)
    return score, f'r2_{prov or "unknown"}', f'taint origin {parts[0]} via {prov} ({hops} call edge(s))'


def score_ast_corroboration_r3(finding):
    """v3 R3: purpose from a caller's sink with a weak check located 0.7, purpose from a
    caller's sink with no check located 0.6, purpose inferred from names 0.4."""
    if finding.get('purpose_inferred'):
        return 0.4, 'r3_purpose_inferred', 'purpose inferred from parameter names'
    if (finding.get('span') or {}).get('sink', {}).get('desc', '').startswith('弱校验'):
        return 0.7, 'r3_weak_check', 'caller sink fixes the purpose; only a weak check found'
    return 0.6, 'r3_no_strong_check', 'caller sink fixes the purpose; no strong check found'


def score_ast_corroboration_r5(finding):
    """v3.2 R5: request-identified data access without a principal check, judged against
    sibling handlers that do check; a structural signal, not a data-flow proof."""
    return 0.6, 'r5_peer_inconsistency', 'sibling handlers check the caller; this one does not'


def score_ast_corroboration_x4(finding):
    """v5.2 X4: chain-template alignment; the LLM's step-to-line map was checked against AST
    call/comparison lines, so the score grows with the aligned share and with siblings that
    do perform the missing step. Not a data-flow proof: capped below R2's net origin."""
    ratio = float(finding.get('aligned_ratio') or 0)
    score = 0.4 + 0.2 * ratio + (0.1 if finding.get('peers_present') else 0.0)
    return round(min(0.7, score), 3), 'x4_chain_alignment', \
        f"{ratio:.0%} template steps on AST lines; missing step absent" + \
        (f"; {finding['peers_present']} sibling(s) perform it" if finding.get('peers_present') else '')


def compute_confidence(finding, data_flow=None, source=None, vuln_db=None,
                       start_line=1):
    """Full weighted scoring. Returns (confidence, breakdown)."""
    dims = {
        'code_evidence': score_code_evidence(finding.get('evidence'), source, start_line),
        'ast_corroboration': (score_ast_corroboration_r1(finding, data_flow) if finding.get('rule_id') == 'R1'
                              else score_ast_corroboration_r2(finding) if finding.get('rule_id') in ('R2', 'R4')
                              else score_ast_corroboration_r3(finding) if finding.get('rule_id') == 'R3'
                              else score_ast_corroboration_r5(finding) if finding.get('rule_id') == 'R5'
                              else score_ast_corroboration_x4(finding) if finding.get('rule_id') == 'X4'
                              else score_ast_corroboration(finding.get('missing_step_category'), data_flow)),
    }
    dims['template_support'] = score_template_support(finding, vuln_db)
    breakdown = {}
    total = 0.0
    for name, (score, prov, detail) in dims.items():
        weight = WEIGHTS[name] if score is not None else 0.0
        breakdown[name] = {'score': score, 'weight': weight,
                           'provenance': prov, 'detail': detail}
        if score is not None:
            total += weight * score
    return round(min(1.0, max(0.0, total)), 3), breakdown


def enrich_findings_with_confidence(findings, data_flow_by_func=None,
                                    source_by_func=None, vuln_db=None,
                                    start_line_by_func=None):
    """Attach confidence/confidence_breakdown/confidence_level to each finding, in place.

    `start_line_by_func` maps "file:function" to the function's first line in
    its file, so absolute `L<line>` evidence refs verify against the right
    range. Omitting it falls back to 1 (snippet-relative).

    """
    data_flow_by_func = data_flow_by_func or {}
    source_by_func = source_by_func or {}
    start_line_by_func = start_line_by_func or {}
    for f in findings:
        key = f.get('function', '')
        conf, breakdown = compute_confidence(
            f,
            data_flow=data_flow_by_func.get(key),
            source=source_by_func.get(key),
            vuln_db=vuln_db,
            start_line=start_line_by_func.get(key, 1))
        f['confidence'] = conf
        f['confidence_breakdown'] = breakdown
        f['confidence_level'] = confidence_level(conf)
    return findings


# ── CLI ───────────────────────────────────────────────────────────────

def _selftest():
    failures = []
    source = 'func handler(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get("name")\n\tfmt.Fprintf(w, "hello %s", name)\n}'

    # Dimension scores
    s, p, _ = score_code_evidence('fmt.Fprintf(w, "hello %s", name)', source)
    if (s, p) != (1.0, 'verified_citation'):
        failures.append(f'code_evidence verified: got {(s, p)}')
    s, p, _ = score_code_evidence('`r.URL.Query().Get("name")` 被直接拼接', source)
    if (s, p) != (1.0, 'verified_citation'):
        failures.append(f'code_evidence backtick: got {(s, p)}')
    s, p, _ = score_code_evidence('这里缺少对输入的校验，存在安全隐患', source)
    if (s, p) != (0.4, 'unverified_citation'):
        failures.append(f'code_evidence unverified: got {(s, p)}')
    s, p, _ = score_code_evidence('', source)
    if (s, p) != (0.0, 'no_evidence'):
        failures.append(f'code_evidence empty: got {(s, p)}')
    s, p, _ = score_code_evidence('fmt.Fprintf(w, "hello %s", name)', None)
    if (s, p) != (0.5, 'source_unavailable'):
        failures.append(f'code_evidence no source: got {(s, p)}')
    # whitespace-insensitive match
    s, _, _ = score_code_evidence('fmt.Fprintf(w,   "hello %s",\n name)', source)
    if s != 1.0:
        failures.append(f'code_evidence ws-normalization failed: got {s}')

    df = {'sources': [{'type': 'http_request'}], 'sinks': [{'type': 'string_format'}]}
    s, p, _ = score_ast_corroboration('output_encoding', df)
    if (s, p) != (1.0, 'source_and_sink'):
        failures.append(f'ast both hit: got {(s, p)}')
    s, p, _ = score_ast_corroboration('output_encoding', {'sources': [{'type': 'http_request'}], 'sinks': []})
    if (s, p) != (0.7, 'source_only'):
        failures.append(f'ast source only: got {(s, p)}')
    s, p, _ = score_ast_corroboration('output_encoding', {'sources': [], 'sinks': [{'type': 'string_format'}]})
    if (s, p) != (0.6, 'sink_only'):
        failures.append(f'ast sink only: got {(s, p)}')
    s, p, _ = score_ast_corroboration('bounds_check', {'sources': [{'type': 'http_request'}], 'sinks': [{'type': 'file_read'}]})
    if (s, p) != (0.2, 'no_match'):
        failures.append(f'ast no match: got {(s, p)}')
    s, p, _ = score_ast_corroboration('error_handling', df)
    if (s, p) != (0.5, 'no_ast_signal'):
        failures.append(f'ast no signal category: got {(s, p)}')
    s, p, _ = score_ast_corroboration('made_up_category', None)
    if (s, p) != (0.5, 'no_data_flow'):
        failures.append(f'ast no data flow: got {(s, p)}')

    # Sanitizer span protection
    san_df = {'sources': [{'type': 'http_request', 'line': 10}],
              'sinks': [{'type': 'string_format', 'line': 40}]}
    s, p, _ = score_ast_corroboration('output_encoding',
                                      {**san_df, 'sanitizers': [{'line': 20, 'category': 'output_encoding', 'pattern': 'html.EscapeString('}]})
    if (s, p) != (0.1, 'sanitizer_on_path'):
        failures.append(f'sanitizer on path: got {(s, p)}')
    s, p, _ = score_ast_corroboration('output_encoding',
                                      {**san_df, 'sanitizers': [{'line': 50, 'category': 'output_encoding', 'pattern': 'x'}]})
    if (s, p) != (0.5, 'sanitizer_off_path'):
        failures.append(f'sanitizer off path: got {(s, p)}')
    s, p, d = score_ast_corroboration('output_encoding',
                                      {**san_df, 'sanitizers': [{'line': 20, 'category': 'path_validation', 'pattern': 'filepath.Clean('}]})
    if (s, p) != (1.0, 'source_and_sink') or 'no category sanitizer' not in d:
        failures.append(f'other-category sanitizer ignored: got {(s, p, d)}')
    s, p, _ = score_ast_corroboration('output_encoding',
                                      {**san_df, 'sanitizers': [{'category': 'output_encoding'}]})
    if (s, p) != (0.5, 'sanitizer_off_path'):
        failures.append(f'sanitizer no line: got {(s, p)}')
    s, p, _ = score_ast_corroboration('origin_validation',
                                      {'sources': [{'type': 'read', 'line': 10}], 'sinks': [{'type': 'string_format', 'line': 40}],
                                       'sanitizers': [{'line': 20, 'category': 'origin_validation', 'pattern': 'csrf.Protect('}]})
    if (s, p) != (0.1, 'sanitizer_on_path'):
        failures.append(f'sanitizer on path low base: got {(s, p)}')
    s, p, _ = score_ast_corroboration('output_encoding',
                                      {'sources': [], 'sinks': [{'type': 'string_format', 'line': 40}],
                                       'sanitizers': [{'line': 50, 'category': 'output_encoding', 'pattern': 'x'}]})
    if (s, p) != (0.5, 'sanitizer_off_path'):
        failures.append(f'sanitizer cap never raises: got {(s, p)}')

    db = {'templates': {
        'tpl_1': {'pattern_names': ['log_injection'], 'missing_step_category': 'output_encoding', 'example_count': 3},
        'tpl_2': {'pattern_names': ['path_traversal'], 'missing_step_category': 'path_validation', 'example_count': 1},
    }}
    s, p, _ = score_template_support({'template_id': 'tpl_1', 'pattern_name': 'log_injection',
                                      'missing_step_category': 'output_encoding'}, db)
    if (s, p) != (1.0, 'known_pattern'):
        failures.append(f'tpl known: got {(s, p)}')
    s, p, _ = score_template_support({'template_id': 'tpl_1', 'pattern_name': 'crlf_new',
                                      'missing_step_category': 'output_encoding'}, db)
    if (s, p) != (0.7, 'novel_pattern'):
        failures.append(f'tpl novel: got {(s, p)}')
    s, p, _ = score_template_support({'template_id': 'tpl_1', 'pattern_name': 'log_injection',
                                      'missing_step_category': 'path_validation'}, db)
    if (s, p) != (0.5, 'category_mismatch'):
        failures.append(f'tpl category mismatch: got {(s, p)}')
    s, p, _ = score_template_support({'template_id': 'tpl_X', 'pattern_name': 'x'}, db)
    if (s, p) != (0.3, 'unresolved_template'):
        failures.append(f'tpl unresolved: got {(s, p)}')
    s, p, _ = score_template_support({'template_id': 'tpl_1', 'pattern_name': 'x'}, None)
    if (s, p) != (0.5, 'db_unavailable'):
        failures.append(f'tpl no db: got {(s, p)}')

    # Line-ref evidence (constructed by decide.py)
    source50 = '\n'.join(f'line {i}' for i in range(1, 51))
    s, p, _ = score_code_evidence('L10 http_request → L40 string_format，跨度内无 output_encoding 检查', source50)
    if (s, p) != (1.0, 'verified_citation'):
        failures.append(f'code_evidence line refs: got {(s, p)}')
    s, p, _ = score_code_evidence('L10 x → L99 y，无检查', source50)
    if (s, p) != (0.4, 'unverified_citation'):
        failures.append(f'code_evidence out-of-bounds ref: got {(s, p)}')
    s, p, _ = score_code_evidence('L10 x，无检查', source50)
    if s != 0.4:
        failures.append(f'code_evidence single ref: got {(s, p)}')

    # Weighted aggregation (hand-computed)
    conf, bd = compute_confidence(
        {'evidence': 'L10 http_request → L40 string_format，跨度内无 output_encoding 检查',
         'template_id': 'tpl_1', 'pattern_name': 'log_injection',
         'missing_step_category': 'output_encoding'},
        data_flow=df, source=source50, vuln_db=db)
    expected = round(0.45 * 1.0 + 0.35 * 1.0 + 0.20 * 1.0, 3)
    if conf != expected or confidence_level(conf) != 'confirmed':
        failures.append(f'aggregation strong: got {conf} (expected {expected}), level {confidence_level(conf)}')

    conf, bd = compute_confidence(
        {'evidence': '', 'template_id': 'tpl_2',
         'pattern_name': 'custom_new', 'missing_step_category': 'path_validation'},
        data_flow={'sources': [{'type': 'read'}], 'sinks': []},
        source=source, vuln_db=db)
    expected = round(0.45 * 0.0 + 0.35 * 0.7 + 0.20 * 0.7, 3)
    if conf != expected or confidence_level(conf) != 'tentative':
        failures.append(f'aggregation weak: got {conf} (expected {expected}), level {confidence_level(conf)}')

    conf, _ = compute_confidence({'evidence': 'missing check', 'template_id': 'tpl_X',
                                  'missing_step_category': 'error_handling'},
                                 data_flow=None, source=None, vuln_db=None)
    expected = round(0.45 * 0.5 + 0.35 * 0.5 + 0.20 * 0.5, 3)
    if conf != expected or confidence_level(conf) != 'likely':
        failures.append(f'aggregation neutral: got {conf} (expected {expected}), level {confidence_level(conf)}')

    # enrich attaches computed fields
    fs = [{'function': 'a.go:f', 'evidence': 'L1 x → L2 y', 'template_id': 't',
           'missing_step_category': 'input_sanitization'}]
    enrich_findings_with_confidence(fs, {}, {'a.go:f': 'a\nb\n'}, db)
    if 'confidence_breakdown' not in fs[0] or 'confidence_level' not in fs[0]:
        failures.append(f'enrich fields wrong: {sorted(fs[0].keys())}')
    fs = [{'function': 'a.go:f'}]
    enrich_findings_with_confidence(fs)
    if not (0 <= fs[0]['confidence'] <= 1) or fs[0].get('llm_confidence') is not None:
        failures.append(f'enrich minimal input failed: {fs[0]}')

    # Robustness: weights sum to 1
    if abs(sum(WEIGHTS.values()) - 1.0) > 1e-9:
        failures.append(f'weights do not sum to 1: {WEIGHTS}')

    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for msg in failures:
            print(f"  - {msg}")
        return 1
    print("SELFTEST PASSED: 9 code_evidence (incl. 3 line-ref), 13 ast_corroboration (incl. 6 sanitizer span), "
          "5 template_support, 3 aggregations, 2 enrich, weights")
    return 0


def _recalc(path, write):
    with open(path, 'r', encoding='utf-8') as fh:
        report = json.load(fh)
    findings = report.get('findings', [])
    if not findings:
        print('No findings in report.')
        return 1

    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, 'vuln_db.json')
    vuln_db = None
    if os.path.isfile(db_path):
        with open(db_path, encoding='utf-8') as fh:
            vuln_db = json.load(fh)

    print(f"{len(findings)} findings (no source available -> code_evidence neutral path)\n")
    enrich_findings_with_confidence(findings, {}, {}, vuln_db)
    levels = {}
    for f in findings:
        level = f['confidence_level']
        levels[level] = levels.get(level, 0) + 1
        old = f.get('llm_confidence', '?')
        print(f"[{level.upper()} {f['confidence']:.2f}] {f.get('function')}: "
              f"{f.get('pattern_name')} (llm was: {old})")
        for dim, info in f['confidence_breakdown'].items():
            print(f"    {dim:<18} {info['score']:.2f} x {info['weight']:.2f}  "
                  f"[{info['provenance']}] {info['detail']}")
    if write:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"\nWritten back to {path}")
    dist = ' '.join(f"{k}:{v}" for k, v in sorted(levels.items()))
    print(f"\nLevel distribution: {dist or 'none'}")
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if args[0] == '--selftest':
        return _selftest()
    if args[0] == '--recalc':
        if len(args) < 2:
            print("usage: python confidence.py --recalc <report.json> [--write]")
            return 1
        return _recalc(args[1], '--write' in args[2:])
    print(__doc__)
    return 1


if __name__ == '__main__':
    sys.exit(main())
