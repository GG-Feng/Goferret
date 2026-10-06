"""
CVSS v3.1 base score computation and severity rating for detection findings.

Scoring model (hybrid):
  - The deep-analysis LLM judges the 8 base metrics (enum values) per finding.
  - This module computes the score deterministically from the official CVSS
    v3.1 formula, so the number is always reproducible.
  - Metrics the LLM omitted or filled with invalid values are backfilled by
    deterministic rules: per-category default vectors, AV derivation from AST
    data-flow source facts, and C/I/A upgrades from sink facts.
  - Objective facts (AST sources/sinks) can only UPGRADE LLM judgments
    (higher weight), never downgrade them. Provenance is tracked per metric.

CLI:
    python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    python cvss.py --selftest
    python cvss.py --recalc projects/<id>/report.json [--write]
"""

import json
import math
import sys

# ── CVSS v3.1 weights ─────────────────────────────────────────────────

AV_WEIGHT = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
AC_WEIGHT = {'L': 0.77, 'H': 0.44}
PR_WEIGHT = {('N', 'U'): 0.85, ('N', 'C'): 0.85,
             ('L', 'U'): 0.62, ('L', 'C'): 0.68,
             ('H', 'U'): 0.27, ('H', 'C'): 0.50}
UI_WEIGHT = {'N': 0.85, 'R': 0.62}
CIA_WEIGHT = {'H': 0.56, 'L': 0.22, 'N': 0.0}

METRIC_ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
VALID_ENUMS = {'AV': {'N', 'A', 'L', 'P'},
               'AC': {'L', 'H'},
               'PR': {'N', 'L', 'H'},
               'UI': {'N', 'R'},
               'S': {'U', 'C'},
               'C': {'H', 'L', 'N'},
               'I': {'H', 'L', 'N'},
               'A': {'H', 'L', 'N'}}

ALIASES = {'NETWORK': 'N', 'ADJACENT': 'A', 'ADJACENT_NETWORK': 'A',
           'LOCAL': 'L', 'PHYSICAL': 'P',
           'NONE': 'N', 'LOW': 'L', 'HIGH': 'H',
           'REQUIRED': 'R', 'UNCHANGED': 'U', 'CHANGED': 'C'}

CIA_RANK = {'N': 0, 'L': 1, 'H': 2}

SEVERITY_BANDS = [(9.0, 'critical'), (7.0, 'high'), (4.0, 'medium'), (0.1, 'low'), (0.0, 'none')]


class CvssParseError(ValueError):
    pass


# ── Fallback rule tables ──────────────────────────────────────────────
# Table A: default vector per missing_step_category. Scores verified against
# the formula (see --selftest).

CATEGORY_DEFAULT_VECTORS = {
    'input_sanitization':        {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
    'bounds_check':              {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'N', 'A': 'H'},
    'origin_validation':         {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
    'access_control':            {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
    'output_encoding':           {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N'},
    'resource_limit':            {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'N', 'A': 'H'},
    'cryptographic_verification': {'AV': 'N', 'AC': 'H', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N'},
    'state_synchronization':     {'AV': 'N', 'AC': 'H', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'H', 'A': 'H'},
    'error_handling':            {'AV': 'N', 'AC': 'H', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'N', 'A': 'L'},
    'path_validation':           {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N'},
    'identity_verification':     {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N'},
    'protocol_validation':       {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'L', 'A': 'L'},
}

GLOBAL_DEFAULT_VECTOR = {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'}

# Table B: AST data-flow source types -> Attack Vector (ast_analyzer/main.go sourcePatterns)

NETWORK_SOURCE_TYPES = {'http_request', 'http_body', 'network_accept', 'network_read', 'read_message'}
LOCAL_SOURCE_TYPES = {'read', 'read_all', 'buffered_read', 'json_decode', 'xml_decode',
                      'binary_read', 'scan', 'io_copy', 'channel_recv'}

# Table C: AST sink types -> minimum C/I/A (upgrade only, never downgrade)

SINK_CIA_UPGRADES = {
    'command_execution': {'C': 'H', 'I': 'H', 'A': 'H'},
    'sql_query':         {'C': 'H', 'I': 'H'},
    'sql_exec':          {'C': 'H', 'I': 'H'},
    'file_write':        {'I': 'H'},
    'file_read':         {'C': 'H'},
    'html_injection':    {'C': 'L', 'I': 'L'},
    'js_injection':      {'C': 'L', 'I': 'L'},
    'string_format':     {'I': 'L'},
    'write':             {'I': 'L'},
}


# ── Metric normalization / validation ─────────────────────────────────

def normalize_metric(key, value):
    """Return a canonical enum value for `key`, or None if invalid/missing."""
    if value is None:
        return None
    v = str(value).strip().upper()
    if not v:
        return None
    valid = VALID_ENUMS.get(key)
    if not valid:
        return None
    if v in valid:
        return v
    mapped = ALIASES.get(v)
    if mapped in valid:
        return mapped
    return None


def validate_metrics(llm_metrics):
    """Keep only the 8 base metrics with legal enum values.

    Returns (normalized_dict, invalid_keys) — extra keys (E/RL/RC...) are
    silently dropped, invalid values are treated as missing.
    """
    norm, invalid = {}, []
    if not isinstance(llm_metrics, dict):
        return norm, invalid
    for key, value in llm_metrics.items():
        if key not in VALID_ENUMS:
            continue
        v = normalize_metric(key, value)
        if v is None:
            if value not in (None, ''):
                invalid.append(key)
        else:
            norm[key] = v
    return norm, invalid


# ── Vector string parse / build ───────────────────────────────────────

def parse_vector(vector_str):
    s = str(vector_str).strip().replace(' ', '')
    if not s:
        raise CvssParseError('empty vector string')
    parts = s.split('/')
    prefix = parts[0].upper()
    if prefix not in ('CVSS:3.1', 'CVSS:3.0'):
        raise CvssParseError(f"bad prefix: {parts[0]!r} (expected CVSS:3.1/ or CVSS:3.0/)")
    metrics, seen = {}, set()
    for part in parts[1:]:
        if not part:
            continue
        if ':' not in part:
            raise CvssParseError(f"bad segment: {part!r}")
        key, _, value = part.partition(':')
        key = key.upper()
        if key not in VALID_ENUMS:
            raise CvssParseError(f"unknown metric: {key}")
        if key in seen:
            raise CvssParseError(f"duplicate metric: {key}")
        seen.add(key)
        v = normalize_metric(key, value)
        if v is None:
            raise CvssParseError(f"illegal value for {key}: {value!r}")
        metrics[key] = v
    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise CvssParseError(f"missing metrics: {', '.join(missing)}")
    return metrics


def build_vector(metrics):
    return 'CVSS:3.1/' + '/'.join(f"{m}:{metrics[m]}" for m in METRIC_ORDER)


# ── Base score (CVSS v3.1 specification) ──────────────────────────────

def roundup(value):
    # Integer-based implementation from the FIRST reference implementation
    # to avoid floating point drift (Roundup(4.02) = 4.1, Roundup(4.00) = 4.0).
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def base_score(metrics):
    scope = metrics['S']
    iss = 1 - ((1 - CIA_WEIGHT[metrics['C']]) *
               (1 - CIA_WEIGHT[metrics['I']]) *
               (1 - CIA_WEIGHT[metrics['A']]))
    if scope == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = (8.22 * AV_WEIGHT[metrics['AV']] * AC_WEIGHT[metrics['AC']] *
                      PR_WEIGHT[(metrics['PR'], scope)] * UI_WEIGHT[metrics['UI']])
    if impact <= 0:
        score = 0.0
    elif scope == 'U':
        score = roundup(min(impact + exploitability, 10))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    detail = {'iss': round(iss, 6), 'impact': round(impact, 6), 'exploitability': round(exploitability, 6)}
    return score, detail


def severity_rating(score):
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            return name
    return 'none'


# ── Deterministic fallbacks ───────────────────────────────────────────

def derive_av_from_sources(source_types):
    """AST source facts -> AV. Network-reachable inputs outrank local ones."""
    types = set(source_types or [])
    if types & NETWORK_SOURCE_TYPES:
        return 'N'
    if types & LOCAL_SOURCE_TYPES:
        return 'L'
    return None


def _max_cia(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return b if CIA_RANK[b] > CIA_RANK[a] else a


def resolve_metrics(llm_metrics, category, source_types=None, sink_types=None):
    """Full fallback decision chain. Returns (metrics, provenance)."""
    norm, _invalid = validate_metrics(llm_metrics)
    default = CATEGORY_DEFAULT_VECTORS.get(category, GLOBAL_DEFAULT_VECTOR)
    provenance = {}
    metrics = {}

    # AV: AST fact upgrades LLM judgment / category default, never downgrades.
    fact_av = derive_av_from_sources(source_types)
    llm_av = norm.get('AV')
    if llm_av is not None:
        if fact_av and AV_WEIGHT[fact_av] > AV_WEIGHT[llm_av]:
            metrics['AV'], provenance['AV'] = fact_av, 'ast_fact'
        else:
            metrics['AV'], provenance['AV'] = llm_av, 'llm'
    elif fact_av and AV_WEIGHT[fact_av] >= AV_WEIGHT[default['AV']]:
        metrics['AV'], provenance['AV'] = fact_av, 'ast_fact'
    else:
        metrics['AV'], provenance['AV'] = default['AV'], 'category_default'

    # C/I/A: sink facts upgrade everything; category defaults only fill gaps.
    sink_up = {}
    for st in (sink_types or []):
        for dim, val in SINK_CIA_UPGRADES.get(st, {}).items():
            sink_up[dim] = _max_cia(sink_up.get(dim), val)
    for m in ('C', 'I', 'A'):
        llm_v = norm.get(m)
        up_v = sink_up.get(m)
        ref = llm_v if llm_v is not None else default[m]
        if up_v is not None and CIA_RANK[up_v] > CIA_RANK[ref]:
            metrics[m], provenance[m] = up_v, 'sink_upgrade'
        elif llm_v is not None:
            metrics[m], provenance[m] = llm_v, 'llm'
        else:
            metrics[m], provenance[m] = default[m], 'category_default'
    if metrics['C'] == 'N' and metrics['I'] == 'N' and metrics['A'] == 'N':
        for m in ('C', 'I', 'A'):
            metrics[m], provenance[m] = default[m], 'all_none_override'

    # AC/PR/UI/S: LLM judgment or category default.
    for m in ('AC', 'PR', 'UI', 'S'):
        if norm.get(m) is not None:
            metrics[m], provenance[m] = norm[m], 'llm'
        else:
            metrics[m], provenance[m] = default[m], 'category_default'

    return metrics, provenance


def enrich_findings_with_cvss(findings, data_flow_by_func=None):
    """Attach cvss_score/cvss_vector/severity (computed) to each finding, in place."""
    data_flow_by_func = data_flow_by_func or {}
    for f in findings:
        llm_metrics = f.get('cvss_metrics') if isinstance(f.get('cvss_metrics'), dict) else {}
        df = data_flow_by_func.get(f.get('function', '')) or {}
        source_types = [s.get('type') for s in (df.get('sources') or []) if s.get('type')]
        sink_types = [s.get('type') for s in (df.get('sinks') or []) if s.get('type')]
        metrics, provenance = resolve_metrics(llm_metrics, f.get('missing_step_category'),
                                              source_types, sink_types)
        score, _detail = base_score(metrics)
        if f.get('severity'):
            f['llm_severity'] = f['severity']
        f['cvss_metrics'] = metrics
        f['cvss_vector'] = build_vector(metrics)
        f['cvss_score'] = score
        f['severity'] = severity_rating(score)
        f['cvss_provenance'] = provenance
        f['cvss_defaults_applied'] = [m for m in METRIC_ORDER if provenance.get(m) != 'llm']
    return findings


# ── CLI ───────────────────────────────────────────────────────────────

# Known vectors with expected scores (verified against the specification by
# hand; several map to famous CVEs whose public NVD scores must match).

SELFTEST_VECTORS = [
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8),
    ('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8),
    ('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8),
    ('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', 5.9),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', 5.3),
    ('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 6.8),
    ('CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 2.0),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0),
    ('CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N', 3.5),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L', 9.4),
]

SELFTEST_CATEGORY_SCORES = {
    'input_sanitization': 6.5, 'bounds_check': 7.5, 'origin_validation': 5.4,
    'access_control': 8.8, 'output_encoding': 6.1, 'resource_limit': 7.5,
    'cryptographic_verification': 5.9, 'state_synchronization': 7.4,
    'error_handling': 4.8, 'path_validation': 7.5, 'identity_verification': 9.1,
    'protocol_validation': 6.5,
}

BAD_VECTORS = [
    'CVSS:3.1/AV:N',
    'CVSS:3.9/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N',
]


def _selftest():
    failures = []

    for vector, expected in SELFTEST_VECTORS:
        metrics = parse_vector(vector)
        score, _ = base_score(metrics)
        if score != expected:
            failures.append(f"{vector}: got {score}, expected {expected}")
        if severity_rating(score) != severity_rating(expected):
            failures.append(f"{vector}: rating mismatch for {score}")
        if build_vector(metrics) != vector:
            failures.append(f"roundtrip mismatch: {vector}")

    if base_score(parse_vector('cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:n/i:n/a:h'))[0] != 7.5:
        failures.append('lenient parsing (lowercase) failed')

    for bad in BAD_VECTORS:
        try:
            parse_vector(bad)
            failures.append(f"bad vector accepted: {bad!r}")
        except CvssParseError:
            pass

    for cat, expected in SELFTEST_CATEGORY_SCORES.items():
        metrics = CATEGORY_DEFAULT_VECTORS[cat]
        score, _ = base_score(metrics)
        if score != expected:
            failures.append(f"category {cat}: got {score}, expected {expected}")
    score, _ = base_score(GLOBAL_DEFAULT_VECTOR)
    if score != 6.5:
        failures.append(f"global default: got {score}, expected 6.5")

    # resolve_metrics decision chain
    m, p = resolve_metrics({'AV': 'L', 'C': 'N', 'I': 'N', 'A': 'N'}, 'input_sanitization',
                           ['http_request'], [])
    if m['AV'] != 'N' or p['AV'] != 'ast_fact':
        failures.append(f"AV ast_fact upgrade failed: {m}, {p}")
    if (m['C'], m['I'], m['A']) != ('L', 'L', 'N') or p['C'] != 'all_none_override':
        failures.append(f"all-none override failed: {m}, {p}")

    m, p = resolve_metrics({}, 'path_validation', [], ['file_write'])
    if m['I'] != 'H' or p['I'] != 'sink_upgrade':
        failures.append(f"sink upgrade failed: {m}, {p}")

    m, p = resolve_metrics({'AV': 'network', 'AC': 'LOW', 'E': 'U'}, 'unknown_category',
                           [], ['command_execution'])
    if m != {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'}:
        failures.append(f"alias/global-default/RCE-sink resolution failed: {m}")
    if p['AC'] != 'llm':
        failures.append(f"alias normalization provenance wrong: {p}")

    if failures:
        print(f"SELFTEST FAILED ({len(failures)}):")
        for msg in failures:
            print(f"  - {msg}")
        return 1
    print(f"SELFTEST PASSED: {len(SELFTEST_VECTORS)} vectors, "
          f"{len(SELFTEST_CATEGORY_SCORES) + 1} category defaults, "
          f"{len(BAD_VECTORS)} bad vectors, 4 resolve_metrics cases")
    return 0


def _recalc(path, write):
    with open(path, 'r', encoding='utf-8') as fh:
        report = json.load(fh)
    findings = report.get('findings', [])
    if not findings:
        print('No findings in report.')
        return 1
    print(f"{len(findings)} findings (no data_flow available -> pure fallback path)\n")
    # Old reports carry no cvss_metrics; emulate the integration entry point.
    for f in findings:
        f.pop('cvss_metrics', None)
    enrich_findings_with_cvss(findings, {})
    changed = 0
    for f in findings:
        old = f.get('llm_severity', '?')
        new = f['severity']
        mark = '' if old == new else '  <-- differs from LLM'
        if old != new:
            changed += 1
        print(f"[{new.upper()} {f['cvss_score']:.1f}] {f.get('function')}: "
              f"{f.get('pattern_name')} (was: {old}){mark}")
        print(f"    {f['cvss_vector']}  defaults: {','.join(f['cvss_defaults_applied'])}")
    if write:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"\nWritten back to {path}")
    print(f"\nSummary: {changed}/{len(findings)} differ from original LLM severity")
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
            print("usage: python cvss.py --recalc <report.json> [--write]")
            return 1
        return _recalc(args[1], '--write' in args[2:])
    try:
        metrics = parse_vector(args[0])
    except CvssParseError as exc:
        print(f"Parse error: {exc}")
        return 1
    score, detail = base_score(metrics)
    print(f"Vector:         {build_vector(metrics)}")
    print(f"Base Score:     {score:.1f}")
    print(f"Severity:       {severity_rating(score)}")
    print(f"ISS:            {detail['iss']}")
    print(f"Impact:         {detail['impact']}")
    print(f"Exploitability: {detail['exploitability']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
