# Remove no-KB Detection Mode Implementation Plan

> **For agentic workers:** Execute these steps inline; keep existing unrelated worktree edits intact.

**Goal:** Make the detector use its knowledge base on every scan and remove the obsolete no-KB switch and scoring path.

**Architecture:** Delete the optional ablation branch in the CLI and confidence scorer. Keep existing `--db`, `--domains`, and `--rules` controls; these configure normal knowledge-backed scans. Update offline CLI stubs to exercise the knowledge path.

**Tech Stack:** Python 3.9, unittest, Go AST analyzer.

---

### Task 1: Detector entry and report

**Files:** `detect_vulns.py`

- [x] Remove `--no-kb` argument and its mutual-exclusion checks.
- [x] Always load `args.db or "vuln_db.json"`, classify domains unless manually specified, and retrieve templates.
- [x] Call confidence scorer without `no_kb`; remove no-KB report dimension selection and filter field.

### Task 2: Confidence scoring and documentation

**Files:** `confidence.py`, `README.md`

- [x] Remove no-KB parameter, conditional normalization, and its two selftest cases.
- [x] Remove the no-KB CLI example and obsolete enhanced-mode note.

### Task 3: Offline integration checks

**Files:** `tests/test_enhanced_detection.py`

- [x] Run enhanced CLI tests with a stubbed domain-classification response and real local `vuln_db.json`.
- [x] Assert knowledge-backed report metadata and reject the removed switch via CLI help/parser.
- [x] Run confidence selftest, enhanced tests, Python compile, and diff whitespace check.

Historical experiment reports and logs remain evidence of prior runs; do not rewrite them.
