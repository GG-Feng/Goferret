# Candidate Exposure Implementation Plan

> **For agentic workers:** Work inline in the current session; preserve the existing uncommitted scanner changes and historical scan artifacts.

**Goal:** Show source-backed `unknown` hypotheses as actionable detected candidates, while retaining verification uncertainty, and improve discovery of rejection paths with success responses.

**Architecture:** Keep `validation_status` unchanged. Build a compact triage queue from `enhanced.findings` in the report writer, with ID, location, evidence, reason, and next question. Print it clearly in CLI. Extend the generic discovery prompt for reject/block/deny response semantics. Validate with an offline report test and a bounded netfoil focused run.

**Tech Stack:** Python 3, unittest, Go AST index, existing DeepSeek configuration for the bounded development-case check.

---

### Task 1: Preserve and expose unresolved candidates

**Files:** `enhanced_detection.py`, `detect_vulns.py`, `tests/test_enhanced_detection.py`, `README.md`.

- [x] Add a test that a discovered candidate verified as `unknown` appears in a compact triage queue with exact location, status, reason and unresolved questions.
- [x] Build the queue from accepted `findings` after source reference validation; put `unknown` first, keep `supported` separate and never imply runtime confirmation.
- [x] Print the queue path/summary and candidate location in CLI; document the field.
- [x] Run the enhanced offline suite.

### Task 2: Cover security-sensitive negative responses

**Files:** `enhanced_detection.py`, `tests/test_enhanced_detection.py`.

- [x] Add a general discovery question for block/reject/deny paths that return success status or fabricated answer data, including caller interpretation.
- [x] Add a small deterministic fixture proving such a candidate can pass source validation and remain visible when verification is unknown.
- [x] Run the enhanced offline suite.

### Task 3: Bounded real-model regression and report

**Files:** `.planning/dev3-smoke-20261008/focused_scan.py`, `.planning/dev3-smoke-20261008/report.md`.

- [x] Run the netfoil vulnerable/fixed focused probe with at most 40 total HTTP calls per snapshot; preserve old reports.
- [x] Check whether the block-response root cause is proposed on the vulnerable version and distinguished from fixed; do not infer full-repo recall.
- [x] Summarize mcp-shell and vault unknown candidates as visible hypotheses, not confirmed vulnerabilities; run `git diff --check` and update the local test record.
