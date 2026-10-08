# OCR Rules and Model Control Implementation Plan

> **For agentic workers:** Implement the checked tasks in this plan in order. Work inline in the current session; preserve all pre-existing uncommitted changes.

**Goal:** Add Go-specific security evidence guidance, make refutation of a finding require an anchor to its dangerous operation, and cap enhanced-mode LLM requests without hiding incomplete work.

**Architecture:** `enhanced_detection.py` owns the shared per-run request counter and verifier contract. `detect_vulns.py` exposes one enhanced-only CLI option. The report records used and configured calls, while exhausted source units remain pending and candidates remain unknown. Existing legacy scanning and the default unlimited enhanced behavior retain their interface.

**Tech Stack:** Python 3 unittest; Go AST analyzer used by the existing offline fixture suite.

---

### Task 1: Tighten source-backed verdicts and Go security questions

**Files:** Modify `enhanced_detection.py`; test `tests/test_enhanced_detection.py`.

- [x] Change `test_verdict_needs_source_backed_claims` so `refuted` with only a protection claim expects `unknown`; `refuted` with both a protection/contradiction claim and an operation claim at the candidate sink expects `refuted`.
- [x] Run the focused verdict test; the new assertion failed before implementation as expected.
- [x] In `verify`, validate claim kinds against `input|operation|impact|protection|contradiction`. Compute an operation reference overlap with the candidate sink for either `supported` or `refuted`; require that overlap for both dispositions. On failure set `unknown` and `insufficient_or_invalid_evidence`, preserving the candidate.
- [x] Update the guard-pair fixture: its effective return guard response includes an operation claim for the allocation line and a protection claim for the blocking return line.
- [x] Add concise Go-specific questions to both discovery and verification instructions: check actual attacker control, rejected branch reachability, path/symlink/redirect behavior, resource limits before expansion, and middleware coverage. State that these are investigation cues, not proof.
- [x] Run the targeted verdict and guard-pair tests; passed.

### Task 2: Add an enhanced-stage request budget with explicit incomplete status

**Files:** Modify `enhanced_detection.py`, `detect_vulns.py`, `README.md`; test `tests/test_enhanced_detection.py`.

- [x] Add a fixture that runs `ed.run(..., max_model_calls=1)` with two discovery units and one existing candidate. Assert exactly one `ask` call; the remaining unit is `pending` with reason `model_call_budget_exhausted`; candidate is `unknown` with the same reason; overall status is `partial`; the report says used=1 and limit=1.
- [x] Run the new test; it failed because `run` had no budget parameter, as expected.
- [x] Add `ModelCallBudget(limit=0)` with `used` and `reserve()` in `enhanced_detection.py`. `model_loop` calls `reserve()` before every `ask` and returns `model_call_budget_exhausted` when it fails. Thread the same budget through discovery and verification. A unit skipped before dispatch is `pending`; exhausted candidate verification stays `unknown`.
- [x] Add `--enhanced-max-model-calls N` in `detect_vulns.py`, default 0 for unlimited, reject negative values, and pass N into `ed.run`. Record `model_calls_used` and `max_model_calls` under `enhanced.limits`. Explain in README that this cap covers the enhanced discovery/verification calls only; prior structural/legacy calls are separate.
- [x] Run the new budget test and existing enhanced suite; passed.

### Task 3: Verify and document the boundary

**Files:** Update `.planning/ocr-rules-llm-control-20261008/findings.md`, `progress.md`, `task_plan.md`.

- [x] Run the enhanced suite and seven module selftests. All passed.
- [x] Run `git diff --check` and inspect touched files. Pre-existing work remains in place.
- [x] Record that these tests validate control flow and evidence protocol with stubs; a real-model, independently labelled evaluation is still needed for precision/recall claims.
