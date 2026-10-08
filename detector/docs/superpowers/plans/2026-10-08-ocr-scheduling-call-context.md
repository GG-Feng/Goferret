# OCR Scheduling and Call Context Implementation Plan

> **For agentic workers:** Implement these tasks inline in the current session. The user has already authorized the change; preserve all pre-existing uncommitted work.

**Goal:** Verify fresh semantic candidates before a bounded discovery run consumes its request budget, and expose source-backed cross-function call evidence to the investigation model.

**Architecture:** Keep `enhanced_detection.py` as the owner of the source snapshot and request budget. Discovery appends candidates in source order; newly discovered semantic candidates are verified immediately, with structural candidates verified after discovery. Enrich existing call-context tools with exact call-site references and bounded target parameter/return facts; mark approximate resolution explicitly.

**Tech Stack:** Python 3 unittest and the existing Go AST analyzer.

---

### Task 1: Interleave discovery and semantic verification

**Files:** Modify `enhanced_detection.py`; test `tests/test_enhanced_detection.py`.

- [x] Add a test with two source units, a candidate from the first unit, and a two-call cap. Assert the call order is DISCOVER, VERIFY, that the second unit is pending, and that the first candidate is not left unverified merely because later discovery used the cap.
- [x] Run the focused test and confirm failure on the existing discovery-first scheduler.
- [x] Track unique candidate IDs while processing units. Verify new semantic candidates immediately, retain every raw candidate, then verify remaining structural candidates. Preserve source order, status, and trace records.
- [x] Run focused scheduling and existing budget tests.

### Task 2: Give the investigator source-backed call edges

**Files:** Modify `enhanced_detection.py`; test `tests/test_enhanced_detection.py`.

- [x] Extend the cross-package fixture to assert `get_callers` and `get_callees` include an exact `site_reference`, argument root facts, and a bounded target summary with parameter and return roots. Confirm ambiguous resolution is labeled and never presented as a unique path.
- [x] Run the focused test and confirm failure before implementation.
- [x] Enrich `Context.tool` using the existing `param_flows` and source snapshot. Keep the current 100-edge cap and explicit truncation flag; skip invalid source references rather than inventing lines.
- [x] Update the discovery and verification prompts to request producer/consumer and URL path representation checks when relevant, without treating the new context as proof of exploitability.
- [x] Run focused and full enhanced offline tests.

### Task 3: Expose protocol field uses

**Files:** Modify `ast_analyzer/source_index.go`, `enhanced_detection.py`; test `tests/test_enhanced_detection.py`.

- [x] Add a Go fixture where one function writes `Message{Path: r.URL.Path}` and another reads `m.Path`. Assert a bounded field-use query returns both exact source lines and labels them as approximate field-name matches.
- [x] Run the focused test and confirm it fails before adding the field-use index.
- [x] Index selector reads/writes and keyed literal fields in the existing source index. Expose `find_field_uses(field,path_prefix)` over only indexed source files, with a 100-result cap and explicit type-ambiguity warning.
- [x] Run the focused Go-backed test; full suite follows in Task 4.

### Task 4: Document and verify the boundary

**Files:** Modify `docs/ENHANCED_DETECTION.md`, `README.md` if necessary; update this plan and `.planning/ocr-scheduling-call-context-20261008/` notes.

- [x] Describe interleaving, call-context output and the remaining limits of name dispatch, build tags and model semantic judgments.
- [x] Run enhanced unittest suite (31 passed), seven module selftests (passed), `go test ./...` (passed), `gofmt -l` (clean), and `git diff --check` (clean).
- [x] Record that offline tests demonstrate control flow and evidence delivery, not improved real-model root-cause recall.
