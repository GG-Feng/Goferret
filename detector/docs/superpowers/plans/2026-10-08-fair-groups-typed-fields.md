# Fair Investigation Groups and Typed Fields Implementation Plan

> **For agentic workers:** Implement inline in this authorized session. Preserve the existing uncommitted detector work.

**Goal:** Prevent duplicate hypotheses and long investigations from monopolizing a bounded scan, and distinguish explicit local struct fields across files while exposing the assignments that feed a protocol field.

**Architecture:** `enhanced_detection.py` retains every candidate but schedules one model round at a time, first across operation-and-category investigation groups and then across remaining members. `ast_analyzer/source_index.go` adds conservative type identities to explicitly typed struct literals and selector roots and indexes local assignments; unresolved uses remain unlabeled and never get merged by type.

**Tech Stack:** Python unittest; Go AST analyzer and standard library.

---

### Task 1: Fair verification scheduler

**Files:** `enhanced_detection.py`, `tests/test_enhanced_detection.py`.

- [x] Write a failing regression with two hypotheses at one operation and another at a second operation. Under a tight cap, one model round must reach each group before either gets a second round. Raw members must remain separate and unverified members unknown.
- [x] Write a failing regression that limits immediate verification to one new group per source unit, leaving a call for the next source unit when the cap allows it.
- [x] Make `model_loop` continue from an existing trace with a round offset. Keep standalone `verify` behavior while allowing the run scheduler to advance one round per candidate.
- [x] Add conservative investigation groups keyed by exact file, operation line and category. Schedule representatives first, then remaining members; never copy a representative verdict onto another member. Record group membership and all pending reasons.
- [x] Run focused and full enhanced tests (33 passed).

### Task 2: Conservative typed field and value context

**Files:** `ast_analyzer/source_index.go`, `enhanced_detection.py`, `tests/test_enhanced_detection.py`.

- [x] Add a Go-backed fixture with two same-named fields on different structs, a cross-package `Message.Path` producer/consumer, and a local variable assigned from `r.URL.Path` before populating the message field. Assert explicit type IDs separate the fields and the assignment evidence is returned.
- [x] Resolve explicit struct literal types and directly typed parameter/local selector roots from Go AST plus the module path and imports. Leave implicit/interface cases unresolved; avoid claiming compiler-level type certainty.
- [x] Index local assignments and return bounded preceding assignments as possible value sources for simple field expressions. Preserve source references and mark branches/reassignments as ambiguous.
- [x] Add optional `type_id` filtering to `find_field_uses`; expose unresolved matches without assigning them to a type and update prompt guidance.
- [x] Run Go build/test and enhanced tests (33 passed).

### Task 3: Documentation and review

**Files:** `README.md`, `docs/ENHANCED_DETECTION.md`, this plan, `.planning/fair-groups-typed-fields-20261008/`.

- [x] Document fairness, grouping as an investigation aid, type-resolution limits, and the effect of finite budgets on coverage.
- [x] Run seven module selftests, enhanced tests (33 passed), Go test, formatting and diff checks. Record observed limits without claiming improved real-model detection.
