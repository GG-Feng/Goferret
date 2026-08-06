# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Go vulnerability dataset pipeline: scrapes Go vulnerability reports from pkg.go.dev, clones affected repos, extracts source snapshots at vulnerable and patched commits, and produces structured per-vuln data for downstream vulnerability research (behavior chain modeling, recurring/0-day detection). The `classification.md` is a Chinese-language prompt for an LLM-based functional domain classifier that categorizes vulnerabilities by the functionality they depend on.

## Pipeline Stages (run in order)

1. **Scrape vulns**: `python scrape_vulns.py` — scrapes all GO-XXXX-XXXX entries from https://pkg.go.dev/vuln/list, saves individual JSONs to `vuln/`. Resumable (skips already-scraped IDs). Uses 5 concurrent threads.

2. **Analyze vulns**: `python analyze_vulns.py` — reads all `vuln/*.json`, resolves patch commits from GitHub/googlesource references, produces `vuln_analysis.json` with per-repo summaries and per-vuln entries indicating whether each vuln has a patch commit.

3. **Download repos**: `python download_repos.py [--limit N] [--workers W]` — clones repos from `vuln_analysis.json` as bare mirrors into `repos/owner/repo`. Resumable. Handles auth-required and retryable errors.

4. **Enrich commits**: `python enrich_commits.py` — for each patch commit, resolves its git parent (the vulnerable commit) using the cloned bare repos. Updates `vuln_analysis.json` in-place.

5. **Generate vuln infos**: `python generate_vuln_infos.py` — produces per-repo JSON files in `vuln_infos/` with go_id, aliases, patch_commit, and vulnerable_commit for each vulnerability.

6. **Create vuln data**: `python create_vuln_data.py [--limit N] [--workers W]` — for each vulnerability, creates `vuln_data/GO-XXXX-XXXX/` containing `vuln.json`, `vulnerable/` (source at vulnerable commit), `patch/` (source at patch commit), and `patch.diff`. Resumable.

7. **Prepare classifier inputs**: `python prepare_input.py --all` — for each vulnerability with a patch, parses the diff to extract changed files/functions and pulls source context from the vulnerable snapshot. Produces per-vuln JSON files in `prepared_inputs/`. Also supports single vuln: `python prepare_input.py GO-XXXX-XXXX`.

8. **Classify vulns**: `python classify_vulns.py [--limit N] [--workers W]` — sends prepared inputs along with `classification.md` as system prompt to a configured LLM API (ARK_BASE_URL/ARK_API_KEY/ARK_MODEL from `.env`). Saves per-vuln classification results to `classifications/`. Resumable (skips already-classified). Supports `--retry-failed` to re-attempt errored entries.

9. **Re-enrich AST data**: `python re_enrich_ast.py [--force] [--limit N] [--workers W]` — re-runs Go AST analyzer on `enriched_inputs/` entries with null `call_chains` or `data_flow_indicators` (without `--focus-funcs`). The improved `ast_analyzer` includes a subdirectory fallback for multi-package projects.

10. **Extract behavior chains**: `python behavior_chain_extract.py [--limit N] [--workers W]` — reads `enriched_inputs/` and `classifications_v2/`, sends them with `behavior_chain.md` as system prompt to the LLM API. Each vulnerability is described as a legitimate operation sequence missing a security step. Results saved to `behavior_chains/`. Supports `--retry-failed`.

11. **Build vulnerability database**: `python build_vuln_db.py [--input-dir behavior_chains] [--output vuln_db.json]` — aggregates behavior chains by (primary_domain, missing_step_category) into pattern templates, builds domain/category/API indices, outputs `vuln_db.json` for detection.

12. **Detect vulnerabilities**: `python detect_vulns.py --target /path/to/project [options]` or `python detect_vulns.py --git-url https://github.com/owner/repo --git-ref v1.0.0 [options]` — 5-stage detection: AST scan → domain classification (1 LLM call) → pattern retrieval → function prioritization → per-function deep analysis (N LLM calls). Creates `projects/YYYYMMDD_HHMMSS/` with source copy (or git clone) and `report.json`. Supports `--git-url` (clone from GitHub), `--git-ref` (branch/tag/commit), `--no-copy` (skip source copy), `--output` (override report path), `--domains` (manual override), `--max-functions` (default 0=all), `--confidence-threshold` (default 0.5).

13. **Generate test cases**: `python gen_testcases.py --project projects/<id> [options]` — reads source and report from project directory, selects category-specific test templates, calls LLM to generate Go unit tests and PoC verification scripts. Outputs `testcases/` inside the project directory. Supports `--categories`, `--severity-filter`, `--skip-compile`, `--retry-failed`. Runs `go vet` compilation verification by default. Also supports legacy mode with `--target` + `--report`.

## Data Directory Layout

- `vuln/` — raw scraped vulnerability JSONs (one per GO-ID)
- `repos/` — bare git mirrors of vulnerable repos (repos/owner/repo)
- `vuln_analysis.json` — master analysis file with repo summaries and all vulnerability entries
- `vuln_infos.json` — aggregated vulnerability info
- `vuln_infos/` — per-repo vulnerability info JSONs
- `vuln_data/` — per-vuln directories with source snapshots and diffs
- `prepared_inputs/` — per-vuln structured JSONs for the classifier (metadata, diff, function source context)
- `classifications/` — per-vuln LLM classification results (primary domain, reasoning)
- `classifications_v2/` — per-vuln LLM classification results (v2, with richer domain analysis)
- `enriched_inputs/` — per-vuln enriched data with AST analysis (call_chains, data_flow_indicators, stdlib_signals, func_sources)
- `behavior_chains/` — per-vuln behavior chain extraction results (chain_type, steps, missing_step_category, vulnerability_pattern)
- `vuln_db.json` — aggregated vulnerability pattern database with templates and indices
- `projects/` — per-scan project directories (each run of `detect_vulns.py` creates one):
  - `projects/YYYYMMDD_HHMMSS/source/` — copy of the scanned Go project source
  - `projects/YYYYMMDD_HHMMSS/report.json` — detection report (findings, domains, scores)
  - `projects/YYYYMMDD_HHMMSS/testcases/` — generated test cases: `unit/` (Go _test.go files), `poc/` (standalone PoC scripts), `metadata.json`
- `.env` — LLM API keys (ARK_API_KEY/ARK_BASE_URL/ARK_MODEL for classification; OpenAI, Anthropic, Google, DeepSeek, ZhipuAI, Moonshot, Qwen, OpenRouter)

## Architecture Notes

- All scripts are standalone Python with no external package requirements beyond `requests` and `beautifulsoup4` (for scraping). Git operations use the `git` CLI via `subprocess`. `classify_vulns.py` uses the ARK API (Volcengine/Doubao) for LLM classification.
- Path collision handling is duplicated across `download_repos.py`, `enrich_commits.py`, and `create_vuln_data.py` — repo paths are computed by hashing the GitHub URL when two repos share the same owner/name (case-insensitive). Changes to path logic must stay consistent across all three scripts.
- Bare repos (`--mirror`) are used throughout — git commands use `--git-dir` or `-C` to operate on them. Source extraction uses `git archive` to stream a zip to disk, then extracts file-by-file to control memory usage.
- All long-running scripts support Ctrl+C graceful shutdown and resumability (they skip already-completed work).
- `classification.md` defines 10 functional domains for vulnerability classification (InputParsingAndDeserialization, PathHandlingAndFilesystemAccess, AuthenticationAndAuthorization, NetworkRequestAndProtocolHandling, CommandExecutionAndExternalProcessInteraction, QueryTemplateAndExpressionConstruction, ArchiveAndCompressionProcessing, ConcurrencyStateAndSharedResourceManagement, ResourceBoundingAndDoSProtection, CryptographicVerificationAndSecurityValidation). It is used as the system prompt in `classify_vulns.py`.
- `ast_analyzer/main.go` includes a subdirectory fallback: when `parser.ParseDir` on the root directory produces empty results (common for multi-package projects with no .go files at root), it extracts parent directories from `--focus-files` and parses each subdirectory separately, merging results.
- `re_enrich_ast.py` improves AST data coverage by re-running the analyzer without `--focus-funcs` (the original `enrich_inputs.py` passes focus functions extracted from diff hunk headers, which often don't match actual Go function names).
- Behavior chain extraction uses `behavior_chain.md` as system prompt, defining 4 chain types (data_flow, control_flow, resource_lifecycle, protocol_exchange) and 12 missing step categories (input_sanitization, bounds_check, origin_validation, access_control, output_encoding, resource_limit, cryptographic_verification, state_synchronization, error_handling, path_validation, identity_verification, protocol_validation).
- The detection pipeline (`detect_vulns.py`) uses progressive filtering: AST scan → domain classification (1 LLM call) → local pattern retrieval → local function scoring → per-function deep analysis (N LLM calls). Each run creates a `projects/YYYYMMDD_HHMMSS/` directory with source copy and report. Supports `--no-copy` to skip source copying and `--output` to override report path.
- Test case generation (`gen_testcases.py`) uses LLM + template combination: each of the 12 `missing_step_category` has an embedded Go test skeleton. LLM fills in specific malicious inputs, function call setup, and assertions. Generates both unit tests (same-package `_test.go`) and standalone PoC scripts (`package main`). For HTTP handler vulns, additionally generates HTTP PoC using `net/http/httptest`. Compiles generated code via `go vet` and reports pass/fail in `compile_report.json`. Supports `--project projects/<id>` to read source/report from a project directory and write testcases into it.



