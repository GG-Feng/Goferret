"""
Extract behavior chains from vulnerabilities using LLM with AST-enriched inputs.

Reads enriched inputs (enriched_inputs/) and classification results
(classifications_v2/), sends them along with behavior_chain.md prompt to the
configured LLM API, and saves structured behavior chains.

Usage:
    python behavior_chain_extract.py                              # extract all
    python behavior_chain_extract.py --limit 10                   # first 10 only
    python behavior_chain_extract.py --go-id GO-2020-0001         # single vuln
    python behavior_chain_extract.py --workers 3                  # concurrent requests
    python behavior_chain_extract.py --retry-failed               # re-attempt failures

Resumable: skips already-extracted vulns.
"""

import json
import os
import sys
import re
import time
import argparse
import signal
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_config import resolve_llm


# ── config ────────────────────────────────────────────────────────────

def load_env():
    """Parse .env file manually (no python-dotenv dependency)."""
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


# ── prompt ────────────────────────────────────────────────────────────

def load_system_prompt():
    """Load behavior_chain.md as the system prompt."""
    prompt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'behavior_chain.md')
    with open(prompt_path, encoding='utf-8') as f:
        return f.read()


def build_user_message(enriched_input, classification=None):
    """Build a structured user message with all available data."""
    parts = []

    # ── Vulnerability info ────────────────────────────────────────────
    parts.append("【漏洞信息】")
    parts.append(f"- ID: {enriched_input['go_id']}")
    parts.append(f"- 模块: {enriched_input['module_path']}")
    parts.append(f"- 描述: {enriched_input['description']}")
    if enriched_input.get('affected_symbols'):
        parts.append(f"- 受影响符号: {', '.join(enriched_input['affected_symbols'][:10])}")
    if enriched_input.get('go_versions'):
        parts.append(f"- 受影响版本: {enriched_input['go_versions']}")
    if enriched_input.get('changed_functions'):
        funcs = [f"{cf['file']}:{cf['function'][:60]}" for cf in enriched_input['changed_functions'][:6]]
        parts.append(f"- 变更函数: {'; '.join(funcs)}")
    parts.append("")

    # ── Classification result ─────────────────────────────────────────
    if classification and 'error' not in classification:
        parts.append("【分类结果】")
        parts.append(f"- 主功能域: {classification.get('primary_domain', '')}")
        parts.append(f"- 上下文域: {classification.get('context_domain', '')}")
        if classification.get('secondary_domains'):
            parts.append(f"- 次要域: {', '.join(classification['secondary_domains'])}")

        evidence = classification.get('evidence', {})
        if evidence.get('reasoning_summary'):
            parts.append(f"- 分类推理: {evidence['reasoning_summary']}")

        rationale = classification.get('classification_rationale', {})
        if rationale.get('why_primary'):
            parts.append(f"- 主域理由: {rationale['why_primary']}")
        parts.append("")

    # ── AST analysis ──────────────────────────────────────────────────
    ast = enriched_input.get('ast_analysis', {})
    has_ast_data = False

    if ast and ast.get('parse_mode') != 'unavailable':
        # Stdlib signals
        signals = ast.get('stdlib_signals', [])
        if signals:
            if not has_ast_data:
                parts.append("【静态分析结果】")
                has_ast_data = True
            for s in signals:
                apis = ', '.join((s.get('apis') or [])[:5])
                parts.append(f"- 标准库调用: {s['package']}.{apis}")
                if s.get('domain_hints'):
                    parts.append(f"  域信号提示: {', '.join(s['domain_hints'])}")

        # Call chains
        chains = ast.get('call_chains')
        if chains:
            if not has_ast_data:
                parts.append("【静态分析结果】")
                has_ast_data = True
            parts.append("")
            parts.append("- 调用链:")
            for cc in chains[:8]:
                calls_str = []
                for c in (cc.get('calls') or [])[:10]:
                    if c['type'] == 'stdlib':
                        calls_str.append(f"{c['callee']} (标准库)")
                    elif c['type'] == 'method':
                        calls_str.append(f"{c['callee']} (方法)")
                    elif c['type'] == 'local':
                        calls_str.append(f"{c['callee']} (同包)")
                    elif c['type'] == 'third_party':
                        calls_str.append(f"{c['callee']} (第三方)")
                    else:
                        calls_str.append(c['callee'])
                calls_text = ' → '.join(calls_str[:6])
                parts.append(f"  {cc['root_function']} → {calls_text}")

        # Data flow
        flows = ast.get('data_flow_indicators')
        if flows:
            if not has_ast_data:
                parts.append("【静态分析结果】")
                has_ast_data = True
            parts.append("")
            parts.append("- 数据流指标:")
            for df in flows[:5]:
                srcs = ', '.join(f"{s['type']}({s['pattern']})" for s in (df.get('sources') or [])[:3])
                snks = ', '.join(f"{s['type']}({s['pattern']})" for s in (df.get('sinks') or [])[:3])
                if srcs:
                    parts.append(f"  {df['function']}: 源=[{srcs}]")
                if snks:
                    parts.append(f"  {df['function']}: 汇=[{snks}]")

        # Concurrency patterns
        conc = ast.get('concurrency_patterns')
        if conc:
            if not has_ast_data:
                parts.append("【静态分析结果】")
                has_ast_data = True
            parts.append("")
            parts.append("- 并发模式:")
            for cp in conc[:5]:
                parts.append(f"  {cp['type']}: {cp['code']} ({cp['file']}:{cp['line']})")

        if has_ast_data:
            parts.append("")

    # ── Changed function sources ──────────────────────────────────────
    func_sources = enriched_input.get('func_sources', [])
    if func_sources:
        parts.append("【变更函数源码】")
        for fs in func_sources[:6]:
            source = fs['source']
            if len(source) > 2000:
                source = source[:2000] + "\n// ... (truncated)"
            parts.append(f"// {fs['file']}: {fs['function']}")
            parts.append(source)
            parts.append("")

    # ── Patch diff ────────────────────────────────────────────────────
    diff = enriched_input.get('patch_diff', '')
    if diff:
        parts.append("【补丁 Diff】")
        if len(diff) > 4000:
            diff = diff[:4000] + "\n// ... (truncated)"
        parts.append(diff)

    return '\n'.join(parts)


# ── Validation ────────────────────────────────────────────────────────

def validate_behavior_chain(result, go_id):
    """Validate and fix the behavior chain output structure."""
    errors = []

    chain = result.get('behavior_chain')
    if not chain or not isinstance(chain, dict):
        errors.append("missing or invalid behavior_chain")
        return errors

    steps = chain.get('steps', [])
    if not isinstance(steps, list):
        errors.append("steps is not a list")
        return errors

    if len(steps) < 2:
        errors.append("chain must have at least 2 steps")
    if len(steps) > 8:
        errors.append("chain must have at most 8 steps, got " + str(len(steps)))

    missing_steps = [s for s in steps if isinstance(s, dict) and s.get('is_missing_step')]
    if len(missing_steps) == 0:
        errors.append("chain must have exactly one MISSING step")
    elif len(missing_steps) > 1:
        errors.append("chain must have exactly one MISSING step, found " + str(len(missing_steps)))

    for s in steps:
        if isinstance(s, dict) and not s.get('action'):
            errors.append(f"step {s.get('step_id', '?')} missing action")

    return errors


# ── API call ──────────────────────────────────────────────────────────


def extract_one(api_cfg, system_prompt, enriched_input, classification, retries=3):
    """Send one vuln to the LLM and return parsed behavior chain."""
    url = api_cfg['LLM_BASE_URL'] + '/chat/completions'
    headers = {
        'Authorization': 'Bearer ' + api_cfg['LLM_API_KEY'],
        'Content-Type': 'application/json',
    }

    user_content = build_user_message(enriched_input, classification)

    max_tokens = 8192
    content = ''
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
            }

            r = requests.post(url, headers=headers, json=payload, timeout=600)

            if r.status_code == 429:
                wait = min(30, 5 * (attempt + 1))
                print(f"    [429 rate limited, waiting {wait}s]", flush=True)
                time.sleep(wait)
                continue

            if r.status_code != 200:
                return None, f"HTTP {r.status_code}: {r.text[:300]}"

            data = r.json()
            finish_reason = data['choices'][0].get('finish_reason', '')
            msg = data['choices'][0]['message']
            content = msg.get('content', '') or ''
            if not content.strip():
                content = msg.get('reasoning_content', '') or ''

            if not content.strip():
                return None, f"empty response, finish_reason={finish_reason}"

            content = content.strip()
            if content.startswith('```'):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
                content = content.strip()

            # If truncated by max_tokens, retry with larger limit
            if finish_reason == 'length' and attempt < retries - 1:
                max_tokens = min(max_tokens * 2, 32768)
                print(f"    [truncated at {finish_reason}, retrying with max_tokens={max_tokens}]", flush=True)
                time.sleep(2)
                continue

            result = json.loads(content)

            # Add metadata
            result['go_id'] = enriched_input.get('go_id', '')
            result['module_path'] = enriched_input.get('module_path', '')
            if classification and 'error' not in classification:
                result['primary_domain'] = classification.get('primary_domain', '')

            # Fill data_availability
            ast = enriched_input.get('ast_analysis', {})
            result['data_availability'] = {
                'has_func_sources': bool(enriched_input.get('func_sources')),
                'has_ast_call_chains': bool(ast.get('call_chains')),
                'has_ast_data_flow': bool(ast.get('data_flow_indicators')),
                'has_classification': classification is not None and 'error' not in (classification or {}),
                'has_diff': bool(enriched_input.get('patch_diff')),
            }

            # Validate
            validation_errors = validate_behavior_chain(result, result['go_id'])
            if validation_errors:
                result['_validation_warnings'] = validation_errors

            return result, None

        except json.JSONDecodeError as e:
            m = re.search(r'\{[\s\S]*\}', content)
            if m:
                try:
                    result = json.loads(m.group())
                    result['go_id'] = enriched_input.get('go_id', '')
                    result['module_path'] = enriched_input.get('module_path', '')
                    return result, None
                except json.JSONDecodeError:
                    pass
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None, f"JSON parse error: {e}, raw: {content[:200]}"
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                print(f"    [timeout, retry {attempt+1}]", flush=True)
                time.sleep(3)
                continue
            return None, "request timed out"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None, str(e)

    return None, "max retries exceeded"


# ── main ──────────────────────────────────────────────────────────────

interrupted = False


def _signal_handler(sig, frame):
    global interrupted
    if interrupted:
        print("\n[FORCE EXIT]")
        sys.exit(1)
    interrupted = True
    print("\n[INTERRUPT] Stopping after current requests...")


def main():
    global interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Extract behavior chains from vulns using LLM")
    parser.add_argument("--go-id", type=str, help="Single GO-ID to process")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process")
    parser.add_argument("--input-dir", default="enriched_inputs", help="Dir with enriched inputs")
    parser.add_argument("--classification-dir", default="classifications_v2", help="Dir with classifications")
    parser.add_argument("--output-dir", default="behavior_chains", help="Output directory")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent API requests")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--retry-failed", action="store_true", help="Re-extract failed entries")
    args = parser.parse_args()

    cfg = load_env()
    for key in ('LLM_API_KEY', 'LLM_BASE_URL', 'LLM_MODEL'):
        if key not in cfg or not cfg[key]:
            print(f"Error: {key} not set in .env", file=sys.stderr)
            sys.exit(1)

    system_prompt = load_system_prompt()
    os.makedirs(args.output_dir, exist_ok=True)

    # Collect tasks
    if args.go_id:
        tasks = [args.go_id]
    else:
        input_files = sorted(f.replace('.json', '') for f in os.listdir(args.input_dir) if f.endswith('.json'))
        tasks = input_files

    if args.limit:
        tasks = tasks[:args.limit]

    # Filter out already completed
    pending = []
    for go_id in tasks:
        out_path = os.path.join(args.output_dir, f"{go_id}.json")
        if os.path.isfile(out_path):
            if not args.retry_failed:
                try:
                    with open(out_path, encoding='utf-8') as f:
                        existing = json.load(f)
                    if 'error' not in existing:
                        continue
                except Exception:
                    pass
        pending.append(go_id)

    print(f"Total: {len(tasks)}, Already done: {len(tasks) - len(pending)}, Pending: {len(pending)}")
    print(f"Model: {cfg['LLM_MODEL']}")
    print(f"Workers: {args.workers}")
    print(f"Output: {os.path.abspath(args.output_dir)}")
    print()

    if not pending:
        print("Nothing to do.")
        return

    results = {'ok': 0, 'failed': 0}
    overall_start = time.time()

    def process(go_id):
        input_path = os.path.join(args.input_dir, f"{go_id}.json")
        if not os.path.isfile(input_path):
            return go_id, None, "input file not found"

        with open(input_path, encoding='utf-8') as f:
            enriched_input = json.load(f)

        # Load classification if available
        classification = None
        classif_path = os.path.join(args.classification_dir, f"{go_id}.json")
        if os.path.isfile(classif_path):
            try:
                with open(classif_path, encoding='utf-8') as f:
                    classification = json.load(f)
            except Exception:
                pass

        chain_result, err = extract_one(cfg, system_prompt, enriched_input, classification)

        if chain_result is not None:
            out_path = os.path.join(args.output_dir, f"{go_id}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(chain_result, f, indent=2, ensure_ascii=False)

            pattern = chain_result.get('vulnerability_pattern', {}).get('pattern_name', '?')
            chain_type = chain_result.get('behavior_chain', {}).get('chain_type', '?')
            return go_id, chain_result, f"{pattern} ({chain_type})"
        else:
            err_entry = {
                'go_id': go_id,
                'module_path': enriched_input.get('module_path', ''),
                'error': err,
            }
            out_path = os.path.join(args.output_dir, f"{go_id}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(err_entry, f, indent=2, ensure_ascii=False)
            return go_id, None, err

    if args.workers <= 1:
        for i, go_id in enumerate(pending):
            if interrupted:
                print(f"\n[INTERRUPT] {len(pending) - i} remaining.")
                break

            gid, result, msg = process(go_id)
            if result:
                print(f"[{i+1}/{len(pending)}] {gid} -> {msg}")
                results['ok'] += 1
            else:
                print(f"[{i+1}/{len(pending)}] {gid} FAILED: {msg}")
                results['failed'] += 1

            if args.delay > 0 and i < len(pending) - 1:
                time.sleep(args.delay)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            for i, go_id in enumerate(pending):
                if interrupted:
                    break
                futures[executor.submit(process, go_id)] = go_id
                if i < len(pending) - 1 and args.delay > 0:
                    time.sleep(args.delay * 0.5)

            done_count = 0
            for future in as_completed(futures):
                if interrupted:
                    break
                done_count += 1
                gid, result, msg = future.result()
                if result:
                    print(f"[{done_count}/{len(pending)}] {gid} -> {msg}")
                    results['ok'] += 1
                else:
                    print(f"[{done_count}/{len(pending)}] {gid} FAILED: {msg}")
                    results['failed'] += 1

    elapsed = time.time() - overall_start
    print()
    print("=" * 50)
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {elapsed:.1f}s")
    print(f"  Extracted: {results['ok']}")
    print(f"  Failed:    {results['failed']}")
    if results['ok'] > 0:
        print(f"  Avg time:  {elapsed / results['ok']:.1f}s per vuln")


if __name__ == "__main__":
    main()
