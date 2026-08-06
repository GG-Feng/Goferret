"""
Classify vulnerabilities using LLM functional domain classifier.

Reads prepared inputs (from prepare_input.py), sends them along with
classification.md prompt to the configured LLM API, and saves results.

Usage:
    python classify_vulns.py                              # classify all
    python classify_vulns.py --limit 10                   # first 10 only
    python classify_vulns.py --go-id GO-2020-0001         # single vuln
    python classify_vulns.py --input-dir prepared_inputs  # custom input dir
    python classify_vulns.py --output-dir classifications # custom output dir
    python classify_vulns.py --workers 3                  # concurrent requests

Resumable: skips already-classified vulns.
"""

import json
import os
import sys
import re
import time
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    return cfg


# ── prompt ────────────────────────────────────────────────────────────

def load_system_prompt():
    """Load classification.md as the system prompt."""
    prompt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'classification.md')
    with open(prompt_path, encoding='utf-8') as f:
        return f.read()


# ── API call ──────────────────────────────────────────────────────────

import requests

_session = None


def get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({
            'Content-Type': 'application/json',
        })
    return _session


def classify_one(api_cfg, system_prompt, vuln_input, retries=3):
    """Send one vuln to the LLM and return parsed classification."""
    url = api_cfg['ARK_BASE_URL'] + '/v1/chat/completions'
    headers = {
        'Authorization': 'Bearer ' + api_cfg['ARK_API_KEY'],
        'Content-Type': 'application/json',
    }

    user_content = json.dumps(vuln_input, ensure_ascii=False)

    payload = {
        'model': api_cfg['ARK_MODEL'],
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_content},
        ],
        'temperature': 0.1,
        'max_tokens': 2048,
    }

    for attempt in range(retries):
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=120)

            if r.status_code == 429:
                wait = min(30, 5 * (attempt + 1))
                print(f"    [429 rate limited, waiting {wait}s]", flush=True)
                time.sleep(wait)
                continue

            if r.status_code != 200:
                return None, f"HTTP {r.status_code}: {r.text[:300]}"

            data = r.json()
            content = data['choices'][0]['message']['content']

            # Parse JSON from response — handle possible markdown wrapping
            content = content.strip()
            if content.startswith('```'):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
                content = content.strip()

            result = json.loads(content)
            return result, None

        except json.JSONDecodeError as e:
            # Try to extract JSON from surrounding text
            m = re.search(r'\{[\s\S]*\}', content if 'content' in dir() else '')
            if m:
                try:
                    result = json.loads(m.group())
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

    parser = argparse.ArgumentParser(description="Classify vulns using LLM")
    parser.add_argument("--go-id", type=str, help="Single GO-ID to classify")
    parser.add_argument("--limit", type=int, default=None, help="Max vulns to process")
    parser.add_argument("--input-dir", default="prepared_inputs", help="Dir with prepared inputs")
    parser.add_argument("--output-dir", default="classifications", help="Output directory")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent API requests")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--retry-failed", action="store_true", help="Re-classify failed entries")
    args = parser.parse_args()

    cfg = load_env()
    for key in ('ARK_API_KEY', 'ARK_BASE_URL', 'ARK_MODEL'):
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

    # Filter out already completed (unless --retry-failed)
    pending = []
    for go_id in tasks:
        out_path = os.path.join(args.output_dir, f"{go_id}.json")
        if os.path.isfile(out_path):
            if not args.retry_failed:
                # Check if it was a failed attempt
                try:
                    with open(out_path, encoding='utf-8') as f:
                        existing = json.load(f)
                    if 'error' not in existing:
                        continue  # successfully classified, skip
                except Exception:
                    pass
        pending.append(go_id)

    print(f"Total: {len(tasks)}, Already done: {len(tasks) - len(pending)}, Pending: {len(pending)}")
    print(f"Model: {cfg['ARK_MODEL']}")
    print(f"Workers: {args.workers}")
    print(f"Output: {os.path.abspath(args.output_dir)}")
    print()

    if not pending:
        print("Nothing to do.")
        return

    results = {'ok': 0, 'failed': 0, 'skipped': 0}
    overall_start = time.time()

    def process(go_id):
        input_path = os.path.join(args.input_dir, f"{go_id}.json")
        if not os.path.isfile(input_path):
            return go_id, None, "input file not found"

        with open(input_path, encoding='utf-8') as f:
            vuln_input = json.load(f)

        classification, err = classify_one(cfg, system_prompt, vuln_input)

        if classification is not None:
            # Merge input metadata into output for traceability
            classification['go_id'] = go_id
            classification['module_path'] = vuln_input.get('module_path', '')
            out_path = os.path.join(args.output_dir, f"{go_id}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(classification, f, indent=2, ensure_ascii=False)
            return go_id, classification, None
        else:
            # Save error for resumability tracking
            err_entry = {
                'go_id': go_id,
                'module_path': vuln_input.get('module_path', ''),
                'error': err,
            }
            out_path = os.path.join(args.output_dir, f"{go_id}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(err_entry, f, indent=2, ensure_ascii=False)
            return go_id, None, err

    if args.workers <= 1:
        # Sequential
        for i, go_id in enumerate(pending):
            if interrupted:
                print(f"\n[INTERRUPT] {len(pending) - i} remaining.")
                break

            gid, result, err = process(go_id)
            if result:
                print(f"[{i+1}/{len(pending)}] {gid} -> {result.get('primary_domain', '?')}")
                results['ok'] += 1
            else:
                print(f"[{i+1}/{len(pending)}] {gid} FAILED: {err}")
                results['failed'] += 1

            if args.delay > 0 and i < len(pending) - 1:
                time.sleep(args.delay)
    else:
        # Parallel
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            for i, go_id in enumerate(pending):
                if interrupted:
                    break
                futures[executor.submit(process, go_id)] = go_id
                # Stagger initial submissions
                if i < len(pending) - 1 and args.delay > 0:
                    time.sleep(args.delay * 0.5)

            done_count = 0
            for future in as_completed(futures):
                if interrupted:
                    break
                done_count += 1
                gid, result, err = future.result()
                if result:
                    print(f"[{done_count}/{len(pending)}] {gid} -> {result.get('primary_domain', '?')}")
                    results['ok'] += 1
                else:
                    print(f"[{done_count}/{len(pending)}] {gid} FAILED: {err}")
                    results['failed'] += 1

    elapsed = time.time() - overall_start
    print()
    print("=" * 50)
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {elapsed:.1f}s")
    print(f"  Classified: {results['ok']}")
    print(f"  Failed:     {results['failed']}")
    print(f"  Skipped:    {results['skipped']}")
    if results['ok'] > 0:
        print(f"  Avg time:   {elapsed / results['ok']:.1f}s per vuln")


if __name__ == "__main__":
    main()
