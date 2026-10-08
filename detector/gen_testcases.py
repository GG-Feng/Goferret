"""
Generate test cases for detected vulnerabilities using LLM + templates.

Reads report.json from detect_vulns.py, loads target function sources,
selects category-specific test templates, calls LLM to generate concrete
Go unit tests and PoC scripts, then verifies compilation.

Usage:
    python gen_testcases.py --target /path/to/go/project
    python gen_testcases.py --target . --report report.json
    python gen_testcases.py --target . --limit 5 --workers 3
    python gen_testcases.py --target . --retry-failed
    python gen_testcases.py --target . --skip-compile

Resumable: skips already-generated findings.
"""

import json
import os
import sys
import re
import hashlib
import time
import argparse
import signal
import subprocess
import tempfile
import shutil
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_config import resolve_llm


# ── config ────────────────────────────────────────────────────────────

def load_env():
    """Parse .env file manually."""
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
    """Load gen_testcase.md as the system prompt."""
    prompt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen_testcase.md')
    with open(prompt_path, encoding='utf-8') as f:
        return f.read()


# ── test templates per missing_step_category ──────────────────────────

TEMPLATES = {}

TEMPLATES['input_sanitization'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}InputSanitization verifies missing input sanitization.
// Missing step: input_sanitization
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}InputSanitization(t *testing.T) {
    tests := []struct {
        name    string
        input   {{INPUT_TYPE}}
        wantErr bool
    }{
        {name: "sql_injection", input: {{INPUT_1}}, wantErr: false},
        {name: "command_injection", input: {{INPUT_2}}, wantErr: false},
        {name: "format_string", input: {{INPUT_3}}, wantErr: false},
        {name: "normal_input", input: {{NORMAL_INPUT}}, wantErr: false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            {{FUNCTION_CALL_SETUP}}
            // Bug: function does NOT reject malicious input
            _ = result
            _ = err
        })
    }
}'''

TEMPLATES['bounds_check'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}BoundsCheck verifies missing bounds checking.
// Missing step: bounds_check
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}BoundsCheck(t *testing.T) {
    t.Run("oversized_input", func(t *testing.T) {
        input := {{OVERSIZED_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Function accepted oversized input without bounds check")
    })

    t.Run("boundary_value", func(t *testing.T) {
        input := {{BOUNDARY_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("Result for boundary input: %v", result)
    })

    t.Run("negative_index", func(t *testing.T) {
        input := {{NEGATIVE_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] No bounds validation on: %v", input)
    })
}'''

TEMPLATES['origin_validation'] = '''package {{PACKAGE}}

import (
    "net/http"
    "net/http/httptest"
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}OriginValidation verifies missing origin validation.
// Missing step: origin_validation
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}OriginValidation(t *testing.T) {
    tests := []struct {
        name   string
        method string
        path   string
        headers map[string]string
    }{
        {name: "cross_origin_no_csrf", method: "POST", path: {{PATH}},
         headers: map[string]string{"Origin": "https://evil.com"}},
        {name: "spoofed_referer", method: "POST", path: {{PATH}},
         headers: map[string]string{"Referer": "https://evil.com"}},
        {name: "no_origin_header", method: "POST", path: {{PATH}},
         headers: map[string]string{}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            req := httptest.NewRequest(tt.method, tt.path, nil)
            for k, v := range tt.headers {
                req.Header.Set(k, v)
            }
            rec := httptest.NewRecorder()
            {{HANDLER_INVOCATION}}
            // Bug: handler does NOT validate request origin
            t.Logf("[VULNERABLE] Request from untrusted origin accepted, status=%d", rec.Code)
        })
    }
}'''

TEMPLATES['access_control'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}AccessControl verifies missing access control.
// Missing step: access_control
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}AccessControl(t *testing.T) {
    t.Run("unprivileged_user", func(t *testing.T) {
        {{SETUP_LOW_PRIVILEGE}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: function does NOT check permissions
        t.Logf("[VULNERABLE] Unprivileged user can perform operation")
    })

    t.Run("expired_session", func(t *testing.T) {
        {{SETUP_EXPIRED_SESSION}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Expired session still has access")
    })
}'''

TEMPLATES['output_encoding'] = '''package {{PACKAGE}}

import (
    "strings"
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}OutputEncoding verifies missing output encoding.
// Missing step: output_encoding
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}OutputEncoding(t *testing.T) {
    tests := []struct {
        name             string
        input            {{INPUT_TYPE}}
        shouldNotContain []string
    }{
        {name: "newline_injection", input: {{NEWLINE_INPUT}},
         shouldNotContain: []string{"\\n", "\\r"}},
        {name: "html_special_chars", input: {{HTML_INPUT}},
         shouldNotContain: []string{"<", ">", "&"}},
        {name: "shell_metacharacters", input: {{SHELL_INPUT}},
         shouldNotContain: []string{";", "|", "`"}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            {{FUNCTION_CALL_SETUP}}
            output := {{OUTPUT_EXPRESSION}}
            for _, forbidden := range tt.shouldNotContain {
                if strings.Contains(output, forbidden) {
                    t.Logf("[VULNERABLE] Output contains unescaped '%s'", forbidden)
                }
            }
        })
    }
}'''

TEMPLATES['resource_limit'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}ResourceLimit verifies missing resource limits.
// Missing step: resource_limit
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}ResourceLimit(t *testing.T) {
    t.Run("oversized_allocation", func(t *testing.T) {
        input := {{OVERSIZED_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: no resource limit enforced
        t.Logf("[VULNERABLE] Function processed oversized input without limit")
    })

    t.Run("deeply_nested_input", func(t *testing.T) {
        input := {{NESTED_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Deep nesting accepted without depth limit")
    })
}'''

TEMPLATES['cryptographic_verification'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}CryptoVerification verifies missing cryptographic verification.
// Missing step: cryptographic_verification
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}CryptoVerification(t *testing.T) {
    t.Run("tampered_signature", func(t *testing.T) {
        {{SETUP_TAMPERED_DATA}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: function does NOT verify signature
        t.Logf("[VULNERABLE] Tampered data accepted without signature check")
    })

    t.Run("expired_certificate", func(t *testing.T) {
        {{SETUP_EXPIRED_CERT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Expired certificate accepted")
    })
}'''

TEMPLATES['state_synchronization'] = '''package {{PACKAGE}}

import (
    "sync"
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}StateSync verifies missing state synchronization.
// Missing step: state_synchronization
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}StateSync(t *testing.T) {
    t.Run("concurrent_write_race", func(t *testing.T) {
        {{SETUP_SHARED_STATE}}
        var wg sync.WaitGroup
        for i := 0; i < {{CONCURRENCY_COUNT}}; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                {{FUNCTION_CALL_SETUP}}
            }()
        }
        wg.Wait()
        // Bug: no proper locking, race condition possible
        t.Logf("[VULNERABLE] Concurrent access without synchronization")
    })
}'''

TEMPLATES['error_handling'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}ErrorHandling verifies missing error handling.
// Missing step: error_handling
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}ErrorHandling(t *testing.T) {
    t.Run("nil_input_no_check", func(t *testing.T) {
        {{FUNCTION_CALL_SETUP_NIL}}
        // Bug: error return is not checked
        t.Logf("[VULNERABLE] Error not checked for nil input")
    })

    t.Run("corrupted_data_no_check", func(t *testing.T) {
        input := {{CORRUPTED_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: function continues despite error
        t.Logf("[VULNERABLE] Corrupted data processed without error check")
    })
}'''

TEMPLATES['path_validation'] = '''package {{PACKAGE}}

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}PathValidation verifies missing path validation.
// Missing step: path_validation
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}PathValidation(t *testing.T) {
    baseDir := t.TempDir()

    tests := []struct {
        name  string
        input string
    }{
        {name: "parent_traversal", input: "../../../etc/passwd"},
        {name: "dot_dot_slash", input: "..\\..\\windows\\system32"},
        {name: "absolute_path", input: "/etc/shadow"},
        {name: "null_byte", input: "safe.txt\\x00../../etc/passwd"},
        {name: "normal_path", input: "subdir/file.txt"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            {{FUNCTION_CALL_SETUP}}
            resolved := {{RESOLVED_PATH}}
            absResolved, _ := filepath.Abs(resolved)
            absBase, _ := filepath.Abs(baseDir)
            if !strings.HasPrefix(absResolved, absBase) {
                t.Logf("[VULNERABLE] Path escapes base dir: %s -> %s",
                    tt.input, absResolved)
            }
        })
    }
}'''

TEMPLATES['identity_verification'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}IdentityVerification verifies missing identity verification.
// Missing step: identity_verification
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}IdentityVerification(t *testing.T) {
    t.Run("forged_token", func(t *testing.T) {
        {{SETUP_FORGED_TOKEN}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: function does NOT verify token authenticity
        t.Logf("[VULNERABLE] Forged token accepted without verification")
    })

    t.Run("empty_credentials", func(t *testing.T) {
        {{SETUP_EMPTY_CREDS}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Empty credentials accepted")
    })
}'''

TEMPLATES['protocol_validation'] = '''package {{PACKAGE}}

import (
    "testing"
    {{ADDITIONAL_IMPORTS}}
)

// Test{{TEST_NAME}}ProtocolValidation verifies missing protocol validation.
// Missing step: protocol_validation
// CWE: {{CWE_LIST}}
func Test{{TEST_NAME}}ProtocolValidation(t *testing.T) {
    t.Run("malformed_message", func(t *testing.T) {
        input := {{MALFORMED_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        // Bug: function does NOT validate protocol format
        t.Logf("[VULNERABLE] Malformed protocol message accepted")
    })

    t.Run("missing_required_field", func(t *testing.T) {
        input := {{MISSING_FIELD_INPUT}}
        {{FUNCTION_CALL_SETUP}}
        t.Logf("[VULNERABLE] Message with missing required field accepted")
    })
}'''

# PoC template (generic)
POC_TEMPLATE = '''package main

import (
    "fmt"
    {{ADDITIONAL_IMPORTS}}
)

// PoC for {{PATTERN_NAME}} in {{FUNCTION_NAME}}
// Vulnerability: {{MISSING_STEP_CATEGORY}} is missing
// Attack vector: {{ATTACK_VECTOR}}

func main() {
    fmt.Println("=== PoC: {{PATTERN_NAME}} ===")
    fmt.Println("Missing security step: {{MISSING_STEP_CATEGORY}}")
    {{POC_BODY}}
    fmt.Println("[VULNERABLE] Exploit succeeded")
}'''

# PoC template (HTTP-specific)
HTTP_POC_TEMPLATE = '''package main

import (
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    {{ADDITIONAL_IMPORTS}}
)

// HTTP PoC for {{PATTERN_NAME}} in {{FUNCTION_NAME}}
// Vulnerability: {{MISSING_STEP_CATEGORY}} is missing

func main() {
    fmt.Println("=== HTTP PoC: {{PATTERN_NAME}} ===")

    {{POC_SETUP_SERVER}}

    maliciousPayload := {{MALICIOUS_PAYLOAD}}
    req, _ := http.NewRequest("{{HTTP_METHOD}}", server.URL+"{{HTTP_PATH}}", nil)
    {{SETUP_HEADERS}}

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Fatalf("Request failed: %v", err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Status: %d\\n", resp.StatusCode)
    fmt.Printf("Response: %s\\n", body)
    fmt.Println("[VULNERABLE] Exploit succeeded")
}'''


def get_template(category):
    """Get unit test template and PoC template for a category."""
    if category == 'other_security':
        return ('Write a case-specific Go test. Derive its trigger and expected security '
                'property from the verified evidence. Assert an observable result; a log '
                'line or successful compilation alone is not a vulnerability proof.',
                POC_TEMPLATE, HTTP_POC_TEMPLATE)
    unit_tpl = TEMPLATES.get(category, TEMPLATES.get('input_sanitization'))
    return unit_tpl, POC_TEMPLATE, HTTP_POC_TEMPLATE


# ── project info ──────────────────────────────────────────────────────

def resolve_project_info(target_dir):
    """Read go.mod to get module path."""
    info = {'module_path': '', 'go_version': ''}
    go_mod = os.path.join(target_dir, 'go.mod')
    if os.path.isfile(go_mod):
        with open(go_mod, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('module '):
                    info['module_path'] = line.split(' ', 1)[1].strip()
                elif line.startswith('go '):
                    info['go_version'] = line.split(' ', 1)[1].strip()
    return info


def get_package_name(target_dir, file_path):
    """Extract package name from a Go source file."""
    full_path = os.path.join(target_dir, file_path)
    if not os.path.isfile(full_path):
        return 'main'
    try:
        with open(full_path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = re.match(r'^\s*package\s+(\w+)', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return 'main'


# ── function source extraction ────────────────────────────────────────

_ENHANCED_TEST_CONTEXT = None

def extract_function_source(target_dir, file_path, function_name, function_id=None):
    """Extract source code for a specific function. Adapted from detect_vulns.py."""
    if _ENHANCED_TEST_CONTEXT is not None:
        if function_id is None:
            ids = _ENHANCED_TEST_CONTEXT.ids_for_key(f'{file_path}:{function_name}')
            function_id = ids[0] if len(ids) == 1 else None
        f = _ENHANCED_TEST_CONTEXT.functions.get(function_id)
        if f and f['file'] == file_path:
            return _ENHANCED_TEST_CONTEXT.reference(file_path, f['line'], f['end_line'])['snippet']
        return None
    source_path = os.path.join(target_dir, file_path)
    if not os.path.isfile(source_path):
        return None

    try:
        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return None

    name_escaped = re.escape(function_name)
    patterns = [
        re.compile(r'^func\s+\(.*?\)\s+' + name_escaped + r'\s*\('),
        re.compile(r'^func\s+' + name_escaped + r'\s*\('),
        re.compile(r'^var\s+' + name_escaped + r'\s*=\s*func\s*\('),
    ]

    for pattern in patterns:
        for i, line in enumerate(lines):
            if pattern.search(line):
                depth = 0
                start = i
                for j in range(i, len(lines)):
                    depth += lines[j].count('{') - lines[j].count('}')
                    if depth == 0 and j > i:
                        return ''.join(lines[start:j + 1]).rstrip()
                break

    return None


# ── finding ID ────────────────────────────────────────────────────────

def make_finding_id(finding):
    """Generate a stable short ID for a finding."""
    if finding.get("finding_id"):
        return finding["finding_id"]
    key = f"{finding.get('function', '')}:{finding.get('pattern_name', '')}:{finding.get('missing_step_category', '')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


# ── build user message ────────────────────────────────────────────────

def build_user_message(finding, func_source, unit_template, poc_template, http_poc_template, project_info, pkg_name):
    """Build structured user message for the LLM."""
    parts = []

    # Finding info
    parts.append("【漏洞发现信息】")
    parts.append(f"- 函数: {finding.get('function', '')}")
    parts.append(f"- 模式: {finding.get('pattern_name', '')}")
    parts.append(f"- 置信度: {finding.get('confidence', 0)}")
    parts.append(f"- 严重度: {finding.get('severity', '')} (CVSS {finding.get('cvss_score', '?')}: {finding.get('cvss_vector', '')})")
    parts.append(f"- 缺失步骤类别: {finding.get('missing_step_category', '')}")
    parts.append(f"- CWE: {', '.join(finding.get('cwe_alignment', []))}")
    parts.append(f"- 推理: {finding.get('reasoning', '')}")
    parts.append(f"- 证据: {finding.get('evidence', '')}")
    parts.append("")

    # Function source
    if func_source:
        parts.append("【函数源码】")
        source = func_source
        if len(source) > 3000:
            source = source[:3000] + "\n// ... (truncated)"
        parts.append(source)
        parts.append("")

    # Template skeletons
    category = finding.get('missing_step_category', 'input_sanitization')
    parts.append("【单元测试模板骨架】")
    parts.append(unit_template)
    parts.append("")
    parts.append("【PoC 模板骨架】")
    parts.append(poc_template)
    parts.append("")

    # Check if HTTP-related
    evidence = finding.get('evidence', '')
    if not isinstance(evidence, str):
        evidence = json.dumps(evidence, ensure_ascii=False)
    evidence_text = (evidence + ' ' + str(finding.get('reasoning', ''))).lower()
    func_name = finding.get('function', '').lower()
    http_keywords = ['http.handler', 'http.handlerfunc', 'http.request', 'gin.context',
                     'echo.context', 'httptest', 'servehttp', 'handler', 'router',
                     'net/http', 'http.handle']
    is_http = any(kw in evidence_text or kw in func_name for kw in http_keywords)
    if is_http:
        parts.append("【HTTP PoC 模板骨架】（该漏洞涉及 HTTP handler，请额外生成 HTTP PoC）")
        parts.append(http_poc_template)
        parts.append("")

    # Project info
    parts.append("【项目包信息】")
    parts.append(f"- module path: {project_info.get('module_path', '')}")
    parts.append(f"- package: {pkg_name}")
    parts.append(f"- go version: {project_info.get('go_version', '1.21')}")
    parts.append(f"- is_http_vuln: {is_http}")

    return '\n'.join(parts)


# ── LLM API call ─────────────────────────────────────────────────────

def generate_one(api_cfg, system_prompt, finding, func_source, unit_template,
                 poc_template, http_poc_template, project_info, pkg_name,
                 finding_id, retries=3):
    """Call LLM to generate test cases for one finding."""
    url = api_cfg['LLM_BASE_URL'] + '/chat/completions'
    headers = {
        'Authorization': 'Bearer ' + api_cfg['LLM_API_KEY'],
        'Content-Type': 'application/json',
    }

    user_content = build_user_message(
        finding, func_source, unit_template, poc_template, http_poc_template,
        project_info, pkg_name
    )

    payload = {
        'model': api_cfg['LLM_MODEL'],
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_content},
        ],
        'temperature': 0.1,
        'max_tokens': 16384,
    }

    content = ''
    for attempt in range(retries):
        try:
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
            raw_content = msg.get('content', '') or ''
            reasoning = msg.get('reasoning_content', '') or ''

            # Try to parse content first (contains structured output)
            # If content is empty or not JSON, try reasoning_content
            for text in [raw_content, reasoning]:
                if not text or not text.strip():
                    continue
                text = text.strip()
                if text.startswith('```'):
                    text = re.sub(r'^```\w*\n?', '', text)
                    text = re.sub(r'\n?```$', '', text)
                    text = text.strip()
                try:
                    result = json.loads(text)
                    result['finding_id'] = finding_id
                    result['finding_function'] = finding.get('function', '')
                    result['missing_step_category'] = finding.get('missing_step_category', '')
                    return result, None
                except json.JSONDecodeError:
                    # Try to extract JSON block from text
                    m = re.search(r'\{[\s\S]*\}', text)
                    if m:
                        try:
                            result = json.loads(m.group())
                            result['finding_id'] = finding_id
                            result['finding_function'] = finding.get('function', '')
                            result['missing_step_category'] = finding.get('missing_step_category', '')
                            return result, None
                        except json.JSONDecodeError:
                            pass
                    content = text  # Save for error message

            if not raw_content.strip() and not reasoning.strip():
                return None, f"empty response, finish_reason={finish_reason}"

            # If truncated, retry with larger max_tokens
            if finish_reason == 'length' and attempt < retries - 1:
                new_max = min(payload['max_tokens'] * 2, 32768)
                payload['max_tokens'] = new_max
                print(f"    [truncated, retrying with max_tokens={new_max}]", flush=True)
                time.sleep(2)
                continue

            return None, f"JSON parse error, raw content (first 300 chars): {(raw_content or reasoning)[:300]}"

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


# ── save outputs ──────────────────────────────────────────────────────

def save_outputs(output_dir, project_name, finding_id, result, finding):
    """Save generated test files and update metadata."""
    base = os.path.join(output_dir, project_name)
    unit_dir = os.path.join(base, 'unit')
    poc_dir = os.path.join(base, 'poc')
    os.makedirs(unit_dir, exist_ok=True)
    os.makedirs(poc_dir, exist_ok=True)

    saved = {'finding_id': finding_id, 'function': finding.get('function', ''),
             'pattern_name': finding.get('pattern_name', ''),
             'category': finding.get('missing_step_category', ''),
             'severity': finding.get('severity', ''),
             'cvss_score': finding.get('cvss_score'),
             'cvss_vector': finding.get('cvss_vector'),
             'files': []}

    # Unit test
    unit = result.get('unit_test', {})
    if unit.get('source'):
        # Match metadata identity so verification finds the generated unit.
        fname = f'{finding_id}_test.go'
        fpath = os.path.join(unit_dir, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(unit['source'])
        saved['files'].append(f'unit/{fname}')

    # PoC
    poc = result.get('poc', {})
    if poc.get('source'):
        fname = f'poc_{finding_id}.go'
        fpath = os.path.join(poc_dir, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(poc['source'])
        saved['files'].append(f'poc/{fname}')

    # HTTP PoC
    if poc.get('is_http_poc') and poc.get('http_poc_source'):
        fname = f'poc_{finding_id}_http.go'
        fpath = os.path.join(poc_dir, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(poc['http_poc_source'])
        saved['files'].append(f'poc/{fname}')

    saved['generation_notes'] = result.get('generation_notes', '')

    # Update metadata
    meta_path = os.path.join(base, 'metadata.json')
    metadata = {}
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding='utf-8') as f:
                metadata = json.load(f)
        except Exception:
            pass

    if 'entries' not in metadata:
        metadata['entries'] = {}
    metadata['entries'][finding_id] = saved

    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return saved


# ── compilation verification ──────────────────────────────────────────

def find_go_path():
    """Find the go executable."""
    go_path = shutil.which('go')
    return go_path


def verify_compilation(output_dir, project_name, target_dir, go_path):
    """Run go vet on generated files and report compilation status."""
    if not go_path:
        print("  [SKIP] go executable not found, skipping compilation verification")
        return None

    base = os.path.join(output_dir, project_name)
    results = {}

    # Verify unit tests
    unit_dir = os.path.join(base, 'unit')
    if os.path.isdir(unit_dir):
        for f in sorted(os.listdir(unit_dir)):
            if not f.endswith('_test.go'):
                continue
            fpath = os.path.join(unit_dir, f)
            # Copy test file into target project for compilation check
            fid = f.replace('_test.go', '')
            # Determine which package directory to place the test in
            meta_path = os.path.join(base, 'metadata.json')
            target_file = ''
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, encoding='utf-8') as fh:
                        meta = json.load(fh)
                    entry = meta.get('entries', {}).get(fid, {})
                    func_ref = entry.get('function', '')
                    if ':' in func_ref:
                        target_file = func_ref.split(':')[0]
                except Exception:
                    pass

            if target_file:
                pkg_dir = os.path.join(target_dir, os.path.dirname(target_file))
                if os.path.isdir(pkg_dir):
                    test_copy = os.path.join(pkg_dir, f)
                    try:
                        shutil.copy2(fpath, test_copy)
                        r = subprocess.run(
                            [go_path, 'vet', './...'],
                            cwd=pkg_dir,
                            capture_output=True, text=True, timeout=30
                        )
                        results[f] = {
                            'file': f'unit/{f}',
                            'vet_ok': r.returncode == 0,
                            'vet_output': r.stderr.strip(),
                        }
                    except (subprocess.TimeoutExpired, Exception) as e:
                        results[f] = {'file': f'unit/{f}', 'vet_ok': False, 'vet_output': str(e)}
                    finally:
                        if os.path.isfile(test_copy):
                            os.remove(test_copy)

    # Verify PoC scripts
    poc_dir = os.path.join(base, 'poc')
    if os.path.isdir(poc_dir):
        for f in sorted(os.listdir(poc_dir)):
            if not f.endswith('.go'):
                continue
            fpath = os.path.join(poc_dir, f)
            with tempfile.TemporaryDirectory() as tmp:
                # Copy PoC file
                tmp_file = os.path.join(tmp, f)
                shutil.copy2(fpath, tmp_file)

                # Generate go.mod with replace directive if needed
                project_info = resolve_project_info(target_dir)
                if project_info['module_path']:
                    go_mod = os.path.join(tmp, 'go.mod')
                    with open(go_mod, 'w') as fh:
                        fh.write(f"module poc\n\ngo 1.21\n\n"
                                 f"require {project_info['module_path']} v0.0.0\n\n"
                                 f"replace {project_info['module_path']} => {os.path.abspath(target_dir)}\n")

                try:
                    r = subprocess.run(
                        [go_path, 'vet', f],
                        cwd=tmp,
                        capture_output=True, text=True, timeout=30
                    )
                    results[f] = {
                        'file': f'poc/{f}',
                        'vet_ok': r.returncode == 0,
                        'vet_output': r.stderr.strip(),
                    }
                except (subprocess.TimeoutExpired, Exception) as e:
                    results[f] = {'file': f'poc/{f}', 'vet_ok': False, 'vet_output': str(e)}

    # Save report
    report_path = os.path.join(base, 'compile_report.json')
    total = len(results)
    ok_count = sum(1 for v in results.values() if v.get('vet_ok'))
    report = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'results': results,
        'summary': {
            'total_files': total,
            'compiled_ok': ok_count,
            'compile_failed': total - ok_count,
        },
    }
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report


# ── main ──────────────────────────────────────────────────────────────

interrupted = False


def _signal_handler(sig, frame):
    global interrupted
    if interrupted:
        print("\n[FORCE EXIT]")
        sys.exit(1)
    interrupted = True
    print("\n[INTERRUPT] Stopping after current requests...")


SEVERITY_ORDER = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def main():
    global interrupted
    signal.signal(signal.SIGINT, _signal_handler)

    parser = argparse.ArgumentParser(description="Generate test cases for detected vulnerabilities")
    parser.add_argument("--project", default=None, help="Project directory (projects/<id>) or project ID")
    parser.add_argument("--target", default=None, help="Path to the scanned Go project (ignored with --project)")
    parser.add_argument("--report", default=None, help="Path to detection report JSON (ignored with --project)")
    parser.add_argument("--output-dir", default=None, help="Base output directory (ignored with --project)")
    parser.add_argument("--limit", type=int, default=None, help="Max findings to process")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent API requests")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--retry-failed", action="store_true", help="Re-generate failed entries")
    parser.add_argument("--categories", type=str, default=None, help="Only these categories (comma-separated)")
    parser.add_argument("--severity-filter", type=str, default=None,
                        choices=['none', 'low', 'medium', 'high', 'critical'], help="Minimum severity filter")
    parser.add_argument("--skip-compile", action="store_true", help="Skip compilation verification")
    parser.add_argument("--include-unknown", action="store_true", help="Also generate tests for enhanced unknown candidates")
    args = parser.parse_args()

    # Resolve project directory
    if args.project:
        project_dir = os.path.abspath(args.project)
        if not os.path.isdir(project_dir):
            # Try as project ID under projects/
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.join(script_dir, 'projects', args.project)
        if not os.path.isdir(project_dir):
            print(f"Error: project directory not found: {args.project}", file=sys.stderr)
            sys.exit(1)
        target_dir = os.path.join(project_dir, 'source')
        report_path = os.path.join(project_dir, 'report.json')
        output_dir = project_dir
        project_name = 'testcases'
    else:
        if not args.target:
            print("Error: --target is required when not using --project", file=sys.stderr)
            sys.exit(1)
        target_dir = os.path.abspath(args.target)
        report_path = args.report or 'report.json'
        output_dir = args.output_dir or 'testcases'
        project_name = os.path.basename(target_dir)

    # Validate target
    if not os.path.isdir(target_dir):
        print(f"Error: target directory not found: {target_dir}", file=sys.stderr)
        sys.exit(1)

    # Validate report
    if not os.path.isfile(report_path):
        print(f"Error: report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    cfg = load_env()
    for key in ('LLM_API_KEY', 'LLM_BASE_URL', 'LLM_MODEL'):
        if key not in cfg or not cfg[key]:
            print(f"Error: {key} not set in .env", file=sys.stderr)
            sys.exit(1)

    system_prompt = load_system_prompt()
    os.makedirs(output_dir, exist_ok=True)

    # Load report
    with open(report_path, encoding='utf-8') as f:
        report = json.load(f)

    global _ENHANCED_TEST_CONTEXT
    _ENHANCED_TEST_CONTEXT = None
    if report.get('schema_version') == 'goforret.enhanced/v1':
        import enhanced_detection as ed
        binary = ed.build_analyzer()
        index = json.loads(subprocess.run([binary, '--dir', target_dir, '--source-index'],
                                          check=True, capture_output=True, text=True, timeout=120).stdout)
        _ENHANCED_TEST_CONTEXT = ed.Context(target_dir, index)
        expected = report.get('enhanced', {}).get('source_hashes', {})
        if expected != {file: data['hash'] for file, data in _ENHANCED_TEST_CONTEXT.files.items()}:
            print('Error: target source differs from the enhanced detection report', file=sys.stderr)
            sys.exit(1)

    findings = report.get('findings', [])
    if report.get('schema_version') == 'goforret.enhanced/v1':
        allowed = {'supported', 'unknown'} if args.include_unknown else {'supported'}
        findings = [f for f in findings if f.get('validation_status') in allowed]
    if not findings:
        print("No findings in report.")
        return

    # Filter by categories
    if args.categories:
        cats = set(c.strip() for c in args.categories.split(','))
        findings = [f for f in findings if f.get('missing_step_category', '') in cats]

    # Filter by severity
    if args.severity_filter:
        min_sev = SEVERITY_ORDER.get(args.severity_filter, 0)
        findings = [f for f in findings
                    if SEVERITY_ORDER.get(f.get('severity', 'low'), 0) >= min_sev]

    # Limit
    if args.limit:
        findings = findings[:args.limit]

    # Resolve project info
    project_info = resolve_project_info(target_dir)

    # Check already-done
    meta_path = os.path.join(output_dir, project_name, 'metadata.json')
    done_ids = set()
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, encoding='utf-8') as f:
                metadata = json.load(f)
            for fid, entry in metadata.get('entries', {}).items():
                if not args.retry_failed:
                    done_ids.add(fid)
        except Exception:
            pass

    pending = []
    for finding in findings:
        fid = make_finding_id(finding)
        if fid not in done_ids:
            pending.append((fid, finding))

    print(f"Findings: {len(findings)}, Already done: {len(done_ids)}, Pending: {len(pending)}")
    print(f"Model: {cfg['LLM_MODEL']}")
    print(f"Target: {target_dir}")
    print(f"Output: {os.path.abspath(output_dir)}/{project_name}/")
    print()

    if not pending:
        print("Nothing to do.")
        return

    # Get templates
    unit_tpl, poc_tpl, http_poc_tpl = None, None, None

    results = {'ok': 0, 'failed': 0}
    overall_start = time.time()

    def process(fid, finding):
        nonlocal unit_tpl, poc_tpl, http_poc_tpl
        # Get templates for this finding's category
        category = finding.get('missing_step_category', 'input_sanitization')
        u_tpl, p_tpl, h_tpl = get_template(category)

        # Extract function source
        func_ref = finding.get('function', '')
        func_source = None
        pkg_name = 'main'
        if ':' in func_ref:
            file_path, func_name = func_ref.rsplit(':', 1)
            func_source = extract_function_source(target_dir, file_path, func_name, finding.get('function_id'))
            pkg_name = get_package_name(target_dir, file_path)

        chain_result, err = generate_one(
            cfg, system_prompt, finding, func_source,
            u_tpl, p_tpl, h_tpl,
            project_info, pkg_name, fid
        )

        if chain_result is not None:
            saved = save_outputs(output_dir, project_name, fid, chain_result, finding)
            files_str = ', '.join(saved['files'])
            return fid, chain_result, files_str
        else:
            # Save error entry
            err_entry = {'finding_id': fid, 'function': finding.get('function', ''),
                         'error': err}
            meta_base = os.path.join(output_dir, project_name)
            os.makedirs(meta_base, exist_ok=True)
            meta_p = os.path.join(meta_base, 'metadata.json')
            metadata = {}
            if os.path.isfile(meta_p):
                try:
                    with open(meta_p, encoding='utf-8') as f:
                        metadata = json.load(f)
                except Exception:
                    pass
            if 'entries' not in metadata:
                metadata['entries'] = {}
            metadata['entries'][fid] = err_entry
            with open(meta_p, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            return fid, None, err

    if args.workers <= 1:
        for i, (fid, finding) in enumerate(pending):
            if interrupted:
                print(f"\n[INTERRUPT] {len(pending) - i} remaining.")
                break

            gid, result, msg = process(fid, finding)
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
            for i, (fid, finding) in enumerate(pending):
                if interrupted:
                    break
                futures[executor.submit(process, fid, finding)] = fid
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

    # Compilation verification
    compile_report = None
    if not args.skip_compile and not interrupted:
        print("\n--- Compilation Verification ---")
        go_path = find_go_path()
        if go_path:
            print(f"Using: {go_path}")
            compile_report = verify_compilation(output_dir, project_name, target_dir, go_path)
            if compile_report:
                s = compile_report['summary']
                print(f"  Files: {s['total_files']}, OK: {s['compiled_ok']}, Failed: {s['compile_failed']}")
                for fname, r in compile_report['results'].items():
                    status = "OK" if r.get('vet_ok') else "FAIL"
                    print(f"    [{status}] {r['file']}")
        else:
            print("  go executable not found, skipped")

    elapsed = time.time() - overall_start
    print()
    print("=" * 50)
    print(f"{'Interrupted!' if interrupted else 'Done.'} Time: {elapsed:.1f}s")
    print(f"  Generated: {results['ok']}")
    print(f"  Failed:    {results['failed']}")
    if compile_report:
        s = compile_report['summary']
        print(f"  Compiled:  {s['compiled_ok']}/{s['total_files']} OK")


if __name__ == "__main__":
    main()
