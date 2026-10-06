"""
Python wrapper for the Go AST analyzer CLI tool.

Provides a Python API to call the ast_analyzer Go binary and return
structured analysis results for use in the enrichment pipeline.
"""

import json
import os
import subprocess
import sys


def find_analyzer_binary():
    """Find the ast_analyzer binary, building it if necessary."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    analyzer_dir = os.path.join(script_dir, 'ast_analyzer')

    # Check for an existing binary, preferring the one built for this platform.
    # A leftover ast_analyzer.exe from a Windows build must not shadow the
    # native binary on POSIX, so also require the executable bit.
    names = (('ast_analyzer.exe', 'ast_analyzer') if os.name == 'nt'
             else ('ast_analyzer', 'ast_analyzer.exe'))
    binary = None
    for name in names:
        candidate = os.path.join(analyzer_dir, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            binary = candidate
            break

    if binary is None:
        binary = os.path.join(analyzer_dir, 'ast_analyzer')
        # Try to build it
        go_path = _find_go()
        if go_path:
            try:
                subprocess.run(
                    [go_path, 'build', '-o',
                     os.path.join(analyzer_dir, 'ast_analyzer'),
                     '.'],
                    cwd=analyzer_dir,
                    capture_output=True,
                    timeout=60,
                    check=True,
                )
                binary = os.path.join(analyzer_dir, 'ast_analyzer')
                if os.name == 'nt' and not os.path.isfile(binary):
                    binary += '.exe'
            except (subprocess.CalledProcessError, FileNotFoundError):
                return None

    return binary if os.path.isfile(binary) else None


def _find_go():
    """Find the Go executable."""
    # Check PATH first
    for name in ('go', 'go.exe'):
        for dir_entry in os.environ.get('PATH', '').split(os.pathsep):
            candidate = os.path.join(dir_entry, name)
            if os.path.isfile(candidate):
                return candidate

    # Common Windows locations
    common = [
        r'D:\Tools\Go\bin\go.exe',
        r'C:\Program Files\Go\bin\go.exe',
        r'C:\Go\bin\go.exe',
    ]
    for p in common:
        if os.path.isfile(p):
            return p

    return None


def analyze_go_source(source_dir, changed_files=None, focus_functions=None):
    """Analyze Go source code in a directory.

    Args:
        source_dir: Path to directory containing Go source files.
        changed_files: Optional list of file paths to focus on.
        focus_functions: Optional list of function names to trace call chains for.

    Returns:
        dict with analysis results, or None if analysis fails.
    """
    binary = find_analyzer_binary()
    if not binary:
        return _empty_result()

    cmd = [binary, '--dir', source_dir]

    if focus_functions:
        cmd.extend(['--focus-funcs', ','.join(focus_functions)])
    if changed_files:
        cmd.extend(['--focus-files', ','.join(changed_files)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return _empty_result()

        data = json.loads(result.stdout)
        return data

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return _empty_result()


def _empty_result():
    """Return an empty analysis result structure."""
    return {
        "imports": {},
        "call_chains": [],
        "data_flow_indicators": [],
        "stdlib_signals": [],
        "concurrency_patterns": [],
        "functions": [],
        "parse_mode": "unavailable",
    }


if __name__ == "__main__":
    # Quick test
    if len(sys.argv) < 2:
        print("Usage: python go_ast_analysis.py <source_dir> [func1,func2]")
        sys.exit(1)

    src_dir = sys.argv[1]
    funcs = sys.argv[2].split(',') if len(sys.argv) > 2 else None

    result = analyze_go_source(src_dir, focus_functions=funcs)
    print(json.dumps(result, indent=2, ensure_ascii=False))
