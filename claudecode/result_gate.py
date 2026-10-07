#!/usr/bin/env python3
"""
Fail-closed gate for the scan step in action.yml.

A scan that errored, did not complete, or exited unexpectedly must fail the
job; it is never reported as 0 findings.

Usage: python -m claudecode.result_gate <results_file> <exit_code>
Prints the findings count (success, exit 0) or the failure reason (exit 1).
"""

import json
import sys


def evaluate(results_path: str, exit_code: str) -> tuple[bool, str]:
    """Return (True, "<findings count>") for a usable scan result, else (False, "<reason>")."""
    try:
        with open(results_path, encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return False, 'results file missing'
    except (OSError, ValueError):
        return False, 'results file invalid'

    if not isinstance(data, dict):
        return False, 'results file invalid'
    findings = data.get('findings', [])
    if not isinstance(findings, list):
        return False, 'results file invalid'

    if 'error' in data:
        return False, 'scan reported an error'

    summary = data.get('analysis_summary')
    if not isinstance(summary, dict) or summary.get('review_completed') is not True:
        return False, 'review not completed'

    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        return False, 'exit code unknown'

    if code == 0:
        return True, str(len(findings))
    has_high = any(isinstance(f, dict) and str(f.get('severity')).upper() == 'HIGH' for f in findings)
    if code == 1 and has_high:
        return True, str(len(findings))
    return False, f'exit code {code}'


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('usage: python -m claudecode.result_gate <results_file> <exit_code>', file=sys.stderr)
        sys.exit(2)
    ok, message = evaluate(sys.argv[1], sys.argv[2])
    print(message)
    sys.exit(0 if ok else 1)
