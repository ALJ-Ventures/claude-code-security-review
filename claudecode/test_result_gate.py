#!/usr/bin/env python3
"""
Unit tests for the fail-closed result gate.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from claudecode.result_gate import evaluate


REPO_ROOT = Path(__file__).resolve().parent.parent


def _complete(findings=None, **extra):
    """A results document from a scan that completed."""
    data = {
        'findings': findings if findings is not None else [],
        'analysis_summary': {'review_completed': True},
    }
    data.update(extra)
    return data


def _write(tmp_path, content):
    path = tmp_path / 'claudecode-results.json'
    if isinstance(content, str):
        path.write_text(content, encoding='utf-8')
    else:
        path.write_text(json.dumps(content), encoding='utf-8')
    return str(path)


class TestEvaluateFileChecks:
    """Results file presence and shape."""

    def test_missing_file(self, tmp_path):
        assert evaluate(str(tmp_path / 'absent.json'), '0') == (False, 'results file missing')

    def test_empty_file(self, tmp_path):
        assert evaluate(_write(tmp_path, ''), '0') == (False, 'results file invalid')

    def test_invalid_json(self, tmp_path):
        assert evaluate(_write(tmp_path, '{"findings": ['), '0') == (False, 'results file invalid')

    def test_json_array(self, tmp_path):
        assert evaluate(_write(tmp_path, '[]'), '0') == (False, 'results file invalid')

    def test_findings_not_a_list(self, tmp_path):
        path = _write(tmp_path, _complete(findings={'file': 'a.py'}))
        assert evaluate(path, '0') == (False, 'results file invalid')

    def test_error_key(self, tmp_path):
        marker = 'SECRET-MARKER-1234'
        path = _write(tmp_path, {'error': f'Security audit failed: {marker}'})
        ok, reason = evaluate(path, '1')
        assert (ok, reason) == (False, 'scan reported an error')
        assert marker not in reason

    def test_error_key_wins_over_complete_result(self, tmp_path):
        path = _write(tmp_path, _complete(error='boom'))
        assert evaluate(path, '0') == (False, 'scan reported an error')


class TestEvaluateReviewCompleted:
    """analysis_summary.review_completed must be exactly true."""

    def test_review_completed_false(self, tmp_path):
        path = _write(tmp_path, {'findings': [], 'analysis_summary': {'review_completed': False}})
        assert evaluate(path, '0') == (False, 'review not completed')

    def test_review_completed_missing(self, tmp_path):
        path = _write(tmp_path, {'findings': [], 'analysis_summary': {'files_reviewed': 3}})
        assert evaluate(path, '0') == (False, 'review not completed')

    def test_analysis_summary_missing(self, tmp_path):
        path = _write(tmp_path, {'findings': []})
        assert evaluate(path, '0') == (False, 'review not completed')

    def test_review_completed_string_true(self, tmp_path):
        path = _write(tmp_path, {'findings': [], 'analysis_summary': {'review_completed': 'true'}})
        assert evaluate(path, '0') == (False, 'review not completed')

    @pytest.mark.parametrize('value', [1, 1.0], ids=['int_1', 'float_1'])
    def test_review_completed_number_one(self, tmp_path, value):
        """1 == True in Python; only the boolean true counts as a completed review."""
        path = _write(tmp_path, {'findings': [], 'analysis_summary': {'review_completed': value}})
        assert evaluate(path, '0') == (False, 'review not completed')


class TestEvaluateExitCode:
    """Exit code rules for a valid, complete results file."""

    def test_exit_0_no_findings(self, tmp_path):
        assert evaluate(_write(tmp_path, _complete()), '0') == (True, '0')

    def test_exit_0_two_findings(self, tmp_path):
        findings = [
            {'file': 'a.py', 'severity': 'MEDIUM'},
            {'file': 'b.py', 'severity': 'LOW'},
        ]
        assert evaluate(_write(tmp_path, _complete(findings)), '0') == (True, '2')

    def test_exit_1_with_high_finding(self, tmp_path):
        findings = [
            {'file': 'a.py', 'severity': 'high'},
            {'file': 'b.py', 'severity': 'LOW'},
        ]
        assert evaluate(_write(tmp_path, _complete(findings)), '1') == (True, '2')

    def test_exit_1_without_high_finding(self, tmp_path):
        findings = [{'file': 'a.py', 'severity': 'MEDIUM'}]
        assert evaluate(_write(tmp_path, _complete(findings)), '1') == (False, 'exit code 1')

    def test_exit_1_no_findings(self, tmp_path):
        assert evaluate(_write(tmp_path, _complete()), '1') == (False, 'exit code 1')

    def test_exit_2_with_valid_complete_file(self, tmp_path):
        assert evaluate(_write(tmp_path, _complete()), '2') == (False, 'exit code 2')

    @pytest.mark.parametrize('exit_code', ['', 'abc', '1.5'])
    def test_non_integer_exit_code(self, tmp_path, exit_code):
        path = _write(tmp_path, _complete())
        assert evaluate(path, exit_code) == (False, 'exit code unknown')


class TestResultGateCli:
    """python -m claudecode.result_gate <results_file> <exit_code>"""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, '-m', 'claudecode.result_gate', *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_cli_success(self, tmp_path):
        findings = [{'file': 'a.py', 'severity': 'LOW'}]
        proc = self._run(_write(tmp_path, _complete(findings)), '0')
        assert proc.returncode == 0
        assert proc.stdout == '1\n'

    def test_cli_failure(self, tmp_path):
        proc = self._run(_write(tmp_path, {'error': 'Security audit failed: x'}), '1')
        assert proc.returncode == 1
        assert proc.stdout == 'scan reported an error\n'

    def test_cli_missing_file(self, tmp_path):
        proc = self._run(str(tmp_path / 'absent.json'), '0')
        assert proc.returncode == 1
        assert proc.stdout == 'results file missing\n'
