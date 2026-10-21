#!/usr/bin/env python3
"""
Tests for the run and input evidence recorded per Claude Code attempt.

The evidence is one SCAN-EVIDENCE stderr line per attempt plus the same data under
`scan_evidence` in the results JSON. It never changes the result gate or the findings.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from claudecode import result_gate
from claudecode.constants import DEFAULT_CLAUDE_MODEL
from claudecode.github_action_audit import SimpleClaudeRunner, main


# action.yml exports CLAUDE_TIMEOUT; an ambient value must not change what these tests run with.
@pytest.fixture(autouse=True)
def isolate_claude_timeout(monkeypatch):
    monkeypatch.delenv('CLAUDE_TIMEOUT', raising=False)


PREFIX = 'SCAN-EVIDENCE '

# Key order of the log line contract (a trailing `reading=not-proven` only when diff=no)
LINE_KEYS = [
    'attempt', 'pr', 'head', 'checkout', 'model', 'models_used', 'exit', 'type', 'subtype',
    'is_error', 'review_completed', 'files_pr', 'files_prompt', 'file_list', 'diff',
    'diff_files', 'diff_bytes', 'prompt_chars', 'turns', 'duration_ms', 'cost_usd',
    'tok_in', 'tok_out', 'tok_cache_read', 'tok_cache_write', 'denials', 'denials_by_tool',
]

LINE_RE = re.compile(r'^SCAN-EVIDENCE( [a-z_]+=[A-Za-z0-9_.:,-]+)+$')

HEAD_SHA = 'a' * 40
CHECKOUT_SHA = 'b' * 40
MODEL_USED = 'claude-opus-4-1-20250805'

COMPLETE_FINDINGS = {
    'findings': [],
    'analysis_summary': {
        'files_reviewed': 3,
        'high_severity': 0,
        'medium_severity': 0,
        'low_severity': 0,
        'review_completed': True,
    },
}

CONTEXT = {
    'pr': 42,
    'head': HEAD_SHA,
    'checkout': CHECKOUT_SHA,
    'files_pr': 3,
    'files_prompt': 3,
    'diff_in_prompt': True,
    'diff_files': 2,
    'diff_bytes': 1234,
}


def cli_result(findings=COMPLETE_FINDINGS, drop=(), **overrides):
    """A fuller Claude Code 2.1.285 `--output-format json` result object."""
    result = {
        'type': 'result',
        'subtype': 'success',
        'is_error': False,
        'duration_ms': 123456,
        'duration_api_ms': 120000,
        'num_turns': 17,
        'stop_reason': 'end_turn',
        'session_id': '11111111-2222-3333-4444-555555555555',
        'total_cost_usd': 1.2345,
        'usage': {
            'input_tokens': 12,
            'output_tokens': 3456,
            'cache_creation_input_tokens': 7890,
            'cache_read_input_tokens': 65432,
            'server_tool_use': {'web_search_requests': 0},
        },
        'modelUsage': {MODEL_USED: {'inputTokens': 12, 'outputTokens': 3456}},
        'permission_denials': [],
        'result': json.dumps(findings),
    }
    result.update(overrides)
    for key in drop:
        result.pop(key, None)
    return result


def proc(result=None, returncode=0, stdout=None, stderr=''):
    """A subprocess.run return value; `result` is serialised as the CLI stdout."""
    if stdout is None:
        stdout = json.dumps(result) if result is not None else ''
    return Mock(returncode=returncode, stdout=stdout, stderr=stderr)


TOO_LONG_DETAIL = 'Prompt is too long · this conversation is a single exchange and cannot be compacted'

# Claude Code results that report an over-long prompt, in the three shapes it emits
TOO_LONG_VARIANTS = {
    'exact-text': cli_result(is_error=True, result='Prompt is too long'),
    'text-with-detail': cli_result(is_error=True, result=TOO_LONG_DETAIL),
    'text-in-errors': cli_result(subtype='error_during_execution', is_error=True,
                                 errors=['Prompt is too long'], drop=('result',)),
}


def evidence_lines(text):
    return [line for line in text.splitlines() if line.startswith(PREFIX)]


def parse_line(line):
    """Return the ordered (key, value) pairs of one evidence line."""
    assert line.startswith(PREFIX)
    pairs = []
    for part in line[len(PREFIX):].split(' '):
        key, _, value = part.partition('=')
        pairs.append((key, value))
    return pairs


def run_runner(side_effect, prompt='test prompt', context=CONTEXT, capsys=None, runner=None):
    """Run SimpleClaudeRunner.run_security_audit with a mocked subprocess; return (outcome, lines, runner)."""
    runner = runner or SimpleClaudeRunner()
    kwargs = {} if context is None else {'evidence_context': context}
    with patch('subprocess.run', side_effect=side_effect), \
            patch('claudecode.github_action_audit.time.sleep'), \
            patch('pathlib.Path.exists', return_value=True):
        outcome = runner.run_security_audit(Path('/tmp/test'), prompt, **kwargs)
    lines = evidence_lines(capsys.readouterr().err) if capsys is not None else []
    return outcome, lines, runner


class TestRunnerEvidence:
    """One evidence entry per subprocess attempt, recorded by SimpleClaudeRunner."""

    def test_success_records_full_entry_and_line(self, capsys):
        (success, error, results), lines, runner = run_runner([proc(cli_result())], capsys=capsys)

        assert success is True and error == ''
        assert results['analysis_summary']['review_completed'] is True
        assert len(lines) == 1

        pairs = parse_line(lines[0])
        assert [k for k, _ in pairs] == LINE_KEYS  # fixed order, no trailing reading key
        values = dict(pairs)
        assert values == {
            'attempt': '1',
            'pr': '42',
            'head': HEAD_SHA,
            'checkout': CHECKOUT_SHA,
            'model': re.sub(r'[^A-Za-z0-9_.:,-]', '_', DEFAULT_CLAUDE_MODEL),
            'models_used': MODEL_USED,
            'exit': '0',
            'type': 'result',
            'subtype': 'success',
            'is_error': 'false',
            'review_completed': 'true',
            'files_pr': '3',
            'files_prompt': '3',
            'file_list': 'complete',
            'diff': 'yes',
            'diff_files': '2',
            'diff_bytes': '1234',
            'prompt_chars': str(len('test prompt')),
            'turns': '17',
            'duration_ms': '123456',
            'cost_usd': '1.2345',
            'tok_in': '12',
            'tok_out': '3456',
            'tok_cache_read': '65432',
            'tok_cache_write': '7890',
            'denials': '0',
            'denials_by_tool': 'none',
        }

        # The runner holds the same data as typed values for the results file
        attempts = runner.scan_evidence()['attempts']
        assert len(attempts) == 1
        entry = attempts[0]
        assert list(entry.keys()) == LINE_KEYS
        assert entry['attempt'] == 1
        assert entry['pr'] == 42
        assert entry['exit'] == 0
        assert entry['is_error'] is False
        assert entry['review_completed'] is True
        assert entry['turns'] == 17
        assert entry['cost_usd'] == 1.2345
        assert entry['tok_cache_read'] == 65432
        assert entry['diff'] == 'yes'
        assert entry['denials_by_tool'] == 'none'
        assert 'reading' not in entry
        json.dumps(entry)  # serialisable

    def test_line_starts_at_column_zero_on_stderr_not_stdout(self, capsys):
        run_runner([proc(cli_result())], capsys=None)
        captured = capsys.readouterr()
        assert captured.out == ''
        assert captured.err.startswith(PREFIX)  # no logger prefix in front of the anchor
        assert captured.err.endswith('\n')
        assert len(captured.err.splitlines()) == 1

    def test_cli_error_three_times_keeps_three_entries(self, capsys):
        # CLI exits non-zero every time: 3 attempts, 3 entries, a failed audit
        side_effect = [proc(returncode=1, stderr='boom') for _ in range(3)]
        (success, error, results), lines, runner = run_runner(side_effect, capsys=capsys)

        assert success is False
        assert 'return code 1' in error
        assert results == {}
        assert len(lines) == 3
        for number, line in enumerate(lines, start=1):
            values = dict(parse_line(line))
            assert values['attempt'] == str(number)
            assert values['exit'] == '1'
            assert values['type'] == values['subtype'] == values['is_error'] == 'unknown'
            assert values['review_completed'] == 'unknown'
            assert values['turns'] == values['cost_usd'] == values['tok_in'] == 'unknown'
            assert values['denials'] == values['denials_by_tool'] == 'unknown'
            assert values['models_used'] == 'unknown'
            assert values['prompt_chars'] == str(len('test prompt'))
        assert [e['attempt'] for e in runner.scan_evidence()['attempts']] == [1, 2, 3]

    def test_cli_error_with_result_json_still_reports_how_the_run_ended(self, capsys):
        # A non-zero exit whose stdout is still a CLI result object (e.g. max turns)
        stdout = json.dumps(cli_result(subtype='error_max_turns', is_error=True, drop=('result',)))
        side_effect = [proc(returncode=1, stdout=stdout) for _ in range(3)]
        (success, _, _), lines, _ = run_runner(side_effect, capsys=capsys)

        assert success is False
        values = dict(parse_line(lines[0]))
        assert values['exit'] == '1'
        assert values['subtype'] == 'error_max_turns'
        assert values['is_error'] == 'true'
        assert values['turns'] == '17'
        assert values['review_completed'] == 'unknown'

    @pytest.mark.parametrize('exit_code', [0, 1])
    @pytest.mark.parametrize('variant', list(TOO_LONG_VARIANTS))
    def test_prompt_too_long_attempt_is_one_entry_that_carries_the_result(self, variant, exit_code, capsys):
        # the early PROMPT_TOO_LONG return still records its attempt, with how the run ended
        stdout = json.dumps(TOO_LONG_VARIANTS[variant])
        (success, error, results), lines, runner = run_runner(
            [proc(stdout=stdout, returncode=exit_code)], capsys=capsys)

        assert (success, error, results) == (False, 'PROMPT_TOO_LONG', {})
        assert len(lines) == 1
        values = dict(parse_line(lines[0]))
        assert values['attempt'] == '1'
        assert values['exit'] == str(exit_code)
        assert values['type'] == 'result'
        assert values['subtype'] == TOO_LONG_VARIANTS[variant]['subtype']
        assert values['is_error'] == 'true'
        assert values['review_completed'] == 'unknown'
        assert [e['attempt'] for e in runner.scan_evidence()['attempts']] == [1]

    def test_error_during_execution_then_success(self, capsys):
        first = cli_result(subtype='error_during_execution', is_error=True, drop=('result',),
                           num_turns=3, total_cost_usd=0.05)
        second = cli_result()
        (success, error, results), lines, runner = run_runner([proc(first), proc(second)], capsys=capsys)

        assert success is True
        assert len(results['findings']) == 0
        assert len(lines) == 2
        one, two = dict(parse_line(lines[0])), dict(parse_line(lines[1]))
        assert (one['attempt'], two['attempt']) == ('1', '2')
        assert one['subtype'] == 'error_during_execution'
        assert one['is_error'] == 'true'
        assert one['review_completed'] == 'unknown'  # no findings JSON was extracted from this attempt
        assert one['turns'] == '3'
        assert one['cost_usd'] == '0.05'
        assert two['subtype'] == 'success'
        assert two['review_completed'] == 'true'
        assert two['turns'] == '17'

    def test_review_completed_false_is_reported(self, capsys):
        incomplete = dict(COMPLETE_FINDINGS, analysis_summary={'review_completed': False})
        (success, _, results), lines, _ = run_runner([proc(cli_result(findings=incomplete))], capsys=capsys)

        assert success is True  # unchanged runner behaviour: the gate/main decide on review_completed
        assert results['analysis_summary']['review_completed'] is False
        assert dict(parse_line(lines[0]))['review_completed'] == 'false'

    def test_timeout_is_one_entry_with_exit_timeout(self, capsys):
        side_effect = subprocess.TimeoutExpired(['claude'], 1200)
        (success, error, results), lines, runner = run_runner(side_effect, capsys=capsys)

        assert success is False
        assert 'timed out after 20 minutes' in error
        assert len(lines) == 1
        values = dict(parse_line(lines[0]))
        assert values['exit'] == 'timeout'
        assert values['type'] == values['turns'] == values['tok_in'] == 'unknown'
        assert runner.scan_evidence()['attempts'][0]['exit'] == 'timeout'

    def test_unexpected_subprocess_exception_is_one_entry_exit_unknown(self, capsys):
        (success, error, _), lines, _ = run_runner(OSError('no claude'), capsys=capsys)

        assert success is False
        assert len(lines) == 1
        assert dict(parse_line(lines[0]))['exit'] == 'unknown'

    def test_json_parse_failure_attempts_are_recorded(self, capsys):
        side_effect = [proc(stdout='Invalid JSON'), proc(stdout='Still invalid')]
        (success, error, _), lines, _ = run_runner(side_effect, capsys=capsys)

        assert success is False
        assert 'Failed to parse Claude output' in error
        assert len(lines) == 2
        assert dict(parse_line(lines[1]))['exit'] == '0'
        assert dict(parse_line(lines[1]))['type'] == 'unknown'

    def test_attempt_counter_runs_across_calls_of_one_runner(self, capsys):
        too_long = cli_result(is_error=True, result='Prompt is too long', drop=())
        runner = SimpleClaudeRunner()
        (success, error, _), lines, _ = run_runner([proc(too_long)], capsys=capsys, runner=runner)
        assert (success, error) == (False, 'PROMPT_TOO_LONG')

        no_diff_context = dict(CONTEXT, diff_in_prompt=False)
        (success, _, _), more, _ = run_runner([proc(cli_result())], context=no_diff_context,
                                              capsys=capsys, runner=runner)
        assert success is True
        assert [dict(parse_line(l))['attempt'] for l in lines + more] == ['1', '2']
        assert [e['attempt'] for e in runner.scan_evidence()['attempts']] == [1, 2]

    def test_missing_directory_records_no_attempt(self, capsys):
        runner = SimpleClaudeRunner()
        success, error, _ = runner.run_security_audit(Path('/non/existent/path'), 'p', evidence_context=CONTEXT)
        assert success is False
        assert runner.scan_evidence() == {'attempts': []}
        assert evidence_lines(capsys.readouterr().err) == []

    def test_default_call_shape_and_missing_context_give_unknown(self, capsys):
        # run_security_audit(repo_dir, prompt) without context; sparse CLI result; usage: null
        sparse = {'type': 'result', 'subtype': 'success', 'result': json.dumps(COMPLETE_FINDINGS), 'usage': None}
        (success, _, _), lines, runner = run_runner([proc(sparse)], context=None, capsys=capsys)

        assert success is True
        values = dict(parse_line(lines[0]))
        for key in ('pr', 'head', 'checkout', 'models_used', 'is_error', 'files_pr', 'files_prompt',
                    'file_list', 'diff_files', 'diff_bytes', 'turns', 'duration_ms', 'cost_usd',
                    'tok_in', 'tok_out', 'tok_cache_read', 'tok_cache_write', 'denials',
                    'denials_by_tool'):
            assert values[key] == 'unknown', key
        assert values['diff'] == 'unknown'  # no statement about the diff without a caller fact
        assert 'reading' not in values
        assert values['type'] == 'result'
        assert values['subtype'] == 'success'
        assert values['review_completed'] == 'true'
        assert values['prompt_chars'] == str(len('test prompt'))
        entry = runner.scan_evidence()['attempts'][0]
        assert entry['tok_in'] == 'unknown'
        assert entry['pr'] == 'unknown'

    @pytest.mark.parametrize('usage', [None, 'text', [1, 2], {}, {'input_tokens': 'many', 'output_tokens': None}],
                             ids=['null', 'string', 'list', 'empty', 'wrong-types'])
    def test_unusable_usage_gives_unknown_tokens(self, usage, capsys):
        (success, _, _), lines, _ = run_runner([proc(cli_result(usage=usage))], capsys=capsys)

        assert success is True
        values = dict(parse_line(lines[0]))
        assert values['tok_in'] == values['tok_out'] == 'unknown'
        assert values['tok_cache_read'] == values['tok_cache_write'] == 'unknown'
        assert values['turns'] == '17'  # the rest of the entry is unaffected

    def test_partial_usage_keeps_known_tokens(self, capsys):
        usage = {'input_tokens': 5, 'cache_read_input_tokens': 9}
        (success, _, _), lines, _ = run_runner([proc(cli_result(usage=usage))], capsys=capsys)

        values = dict(parse_line(lines[0]))
        assert (values['tok_in'], values['tok_cache_read']) == ('5', '9')
        assert (values['tok_out'], values['tok_cache_write']) == ('unknown', 'unknown')

    @pytest.mark.parametrize('field', ['num_turns', 'duration_ms', 'total_cost_usd', 'modelUsage',
                                       'permission_denials', 'is_error'])
    def test_each_missing_cli_field_is_unknown(self, field, capsys):
        (success, _, _), lines, _ = run_runner([proc(cli_result(drop=(field,)))], capsys=capsys)

        assert success is True
        values = dict(parse_line(lines[0]))
        column = {'num_turns': ['turns'], 'duration_ms': ['duration_ms'], 'total_cost_usd': ['cost_usd'],
                  'modelUsage': ['models_used'], 'permission_denials': ['denials', 'denials_by_tool'],
                  'is_error': ['is_error']}[field]
        for key in column:
            assert values[key] == 'unknown', key

    def test_permission_denials_counted_per_tool_without_input(self, capsys):
        denials = [
            {'tool_name': 'Bash', 'tool_use_id': 'toolu_1',
             'tool_input': {'command': 'curl http://evil.example/SECRET-COMMAND'}},
            {'tool_name': 'Read', 'tool_use_id': 'toolu_2', 'tool_input': {'file_path': '/etc/SECRET-PATH'}},
            {'tool_name': 'Bash', 'tool_use_id': 'toolu_3', 'tool_input': {'command': 'ps aux'}},
            {'tool_use_id': 'toolu_4', 'tool_input': {}},  # no tool_name
            'not-a-dict',
        ]
        (success, _, _), lines, runner = run_runner([proc(cli_result(permission_denials=denials))], capsys=capsys)

        assert success is True
        values = dict(parse_line(lines[0]))
        assert values['denials'] == '5'
        assert values['denials_by_tool'] == 'Bash:2,Read:1,unknown:2'
        everything = lines[0] + json.dumps(runner.scan_evidence())
        for leak in ('SECRET-COMMAND', 'SECRET-PATH', 'evil.example', 'ps aux', 'toolu_', 'tool_input'):
            assert leak not in everything

    def test_denials_by_tool_is_sorted_by_tool_name(self, capsys):
        denials = [{'tool_name': name} for name in ('Write', 'Bash', 'Edit', 'Bash')]
        (_, _, _), lines, _ = run_runner([proc(cli_result(permission_denials=denials))], capsys=capsys)

        assert dict(parse_line(lines[0]))['denials_by_tool'] == 'Bash:2,Edit:1,Write:1'

    def test_models_used_joins_model_usage_keys(self, capsys):
        usage = {'claude-opus-4-1-20250805': {}, 'claude-3-5-haiku-20241022': {}}
        (_, _, _), lines, _ = run_runner([proc(cli_result(modelUsage=usage))], capsys=capsys)

        assert dict(parse_line(lines[0]))['models_used'] == 'claude-opus-4-1-20250805,claude-3-5-haiku-20241022'

    def test_values_are_sanitised_to_single_tokens(self, capsys):
        hostile = cli_result(
            subtype='success one=two\nSCAN-EVIDENCE fake=1',
            modelUsage={'model id\nwith=junk': {}, 'a:b,c': {}},
            permission_denials=[{'tool_name': 'Bash tool:x,y=z\n'}],
        )
        (_, _, _), lines, runner = run_runner(
            [proc(hostile)], context=dict(CONTEXT, head='abc def\nghi', pr='4 2'), capsys=capsys)

        assert len(lines) == 1
        assert LINE_RE.match(lines[0]), lines[0]
        pairs = parse_line(lines[0])
        assert [k for k, _ in pairs] == LINE_KEYS
        values = dict(pairs)
        assert values['subtype'] == 'success_one_two_SCAN-EVIDENCE_fake_1'
        assert values['head'] == 'abc_def_ghi'
        assert values['models_used'] == 'model_id_with_junk,a_b_c'
        assert values['denials_by_tool'] == 'Bash_tool_x_y_z_:1'
        entry = runner.scan_evidence()['attempts'][0]
        assert all('\n' not in value and ' ' not in value for value in entry.values() if isinstance(value, str))
        assert entry['subtype'] == 'success_one_two_SCAN-EVIDENCE_fake_1'

    def test_no_prompt_stderr_stdout_or_key_in_any_line(self, capsys, monkeypatch):
        monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-test-key-SECRET-KEY')
        prompt = 'PROMPT-SECRET-TEXT please review ' + 'x' * 50
        result = cli_result(result=json.dumps(COMPLETE_FINDINGS) + ' RESULT-SECRET-TEXT',
                            session_id='SESSION-SECRET-ID')
        side_effect = [
            proc(returncode=1, stdout='STDOUT-SECRET-TEXT', stderr='STDERR-SECRET-TEXT sk-ant-test-key-SECRET-KEY'),
            proc(result, stderr='STDERR-SECRET-TEXT'),
        ]
        (success, _, _), lines, runner = run_runner(side_effect, prompt=prompt, capsys=capsys)

        assert success is True
        assert len(lines) == 2
        everything = '\n'.join(lines) + json.dumps(runner.scan_evidence())
        for secret in ('PROMPT-SECRET-TEXT', 'STDERR-SECRET-TEXT', 'STDOUT-SECRET-TEXT', 'RESULT-SECRET-TEXT',
                       'SESSION-SECRET-ID', 'sk-ant-test-key', 'SECRET-KEY'):
            assert secret not in everything, secret
        for line in lines:
            assert LINE_RE.match(line), line
            assert PREFIX not in line[len(PREFIX):]  # one line, one record

    def test_no_diff_statement_limit(self, capsys):
        context = dict(CONTEXT, diff_in_prompt=False)
        (success, _, _), lines, runner = run_runner([proc(cli_result())], context=context, capsys=capsys)

        assert success is True  # the run stays "scanned"
        pairs = parse_line(lines[0])
        assert pairs[-1] == ('reading', 'not-proven')
        assert [k for k, _ in pairs[:-1]] == LINE_KEYS
        assert dict(pairs)['diff'] == 'no'
        entry = runner.scan_evidence()['attempts'][0]
        assert entry['diff'] == 'no'
        assert entry['reading'] == 'not-proven'
        assert list(entry.keys())[-1] == 'reading'

    @pytest.mark.parametrize('files_pr, files_prompt, expected', [
        (194, 100, '100-of-194'),
        (3, 3, 'complete'),
        (3, 5, 'complete'),
        ('unknown', 3, 'unknown'),
        (3, 'unknown', 'unknown'),
    ])
    def test_file_list_statement_limit(self, files_pr, files_prompt, expected, capsys):
        context = dict(CONTEXT, files_pr=files_pr, files_prompt=files_prompt)
        (_, _, _), lines, runner = run_runner([proc(cli_result())], context=context, capsys=capsys)

        values = dict(parse_line(lines[0]))
        assert values['file_list'] == expected
        assert runner.scan_evidence()['attempts'][0]['file_list'] == expected


class TestEvidenceNeverRaises:
    """Evidence code must not raise into the scan."""

    def test_builder_failure_does_not_change_the_scan(self, capsys):
        with patch('claudecode.github_action_audit._build_attempt_evidence', side_effect=RuntimeError('boom')):
            (success, error, results), lines, runner = run_runner([proc(cli_result())], capsys=capsys)

        assert success is True and error == ''
        assert results['analysis_summary']['review_completed'] is True
        # the attempt is still counted, with every other field unknown
        assert len(lines) == 1
        values = dict(parse_line(lines[0]))
        assert values['attempt'] == '1'
        assert values['turns'] == values['exit'] == 'unknown'
        assert len(runner.scan_evidence()['attempts']) == 1

    def test_broken_stderr_does_not_change_the_scan(self, monkeypatch):
        class BrokenStream:
            def write(self, _text):
                raise OSError('stderr closed')

            def flush(self):
                raise OSError('stderr closed')

        monkeypatch.setattr(sys, 'stderr', BrokenStream())
        (success, error, results), _, runner = run_runner([proc(cli_result())])

        assert success is True and error == ''
        assert results['analysis_summary']['review_completed'] is True
        assert len(runner.scan_evidence()['attempts']) == 1  # the entry is kept even if the line is lost

    def test_exception_after_the_cli_returned_still_records_the_attempt(self, capsys):
        # A JSON scalar in `result` makes findings extraction raise; the outer handler reports it as before
        weird = cli_result(result='5')
        with patch.object(SimpleClaudeRunner, '_extract_security_findings', side_effect=TypeError('bad')):
            (success, error, _), lines, _ = run_runner([proc(weird)], capsys=capsys)

        assert success is False
        assert 'Claude Code execution error' in error
        assert len(lines) == 1
        assert dict(parse_line(lines[0]))['exit'] == '0'


# --- main(): context, results file, gate ---------------------------------------------------------------

def make_pr_data(files=3, changed_files=None):
    return {
        'number': 42,
        'title': 'Evidence PR',
        'body': 'Body',
        'user': 'dev',
        'head': {'ref': 'branch', 'sha': HEAD_SHA, 'repo': {'full_name': 'owner/repo'}},
        'base': {'ref': 'main', 'sha': 'c' * 40},
        'files': [{'filename': f'src/file{i}.py', 'status': 'modified', 'additions': 1,
                   'deletions': 0, 'changes': 1, 'patch': ''} for i in range(files)],
        'additions': 10,
        'deletions': 2,
        'changed_files': changed_files if changed_files is not None else files,
    }


DIFF = 'diff --git a/src/file0.py b/src/file0.py\n+x = 1\ndiff --git a/src/file1.py b/src/file1.py\n+y = é\n'


def make_git_repo(path):
    if shutil.which('git') is None:
        pytest.skip('git not available')
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), '-c', 'user.email=t@example.com', '-c', 'user.name=t',
                    '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'init'], check=True)
    out = subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def run_main(tmp_path, claude_calls, pr_data=None, pr_diff=DIFF, repo_dir=None, client_setup=None):
    """Run main() against a mocked GitHub client and mocked claude subprocesses.

    Returns (exit_code, results_json, stderr_text, subprocess_mock)."""
    client = Mock()
    client.get_pr_data.return_value = pr_data if pr_data is not None else make_pr_data()
    client.get_pr_diff.return_value = pr_diff
    client._is_excluded.return_value = False
    if client_setup:
        client_setup(client)
    version = Mock(returncode=0, stdout='2.1.285 (Claude Code)', stderr='')
    env = {
        'GITHUB_REPOSITORY': 'owner/repo',
        'PR_NUMBER': '42',
        'GITHUB_TOKEN': 'test-token',
        'ANTHROPIC_API_KEY': 'sk-ant-test-key-SECRET-KEY',
        'ENABLE_CLAUDE_FILTERING': 'false',
        'REPO_PATH': str(repo_dir if repo_dir is not None else tmp_path),
    }
    with patch('claudecode.github_action_audit.GitHubActionClient', return_value=client), \
            patch('subprocess.run', side_effect=[version] + list(claude_calls)) as mock_run, \
            patch('claudecode.github_action_audit.time.sleep'), \
            patch.dict(os.environ, env):
        for name in ('EXCLUDE_DIRECTORIES', 'FALSE_POSITIVE_FILTERING_INSTRUCTIONS',
                     'CUSTOM_SECURITY_SCAN_INSTRUCTIONS'):
            os.environ.pop(name, None)
        with pytest.raises(SystemExit) as exc_info:
            main()
    return exc_info.value.code, mock_run


def run_main_capture(capsys, *args, **kwargs):
    code, mock_run = run_main(*args, **kwargs)
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err, mock_run


def gate(tmp_path, results, exit_code):
    path = tmp_path / 'results.json'
    path.write_text(json.dumps(results), encoding='utf-8')
    return result_gate.evaluate(str(path), str(exit_code))


class TestMainEvidence:
    def test_success_output_carries_scan_evidence_first_and_a_line(self, tmp_path, capsys):
        sha = make_git_repo(tmp_path / 'repo')
        code, output, err, mock_run = run_main_capture(
            capsys, tmp_path, [proc(cli_result())], repo_dir=tmp_path / 'repo')

        assert code == 0
        assert list(output.keys())[0] == 'scan_evidence'
        attempts = output['scan_evidence']['attempts']
        assert len(attempts) == 1
        entry = attempts[0]
        assert list(entry.keys()) == LINE_KEYS
        assert entry['pr'] == 42
        assert entry['head'] == HEAD_SHA
        assert entry['checkout'] == sha  # git rev-parse HEAD in the scanned directory
        assert entry['files_pr'] == 3 and entry['files_prompt'] == 3 and entry['file_list'] == 'complete'
        assert entry['diff'] == 'yes'
        assert entry['diff_files'] == 2
        assert entry['diff_bytes'] == len(DIFF.encode('utf-8'))  # UTF-8 bytes, not characters
        assert entry['prompt_chars'] > len(DIFF)
        assert entry['review_completed'] is True

        lines = evidence_lines(err)
        assert len(lines) == 1
        assert dict(parse_line(lines[0]))['checkout'] == sha
        # the existing output keys are untouched
        assert output['pr_number'] == 42 and output['repo'] == 'owner/repo'
        assert output['findings'] == []
        # the git lookup does not go through subprocess.run: version check + one claude call only
        assert mock_run.call_count == 2

    def test_checkout_is_unknown_outside_a_git_repository(self, tmp_path, capsys):
        plain = tmp_path / 'plain'
        plain.mkdir()
        code, output, err, _ = run_main_capture(capsys, tmp_path, [proc(cli_result())], repo_dir=plain)

        assert code == 0
        assert output['scan_evidence']['attempts'][0]['checkout'] == 'unknown'
        assert dict(parse_line(evidence_lines(err)[0]))['checkout'] == 'unknown'

    def test_checkout_is_computed_once_for_all_attempts(self, tmp_path, capsys):
        sha = make_git_repo(tmp_path / 'repo')
        calls = [proc(cli_result(subtype='error_during_execution', is_error=True, drop=('result',))),
                 proc(cli_result())]
        with patch('claudecode.github_action_audit._resolve_checkout_sha', return_value=sha) as resolve:
            code, output, err, _ = run_main_capture(capsys, tmp_path, calls, repo_dir=tmp_path / 'repo')

        assert code == 0
        assert resolve.call_count == 1
        assert [a['checkout'] for a in output['scan_evidence']['attempts']] == [sha, sha]

    def test_prompt_too_long_then_no_diff_retry_keeps_both_attempts(self, tmp_path, capsys):
        too_long = cli_result(is_error=True, result='Prompt is too long', total_cost_usd=0, num_turns=1,
                              usage={'input_tokens': 0, 'output_tokens': 0})
        calls = [proc(too_long), proc(cli_result())]
        code, output, err, mock_run = run_main_capture(capsys, tmp_path, calls)

        assert code == 0  # the retry completed: the run stays scanned, gate unchanged
        attempts = output['scan_evidence']['attempts']
        assert [a['attempt'] for a in attempts] == [1, 2]
        first, second = attempts
        assert (first['diff'], second['diff']) == ('yes', 'no')
        assert 'reading' not in first
        assert second['reading'] == 'not-proven'
        assert first['subtype'] == 'success' and first['is_error'] is True
        assert first['review_completed'] == 'unknown'
        assert second['review_completed'] is True
        assert second['prompt_chars'] < first['prompt_chars']
        # facts about the fetched diff are carried on both entries; diff=no says it was not sent
        assert first['diff_bytes'] == second['diff_bytes'] == len(DIFF.encode('utf-8'))

        lines = evidence_lines(err)
        assert len(lines) == 2
        assert dict(parse_line(lines[0]))['diff'] == 'yes'
        assert parse_line(lines[1])[-1] == ('reading', 'not-proven')
        assert mock_run.call_count == 3  # version check + two claude calls
        assert gate(tmp_path, output, code) == (True, '0')

    @pytest.mark.parametrize('exit_code', [0, 1])
    @pytest.mark.parametrize('variant', list(TOO_LONG_VARIANTS))
    def test_prompt_too_long_with_any_exit_code_runs_the_no_diff_attempt(self, variant, exit_code,
                                                                         tmp_path, capsys):
        calls = [proc(TOO_LONG_VARIANTS[variant], returncode=exit_code), proc(cli_result())]
        code, output, err, mock_run = run_main_capture(capsys, tmp_path, calls)

        assert code == 0  # the no-diff attempt completed: the scan completes
        attempts = output['scan_evidence']['attempts']
        assert [a['attempt'] for a in attempts] == [1, 2]  # both attempts are in the evidence
        first, second = attempts
        assert (first['diff'], second['diff']) == ('yes', 'no')
        assert 'reading' not in first
        assert second['reading'] == 'not-proven'
        assert (first['exit'], second['exit']) == (exit_code, 0)
        assert first['type'] == 'result' and first['is_error'] is True
        assert first['review_completed'] == 'unknown'
        assert second['review_completed'] is True
        assert second['prompt_chars'] < first['prompt_chars']

        lines = evidence_lines(err)
        assert len(lines) == 2
        assert parse_line(lines[1])[-1] == ('reading', 'not-proven')
        assert mock_run.call_count == 3  # version check + the attempt with the diff + the one without
        assert gate(tmp_path, output, code) == (True, '0')

    @pytest.mark.parametrize('exit_code', [0, 1])
    @pytest.mark.parametrize('result', [
        cli_result(is_error=True, result='API Error: 401 authentication_error'),
        cli_result(subtype='error_during_execution', is_error=True, errors=['API Error: 529 overloaded_error'],
                   drop=('result',)),
        cli_result(is_error=False, result='Prompt is too long'),
        cli_result(type='assistant', is_error=True, result='Prompt is too long'),
    ], ids=['other-error', 'other-error-in-errors', 'phrase-without-error-flag', 'phrase-but-not-a-result'])
    def test_other_results_never_give_a_successful_scan_or_a_no_diff_attempt(self, result, exit_code,
                                                                            tmp_path, capsys):
        calls = [proc(result, returncode=exit_code) for _ in range(3)]
        code, output, err, mock_run = run_main_capture(capsys, tmp_path, calls)

        assert code == 1  # a failed scan, never a clean one
        assert 'error' in output and 'findings' not in output
        assert 'PROMPT_TOO_LONG' not in output['error']
        assert gate(tmp_path, output, code) == (False, 'scan reported an error')
        attempts = output['scan_evidence']['attempts']
        assert all(a['diff'] == 'yes' and 'reading' not in a for a in attempts)  # no run without the diff
        assert 'Prompt too long, retrying without diff' not in err

    def test_empty_diff_means_no_diff_in_prompt(self, tmp_path, capsys):
        code, output, err, _ = run_main_capture(capsys, tmp_path, [proc(cli_result())], pr_diff='')

        assert code == 0
        entry = output['scan_evidence']['attempts'][0]
        assert entry['diff'] == 'no'
        assert entry['reading'] == 'not-proven'
        assert entry['diff_files'] == 0 and entry['diff_bytes'] == 0
        assert parse_line(evidence_lines(err)[0])[-1] == ('reading', 'not-proven')

    def test_more_than_100_files_is_reported_as_n_of_m(self, tmp_path, capsys):
        pr_data = make_pr_data(files=100, changed_files=194)
        code, output, err, _ = run_main_capture(capsys, tmp_path, [proc(cli_result())], pr_data=pr_data)

        assert code == 0
        entry = output['scan_evidence']['attempts'][0]
        assert entry['files_pr'] == 194
        assert entry['files_prompt'] == 100
        assert entry['file_list'] == '100-of-194'
        values = dict(parse_line(evidence_lines(err)[0]))
        assert values['file_list'] == '100-of-194'
        assert gate(tmp_path, output, code) == (True, '0')  # statement limit only: the verdict is unchanged

    def test_missing_pr_fields_are_unknown(self, tmp_path, capsys):
        sparse_pr = {'number': 42, 'title': 'T', 'body': '', 'user': 'dev', 'additions': 1, 'deletions': 1}
        with patch('claudecode.github_action_audit.get_security_audit_prompt', return_value='prompt'):
            code, output, err, _ = run_main_capture(capsys, tmp_path, [proc(cli_result())], pr_data=sparse_pr)

        assert code == 0
        entry = output['scan_evidence']['attempts'][0]
        assert entry['head'] == entry['files_pr'] == entry['files_prompt'] == entry['file_list'] == 'unknown'
        assert entry['pr'] == 42

    def test_every_error_output_carries_scan_evidence(self, tmp_path, capsys):
        # audit failure: the three CLI failures are kept in the error output
        calls = [proc(returncode=1, stderr='boom') for _ in range(3)]
        code, output, err, _ = run_main_capture(capsys, tmp_path, calls)

        assert code == 1
        assert output['error'].startswith('Security audit failed:')
        assert [a['attempt'] for a in output['scan_evidence']['attempts']] == [1, 2, 3]
        assert [a['exit'] for a in output['scan_evidence']['attempts']] == [1, 1, 1]
        assert len(evidence_lines(err)) == 3
        assert gate(tmp_path, output, code) == (False, 'scan reported an error')

    def test_incomplete_audit_error_output_carries_the_attempt(self, tmp_path, capsys):
        incomplete = dict(COMPLETE_FINDINGS, analysis_summary={'review_completed': False})
        code, output, _, _ = run_main_capture(capsys, tmp_path, [proc(cli_result(findings=incomplete))])

        assert code == 1
        assert output['error'] == 'Security audit incomplete: analysis_summary.review_completed is not true'
        attempts = output['scan_evidence']['attempts']
        assert len(attempts) == 1 and attempts[0]['review_completed'] is False

    def test_error_paths_before_any_attempt_carry_an_empty_list(self, tmp_path, capsys):
        # configuration error
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit):
                main()
        assert json.loads(capsys.readouterr().out)['scan_evidence'] == {'attempts': []}

        # PR data fetch failure
        code, output, _, _ = run_main_capture(
            capsys, tmp_path, [], client_setup=lambda c: setattr(c.get_pr_data, 'side_effect', Exception('API')))
        assert code == 1
        assert 'Failed to fetch PR data' in output['error']
        assert output['scan_evidence'] == {'attempts': []}

    def test_unexpected_error_output_carries_scan_evidence(self, tmp_path, capsys):
        with patch('claudecode.github_action_audit.get_security_audit_prompt', side_effect=RuntimeError('oops')):
            code, output, _, _ = run_main_capture(capsys, tmp_path, [])

        assert code == 2
        assert 'Unexpected error: oops' in output['error']
        assert output['scan_evidence'] == {'attempts': []}

    def test_runner_without_evidence_gives_an_empty_list(self, tmp_path, capsys):
        # e.g. a runner double: main() must not trust the shape of what it gets back
        with patch.object(SimpleClaudeRunner, 'scan_evidence', side_effect=RuntimeError('boom')):
            code, output, err, _ = run_main_capture(capsys, tmp_path, [proc(cli_result())])

        assert code == 0
        assert output['scan_evidence'] == {'attempts': []}
        assert output['findings'] == []

    def test_gate_verdict_and_findings_count_unchanged_by_evidence(self, tmp_path, capsys):
        findings = {
            'findings': [{'file': 'a.py', 'line': 1, 'severity': 'HIGH', 'category': 'x',
                          'description': 'd', 'exploit_scenario': 'e', 'recommendation': 'r', 'confidence': 0.9},
                         {'file': 'b.py', 'line': 2, 'severity': 'MEDIUM', 'category': 'x',
                          'description': 'd', 'exploit_scenario': 'e', 'recommendation': 'r', 'confidence': 0.9}],
            'analysis_summary': COMPLETE_FINDINGS['analysis_summary'],
        }
        code, output, _, _ = run_main_capture(capsys, tmp_path, [proc(cli_result(findings=findings))])
        assert 'scan_evidence' in output

        without = {k: v for k, v in output.items() if k != 'scan_evidence'}
        assert gate(tmp_path, output, code) == gate(tmp_path, without, code)
        ok, count = gate(tmp_path, output, code)
        assert ok is True and count == str(len(output['findings']))

    @pytest.mark.parametrize('payload', [
        {'findings': [], 'analysis_summary': {'review_completed': True}},
        {'findings': [], 'analysis_summary': {'review_completed': False}},
        {'findings': [], 'analysis_summary': {}},
        {'findings': [], 'error': 'Security audit failed: x'},
        {'findings': [{'severity': 'HIGH'}], 'analysis_summary': {'review_completed': True}},
        {'findings': 'nope', 'analysis_summary': {'review_completed': True}},
    ])
    @pytest.mark.parametrize('exit_code', [0, 1, 2])
    def test_gate_is_independent_of_the_scan_evidence_key(self, payload, exit_code, tmp_path):
        evidence = {'attempts': [{'attempt': 1, 'exit': 0, 'review_completed': True}]}
        assert gate(tmp_path, dict(payload, scan_evidence=evidence), exit_code) == gate(tmp_path, payload, exit_code)
        assert gate(tmp_path, dict(payload, scan_evidence={'attempts': []}), exit_code) == \
            gate(tmp_path, payload, exit_code)

    def test_no_prompt_stderr_or_key_in_the_results_file_or_lines(self, tmp_path, capsys):
        pr_data = make_pr_data()
        pr_data['title'] = 'PROMPT-SECRET-TITLE'
        calls = [proc(returncode=1, stdout='STDOUT-SECRET-TEXT', stderr='STDERR-SECRET-TEXT'),
                 proc(cli_result(permission_denials=[{'tool_name': 'Bash',
                                                      'tool_input': {'command': 'echo SECRET-COMMAND'}}]),
                      stderr='STDERR-SECRET-TEXT')]
        code, output, err, _ = run_main_capture(capsys, tmp_path, calls, pr_data=pr_data)

        assert code == 0
        evidence_text = json.dumps(output['scan_evidence']) + '\n'.join(evidence_lines(err))
        for secret in ('PROMPT-SECRET-TITLE', 'STDOUT-SECRET-TEXT', 'STDERR-SECRET-TEXT', 'SECRET-COMMAND',
                       'sk-ant-test-key', 'SECRET-KEY', 'test-token'):
            assert secret not in evidence_text, secret
        assert output['scan_evidence']['attempts'][1]['denials_by_tool'] == 'Bash:1'


# --- result gate: every existing gate case, with and without the evidence block ---------------------------

def _gate_complete(findings=None, **extra):
    """Mirror of test_result_gate._complete: a results document from a scan that completed."""
    data = {'findings': findings if findings is not None else [], 'analysis_summary': {'review_completed': True}}
    data.update(extra)
    return data


# One row per case of claudecode/test_result_gate.py that has a results document to add the key to,
# with the (ok, message) that test asserts: (source test, payload, exit code, expected verdict).
# Not mirrored, because there is no JSON object to carry `scan_evidence`: test_missing_file,
# test_empty_file, test_invalid_json, test_json_array and the TestResultGateCli missing-file case.
# The two other TestResultGateCli cases are rows below (the CLI prints evaluate()'s message).
GATE_CASES = [
    # TestEvaluateFileChecks
    ('test_findings_not_a_list', _gate_complete(findings={'file': 'a.py'}), '0', (False, 'results file invalid')),
    ('test_error_key', {'error': 'Security audit failed: SECRET-MARKER-1234'}, '1',
     (False, 'scan reported an error')),
    ('test_error_key_wins_over_complete_result', _gate_complete(error='boom'), '0',
     (False, 'scan reported an error')),
    # TestEvaluateReviewCompleted
    ('test_review_completed_false', {'findings': [], 'analysis_summary': {'review_completed': False}}, '0',
     (False, 'review not completed')),
    ('test_review_completed_missing', {'findings': [], 'analysis_summary': {'files_reviewed': 3}}, '0',
     (False, 'review not completed')),
    ('test_analysis_summary_missing', {'findings': []}, '0', (False, 'review not completed')),
    ('test_review_completed_string_true', {'findings': [], 'analysis_summary': {'review_completed': 'true'}}, '0',
     (False, 'review not completed')),
    ('test_review_completed_number_one[int_1]', {'findings': [], 'analysis_summary': {'review_completed': 1}}, '0',
     (False, 'review not completed')),
    ('test_review_completed_number_one[float_1]', {'findings': [], 'analysis_summary': {'review_completed': 1.0}},
     '0', (False, 'review not completed')),
    # TestEvaluateExitCode
    ('test_exit_0_no_findings', _gate_complete(), '0', (True, '0')),
    ('test_exit_0_two_findings',
     _gate_complete([{'file': 'a.py', 'severity': 'MEDIUM'}, {'file': 'b.py', 'severity': 'LOW'}]), '0',
     (True, '2')),
    ('test_exit_1_with_high_finding',
     _gate_complete([{'file': 'a.py', 'severity': 'high'}, {'file': 'b.py', 'severity': 'LOW'}]), '1',
     (True, '2')),
    ('test_exit_1_without_high_finding', _gate_complete([{'file': 'a.py', 'severity': 'MEDIUM'}]), '1',
     (False, 'exit code 1')),
    ('test_exit_1_no_findings', _gate_complete(), '1', (False, 'exit code 1')),
    ('test_exit_2_with_valid_complete_file', _gate_complete(), '2', (False, 'exit code 2')),
    ('test_non_integer_exit_code[empty]', _gate_complete(), '', (False, 'exit code unknown')),
    ('test_non_integer_exit_code[abc]', _gate_complete(), 'abc', (False, 'exit code unknown')),
    ('test_non_integer_exit_code[1.5]', _gate_complete(), '1.5', (False, 'exit code unknown')),
    # TestResultGateCli
    ('test_cli_success', _gate_complete([{'file': 'a.py', 'severity': 'LOW'}]), '0', (True, '1')),
    ('test_cli_failure', {'error': 'Security audit failed: x'}, '1', (False, 'scan reported an error')),
]


class TestGateWithAndWithoutEvidence:
    """The result gate returns the identical (ok, message) with and without `scan_evidence`."""

    @staticmethod
    def recorded_evidence(capsys):
        """A realistic evidence block: a retried attempt, then a no-diff attempt (has the `reading` key)."""
        first = proc(cli_result(subtype='error_during_execution', is_error=True, drop=('result',)))
        runner = SimpleClaudeRunner()
        run_runner([first, proc(cli_result())], context=dict(CONTEXT, diff_in_prompt=False), runner=runner)
        capsys.readouterr()
        evidence = runner.scan_evidence()
        assert len(evidence['attempts']) == 2 and evidence['attempts'][1]['reading'] == 'not-proven'
        return evidence

    @pytest.mark.parametrize('source, payload, exit_code, expected', GATE_CASES, ids=[c[0] for c in GATE_CASES])
    @pytest.mark.parametrize('evidence_kind', ['empty', 'recorded'])
    def test_every_gate_case_has_the_same_verdict(self, source, payload, exit_code, expected, evidence_kind,
                                                  tmp_path, capsys):
        evidence = {'attempts': []} if evidence_kind == 'empty' else self.recorded_evidence(capsys)

        without = gate(tmp_path, payload, exit_code)
        with_evidence = gate(tmp_path, dict(payload, scan_evidence=evidence), exit_code)

        assert without == expected  # the verdict test_result_gate.py asserts for this case
        assert with_evidence == without
        assert 'SECRET-MARKER-1234' not in with_evidence[1]

# --- action.yml: the echo between the scan and the gate ------------------------------------------------

ACTION_YML = Path(__file__).resolve().parent.parent / 'action.yml'

# The scan step writes its stderr log straight to the workspace root; GitHub expands this expression
# (inside double quotes in the script) before bash runs, so the test expands it the same way.
WORKSPACE_EXPR = '${{ github.workspace }}'
ERROR_LOG_EXPR = '"' + WORKSPACE_EXPR + '/claudecode-error.log"'


def echo_block(workspace):
    """The evidence echo of the scan step, dedented to a standalone shell snippet."""
    text = ACTION_YML.read_text(encoding='utf-8')
    start = text.index('        # Run and input evidence')
    end = text.index('        fi\n', start) + len('        fi\n')
    block = '\n'.join(line[8:] for line in text[start:end].splitlines()) + '\n'
    return block.replace(WORKSPACE_EXPR, str(workspace))


class TestActionEvidenceEcho:
    def test_echo_sits_between_the_scan_and_the_result_gate(self):
        text = ACTION_YML.read_text(encoding='utf-8')
        python_call = text.index('python -u claudecode/github_action_audit.py')
        echo = text.index(f"grep '^SCAN-EVIDENCE ' {ERROR_LOG_EXPR} || true")
        gate_block = text.index('# Result gate (fail closed)')
        assert python_call < echo < gate_block
        # only the echo is allowed to swallow a failure; the gate call and the scan call stay strict
        assert 'result_gate claudecode/claudecode-results.json "${CLAUDECODE_EXIT_CODE:-0}")' in text
        assert 'result_gate' not in text[echo - 200:echo + 200]

    def test_error_log_is_written_at_the_workspace_root_from_the_start(self):
        # a job timeout cancels the step before any end-of-step copy runs, so the log must not need one
        text = ACTION_YML.read_text(encoding='utf-8')
        python_line = next(line for line in text.splitlines() if 'python -u claudecode/github_action_audit.py' in line)
        assert f'2>{ERROR_LOG_EXPR} ||' in python_line
        assert 'claudecode/claudecode-error.log' not in text  # no reference to a log under the action dir
        assert 'cp claudecode/claudecode-error.log' not in text  # and no end-of-step copy of it

    def test_echo_prints_outside_any_log_group(self):
        text = ACTION_YML.read_text(encoding='utf-8')
        python_call = text.index('python -u claudecode/github_action_audit.py')
        echo = text.index(f"grep '^SCAN-EVIDENCE ' {ERROR_LOG_EXPR} || true")
        gate_block = text.index('# Result gate (fail closed)')
        before = text[python_call:echo]
        # the group opened for the scan is closed before the echo, so the Actions UI does not collapse it
        assert '::endgroup::' in before and '::group::' not in before
        # the gate keeps its place in the (re-opened) group
        assert text.index('::group::', echo) < gate_block

    @pytest.mark.skipif(shutil.which('bash') is None, reason='bash not available')
    def test_echo_prints_only_evidence_lines_and_never_fails_the_step(self, tmp_path):
        # workspace and action dir differ, as in a normal run (the step cd's into the action dir);
        # the workspace path holds a space to prove the quoting
        workspace = tmp_path / 'work space'
        action_dir = tmp_path / 'action'
        workspace.mkdir()
        action_dir.mkdir()
        log = workspace / 'claudecode-error.log'

        def run():
            # the same shell flags GitHub uses for `shell: bash`
            return subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', echo_block(workspace)],
                                  cwd=action_dir, capture_output=True, text=True)

        log.write_text('[Info] something\nSCAN-EVIDENCE attempt=1 pr=42\n'
                       '[mod] SCAN-EVIDENCE not=at-column-zero\nSCAN-EVIDENCE attempt=2 pr=42\n', encoding='utf-8')
        done = run()
        assert done.returncode == 0
        assert done.stdout == 'SCAN-EVIDENCE attempt=1 pr=42\nSCAN-EVIDENCE attempt=2 pr=42\n'

        log.write_text('[Info] no evidence in this log\n', encoding='utf-8')  # grep exits 1 here
        done = run()
        assert (done.returncode, done.stdout) == (0, '')

        log.unlink()  # no log at all
        done = run()
        assert (done.returncode, done.stdout) == (0, '')
