#!/usr/bin/env python3
"""
Tests for the action's work directory.

Everything the composite action writes or uploads (results file, findings.json, error log and the
reservation marker) lives in one directory under the runner temp dir, created fresh and empty at the
start of the action. A pull request controls the workspace (in the self-scan, `uses: ./`, also the
action path), so a symlink it places there must never redirect a write or an upload.

The YAML is read as text so the suite needs no YAML library in CI; one test checks that reading
against PyYAML where it is installed.
"""

import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path

import pytest

from claudecode import result_gate
from claudecode.test_scan_evidence import ACTION_YML, WORK_EXPR, run_bash, step_script, step_text

REPO_ROOT = ACTION_YML.parent

CHECK_STEP = 'Check gh and jq'
PREPARE_STEP = "Prepare the action's work directory"
RESTORE_STEP = 'Check ClaudeCode run history'
ENABLE_STEP = 'Determine ClaudeCode enablement'
RESERVE_STEP = 'Reserve ClaudeCode slot to prevent race conditions'
SCAN_STEP = 'Run ClaudeCode scan'
SAVE_STEP = 'Save ClaudeCode run marker to cache (completed scans only)'
UPLOAD_STEP = 'Upload scan results'
COMMENT_STEP = 'Comment PR with findings'
STAGE_STEP = 'Stage scan log for upload'

# The three files of the artifact, in the upload's order
UPLOADED = ('findings.json', 'claudecode-results.json', 'claudecode-error.log')
MARKER_EXPR = WORK_EXPR + '/claudecode-marker'
# The run marker's cache keys are the same as before the marker moved into the work directory
CACHE_KEY = 'claudecode-${{ github.repository_id }}-pr-${{ github.event.pull_request.number }}-${{ github.sha }}'
RESTORE_KEY = 'claudecode-${{ github.repository_id }}-pr-${{ github.event.pull_request.number }}-'


# --- reading action.yml ------------------------------------------------------------------------------

def step_names():
    """The names of the composite steps, in order."""
    return re.findall(r'^    - name: (.+)$', ACTION_YML.read_text(encoding='utf-8'), re.MULTILINE)


def scalar(value):
    """A one-line YAML scalar as GitHub reads it: quotes removed, or a plain value without its comment."""
    value = value.strip()
    if value[:1] in ('"', "'") and value[0] in value[1:]:
        return value[1:value.index(value[0], 1)]
    return re.sub(r'\s+#.*$', '', value)


def step_field(name, key):
    """A scalar key of one step (`if`, `shell`, `uses`, `working-directory`), or None."""
    match = re.search(rf'^      {re.escape(key)}: (.*)$', step_text(name), re.MULTILINE)
    return scalar(match.group(1)) if match else None


def step_mapping(name, key):
    """The `with:` or `env:` mapping of one step; a block scalar value comes back as its list of lines."""
    lines = step_text(name).splitlines()
    if f'      {key}:' not in lines:
        return {}
    result, block = {}, None
    for line in lines[lines.index(f'      {key}:') + 1:]:
        if not line.strip() or line.strip().startswith('#'):
            continue
        if not line.startswith('        '):  # back at the step's own keys
            break
        if block is not None and line.startswith('          '):
            result[block].append(line.strip())
            continue
        item, _, value = line.strip().partition(':')
        if value.strip() == '|':
            result[item], block = [], item
        else:
            result[item], block = scalar(value), None
    return result


def script_lines(name):
    """The run script of one step without its comment lines (empty for a `uses:` step)."""
    if 'run: |' not in step_text(name):
        return []
    return [line for line in step_script(name).splitlines() if not line.lstrip().startswith('#')]


# A redirection that writes (`>`, `>>`, `2>`, `&>`; not `2>&1`) and its target; a heredoc (`<<`) is a read
REDIRECT = re.compile(r'(?<![<>])(?:\d|&)?>>?(?!&)\s*("[^"]*"|[^\s;|&)]+)')
# A command that creates, changes or removes files, with its operands up to the end of the command
WRITE_COMMAND = re.compile(r'(?:^|[\s;&|({])(cp|mv|tee|touch|mkdir|rm|ln|truncate|dd|install|rsync)\s+([^;&|\n]*)')
OPERAND = re.compile(r'"[^"]*"|\S+')
# Writes that are not files of the job: step outputs and the null device
NON_FILE_SINKS = ('$GITHUB_OUTPUT', '/dev/null')


def write_targets(name):
    """Every path the run script of one step writes to: redirection targets and file-command operands."""
    targets = []
    for line in script_lines(name):
        targets += REDIRECT.findall(line)
        for command, operands in WRITE_COMMAND.findall(line):
            if command == 'install' and re.search(r'\b(pip|npm)\s+install\b', line):
                continue  # package installs write to the tool caches, never to a path of the script
            targets += [operand for operand in OPERAND.findall(operands) if not operand.startswith('-')]
    return targets


def in_work_dir(target):
    """A quoted path that is the work directory or lies inside it."""
    return target == f'"{WORK_EXPR}"' or target.startswith(f'"{WORK_EXPR}/')


# --- the structure of action.yml ---------------------------------------------------------------------

class TestWorkDirStructure:
    def test_text_reading_matches_yaml(self):
        yaml = pytest.importorskip('yaml')
        steps = yaml.safe_load(ACTION_YML.read_text(encoding='utf-8'))['runs']['steps']
        assert [step['name'] for step in steps] == step_names()
        for step in steps:
            name = step['name']
            for key in ('if', 'shell', 'uses', 'working-directory'):
                expected = step.get(key)
                assert step_field(name, key) == (None if expected is None else str(expected)), (name, key)
            for key in ('with', 'env'):
                expected = {item: value.splitlines() if isinstance(value, str) and '\n' in value else str(value)
                            for item, value in (step.get(key) or {}).items()}
                assert step_mapping(name, key) == expected, (name, key)
            if 'run' in step:
                assert step_script(name).rstrip('\n') == step['run'].rstrip('\n'), name

    def test_prepare_step_makes_a_fresh_empty_work_dir_right_after_the_tool_check(self):
        names = step_names()
        assert names.index(PREPARE_STEP) == names.index(CHECK_STEP) + 1
        assert step_field(PREPARE_STEP, 'if') is None  # unconditional
        assert step_field(PREPARE_STEP, 'shell') == 'bash'
        assert script_lines(PREPARE_STEP) == [f'rm -rf "{WORK_EXPR}"', f'mkdir -p "{WORK_EXPR}"']

    def test_every_write_target_is_in_the_work_dir(self):
        found = {name: write_targets(name) for name in step_names()}
        assert found[RESERVE_STEP] and found[SCAN_STEP]  # the reading finds the writes it must check
        for name, targets in found.items():
            for target in targets:
                assert target in NON_FILE_SINKS or in_work_dir(target), (name, target)
        # every file the scan step writes, by name
        scan = found[SCAN_STEP]
        for path in ('claudecode-results.json', 'claudecode-error.log', 'findings.json'):
            assert f'"{WORK_EXPR}/{path}"' in scan, path
        assert f'"{MARKER_EXPR}/marker.json"' in found[RESERVE_STEP]

    def test_the_workspace_is_never_written(self):
        text = ACTION_YML.read_text(encoding='utf-8')
        assert 'github.workspace' not in text
        assert '.claudecode-marker' not in text
        assert re.search(r'(?:^|[\s;&|(])cp\s', text, re.MULTILINE) is None  # nothing is copied anywhere
        # the only directory change is into the action path, which only Python reads (no bytecode, below)
        assert re.findall(r'(?:^|[\s;&|(])cd\s+(\S+)', text, re.MULTILINE) == ['"$ACTION_PATH"']

    def test_prepare_step_comes_before_every_step_that_writes(self):
        names = step_names()
        prepare = names.index(PREPARE_STEP)
        for index, name in enumerate(names):
            writes_files = any(target not in NON_FILE_SINKS for target in write_targets(name))
            uses_work_dir = WORK_EXPR in step_text(name)
            if name != PREPARE_STEP and (writes_files or uses_work_dir):
                assert index > prepare, name

    def test_both_cache_steps_keep_the_marker_in_the_work_dir_under_the_same_key(self):
        restore = step_mapping(RESTORE_STEP, 'with')
        save = step_mapping(SAVE_STEP, 'with')
        assert restore['path'] == save['path'] == MARKER_EXPR
        assert restore['key'] == save['key'] == CACHE_KEY
        assert restore['restore-keys'] == [RESTORE_KEY]
        assert step_field(RESTORE_STEP, 'uses') == 'actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830'
        assert step_field(SAVE_STEP, 'uses') == 'actions/cache/save@0057852bfaa89a56745cba8c7296529d2fc39830'
        # the marker is reserved and checked where the cache restores and saves it
        enable = '\n'.join(script_lines(ENABLE_STEP))
        assert enable.count(f'[ -f "{MARKER_EXPR}/marker.json" ]') == 2
        assert f'mkdir -p "{MARKER_EXPR}"' in script_lines(RESERVE_STEP)

    def test_upload_reads_only_the_three_files_from_the_work_dir(self):
        upload = step_mapping(UPLOAD_STEP, 'with')
        # one directory holds all three, so the artifact stays flat with the same three names
        assert upload['path'] == [f'{WORK_EXPR}/{name}' for name in UPLOADED]
        assert upload['name'] == 'security-review-results'
        assert upload['retention-days'] == '7'
        assert upload['if-no-files-found'] == 'ignore'
        assert step_field(UPLOAD_STEP, 'if') == "always() && inputs.upload-results == 'true'"

    def test_stage_step_is_gone(self):
        assert STAGE_STEP not in step_names()
        assert STAGE_STEP not in ACTION_YML.read_text(encoding='utf-8')

    def test_comment_step_runs_in_the_work_dir(self):
        # comment-pr-findings.js reads findings.json from its working directory
        assert step_field(COMMENT_STEP, 'working-directory') == WORK_EXPR
        assert step_field(COMMENT_STEP, 'if') == (
            "github.event_name == 'pull_request' && inputs.comment-pr == 'true' && "
            "steps.claudecode-check.outputs.enable_claudecode == 'true'")

    def test_results_file_output_points_into_the_work_dir(self):
        assert f'echo "results_file={WORK_EXPR}/claudecode-results.json" >> $GITHUB_OUTPUT' in script_lines(SCAN_STEP)

    def test_scan_step_writes_no_bytecode(self):
        # in the self-scan the action path is the PR checkout, where Python would put __pycache__
        assert step_mapping(SCAN_STEP, 'env')['PYTHONDONTWRITEBYTECODE'] == '1'


# --- simulated runs of the step scripts -------------------------------------------------------------

SENTINEL = b'SENTINEL: outside the workspace, never to be written\n'
PLANTED_MARKER = '{"status": "planted by the pull request"}\n'

# Values for the expressions in the scripts and env of the simulated steps (GitHub expands them before
# bash runs). An expression missing here fails the test, so a new one is never silently left in.
EXPRESSIONS = {
    '${{ github.event_name }}': 'pull_request',
    '${{ github.token }}': 'test-token',
    '${{ github.repository }}': 'owner/repo',
    '${{ github.repository_id }}': '123456',
    '${{ github.event.pull_request.number }}': '42',
    '${{ github.sha }}': 'a' * 40,
    '${{ github.run_id }}': '7',
    '${{ github.run_number }}': '3',
    '${{ inputs.run-every-commit }}': 'false',
    '${{ inputs.claude-api-key }}': 'sk-ant-test-key',
    '${{ inputs.exclude-directories }}': '',
    '${{ inputs.false-positive-filtering-instructions }}': '',
    '${{ inputs.custom-security-scan-instructions }}': '',
    '${{ inputs.claude-model }}': '',
    '${{ inputs.claudecode-timeout }}': '20',
    '${{ steps.claudecode-history.outputs.cache-hit }}': '',
    '${{ steps.claudecode-check.outputs.enable_claudecode }}': 'true',
    '${{ steps.claudecode-check.outputs.silence_claudecode_comments }}': 'false',
    '${{ steps.claudecode-scan.outputs.findings_count }}': '',
}


def make_executable(path, text):
    path.write_text(text, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def snapshot(root):
    """Every entry under root, links not followed: (kind, link target or file bytes)."""
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                entries[rel] = ('link', os.readlink(path))
            elif path.is_dir():
                entries[rel] = ('dir', None)
            else:
                entries[rel] = ('file', path.read_bytes())
    return entries


class Job:
    """One simulated job: runner temp dir, workspace, action path, and a sentinel outside all of them.

    `layout` 'self-scan' is `uses: ./`, where the action path is the workspace (the PR checkout).
    The action path holds a stand-in `claudecode` package: the real result gate and a shim audit script.
    """

    def __init__(self, tmp_path, layout='action dir'):
        self.temp = tmp_path / 'runner temp'  # the spaces prove the quoting
        self.workspace = tmp_path / 'work space'
        self.outside = tmp_path / 'outside'
        self.bin = tmp_path / 'bin'
        self.home = tmp_path / 'home'
        self.action = self.workspace if layout == 'self-scan' else tmp_path / 'action'
        for path in (self.temp, self.workspace, self.outside / 'sentinel-dir', self.bin, self.home,
                     self.action / 'claudecode'):
            path.mkdir(parents=True, exist_ok=True)
        (self.outside / 'sentinel.txt').write_bytes(SENTINEL)
        (self.outside / 'sentinel-dir' / 'marker.json').write_text(PLANTED_MARKER, encoding='utf-8')
        (self.action / 'claudecode' / '__init__.py').write_text('', encoding='utf-8')
        shutil.copy(REPO_ROOT / 'claudecode' / 'result_gate.py', self.action / 'claudecode' / 'result_gate.py')
        make_executable(self.bin / 'python', f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        make_executable(self.bin / 'claude', '#!/bin/sh\necho "2.1.285 (Claude Code)"\n')
        self.values = dict(EXPRESSIONS)
        self.values.update({
            '${{ runner.temp }}': str(self.temp),
            '${{ github.workspace }}': str(self.workspace),
            '${{ github.action_path }}': str(self.action),
        })
        self.work = Path(self.expand(WORK_EXPR))

    def expand(self, text):
        for expression, value in self.values.items():
            text = text.replace(expression, value)
        assert '${{' not in text, text
        return text

    def write_audit_shim(self, results, exit_code):
        """Stand-in for github_action_audit.py: a fixed results JSON on stdout, one evidence line on stderr."""
        (self.action / 'claudecode' / 'github_action_audit.py').write_text(
            'import sys\n'
            "sys.stderr.write('[Info] shim audit\\nSCAN-EVIDENCE attempt=1 pr=42 exit=%d\\n')\n"
            'sys.stdout.write(%r)\n'
            'sys.exit(%d)\n' % (exit_code, json.dumps(results), exit_code),
            encoding='utf-8')

    def plant_links(self):
        """What a pull request can commit: links named like the action's files, pointing outside."""
        for name in UPLOADED:
            (self.workspace / name).symlink_to(self.outside / 'sentinel.txt')
        (self.workspace / '.claudecode-marker').symlink_to(self.outside / 'sentinel-dir', target_is_directory=True)
        (self.action / 'claudecode' / 'claudecode-results.json').symlink_to(self.outside / 'sentinel.txt')

    def state(self):
        """Everything outside the work directory that a step could change."""
        return {root: snapshot(root) for root in {self.workspace, self.action, self.outside}}

    def upload_paths(self):
        """The upload step's paths as upload-artifact resolves them (relative to the workspace)."""
        return [self.workspace / self.expand(path) for path in step_mapping(UPLOAD_STEP, 'with')['path']]

    def run(self, name):
        """Run one step's script as GitHub does: expanded, its env, `bash --noprofile --norc -eo pipefail`."""
        output = self.temp.parent / 'github-output'
        output.write_text('', encoding='utf-8')
        env = {'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", "")}', 'HOME': str(self.home),
               'GITHUB_OUTPUT': str(output)}
        env.update({key: self.expand(value) for key, value in step_mapping(name, 'env').items()})
        directory = step_field(name, 'working-directory')
        cwd = self.expand(directory) if directory else self.workspace  # composite steps default to the workspace
        done = run_bash(self.expand(step_script(name)), cwd, env=env)
        outputs = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').splitlines() if '=' in line)
        return done, outputs

    def work_files(self):
        return sorted(str(path.relative_to(self.work)) for path in self.work.rglob('*'))


def complete(findings):
    return {'findings': findings, 'analysis_summary': {'review_completed': True}}


TWO_FINDINGS = [{'file': 'a.py', 'line': 3, 'severity': 'MEDIUM'}, {'file': 'b.py', 'line': 9, 'severity': 'LOW'}]

needs_tools = pytest.mark.skipif(shutil.which('bash') is None or shutil.which('jq') is None,
                                 reason='bash and jq are needed to run the step scripts')


@needs_tools
class TestPlantedLinks:
    @pytest.mark.parametrize('layout', ['action dir', 'self-scan'])
    def test_links_in_the_workspace_redirect_no_write(self, tmp_path, layout):
        job = Job(tmp_path, layout)
        job.write_audit_shim(complete(TWO_FINDINGS), 0)
        job.plant_links()
        before = job.state()

        for name in (PREPARE_STEP, ENABLE_STEP, RESERVE_STEP, SCAN_STEP):
            done, outputs = job.run(name)
            assert done.returncode == 0, (name, done.stdout, done.stderr)
            if name == ENABLE_STEP:
                # the planted .claudecode-marker/marker.json does not count as an earlier run
                assert outputs['enable_claudecode'] == 'true'

        assert job.state() == before  # sentinel byte-identical, workspace and action path unchanged
        assert (job.outside / 'sentinel.txt').read_bytes() == SENTINEL
        assert job.work_files() == ['claudecode-error.log', 'claudecode-marker', 'claudecode-marker/marker.json',
                                    'claudecode-results.json', 'findings.json']
        assert not any(path.is_symlink() for path in job.work.rglob('*'))
        marker = json.loads((job.work / 'claudecode-marker' / 'marker.json').read_text(encoding='utf-8'))
        assert (marker['status'], marker['pr_number']) == ('reserved', 42)


@needs_tools
class TestNoScanStarted:
    @pytest.mark.parametrize('leftover', ['none', 'files', 'link'])
    def test_upload_paths_resolve_to_nothing(self, tmp_path, leftover):
        job = Job(tmp_path)
        for name in UPLOADED:
            (job.workspace / name).write_text('a file of the pull request\n', encoding='utf-8')
        if leftover == 'files':  # e.g. an earlier job on a reused self-hosted runner
            (job.work / 'claudecode-marker').mkdir(parents=True)
            (job.work / 'claudecode-marker' / 'marker.json').write_text('{}', encoding='utf-8')
            for name in UPLOADED:
                (job.work / name).write_text('stale\n', encoding='utf-8')
        elif leftover == 'link':
            job.work.symlink_to(job.outside / 'sentinel-dir', target_is_directory=True)
        before = job.state()

        done, _ = job.run(PREPARE_STEP)
        assert (done.returncode, done.stderr) == (0, '')
        assert job.work.is_dir() and not job.work.is_symlink()
        assert job.work_files() == []

        job.values['${{ github.event_name }}'] = 'push'  # the scan step skips itself before Python starts
        done, outputs = job.run(SCAN_STEP)
        assert done.returncode == 0
        assert 'findings_count' not in outputs

        for path in job.upload_paths():
            assert path.parent == job.work
            assert not os.path.lexists(path), path
        assert job.state() == before


GATE_CASES = [
    # (results document, audit exit code, the verdict claudecode/test_result_gate.py asserts for it)
    (complete(TWO_FINDINGS), 0, (True, '2')),
    (complete([]), 0, (True, '0')),
    (complete([{'file': 'a.py', 'severity': 'high'}, {'file': 'b.py', 'severity': 'LOW'}]), 1, (True, '2')),
    (complete([{'file': 'a.py', 'severity': 'MEDIUM'}]), 1, (False, 'exit code 1')),
    ({'error': 'Security audit failed: x'}, 1, (False, 'scan reported an error')),
    ({'findings': [], 'analysis_summary': {'review_completed': False}}, 0, (False, 'review not completed')),
]


@needs_tools
class TestHandOver:
    @pytest.mark.parametrize('results, exit_code, verdict', GATE_CASES)
    def test_findings_and_count_come_from_the_work_dir(self, tmp_path, results, exit_code, verdict):
        job = Job(tmp_path)
        job.write_audit_shim(results, exit_code)
        job.run(PREPARE_STEP)

        done, outputs = job.run(SCAN_STEP)

        gate_input = tmp_path / 'gate-input.json'
        gate_input.write_text(json.dumps(results), encoding='utf-8')
        assert result_gate.evaluate(str(gate_input), str(exit_code)) == verdict  # the gate itself, unchanged
        assert outputs['results_file'] == str(job.work / 'claudecode-results.json')
        assert json.loads((job.work / 'claudecode-results.json').read_text(encoding='utf-8')) == results
        assert 'SCAN-EVIDENCE attempt=1 pr=42' in done.stdout  # the echo reads the log in the work dir
        log = job.work / 'claudecode-error.log'
        assert log in job.upload_paths() and 'SCAN-EVIDENCE attempt=1 pr=42' in log.read_text(encoding='utf-8')
        ok, message = verdict
        if ok:
            assert done.returncode == 0, done.stdout
            assert outputs['findings_count'] == message
            findings = json.loads((job.work / 'findings.json').read_text(encoding='utf-8'))
            assert findings == results['findings'] and len(findings) == int(message)
        else:
            assert done.returncode == 1
            assert 'findings_count' not in outputs
            assert not (job.work / 'findings.json').exists()
            assert f'::error::Security scan failed: {message}. A failed scan is never reported as 0 findings.' \
                in done.stdout
        assert job.work_files() == sorted(['claudecode-error.log', 'claudecode-results.json']
                                          + (['findings.json'] if ok else []))
        assert list(job.workspace.iterdir()) == []

    @pytest.mark.skipif(shutil.which('node') is None, reason='node is needed to run the comment script')
    @pytest.mark.parametrize('findings', [TWO_FINDINGS, []])
    def test_comment_step_reads_the_findings_of_the_work_dir(self, tmp_path, findings):
        job = Job(tmp_path)
        job.write_audit_shim(complete(findings), 0)
        job.run(PREPARE_STEP)
        done, outputs = job.run(SCAN_STEP)
        assert done.returncode == 0, done.stdout
        # a findings.json of the pull request with another count: reading it would fail the hand-over
        (job.workspace / 'findings.json').write_text('[{"decoy": 1}, {"decoy": 2}, {"decoy": 3}]', encoding='utf-8')
        job.values.update({
            '${{ steps.claudecode-scan.outputs.findings_count }}': outputs['findings_count'],
            # silenced: the script checks the hand-over and stops before any gh call
            '${{ steps.claudecode-check.outputs.silence_claudecode_comments }}': 'true',
            '${{ github.action_path }}': str(REPO_ROOT),  # the real comment script
        })

        done, _ = job.run(COMMENT_STEP)

        assert done.returncode == 0, (done.stdout, done.stderr)
        if findings:
            assert f'excluding {len(findings)} findings' in done.stdout
