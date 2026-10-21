#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions
Runs Claude Code security audit on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import math
import time 

# Import existing components we can reuse
from claudecode.prompts import get_security_audit_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    DEFAULT_CLAUDE_MODEL,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
)
from claudecode.logger import get_logger

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""
    
    # The list-files endpoint pages at 100 entries and returns at most 3,000 files (30 pages).
    FILES_PER_PAGE = 100
    FILES_MAX_PAGES = 30
    
    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")
            
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        # Get excluded directories from environment
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            print(f"[Debug] Excluded directories: {self.excluded_dirs}", file=sys.stderr)
    
    def get_pr_data(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Dictionary containing PR data
        """
        # Get PR metadata
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_data = response.json()
        
        # Get every page of the PR file list. A page that fails raises out of this method: a
        # partial list must never pass as the complete one.
        files_data = []
        for page in range(1, self.FILES_MAX_PAGES + 1):
            files_url = (
                f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
                f"?per_page={self.FILES_PER_PAGE}&page={page}"
            )
            response = requests.get(files_url, headers=self.headers)
            response.raise_for_status()
            page_files = response.json()
            files_data.extend(page_files)
            if len(page_files) < self.FILES_PER_PAGE:
                break
        else:
            # No short page: page FILES_MAX_PAGES was full, so the list stopped at the API cap, not
            # at the end of the PR. A PR with more changed files than the cap has files this scan
            # would never see, and a partial list must not pass as complete.
            if pr_data['changed_files'] > len(files_data):
                raise AuditError(
                    f"PR has {pr_data['changed_files']} changed files, but the GitHub API lists at most "
                    f"{len(files_data)} (cap of {self.FILES_MAX_PAGES} pages of {self.FILES_PER_PAGE}); "
                    f"the file list would be incomplete"
                )
        
        return {
            'number': pr_data['number'],
            'title': pr_data['title'],
            'body': pr_data.get('body', ''),
            'user': pr_data['user']['login'],
            'created_at': pr_data['created_at'],
            'updated_at': pr_data['updated_at'],
            'state': pr_data['state'],
            'head': {
                'ref': pr_data['head']['ref'],
                'sha': pr_data['head']['sha'],
                'repo': {
                    'full_name': pr_data['head']['repo']['full_name'] if pr_data['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_data['base']['ref'],
                'sha': pr_data['base']['sha']
            },
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f['additions'],
                    'deletions': f['deletions'],
                    'changes': f['changes'],
                    'patch': f.get('patch', '')
                }
                for f in files_data
                if not self._is_excluded(f['filename'])
            ],
            'additions': pr_data['additions'],
            'deletions': pr_data['deletions'],
            'changed_files': pr_data['changed_files']
        }
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Complete PR diff in unified format
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return self._filter_generated_files(response.text)
    
    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns."""
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir
            
            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            
            # Check if excluded directory appears anywhere in the path
            if '/' + normalized_excluded + '/' in filepath:
                return True
            
        return False
    
    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []
        
        for section in file_sections:
            if not section.strip():
                continue
                
            # Skip generated files
            if ('@generated by' in section or 
                '@generated' in section or 
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue
            
            # Extract filename from diff header
            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    print(f"[Debug] Filtering out excluded file: {filename}", file=sys.stderr)
                    continue
            
            filtered_sections.append(section)
        
        return ''.join(filtered_sections)


# Run and input evidence: one record per Claude Code attempt, printed as a SCAN-EVIDENCE line on
# stderr and returned under `scan_evidence` in the results JSON. It states what the scan received
# and how each run ended; it never claims the model read anything and never feeds the result gate.
EVIDENCE_PREFIX = 'SCAN-EVIDENCE'
UNKNOWN = 'unknown'
NOT_PROVEN = 'not-proven'
EVIDENCE_KEYS = [
    'attempt', 'pr', 'head', 'checkout', 'model', 'models_used', 'exit', 'type', 'subtype',
    'is_error', 'review_completed', 'files_pr', 'files_prompt', 'file_list', 'diff',
    'diff_files', 'diff_bytes', 'prompt_chars', 'turns', 'duration_ms', 'cost_usd',
    'tok_in', 'tok_out', 'tok_cache_read', 'tok_cache_write', 'denials', 'denials_by_tool',
]
_UNSAFE_TOKEN_CHARS = re.compile(r'[^A-Za-z0-9_.:,-]')
_MAX_TOKEN_LENGTH = 500


def _token(value: Any) -> str:
    """Reduce a value to one log-safe token: no whitespace, no '=', no newline."""
    return _UNSAFE_TOKEN_CHARS.sub('_', str(value))[:_MAX_TOKEN_LENGTH] or UNKNOWN


def _list_part(value: Any) -> str:
    """A token that is one element of a ','- or ':'-joined list value."""
    return _token(value).replace(',', '_').replace(':', '_')


def _text_value(value: Any) -> Any:
    return _token(value) if isinstance(value, str) else UNKNOWN


def _int_value(value: Any) -> Any:
    return value if isinstance(value, int) and not isinstance(value, bool) else UNKNOWN


def _number_value(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return UNKNOWN
    return value if math.isfinite(value) else UNKNOWN


def _bool_value(value: Any) -> Any:
    return value if isinstance(value, bool) else UNKNOWN


def _dig(data: Any, *keys: str) -> Any:
    """Nested dict lookup that yields None instead of raising."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _cli_result_object(cli_result: Any, stdout: Any) -> Dict[str, Any]:
    """The CLI result object of an attempt; a failed run's stdout is read on a best-effort basis."""
    if isinstance(cli_result, dict):
        return cli_result
    if isinstance(stdout, str):
        try:
            parsed = json.loads(stdout)
        except Exception:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _models_used(model_usage: Any) -> str:
    if not isinstance(model_usage, dict):
        return UNKNOWN
    return ','.join(_list_part(name) for name in model_usage) or 'none'


def _denials_by_tool(denials: Any) -> Tuple[Any, Any]:
    """(total, 'Tool:count,...' sorted by tool name); only tool names are read, never tool_input."""
    if not isinstance(denials, list):
        return UNKNOWN, UNKNOWN
    counts: Dict[str, int] = {}
    for denial in denials:
        name = denial.get('tool_name') if isinstance(denial, dict) else None
        key = _list_part(name) if isinstance(name, str) and name else UNKNOWN
        counts[key] = counts.get(key, 0) + 1
    return len(denials), ','.join(f'{name}:{count}' for name, count in sorted(counts.items())) or 'none'


def _build_attempt_evidence(number: int, context: Any, prompt: str, exit_code: Any,
                            cli_result: Any, stdout: Any, results: Any) -> Dict[str, Any]:
    """Build the evidence entry of one attempt (see EVIDENCE_KEYS); a missing fact is "unknown"."""
    context = context if isinstance(context, dict) else {}
    cli = _cli_result_object(cli_result, stdout)
    usage = cli.get('usage') if isinstance(cli.get('usage'), dict) else {}
    files_pr = _int_value(context.get('files_pr'))
    files_prompt = _int_value(context.get('files_prompt'))
    if files_pr == UNKNOWN or files_prompt == UNKNOWN:
        file_list = UNKNOWN
    else:
        file_list = 'complete' if files_prompt >= files_pr else f'{files_prompt}-of-{files_pr}'
    diff_in_prompt = context.get('diff_in_prompt')
    denials, denials_by_tool = _denials_by_tool(cli.get('permission_denials'))

    entry = {
        'attempt': number,
        'pr': _int_value(context.get('pr')),
        'head': _text_value(context.get('head')),
        'checkout': _text_value(context.get('checkout')),
        'model': _text_value(DEFAULT_CLAUDE_MODEL),
        'models_used': _models_used(cli.get('modelUsage')),
        'exit': 'timeout' if exit_code == 'timeout' else _int_value(exit_code),
        'type': _text_value(cli.get('type')),
        'subtype': _text_value(cli.get('subtype')),
        'is_error': _bool_value(cli.get('is_error')),
        'review_completed': _bool_value(_dig(results, 'analysis_summary', 'review_completed')),
        'files_pr': files_pr,
        'files_prompt': files_prompt,
        'file_list': file_list,
        'diff': 'yes' if diff_in_prompt is True else 'no' if diff_in_prompt is False else UNKNOWN,
        'diff_files': _int_value(context.get('diff_files')),
        'diff_bytes': _int_value(context.get('diff_bytes')),
        'prompt_chars': len(prompt),
        'turns': _int_value(cli.get('num_turns')),
        'duration_ms': _number_value(cli.get('duration_ms')),
        'cost_usd': _number_value(cli.get('total_cost_usd')),
        'tok_in': _int_value(usage.get('input_tokens')),
        'tok_out': _int_value(usage.get('output_tokens')),
        'tok_cache_read': _int_value(usage.get('cache_read_input_tokens')),
        'tok_cache_write': _int_value(usage.get('cache_creation_input_tokens')),
        'denials': denials,
        'denials_by_tool': denials_by_tool,
    }
    if entry['diff'] == 'no':
        entry['reading'] = NOT_PROVEN  # the prompt carried no diff: nothing proves the model read the changes
    return entry


def _unknown_attempt_evidence(number: int) -> Dict[str, Any]:
    """Fallback entry when building the real one failed: the attempt is still counted."""
    entry = {key: UNKNOWN for key in EVIDENCE_KEYS}
    entry['attempt'] = number
    return entry


def _format_evidence_line(entry: Dict[str, Any]) -> str:
    """One SCAN-EVIDENCE line: fixed prefix, then space-separated key=value tokens."""
    def render(value: Any) -> str:
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return _token(value)

    return ' '.join([EVIDENCE_PREFIX] + [f'{key}={render(value)}' for key, value in entry.items()])


PROMPT_TOO_LONG_PHRASE = 'prompt is too long'


def _is_prompt_too_long(cli_result: Any) -> bool:
    """True if a parsed Claude Code result is an error that reports an over-long prompt.

    This is the one detection rule. It matches a result object (`type` is "result") with
    `is_error` true whose `result` text, or any text entry of its `errors` list, contains
    "prompt is too long" in any letter case. Claude Code words it in more than one way, for
    example "Prompt is too long" or "Prompt is too long · ...", and puts it in `result` or in
    `errors`. The exit code and `subtype` play no part. Every other result is not a match.
    """
    if not isinstance(cli_result, dict):
        return False
    if cli_result.get('type') != 'result' or cli_result.get('is_error') is not True:
        return False
    texts = []
    result_text = cli_result.get('result')
    if isinstance(result_text, str):
        texts.append(result_text)
    errors = cli_result.get('errors')
    if isinstance(errors, list):
        texts.extend(entry for entry in errors if isinstance(entry, str))
    return any(PROMPT_TOO_LONG_PHRASE in text.lower() for text in texts)


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner.
        
        Args:
            timeout_minutes: Timeout for Claude execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT
        # Evidence of every Claude Code attempt of this run (the no-diff retry continues the count)
        self._attempt_evidence: List[Dict[str, Any]] = []
        self._attempt_count = 0
    
    def scan_evidence(self) -> Dict[str, Any]:
        """Evidence of every Claude Code attempt so far, as published under `scan_evidence`."""
        return {'attempts': [dict(entry) for entry in self._attempt_evidence]}
    
    def _record_attempt(self, number: int, context: Any, prompt: str, state: Dict[str, Any]) -> None:
        """Record one attempt and print its SCAN-EVIDENCE line. Never raises into the scan."""
        try:
            try:
                entry = _build_attempt_evidence(number, context, prompt, state.get('exit'),
                                                state.get('cli_result'), state.get('stdout'),
                                                state.get('results'))
            except Exception:
                entry = _unknown_attempt_evidence(number)
            self._attempt_evidence.append(entry)
            print(_format_evidence_line(entry), file=sys.stderr, flush=True)
        except Exception:
            pass
    
    def run_security_audit(self, repo_dir: Path, prompt: str,
                           evidence_context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code security audit.
        
        Args:
            repo_dir: Path to repository directory
            prompt: Security audit prompt
            evidence_context: Optional per-call facts for the attempt evidence (PR number, PR head
                and checkout SHA, file counts, diff facts); anything missing is reported as unknown
            
        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)
        
        try:
            # Construct Claude Code command
            # Use stdin for prompt to avoid "argument list too long" error
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', DEFAULT_CLAUDE_MODEL,
                '--disallowed-tools', 'Bash(ps:*)'
            ]
            
            # Run Claude Code with retry logic
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                self._attempt_count += 1
                attempt_number = self._attempt_count
                attempt_state: Dict[str, Any] = {}
                try:
                    try:
                        result = subprocess.run(
                            cmd,
                            input=prompt,  # Pass prompt via stdin
                            cwd=repo_dir,
                            capture_output=True,
                            text=True,
                            timeout=self.timeout_seconds
                        )
                    except subprocess.TimeoutExpired:
                        attempt_state['exit'] = 'timeout'
                        raise
                    attempt_state['exit'] = result.returncode
                    attempt_state['stdout'] = result.stdout
                    
                    # Read stdout as JSON first, whatever the exit code: Claude Code can report an
                    # over-long prompt together with a failing exit code. That is not a crash to
                    # repeat three times; main() runs the attempt without the diff on it instead.
                    success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                    if success and _is_prompt_too_long(parsed_result):
                        attempt_state['cli_result'] = parsed_result
                        return False, "PROMPT_TOO_LONG", {}
                    
                    if result.returncode != 0:
                        if attempt == NUM_RETRIES - 1:
                            error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                            error_details += f"Stderr: {result.stderr}\n"
                            error_details += f"Stdout: {result.stdout[:500]}..."  # First 500 chars
                            return False, error_details, {}
                        else:
                            time.sleep(5*attempt)
                            # Note: We don't do exponential backoff here to keep the runtime reasonable
                            continue  # Retry
                    
                    if success:
                        attempt_state['cli_result'] = parsed_result
                        # Check for error_during_execution that should trigger retry
                        if (isinstance(parsed_result, dict) and 
                            parsed_result.get('type') == 'result' and 
                            parsed_result.get('subtype') == 'error_during_execution' and
                            attempt == 0):
                            continue  # Retry
                        
                        # Any other error result is a failed audit, never an empty one
                        if (isinstance(parsed_result, dict) and
                            parsed_result.get('type') == 'result' and
                            parsed_result.get('is_error')):
                            return False, f"Claude Code reported an error (subtype: {parsed_result.get('subtype')})", {}
                        
                        # Extract security findings
                        parsed_results = self._extract_security_findings(parsed_result)
                        attempt_state['results'] = parsed_results
                        return True, "", parsed_results
                    else:
                        if attempt == 0:
                            continue  # Retry once
                        else:
                            return False, "Failed to parse Claude output", {}
                finally:
                    # One evidence record per subprocess attempt, however the attempt ended
                    self._record_attempt(attempt_number, evidence_context, prompt, attempt_state)
            
            return False, "Unexpected error in retry logic", {}
            
        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}
    
    def _extract_security_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract security findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            # Only accept Claude Code wrapper with result field
            # Direct format without wrapper is not supported
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json:
                        return result_json
        
        # Return empty structure if no findings found
        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
        }
    
    
    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['claude', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Also check if API key is configured
                api_key = os.environ.get('ANTHROPIC_API_KEY', '')
                if not api_key:
                    return False, "ANTHROPIC_API_KEY environment variable is not set"
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {str(e)}"




def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration.
    
    Returns:
        Tuple of (repo_name, pr_number)
        
    Raises:
        ConfigurationError: If required environment variables are missing or invalid
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')
    
    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')
    
    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubActionClient, SimpleClaudeRunner]:
    """Initialize GitHub and Claude clients.

    CLAUDE_TIMEOUT (minutes, the claudecode-timeout input) sets the timeout of each Claude Code attempt;
    unset or empty keeps the default.
    
    Returns:
        Tuple of (github_client, claude_runner)
        
    Raises:
        ConfigurationError: If client initialization fails or CLAUDE_TIMEOUT is not a positive whole number
    """
    timeout_value = os.environ.get('CLAUDE_TIMEOUT', '').strip()
    timeout_minutes = None
    if timeout_value:
        # Fail closed: only a positive whole number of minutes is accepted (no sign, no decimal point)
        try:
            timeout_minutes = int(timeout_value) if re.fullmatch(r'[0-9]+', timeout_value) else 0
        except ValueError:  # more digits than int() accepts
            timeout_minutes = 0
        if timeout_minutes < 1:
            raise ConfigurationError(
                f"CLAUDE_TIMEOUT must be a positive whole number of minutes, got '{timeout_value}'"
            )

    try:
        github_client = GitHubActionClient()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')
    
    try:
        if timeout_minutes is None:
            claude_runner = SimpleClaudeRunner()
        else:
            claude_runner = SimpleClaudeRunner(timeout_minutes=timeout_minutes)
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {str(e)}')
        
    return github_client, claude_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.
    
    Args:
        custom_filtering_instructions: Optional custom filtering instructions
        
    Returns:
        FindingsFilter instance
        
    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        # Check if we should use Claude API filtering
        use_claude_filtering = os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        if use_claude_filtering and api_key:
            # Use full filtering with Claude API
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')



def run_security_audit(claude_runner: SimpleClaudeRunner, prompt: str) -> Dict[str, Any]:
    """Run the security audit with Claude Code.
    
    Args:
        claude_runner: Claude runner instance
        prompt: The security audit prompt
        
    Returns:
        Audit results dictionary
        
    Raises:
        AuditError: If the audit fails
    """
    # Get repo directory from environment or use current directory
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)
    
    if not success:
        raise AuditError(f'Security audit failed: {error_msg}')
        
    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                         pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.
    
    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Apply FindingsFilter
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )
    
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        # Filtering failed, keep all findings
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply final directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Update excluded findings list
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Update analysis summary with directory filtering stats
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)
    
    return final_kept_findings, all_excluded_findings, analysis_summary


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: GitHubActionClient) -> bool:
    """Check if a finding references a file in an excluded directory.
    
    Args:
        finding: Security finding dictionary
        github_client: GitHub client with exclusion logic
        
    Returns:
        True if finding should be excluded, False otherwise
    """
    file_path = finding.get('file', '')
    if not file_path:
        return False
    
    return github_client._is_excluded(file_path)


def _resolve_checkout_sha(repo_dir: Path) -> str:
    """`git rev-parse HEAD` in the scanned directory, or "unknown" if it cannot be read.

    Evidence only, computed once per run. It uses Popen so the lookup never shares call
    accounting with the Claude Code runs, which go through subprocess.run.
    """
    try:
        git = subprocess.Popen(
            ['git', 'rev-parse', 'HEAD'],
            cwd=repo_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        try:
            stdout, _ = git.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            git.kill()
            git.communicate()
            return UNKNOWN
        sha = stdout.strip()
        if git.returncode == 0 and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', sha):
            return sha
    except Exception:
        pass
    return UNKNOWN


def _build_evidence_context(pr_number: Any, pr_data: Any, pr_diff: Any, checkout_sha: str) -> Dict[str, Any]:
    """Per-scan facts for the attempt evidence. Never raises; a fact it cannot read is left out."""
    context: Dict[str, Any] = {'pr': pr_number, 'checkout': checkout_sha}
    try:
        context['head'] = _dig(pr_data, 'head', 'sha')
        context['files_pr'] = _dig(pr_data, 'changed_files')
        files = _dig(pr_data, 'files')
        if isinstance(files, list):
            context['files_prompt'] = len(files)  # the list the prompt names
        if isinstance(pr_diff, str):
            context['diff_files'] = len(re.findall(r'^diff --git', pr_diff, flags=re.MULTILINE))
            context['diff_bytes'] = len(pr_diff.encode('utf-8'))
    except Exception:
        pass
    return context


def _diff_in_prompt(pr_diff: Any, prompt: Any) -> bool:
    """True only if the fetched diff text is actually part of this attempt's prompt."""
    return bool(isinstance(pr_diff, str) and isinstance(prompt, str) and pr_diff and pr_diff in prompt)


def _scan_evidence_payload(claude_runner: Any) -> Dict[str, Any]:
    """The `scan_evidence` value for the results JSON; an empty list if the runner has none to give."""
    try:
        attempts = claude_runner.scan_evidence()['attempts']
        if isinstance(attempts, list):
            json.dumps(attempts)  # it must serialise, or it is dropped
            return {'attempts': attempts}
    except Exception:
        pass
    return {'attempts': []}


def _error_json(message: str, claude_runner: Any = None) -> str:
    """The {"error": ...} output of main(), with the attempt evidence collected so far."""
    return json.dumps({'error': message, 'scan_evidence': _scan_evidence_payload(claude_runner)})


def main():
    """Main execution function for GitHub Action."""
    claude_runner = None  # set once the clients exist; its evidence is attached to every output
    try:
        # Get environment configuration
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(_error_json(str(e), claude_runner))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Load custom filtering instructions if provided
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")
        
        # Load custom security scan instructions if provided
        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {scan_file}: {e}")
        
        # Initialize components
        try:
            github_client, claude_runner = initialize_clients()
        except ConfigurationError as e:
            print(_error_json(str(e), claude_runner))
            sys.exit(EXIT_CONFIGURATION_ERROR)
            
        # Initialize findings filter
        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(_error_json(str(e), claude_runner))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Validate Claude Code is available
        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(_error_json(f'Claude Code not available: {claude_error}', claude_runner))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(_error_json(f'Failed to fetch PR data: {str(e)}', claude_runner))
            sys.exit(EXIT_GENERAL_ERROR)
                
        # Generate security audit prompt
        prompt = get_security_audit_prompt(pr_data, pr_diff, custom_scan_instructions=custom_scan_instructions)
        
        # Run Claude Code security audit
        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        evidence_context = _build_evidence_context(pr_number, pr_data, pr_diff, _resolve_checkout_sha(repo_dir))
        success, error_msg, results = claude_runner.run_security_audit(
            repo_dir, prompt,
            evidence_context=dict(evidence_context, diff_in_prompt=_diff_in_prompt(pr_diff, prompt))
        )
        
        # If prompt is too long, retry without diff
        if not success and error_msg == "PROMPT_TOO_LONG":
            print(f"[Info] Prompt too long, retrying without diff. Original prompt length: {len(prompt)} characters", file=sys.stderr)
            prompt_without_diff = get_security_audit_prompt(pr_data, pr_diff, include_diff=False, custom_scan_instructions=custom_scan_instructions)
            print(f"[Info] New prompt length: {len(prompt_without_diff)} characters", file=sys.stderr)
            success, error_msg, results = claude_runner.run_security_audit(
                repo_dir, prompt_without_diff,
                evidence_context=dict(evidence_context, diff_in_prompt=_diff_in_prompt(pr_diff, prompt_without_diff))
            )
        
        if not success:
            print(_error_json(f'Security audit failed: {error_msg}', claude_runner))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # An audit that did not complete must never be reported as 0 findings
        audit_summary = results.get('analysis_summary', {})
        if not isinstance(audit_summary, dict) or audit_summary.get('review_completed') is not True:
            print(_error_json('Security audit incomplete: analysis_summary.review_completed is not true', claude_runner))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Filter findings to reduce false positives
        original_findings = results.get('findings', [])
        
        # Prepare PR context for better filtering
        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', '')
        }
        
        # Apply findings filter (including final directory exclusion)
        kept_findings, excluded_findings, analysis_summary = apply_findings_filter(
            findings_filter, original_findings, pr_context, github_client
        )
        
        # Prepare output
        output = {
            'scan_evidence': _scan_evidence_payload(claude_runner),  # first, so the log preview shows it
            'pr_number': pr_number,
            'repo': repo_name,
            'findings': kept_findings,
            'analysis_summary': results.get('analysis_summary', {}),
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_analysis': analysis_summary,
                'excluded_findings_details': excluded_findings  # Include full details of what was filtered
            }
        }
        
        # Output JSON to stdout
        print(json.dumps(output, indent=2))
        
        # Exit with appropriate code
        high_severity_count = len([f for f in kept_findings if f.get('severity', '').upper() == 'HIGH'])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)
        
    except Exception as e:
        print(_error_json(f'Unexpected error: {str(e)}', claude_runner))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
