#!/usr/bin/env python3
"""
Unit tests for GitHubActionClient.
"""

import pytest
import os
import re
import requests
from unittest.mock import Mock, patch

from claudecode.github_action_audit import AuditError, GitHubActionClient


FILES_URL = 'https://api.github.com/repos/owner/repo/pulls/123/files?per_page=100&page={page}'


def make_pr_response(changed_files):
    """Mock response for the PR metadata request."""
    response = Mock()
    response.json.return_value = {
        'number': 123,
        'title': 'Large PR',
        'body': 'Many files',
        'user': {'login': 'testuser'},
        'created_at': '2024-01-01T00:00:00Z',
        'updated_at': '2024-01-01T01:00:00Z',
        'state': 'open',
        'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
        'base': {'ref': 'main', 'sha': 'def456'},
        'additions': changed_files * 10,
        'deletions': 0,
        'changed_files': changed_files
    }
    return response


def make_file_entries(start, count):
    """`count` file entries named file{start}.py .. file{start + count - 1}.py."""
    return [
        {
            'filename': f'file{i}.py',
            'status': 'added',
            'additions': 10,
            'deletions': 0,
            'changes': 10,
            'patch': f'@@ -0,0 +1,10 @@\n+# File {i}'
        }
        for i in range(start, start + count)
    ]


def make_files_page(entries):
    """Mock response for one page of the PR file list."""
    response = Mock()
    response.json.return_value = entries
    return response


def requested_urls(mock_get):
    """URLs of every requests.get call, in call order."""
    return [call.args[0] for call in mock_get.call_args_list]


def make_files_pages(page_sizes, prefix=''):
    """One mocked file page per size, with consecutively numbered files across the pages."""
    pages, start = [], 0
    for size in page_sizes:
        entries = make_file_entries(start, size)
        for entry in entries:
            entry['filename'] = prefix + entry['filename']
        pages.append(make_files_page(entries))
        start += size
    return pages


# Every way the page loop can end on a list shorter than changed_files (194): (page sizes, files listed)
SHORT_LIST_CASES = {
    'empty-first-page': ([0], 0),
    'short-page-before-the-end': ([93], 93),
    'full-first-page-then-empty-second-page': ([100, 0], 100),
}


class TestGitHubActionClient:
    """Test GitHubActionClient functionality."""
    
    def test_init_requires_token(self):
        """Test that client initialization requires GITHUB_TOKEN."""
        # Remove token if it exists
        original_token = os.environ.pop('GITHUB_TOKEN', None)
        
        try:
            with pytest.raises(ValueError, match="GITHUB_TOKEN environment variable required"):
                GitHubActionClient()
        finally:
            # Restore token
            if original_token:
                os.environ['GITHUB_TOKEN'] = original_token
    
    def test_init_with_token(self):
        """Test successful initialization with token."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            assert client.github_token == 'test-token'
            assert client.headers['Authorization'] == 'Bearer test-token'
            assert 'Accept' in client.headers
            assert 'X-GitHub-Api-Version' in client.headers
    
    @patch('requests.get')
    def test_get_pr_data_success(self, mock_get):
        """Test successful PR data retrieval."""
        # Mock responses
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': 'PR description',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {
                'ref': 'feature-branch',
                'sha': 'abc123',
                'repo': {
                    'full_name': 'owner/repo'
                }
            },
            'base': {
                'ref': 'main',
                'sha': 'def456'
            },
            'additions': 50,
            'deletions': 10,
            'changed_files': 2
        }
        
        files_response = Mock()
        files_response.json.return_value = [
            {
                'filename': 'src/main.py',
                'status': 'modified',
                'additions': 30,
                'deletions': 5,
                'changes': 35,
                'patch': '@@ -1,5 +1,10 @@\n+import os\n def main():'
            },
            {
                'filename': 'tests/test_main.py',
                'status': 'added',
                'additions': 20,
                'deletions': 5,
                'changes': 25,
                'patch': '@@ -0,0 +1,20 @@\n+def test_main():'
            }
        ]
        
        mock_get.side_effect = [pr_response, files_response]
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)
        
        # Verify API calls
        assert mock_get.call_count == 2
        mock_get.assert_any_call(
            'https://api.github.com/repos/owner/repo/pulls/123',
            headers=client.headers,
            timeout=(10, 60)
        )
        mock_get.assert_any_call(
            'https://api.github.com/repos/owner/repo/pulls/123/files?per_page=100&page=1',
            headers=client.headers,
            timeout=(10, 60)
        )

        # Verify result structure
        assert result['number'] == 123
        assert result['title'] == 'Test PR'
        assert result['user'] == 'testuser'
        assert len(result['files']) == 2
        assert result['files'][0]['filename'] == 'src/main.py'
        assert result['files'][1]['status'] == 'added'
    
    @patch('requests.get')
    def test_get_pr_data_null_head_repo(self, mock_get):
        """Test PR data retrieval when head repo is null (deleted fork)."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            # Don't include body key to test the get() default
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {
                'ref': 'feature-branch',
                'sha': 'abc123',
                'repo': None  # Deleted fork
            },
            'base': {
                'ref': 'main',
                'sha': 'def456'
            },
            'additions': 50,
            'deletions': 10,
            'changed_files': 0
        }
        
        files_response = Mock()
        files_response.json.return_value = []
        
        mock_get.side_effect = [pr_response, files_response]
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)
        
        # Should use original repo name when head repo is None
        assert result['head']['repo']['full_name'] == 'owner/repo'
        # The implementation passes None through, test should match that
        assert result['body'] == ''
    
    @patch('requests.get')
    def test_get_pr_data_api_error(self, mock_get):
        """Test PR data retrieval with API error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("API Error")
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(Exception, match="API Error"):
                client.get_pr_data('owner/repo', 123)
    
    @patch('requests.get')
    def test_get_pr_diff_success(self, mock_get):
        """Test successful PR diff retrieval."""
        diff_content = """diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,5 +1,10 @@
+import os
 def main():
     print("Hello")
+    # New feature
+    process_data()
"""
        
        mock_response = Mock()
        mock_response.text = diff_content
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_diff('owner/repo', 123)
        
        # Verify API call
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args[0][0] == 'https://api.github.com/repos/owner/repo/pulls/123'
        assert call_args[1]['headers']['Accept'] == 'application/vnd.github.diff'
        
        # Verify result
        assert 'import os' in result
        assert 'process_data()' in result
    
    @patch('requests.get')
    def test_get_pr_diff_filters_generated_files(self, mock_get):
        """Test that generated files are filtered from diff."""
        diff_with_generated = """diff --git a/src/main.py b/src/main.py
index abc123..def456 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,5 +1,10 @@
+import os
 def main():
     print("Hello")
diff --git a/generated/code.py b/generated/code.py
index 111..222 100644
--- a/generated/code.py
+++ b/generated/code.py
@@ -1,3 +1,5 @@
# @generated by protoc
+# More generated code
+print("generated")
diff --git a/src/feature.py b/src/feature.py
index 333..444 100644
--- a/src/feature.py
+++ b/src/feature.py
@@ -1,3 +1,5 @@
+# Real code
 def feature():
     pass
"""
        
        mock_response = Mock()
        mock_response.text = diff_with_generated
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_diff('owner/repo', 123)
        
        # Verify generated file is filtered out
        assert 'src/main.py' in result
        assert 'src/feature.py' in result
        assert 'generated/code.py' not in result
        assert '@generated' not in result
        assert 'More generated code' not in result
    
    def test_filter_generated_files_edge_cases(self):
        """Test edge cases in generated file filtering."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            
            # Empty diff
            assert client._filter_generated_files('') == ''
            
            # No diff markers - if no diff format, everything is filtered
            text = "Just some random text\nwith @generated in it"
            # Since there's no 'diff --git' marker, the split results in one section
            # that contains @generated, so it gets filtered out
            assert client._filter_generated_files(text) == ''
            
            # Multiple generated markers
            diff = """diff --git a/a.py b/a.py
@generated by tool
content
diff --git a/b.py b/b.py
normal content
diff --git a/c.py b/c.py
# This file is @generated
more content
"""
            result = client._filter_generated_files(diff)
            assert 'a.py' not in result
            assert 'b.py' in result
            assert 'c.py' not in result


class TestGitHubAPIIntegration:
    """Test GitHub API integration scenarios."""
    
    @patch('requests.get')
    def test_rate_limit_handling(self, mock_get):
        """Test that rate limit headers are respected."""
        mock_response = Mock()
        mock_response.headers = {
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': '1234567890'
        }
        mock_response.status_code = 403
        mock_response.json.return_value = {
            'message': 'API rate limit exceeded'
        }
        mock_response.raise_for_status.side_effect = Exception("Rate limit exceeded")
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(Exception, match="Rate limit exceeded"):
                client.get_pr_data('owner/repo', 123)
    
    @patch('requests.get')
    def test_exactly_100_files_requests_page_2_and_keeps_all_100(self, mock_get):
        """A full first page of 100 files is not proof of completeness: page 2 is requested.

        The files endpoint pages at 100 entries. Exactly 100 files on page 1 could be the
        whole list or the first of several pages, so the client asks for page 2; here it
        comes back empty and the result holds the 100 files.
        """
        large_file_list = make_file_entries(0, 100)

        pr_response = make_pr_response(changed_files=100)
        page_1 = make_files_page(large_file_list)
        page_2 = make_files_page([])

        mock_get.side_effect = [pr_response, page_1, page_2]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)

        assert requested_urls(mock_get)[1:] == [FILES_URL.format(page=1), FILES_URL.format(page=2)]
        page_2.raise_for_status.assert_called_once()
        assert len(result['files']) == 100
        assert result['files'][0]['filename'] == 'file0.py'
        assert result['files'][99]['filename'] == 'file99.py'

    @patch('requests.get')
    def test_250_files_load_over_three_pages_in_order(self, mock_get):
        """250 files arrive as pages of 100, 100 and 50: all 250 in order, three file-page requests."""
        pr_response = make_pr_response(changed_files=250)
        mock_get.side_effect = [
            pr_response,
            make_files_page(make_file_entries(0, 100)),
            make_files_page(make_file_entries(100, 100)),
            make_files_page(make_file_entries(200, 50)),
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)

        file_page_urls = [u for u in requested_urls(mock_get) if '/files?' in u]
        assert file_page_urls == [FILES_URL.format(page=n) for n in (1, 2, 3)]
        assert mock_get.call_count == 4  # PR metadata + three file pages
        assert [f['filename'] for f in result['files']] == [f'file{i}.py' for i in range(250)]
        assert result['changed_files'] == 250

    @patch('requests.get')
    def test_error_on_page_2_raises_without_partial_list(self, mock_get):
        """A failing follow-up page raises out of get_pr_data; the first page is never returned alone."""
        pr_response = make_pr_response(changed_files=250)
        page_2 = Mock()
        page_2.raise_for_status.side_effect = requests.HTTPError('500 Server Error: page 2')
        mock_get.side_effect = [
            pr_response,
            make_files_page(make_file_entries(0, 100)),
            page_2,
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(requests.HTTPError, match='page 2'):
                client.get_pr_data('owner/repo', 123)

        assert requested_urls(mock_get)[1:] == [FILES_URL.format(page=1), FILES_URL.format(page=2)]
        page_2.json.assert_not_called()

    @patch('requests.get')
    def test_file_list_stops_after_page_30_and_fails_when_the_pr_has_more_files(self, mock_get):
        """The list-files endpoint returns at most 3,000 files: no page 31 request, and a PR with
        more changed files than that fails closed instead of being scanned on a partial list."""
        pr_response = make_pr_response(changed_files=3200)
        mock_get.side_effect = [pr_response] + [
            make_files_page(make_file_entries(n * 100, 100)) for n in range(30)
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(ValueError) as exc_info:
                client.get_pr_data('owner/repo', 123)

        message = str(exc_info.value)
        assert '3200' in message and '3000' in message
        assert 'file0.py' not in message  # counts only, no file names

        file_page_urls = [u for u in requested_urls(mock_get) if '/files?' in u]
        assert file_page_urls == [FILES_URL.format(page=n) for n in range(1, 31)]
        assert FILES_URL.format(page=31) not in file_page_urls
        assert mock_get.call_count == 31  # PR metadata + 30 file pages

    @patch('requests.get')
    def test_exactly_3000_files_load_at_the_cap_without_error(self, mock_get):
        """A PR with exactly 3,000 changed files fills 30 pages and is complete: all 3,000 returned."""
        pr_response = make_pr_response(changed_files=3000)
        mock_get.side_effect = [pr_response] + [
            make_files_page(make_file_entries(n * 100, 100)) for n in range(30)
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)

        file_page_urls = [u for u in requested_urls(mock_get) if '/files?' in u]
        assert file_page_urls == [FILES_URL.format(page=n) for n in range(1, 31)]
        assert mock_get.call_count == 31  # PR metadata + 30 file pages
        assert len(result['files']) == 3000
        assert result['files'][0]['filename'] == 'file0.py'
        assert result['files'][2999]['filename'] == 'file2999.py'
        assert result['changed_files'] == 3000

    @patch('requests.get')
    def test_cap_check_counts_files_before_directory_exclusion(self, mock_get):
        """At the cap, completeness compares changed_files with the files the API listed, not with
        what is left after directory exclusion: excluding files does not turn a complete list into a failure."""
        pages = [make_file_entries(n * 100, 100) for n in range(30)]
        for entry in pages[4]:
            entry['filename'] = 'vendor/' + entry['filename']
        mock_get.side_effect = [make_pr_response(changed_files=3000)] + [
            make_files_page(entries) for entries in pages
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': 'vendor'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)

        assert len(result['files']) == 2900
        assert result['changed_files'] == 3000

    @patch('requests.get')
    def test_short_last_page_below_changed_files_fails(self, mock_get):
        """The completeness check is not limited to the 3,000-file cap: a short last page that
        leaves the list below changed_files fails closed instead of ending the list."""
        mock_get.side_effect = [
            make_pr_response(changed_files=500),
            make_files_page(make_file_entries(0, 100)),
            make_files_page(make_file_entries(100, 20)),
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(AuditError) as exc_info:
                client.get_pr_data('owner/repo', 123)

        assert sorted(int(n) for n in re.findall(r'\d+', str(exc_info.value))) == [120, 500]
        assert requested_urls(mock_get)[1:] == [FILES_URL.format(page=1), FILES_URL.format(page=2)]

    @patch('requests.get')
    def test_excluded_directories_apply_to_the_collected_list(self, mock_get):
        """Exclusion runs over every page: an excluded file on page 2 is dropped, the rest keep their order."""
        entries = make_file_entries(0, 120)
        entries[110]['filename'] = 'vendor/lib/skip.py'
        mock_get.side_effect = [
            make_pr_response(changed_files=120),
            make_files_page(entries[:100]),
            make_files_page(entries[100:]),
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': 'vendor'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)

        names = [f['filename'] for f in result['files']]
        assert len(names) == 119
        assert 'vendor/lib/skip.py' not in names
        assert names[:100] == [f'file{i}.py' for i in range(100)]
        assert set(result['files'][0]) == {
            'filename', 'status', 'additions', 'deletions', 'changes', 'patch'
        }


class TestFileListCompleteness:
    """Q4: after every exit of the page loop the files the API listed, counted before directory
    exclusion, are compared with changed_files. A shorter list fails closed; a longer one passes."""

    @pytest.mark.parametrize('page_sizes, listed', list(SHORT_LIST_CASES.values()), ids=list(SHORT_LIST_CASES))
    @patch('requests.get')
    def test_list_shorter_than_changed_files_raises(self, mock_get, page_sizes, listed):
        """0, 93 or 100 of 194 files: AuditError naming both counts, and no file names."""
        mock_get.side_effect = [make_pr_response(changed_files=194)] + make_files_pages(page_sizes)

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(AuditError) as exc_info:
                client.get_pr_data('owner/repo', 123)

        message = str(exc_info.value)
        assert sorted(int(n) for n in re.findall(r'\d+', message)) == sorted([194, listed])
        assert 'file0.py' not in message
        assert requested_urls(mock_get)[1:] == [FILES_URL.format(page=n) for n in range(1, len(page_sizes) + 1)]

    @patch('requests.get')
    def test_complete_list_over_two_pages_passes(self, mock_get):
        """194 = 100 + 94: the list is complete, every file is returned."""
        mock_get.side_effect = [make_pr_response(changed_files=194)] + make_files_pages([100, 94])

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            result = GitHubActionClient().get_pr_data('owner/repo', 123)

        assert [f['filename'] for f in result['files']] == [f'file{i}.py' for i in range(194)]
        assert result['changed_files'] == 194

    @patch('requests.get')
    def test_complete_list_with_every_file_excluded_returns_no_files(self, mock_get):
        """The check counts the listed files, not those left after exclusion: a complete list whose
        files are all excluded gives an empty `files` and no error."""
        mock_get.side_effect = [make_pr_response(changed_files=194)] + make_files_pages([100, 94], prefix='vendor/')

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': 'vendor'}):
            result = GitHubActionClient().get_pr_data('owner/repo', 123)

        assert result['files'] == []
        assert result['changed_files'] == 194

    @patch('requests.get')
    def test_empty_list_passes_when_changed_files_is_0(self, mock_get):
        """An empty first page is complete when the PR reports 0 changed files: no blanket empty guard."""
        mock_get.side_effect = [make_pr_response(changed_files=0)] + make_files_pages([0])

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            result = GitHubActionClient().get_pr_data('owner/repo', 123)

        assert result['files'] == []
        assert result['changed_files'] == 0

    @pytest.mark.parametrize('page_sizes', [[5], [100, 0]], ids=['short-page', 'full-page-then-empty-page'])
    @patch('requests.get')
    def test_list_longer_than_changed_files_passes(self, mock_get, page_sizes):
        """More listed files than changed_files changes nothing: every listed file is returned."""
        mock_get.side_effect = [make_pr_response(changed_files=3)] + make_files_pages(page_sizes)

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            result = GitHubActionClient().get_pr_data('owner/repo', 123)

        assert len(result['files']) == sum(page_sizes)
        assert result['changed_files'] == 3

    @pytest.mark.parametrize('changed_files', ['missing', None, -1, '194', 194.0, True],
                             ids=['missing', 'none', 'negative', 'string', 'float', 'bool'])
    @patch('requests.get')
    def test_missing_or_invalid_changed_files_raises(self, mock_get, changed_files):
        """Without a non-negative integer changed_files the completeness cannot be checked: fail closed."""
        pr_response = make_pr_response(changed_files=3)
        metadata = pr_response.json.return_value
        if changed_files == 'missing':
            del metadata['changed_files']
        else:
            metadata['changed_files'] = changed_files
        mock_get.side_effect = [pr_response] + make_files_pages([3])

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(AuditError, match='changed_files'):
                client.get_pr_data('owner/repo', 123)


TIMEOUT_ERRORS =[requests.exceptions.Timeout, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout]
TIMEOUT_IDS = ['timeout', 'connect-timeout', 'read-timeout']


class TestGitHubApiTimeouts:
    """Every GitHub API call has a timeout, and a timeout is a fetch error that fails closed."""

    def test_timeout_constant_is_connect_10_read_60(self):
        assert GitHubActionClient.HTTP_TIMEOUT == (10, 60)

    @patch('requests.get')
    def test_every_pr_data_request_carries_the_timeout(self, mock_get):
        """The PR metadata request and every file-page request get timeout=(10, 60)."""
        mock_get.side_effect = [
            make_pr_response(changed_files=250),
            make_files_page(make_file_entries(0, 100)),
            make_files_page(make_file_entries(100, 100)),
            make_files_page(make_file_entries(200, 50)),
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            GitHubActionClient().get_pr_data('owner/repo', 123)

        assert mock_get.call_count == 4  # PR metadata + three file pages
        assert [call.kwargs.get('timeout') for call in mock_get.call_args_list] == [(10, 60)] * 4

    @patch('requests.get')
    def test_the_diff_request_carries_the_timeout(self, mock_get):
        response = Mock()
        response.text = 'diff --git a/a.py b/a.py\n+x = 1\n'
        mock_get.return_value = response

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            GitHubActionClient().get_pr_diff('owner/repo', 123)

        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs['timeout'] == (10, 60)

    @pytest.mark.parametrize('error', TIMEOUT_ERRORS, ids=TIMEOUT_IDS)
    @patch('requests.get')
    def test_timeout_on_the_pr_metadata_raises(self, mock_get, error):
        mock_get.side_effect = error('metadata timed out')

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(requests.exceptions.Timeout, match='metadata timed out'):
                client.get_pr_data('owner/repo', 123)

        assert mock_get.call_count == 1  # no file page is requested after it

    @pytest.mark.parametrize('error', TIMEOUT_ERRORS, ids=TIMEOUT_IDS)
    @patch('requests.get')
    def test_timeout_on_a_file_page_raises_without_partial_list(self, mock_get, error):
        """A timeout on page 2 raises out of get_pr_data; page 1 is never returned alone."""
        mock_get.side_effect = [
            make_pr_response(changed_files=250),
            make_files_page(make_file_entries(0, 100)),
            error('page 2 timed out'),
        ]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(requests.exceptions.Timeout, match='page 2 timed out'):
                client.get_pr_data('owner/repo', 123)

        assert requested_urls(mock_get)[1:] == [FILES_URL.format(page=1), FILES_URL.format(page=2)]

    @pytest.mark.parametrize('error', TIMEOUT_ERRORS, ids=TIMEOUT_IDS)
    @patch('requests.get')
    def test_timeout_on_the_diff_raises(self, mock_get, error):
        mock_get.side_effect = error('diff timed out')

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(requests.exceptions.Timeout, match='diff timed out'):
                client.get_pr_diff('owner/repo', 123)
