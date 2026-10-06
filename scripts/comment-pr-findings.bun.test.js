#!/usr/bin/env bun

/**
 * Unit tests for comment-pr-findings.js using Bun test runner
 */

import { test, expect, describe, beforeEach, afterEach, mock, spyOn } from "bun:test";

describe('comment-pr-findings.js', () => {
  let originalEnv;
  let consoleLogSpy;
  let consoleErrorSpy;
  let processExitSpy;
  let readFileSyncSpy;
  let spawnSyncSpy;

  // Helper function to create mock responses for spawnSync
  function mockSpawnSyncResponse(endpoint, method = 'GET', captureData = null) {
    return (cmd, args, options) => {
      if (cmd === 'gh' && args.includes('api')) {
        const apiEndpoint = args[1];
        const apiMethod = args[args.indexOf('--method') + 1] || 'GET';
        
        if (apiEndpoint.includes(endpoint) && apiMethod === method) {
          if (captureData && options && options.input) {
            captureData.data = JSON.parse(options.input);
          }
          return { status: 0, stdout: captureData?.response || '{}', stderr: '' };
        }
      }
      return null;
    };
  }

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Clear process.env completely first
    for (const key in process.env) {
      delete process.env[key];
    }
    setupTestEnvironment();
    
    // Set up spies
    consoleLogSpy = spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = spyOn(console, 'error').mockImplementation(() => {});
    processExitSpy = spyOn(process, 'exit').mockImplementation(() => {});
    
    // Mock fs and child_process
    readFileSyncSpy = spyOn(require('fs'), 'readFileSync');
    spawnSyncSpy = spyOn(require('child_process'), 'spawnSync');
  });

  afterEach(() => {
    // Restore environment
    process.env = originalEnv;
    
    // Clear module cache to allow re-running the script
    delete require.cache[require.resolve('./comment-pr-findings.js')];
  });

  // Set up common test environment
  function setupTestEnvironment() {
    process.env.GITHUB_REPOSITORY = 'owner/repo';
    process.env.GITHUB_EVENT_PATH = 'github-event.json';
  }

  describe('Environment Setup', () => {
    test('should parse GitHub context correctly', async () => {

      const mockEventData = {
        pull_request: {
          number: 123,
          head: { sha: 'abc123' }
        }
      };
      
      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify(mockEventData);
        }
        if (path === 'findings.json') {
          return '[]'; // Empty findings to exit early
        }
      });

      await import('./comment-pr-findings.js');
      
      expect(readFileSyncSpy).toHaveBeenCalledWith(expect.stringContaining('github-event.json'), 'utf8');
    });
  });

  describe('Finding Processing', () => {
    test('should exit early when no findings file exists', async () => {
      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: {
              number: 123,
              head: { sha: 'abc123' }
            }
          });
        }
        if (path === 'findings.json') {
          throw new Error('File not found');
        }
        // For any other file (like the script itself), throw to prevent loading
        throw new Error('Unexpected file read: ' + path);
      });

      await import('./comment-pr-findings.js');
      
      expect(consoleLogSpy).toHaveBeenCalledWith('Could not read findings file');
      expect(spawnSyncSpy).not.toHaveBeenCalled();
    });

    test('should exit early when findings array is empty', async () => {
      readFileSyncSpy.mockReturnValue('[]');

      await import('./comment-pr-findings.js');
      
      expect(spawnSyncSpy).not.toHaveBeenCalled();
    });

    test('should process findings correctly', async () => {
      const mockFindings = [{
        path: 'test.py',
        start: { line: 10 },
        check_id: 'rules.insecure-pickle-loads-autofix',
        extra: {
          message: 'Detected use of pickle deserialization',
          fix: 'json.loads($DATA)  # Use json.loads() instead of pickle for security'
        }
      }];

      const mockPrFiles = [{
        filename: 'test.py',
        patch: '@@ -10,1 +10,1 @@'
      }];

      const mockFileContent = {
        content: Buffer.from('    data = pickle.loads(user_input)').toString('base64')
      };

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: {
              number: 123,
              head: { sha: 'abc123' }
            }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let reviewDataCaptured = null;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify(mockPrFiles), stderr: '' };
          }
          if (endpoint.includes('/contents/test.py')) {
            return { status: 0, stdout: JSON.stringify(mockFileContent), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No existing comments
          }
          if (endpoint.includes('/pulls/123/reviews') && args.includes('POST')) {
            // Capture the review data if passed
            if (options && options.input) {
              reviewDataCaptured = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js');

      // Verify API calls were made
      expect(spawnSyncSpy).toHaveBeenCalledWith('gh', expect.arrayContaining(['api', expect.stringContaining('/pulls/123/files')]), expect.any(Object));
      expect(spawnSyncSpy).toHaveBeenCalledWith('gh', expect.arrayContaining(['api', expect.stringContaining('/pulls/123/reviews')]), expect.any(Object));
      expect(consoleLogSpy).toHaveBeenCalledWith('Created review with 1 inline comments');
      
      // Verify review data was captured
      expect(reviewDataCaptured).toBeTruthy();
      expect(reviewDataCaptured.comments).toHaveLength(1);
    });
  });

  describe('Autofix Suggestions', () => {
    test('should generate correct pickle.loads autofix', async () => {
     
      const mockFindings = [{
        path: 'test.py',
        start: { line: 1 },
        check_id: 'rules.insecure-pickle-loads-autofix',
        extra: {
          message: 'Insecure pickle loads',
          fix: 'json.loads($DATA)  # Use json.loads() instead of pickle for security'
        }
      }];

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let capturedReviewData;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          const method = args[args.indexOf('--method') + 1] || 'GET';
          
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify([{ filename: 'test.py' }]), stderr: '' };
          }
          if (endpoint.includes('/contents/test.py')) {
            return { status: 0, stdout: JSON.stringify({
              content: Buffer.from('result = pickle.loads(data)').toString('base64')
            }), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
            return { status: 0, stdout: '[]', stderr: '' };
          }
          if (endpoint.includes('/pulls/123/reviews') && method === 'POST') {
            if (options && options.input) {
              capturedReviewData = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js')
      expect(capturedReviewData).toBeDefined();
      expect(capturedReviewData.comments[0].body).toContain('🤖 **Security Issue: Insecure pickle loads**');
    });

    test('should generate correct yaml.load autofix', async () => {
     
      const mockFindings = [{
        path: 'config.py',
        start: { line: 1 },
        check_id: 'rules.insecure-yaml-loads-no-loader',
        extra: {
          message: 'Unsafe YAML deserialization',
          fix: 'yaml.safe_load($DATA)'
        }
      }];

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let capturedReviewData;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          const method = args[args.indexOf('--method') + 1] || 'GET';
          
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify([{ filename: 'config.py' }]), stderr: '' };
          }
          if (endpoint.includes('/contents/config.py')) {
            return { status: 0, stdout: JSON.stringify({
              content: Buffer.from('config = yaml.load(config_file)').toString('base64')
            }), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
            return { status: 0, stdout: '[]', stderr: '' };
          }
          if (endpoint.includes('/pulls/123/reviews') && method === 'POST') {
            if (options && options.input) {
              capturedReviewData = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js')
      expect(capturedReviewData).toBeDefined();
      expect(capturedReviewData.comments[0].body).toContain('🤖 **Security Issue: Unsafe YAML deserialization**');
    });

    test('should preserve indentation in autofix', async () => {
     
      const mockFindings = [{
        path: 'test.py',
        start: { line: 1 },
        check_id: 'rules.insecure-pickle-loads-autofix',
        extra: {
          message: 'Insecure pickle loads',
          fix: 'json.loads($DATA)  # Use json.loads() instead of pickle for security'
        }
      }];

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let capturedReviewData;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          const method = args[args.indexOf('--method') + 1] || 'GET';
          
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify([{ filename: 'test.py' }]), stderr: '' };
          }
          if (endpoint.includes('/contents/test.py')) {
            return { status: 0, stdout: JSON.stringify({
              content: Buffer.from('        data = pickle.loads(user_input)').toString('base64')
            }), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
            return { status: 0, stdout: '[]', stderr: '' };
          }
          if (endpoint.includes('/pulls/123/reviews') && method === 'POST') {
            if (options && options.input) {
              capturedReviewData = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js')
      expect(capturedReviewData).toBeDefined();
      expect(capturedReviewData.comments[0].body).toContain('🤖 **Security Issue: Insecure pickle loads**');
    });
  });

  describe('Finding Limits', () => {
    test('should process all ClaudeCode findings without limit', async () => {
      // Create 8 ClaudeCode findings
      const mockFindings = [];
      for (let i = 1; i <= 8; i++) {
        mockFindings.push({
          file: `test${i}.py`,
          line: 10,
          message: `Finding ${i}`,
          severity: 'HIGH',
          metadata: {
            vulnerability_type: 'security_issue',
            tool: 'ClaudeCode AI Security Analysis',
            check_id: `check-${i}`
          }
        });
      }

      const mockPrFiles = mockFindings.map(f => ({
        filename: f.file,
        patch: '@@ -10,1 +10,1 @@'
      }));

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let capturedReviewData;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          const method = args[args.indexOf('--method') + 1] || 'GET';
          
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify(mockPrFiles), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
            return { status: 0, stdout: '[]', stderr: '' };
          }
          if (endpoint.includes('/pulls/123/reviews') && method === 'POST') {
            if (options && options.input) {
              capturedReviewData = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js');
      
      expect(capturedReviewData).toBeDefined();
      expect(capturedReviewData.comments).toHaveLength(8); // Should process all 8 findings
      expect(consoleLogSpy).toHaveBeenCalledWith('Created review with 8 inline comments');
    });


    test('should handle findings with all required fields', async () => {
      // Create a ClaudeCode finding with all fields
      const mockFindings = [{
        file: 'test.py',
        line: 10,
        message: 'Insecure pickle usage detected',
        severity: 'HIGH',
        metadata: {
          vulnerability_type: 'security_issue',
          tool: 'ClaudeCode AI Security Analysis',
          check_id: 'pickle-insecure-usage'
        }
      }];

      const mockPrFiles = [{
        filename: 'test.py',
        patch: '@@ -10,1 +10,1 @@'
      }];

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      let capturedReviewData;
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          const method = args[args.indexOf('--method') + 1] || 'GET';
          
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify(mockPrFiles), stderr: '' };
          }
          if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
            return { status: 0, stdout: '[]', stderr: '' };
          }
          if (endpoint.includes('/pulls/123/reviews') && method === 'POST') {
            if (options && options.input) {
              capturedReviewData = JSON.parse(options.input);
            }
            return { status: 0, stdout: '{}', stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js');
      
      expect(capturedReviewData).toBeDefined();
      expect(capturedReviewData.comments).toHaveLength(1);
      
      const comment = capturedReviewData.comments[0];
      expect(comment.body).toContain('🤖 **Security Issue:');
      expect(comment.body).toContain('**Severity:** HIGH');
      expect(comment.body).toContain('**Category:** security_issue');
      expect(comment.body).toContain('**Tool:** ClaudeCode AI Security Analysis');
      expect(consoleLogSpy).toHaveBeenCalledWith('Created review with 1 inline comments');
    });
  });

  describe('Error Handling', () => {
    test('should handle GitHub API errors gracefully', async () => {
     
      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify([{
            path: 'test.py',
            start: { line: 10 },
            check_id: 'rules.insecure-pickle-loads-autofix',
            extra: { message: 'Test', fix: 'test' }
          }]);
        }
      });

      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            throw new Error('API rate limit exceeded');
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      processExitSpy.mockClear(); // Bun spies keep calls across tests
      await import('./comment-pr-findings.js')

      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to post inline review comments (the findings summary comment stands):', expect.any(Error));
      expect(processExitSpy).not.toHaveBeenCalledWith(1);
    });

    test('should skip files not in PR diff', async () => {
      const mockFindings = [{
        path: 'not-in-diff.py',
        start: { line: 10 },
        check_id: 'rules.insecure-pickle-loads-autofix',
        extra: { message: 'Test', fix: 'test' }
      }];

      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({
            pull_request: { number: 123, head: { sha: 'abc123' } }
          });
        }
        if (path === 'findings.json') {
          return JSON.stringify(mockFindings);
        }
      });

      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd === 'gh' && args.includes('api')) {
          const endpoint = args[1];
          if (endpoint.includes('/issues/123/comments') && args.includes('GET')) {
            return { status: 0, stdout: '[]', stderr: '' }; // No findings summary yet
          }
          if (endpoint.includes('/pulls/123/files')) {
            return { status: 0, stdout: JSON.stringify([{ filename: 'other-file.py' }]), stderr: '' };
          }
          return { status: 0, stdout: '{}', stderr: '' };
        }
        return { status: 0, stdout: '{}', stderr: '' };
      });

      await import('./comment-pr-findings.js');
      expect(consoleLogSpy).toHaveBeenCalledWith('File not-in-diff.py not in PR diff, skipping');
      expect(consoleLogSpy).toHaveBeenCalledWith('No findings to comment on PR diff');
    });
  });

  describe('Findings summary comment (one per scanned head)', () => {
    const HEAD_1 = '1111111111111111111111111111111111111111';
    const HEAD_2 = '2222222222222222222222222222222222222222';
    const marker = (sha) => `<!-- claude-code-security-review:summary head=${sha} -->`;
    const ok = (value) => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

    beforeEach(() => {
      // Bun spies keep their calls across tests; these assertions need a clean slate.
      processExitSpy.mockClear();
      spawnSyncSpy.mockClear();
    });

    function givenEvent(headSha, findings) {
      readFileSyncSpy.mockImplementation((path) => {
        if (path.includes('github-event.json')) {
          return JSON.stringify({ pull_request: { number: 123, head: { sha: headSha } } });
        }
        if (path === 'findings.json') {
          return JSON.stringify(findings);
        }
      });
    }

    // Simulated gh CLI: records every API call and answers through respond(endpoint, method, input).
    // A respond() that returns undefined falls back to a successful '{}'.
    function fakeGh(respond) {
      const calls = [];
      spawnSyncSpy.mockImplementation((cmd, args, options) => {
        if (cmd !== 'gh' || !args.includes('api')) {
          return { status: 0, stdout: '{}', stderr: '' };
        }
        const endpoint = args[1];
        const method = args[args.indexOf('--method') + 1] || 'GET';
        const input = options && options.input ? JSON.parse(options.input) : undefined;
        calls.push({ endpoint, method, input });
        return respond(endpoint, method, input) || { status: 0, stdout: '{}', stderr: '' };
      });
      return calls;
    }

    // Answers for the unchanged inline path: the PR diff holds app.py, no inline comments exist yet.
    function inlineAnswers(endpoint, method) {
      if (endpoint.includes('/pulls/123/files')) return ok([{ filename: 'app.py' }]);
      if (endpoint.includes('/pulls/123/comments') && method === 'GET') return ok([]);
      if (endpoint.includes('/pulls/123/reviews') && method === 'POST') return ok({ id: 1 });
      return undefined;
    }

    const isSummaryList = (c) => c.method === 'GET' && c.endpoint.includes('/issues/123/comments');
    const isSummaryPost = (c) => c.method === 'POST' && c.endpoint.endsWith('/issues/123/comments');
    const failedExit = () => processExitSpy.mock.calls.some(([code]) => code !== undefined && code !== 0);

    test('owner case 1: a new finding on a later head is posted although old bot inline security comments exist', async () => {
      givenEvent(HEAD_2, [{ file: 'app.py', line: 12, severity: 'HIGH', title: 'Finding B: SQL injection' }]);
      const head1Summary = [
        marker(HEAD_1),
        `**ClaudeCode security scan — 1 finding(s) on head \`${HEAD_1}\`**`,
        '',
        '- **HIGH** · `app.py:3` · Finding A'
      ].join('\n');
      const calls = fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') {
          return ok([{ id: 901, user: { type: 'Bot' }, body: head1Summary }]);
        }
        if (endpoint.includes('/pulls/123/comments') && method === 'GET') {
          return ok([{ id: 700, user: { type: 'Bot' }, body: '🤖 **Security Issue: Finding A**\n\n**Severity:** HIGH\n' }]);
        }
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      const posts = calls.filter(isSummaryPost);
      expect(posts).toHaveLength(1);
      expect(posts[0].endpoint).toBe('/repos/owner/repo/issues/123/comments');
      expect(posts[0].input.body.startsWith(`${marker(HEAD_2)}\n`)).toBe(true);
      expect(posts[0].input.body).toContain('- **HIGH** · `app.py:12` · Finding B: SQL injection');
      // The summary of head 1 is never touched.
      expect(calls.filter((c) => c.method === 'PATCH')).toHaveLength(0);
      // The existing duplicate check still suppresses the inline review, and only that.
      expect(consoleLogSpy).toHaveBeenCalledWith('Found 1 existing security comments, skipping to avoid duplicates');
      expect(calls.some((c) => c.endpoint.includes('/pulls/123/reviews'))).toBe(false);
      expect(failedExit()).toBe(false);
    });

    test('owner case 2: a re-run of the same head PATCHes the existing summary with the full content, no second POST', async () => {
      const longTitle = 'X'.repeat(250);
      givenEvent(HEAD_2, [
        { file: 'app.py', line: 12, severity: 'HIGH', title: 'SQL injection in login', description: 'not used' },
        { path: 'lib/util.py', start: { line: 7 }, description: 'Command injection via shell=True\nSecond line is not part of the title' },
        { file: 'app.py', line: 30, severity: 'LOW', title: longTitle },
        { file: 'app.py', severity: 'MEDIUM', title: '' }
      ]);
      // Page 1 is full (100 entries): a bot comment quoting the marker mid-body, a user comment
      // carrying the marker, and the summary of another head. None of them is this head's summary.
      const page1 = Array.from({ length: 97 }, (_, i) => ({ id: 1000 + i, user: { type: 'User' }, body: `comment ${i}` }));
      page1.push({ id: 222, user: { type: 'Bot' }, body: `Quoted: ${marker(HEAD_2)}` });
      page1.push({ id: 333, user: { type: 'User' }, body: `${marker(HEAD_2)}\nquoted by a human` });
      page1.push({ id: 444, user: { type: 'Bot' }, body: `${marker(HEAD_1)}\n**ClaudeCode security scan — 1 finding(s) on head \`${HEAD_1}\`**` });
      // Page 2 holds this head's earlier summary with outdated content.
      const page2 = [{ id: 555, user: { type: 'Bot' }, body: `${marker(HEAD_2)}\n**ClaudeCode security scan — 1 finding(s) on head \`${HEAD_2}\`**\n\n- **HIGH** · \`app.py:12\` · SQL injection in login` }];
      const calls = fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') {
          const page = Number((endpoint.match(/[?&]page=(\d+)/) || [])[1]);
          return ok(page === 1 ? page1 : page === 2 ? page2 : []);
        }
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      expect(calls.filter(isSummaryList).map((c) => c.endpoint)).toEqual([
        '/repos/owner/repo/issues/123/comments?per_page=100&page=1',
        '/repos/owner/repo/issues/123/comments?per_page=100&page=2'
      ]);
      expect(calls.filter(isSummaryPost)).toHaveLength(0);
      const patches = calls.filter((c) => c.method === 'PATCH');
      expect(patches).toHaveLength(1);
      expect(patches[0].endpoint).toBe('/repos/owner/repo/issues/comments/555');
      expect(patches[0].input).toEqual({
        body: [
          marker(HEAD_2),
          `**ClaudeCode security scan — 4 finding(s) on head \`${HEAD_2}\`**`,
          '',
          '- **HIGH** · `app.py:12` · SQL injection in login',
          '- **HIGH** · `lib/util.py:7` · Command injection via shell=True',
          `- **LOW** · \`app.py:30\` · ${'X'.repeat(200)}`,
          '- **MEDIUM** · `app.py:1` · Security vulnerability detected'
        ].join('\n')
      });
      expect(failedExit()).toBe(false);
    });

    test('owner case 3: a finding whose file is not in the PR diff appears in the summary', async () => {
      givenEvent(HEAD_1, [
        { file: 'app.py', line: 7, severity: 'HIGH', title: 'SQL injection in login' },
        { file: 'not-in-diff.py', line: 42, severity: 'MEDIUM', title: 'Hardcoded secret' }
      ]);
      const calls = fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') return ok([]);
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      const posts = calls.filter(isSummaryPost);
      expect(posts).toHaveLength(1);
      expect(posts[0].input).toEqual({
        body: [
          marker(HEAD_1),
          `**ClaudeCode security scan — 2 finding(s) on head \`${HEAD_1}\`**`,
          '',
          '- **HIGH** · `app.py:7` · SQL injection in login',
          '- **MEDIUM** · `not-in-diff.py:42` · Hardcoded secret'
        ].join('\n')
      });
      // The summary is posted before any inline work starts.
      expect(calls.indexOf(posts[0])).toBeLessThan(calls.findIndex((c) => c.endpoint.includes('/pulls/123/files')));
      // The inline path is unchanged: only the placeable finding becomes an inline comment.
      expect(consoleLogSpy).toHaveBeenCalledWith('File not-in-diff.py not in PR diff, skipping');
      const review = calls.find((c) => c.method === 'POST' && c.endpoint.includes('/pulls/123/reviews'));
      expect(review.input.comments.map((c) => c.path)).toEqual(['app.py']);
      expect(failedExit()).toBe(false);
    });

    test('owner case 4: a failed summary POST makes the script exit non-zero', async () => {
      givenEvent(HEAD_1, [{ file: 'app.py', line: 7, severity: 'HIGH', title: 'SQL injection in login' }]);
      fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') return ok([]);
        if (endpoint.includes('/issues/123/comments') && method === 'POST') {
          return { status: 1, stdout: '', stderr: 'HTTP 403: Resource not accessible by integration' };
        }
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      expect(failedExit()).toBe(true);
    });

    test('owner case 5: 0 findings means no summary call at all and no non-zero exit', async () => {
      givenEvent(HEAD_1, []);
      const calls = fakeGh(() => undefined);

      await import('./comment-pr-findings.js');

      expect(calls).toEqual([]);
      expect(failedExit()).toBe(false);
    });

    test('listing stops after 20 full pages and a new summary is posted', async () => {
      givenEvent(HEAD_1, [{ file: 'app.py', line: 7, severity: 'HIGH', title: 'SQL injection in login' }]);
      const fullPage = Array.from({ length: 100 }, (_, i) => ({ id: i, user: { type: 'Bot' }, body: 'unrelated bot comment' }));
      const calls = fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') return ok(fullPage);
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      expect(calls.filter(isSummaryList).map((c) => c.endpoint)).toEqual(
        Array.from({ length: 20 }, (_, i) => `/repos/owner/repo/issues/123/comments?per_page=100&page=${i + 1}`)
      );
      expect(calls.filter(isSummaryPost)).toHaveLength(1);
      expect(failedExit()).toBe(false);
    });

    test('SILENCE_CLAUDECODE_COMMENTS=true still means no comments at all, summary included', async () => {
      process.env.SILENCE_CLAUDECODE_COMMENTS = 'true';
      givenEvent(HEAD_1, [{ file: 'app.py', line: 7, severity: 'HIGH', title: 'SQL injection in login' }]);
      const calls = fakeGh((endpoint, method) => {
        if (endpoint.includes('/issues/123/comments') && method === 'GET') return ok([]);
        return inlineAnswers(endpoint, method);
      });

      await import('./comment-pr-findings.js');

      expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
      expect(failedExit()).toBe(false);
    });

    describe('untrusted finding fields are neutralized in the summary', () => {
      const OTHER = 'abcdefabcdefabcdefabcdefabcdefabcdefabcd';
      const count = (text, needle) => text.split(needle).length - 1;

      // Runs the script once for headSha and returns the summary POST body.
      async function summaryBodyFor(headSha, findings, existingComments = []) {
        givenEvent(headSha, findings);
        const calls = fakeGh((endpoint, method) => {
          if (endpoint.includes('/issues/123/comments') && method === 'GET') return ok(existingComments);
          return inlineAnswers(endpoint, method);
        });
        await import('./comment-pr-findings.js');
        return calls;
      }

      test('(a) a title opening an HTML comment cannot hide the findings after it', async () => {
        const calls = await summaryBodyFor(HEAD_1, [
          { file: 'app.py', line: 7, severity: 'HIGH', title: 'Looks harmless <!-- hidden' },
          { file: 'app.py', line: 9, severity: 'HIGH', title: 'Second finding stays visible' }
        ]);

        const body = calls.find(isSummaryPost).input.body;
        expect(count(body, '<!--')).toBe(1);
        expect(body.startsWith(`${marker(HEAD_1)}\n`)).toBe(true);
        expect(body).toContain('- **HIGH** · `app.py:7` · Looks harmless &lt;!-- hidden');
        expect(body).toContain('- **HIGH** · `app.py:9` · Second finding stays visible');
      });

      test('(b) a title quoting another head\'s marker is never taken for that head\'s summary', async () => {
        const quoted = `Quoted ${marker(OTHER)} here`;
        const calls = await summaryBodyFor(HEAD_1, [{ file: 'app.py', line: 7, severity: 'HIGH', title: quoted }]);
        const body = calls.find(isSummaryPost).input.body;
        expect(count(body, '<!--')).toBe(1);
        expect(body.includes(marker(OTHER))).toBe(false);

        // The run for head OTHER sees that bot comment and still posts its own summary.
        delete require.cache[require.resolve('./comment-pr-findings.js')];
        const otherCalls = await summaryBodyFor(OTHER, [{ file: 'app.py', line: 7, severity: 'HIGH', title: 'Other head finding' }], [
          { id: 777, user: { type: 'Bot' }, body }
        ]);
        expect(otherCalls.filter((c) => c.method === 'PATCH')).toHaveLength(0);
        expect(otherCalls.filter(isSummaryPost)).toHaveLength(1);
      });

      test('(c) backtick in the file, @mention and newline in the title: code span intact, no ping, one line per finding', async () => {
        const calls = await summaryBodyFor(HEAD_1, [
          { file: 'src/a`b.py', line: 3, severity: 'HIGH', title: 'Ping @someone\r\nsecond line' },
          { file: 'app.py', line: 5, severity: 'LOW', title: 'Second' }
        ]);

        const lines = calls.find(isSummaryPost).input.body.split('\n');
        expect(lines).toHaveLength(5); // marker, heading, blank, one line per finding
        expect(lines[3]).toBe("- **HIGH** · `src/a'b.py:3` · Ping @​someone second line");
        expect(count(lines[3], '`')).toBe(2);
        expect(lines[4]).toBe('- **LOW** · `app.py:5` · Second');
      });

      test('severity is neutralized, & is encoded and a non-numeric line falls back to 1', async () => {
        const calls = await summaryBodyFor(HEAD_1, [
          { file: 'app.py', line: 'x<y', severity: 'HIGH\n<img src=x onerror=alert(1)>', title: 'T &lt; U' }
        ]);

        const body = calls.find(isSummaryPost).input.body;
        expect(body.split('\n')[3]).toBe('- **HIGH &lt;img src=x onerror=alert(1)&gt;** · `app.py:1` · T &amp;lt; U');
      });
    });
  });
});