#!/usr/bin/env node

/**
 * Script to comment on PRs with security findings from ClaudeCode
 */

const fs = require('fs');
const { spawnSync } = require('child_process');

// Parse GitHub context from environment
const context = {
  repo: {
    owner: process.env.GITHUB_REPOSITORY?.split('/')[0] || '',
    repo: process.env.GITHUB_REPOSITORY?.split('/')[1] || ''
  },
  issue: {
    number: parseInt(process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')).pull_request?.number : '') || 0
  },
  payload: {
    pull_request: process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')).pull_request : {}
  }
};

// GitHub API helper using gh CLI
function ghApi(endpoint, method = 'GET', data = null) {
  // Build arguments array safely to prevent command injection
  const args = ['api', endpoint, '--method', method];
  
  if (data) {
    args.push('--input', '-');
  }
  
  try {
    const result = spawnSync('gh', args, {
      encoding: 'utf8',
      input: data ? JSON.stringify(data) : undefined,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    if (result.error) {
      throw new Error(`Failed to spawn gh process: ${result.error.message}`);
    }
    
    if (result.status !== 0) {
      console.error(`Error calling GitHub API: ${result.stderr}`);
      throw new Error(`gh process exited with code ${result.status}: ${result.stderr}`);
    }
    
    return JSON.parse(result.stdout);
  } catch (error) {
    console.error(`Error calling GitHub API: ${error.message}`);
    throw error;
  }
}

// Helper function to add reactions to a comment
function addReactionsToComment(commentId, isReviewComment = true) {
  const reactions = ['+1', '-1']; // thumbs up and thumbs down
  const endpoint = isReviewComment 
    ? `/repos/${context.repo.owner}/${context.repo.repo}/pulls/comments/${commentId}/reactions`
    : `/repos/${context.repo.owner}/${context.repo.repo}/issues/comments/${commentId}/reactions`;
  
  for (const reaction of reactions) {
    try {
      ghApi(endpoint, 'POST', { content: reaction });
      console.log(`Added ${reaction} reaction to comment ${commentId}`);
    } catch (error) {
      console.error(`Failed to add ${reaction} reaction to comment ${commentId}:`, error.message);
    }
  }
}

// Helper function to add reactions to all comments in a review
function addReactionsToReview(reviewId) {
  try {
    // Get all comments from the review
    const reviewComments = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews/${reviewId}/comments`);
    
    if (reviewComments && Array.isArray(reviewComments)) {
      for (const comment of reviewComments) {
        if (comment.id) {
          addReactionsToComment(comment.id, true);
        }
      }
    }
  } catch (error) {
    console.error(`Failed to get review comments for review ${reviewId}:`, error.message);
  }
}

// Marker line that identifies the findings summary comment of one scanned head
function summaryMarker(headSha) {
  return `<!-- claude-code-security-review:summary head=${headSha} -->`;
}

// Severity, file and title are model output the scanned PR can influence. Neutralize them before
// they enter the summary markdown: no HTML (the leading marker stays the only "<!--"), no code-span
// breakout, no @mention pings, one line per finding.
function sanitizeSummaryField(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/`/g, "'")
    .replace(/@/g, '@\u200B')
    .replace(/[\u0000-\u001F\u007F-\u009F]+/g, ' ')
    .trim();
}

// Short title for one finding in the summary comment (raw; sanitized where the body is built)
function summaryTitle(finding) {
  let title = '';
  if (typeof finding.title === 'string' && finding.title.trim() !== '') {
    title = finding.title.trim();
  } else if (typeof finding.description === 'string') {
    title = finding.description.split('\n')[0].trim();
  }
  return (title || 'Security vulnerability detected').slice(0, 200);
}

function buildSummaryBody(findings, headSha) {
  const lines = findings.map(finding => {
    // Resolved exactly as the inline comments resolve them, then neutralized
    const severity = sanitizeSummaryField(finding.severity || 'HIGH');
    const file = sanitizeSummaryField(finding.file || finding.path);
    const rawLine = Number(finding.line || finding.start?.line || 1);
    const line = Number.isFinite(rawLine) ? rawLine : 1;
    const title = sanitizeSummaryField(summaryTitle(finding)) || 'Security vulnerability detected';
    return `- **${severity}** · \`${file}:${line}\` · ${title}`;
  });
  return [
    summaryMarker(headSha),
    `**ClaudeCode security scan — ${findings.length} finding(s) on head \`${headSha}\`**`,
    '',
    ...lines
  ].join('\n');
}

// Post (or, on a re-run of the same head, update) one top-level PR comment that lists all
// findings of the scanned head. Issue comments on a PR need only the pull-requests: write
// permission the consumer already grants. Any failure here throws: the caller fails closed.
function upsertFindingsSummary(findings) {
  const headSha = context.payload.pull_request?.head?.sha;
  if (!headSha) {
    throw new Error('Pull request head SHA missing from the event payload');
  }
  const marker = summaryMarker(headSha);
  const body = buildSummaryBody(findings, headSha);
  const repoPath = `/repos/${context.repo.owner}/${context.repo.repo}`;

  let existing = null;
  for (let page = 1; page <= 20 && !existing; page++) {
    const comments = ghApi(`${repoPath}/issues/${context.issue.number}/comments?per_page=100&page=${page}`);
    if (!Array.isArray(comments)) {
      throw new Error(`Unexpected response listing PR comments (page ${page})`);
    }
    // Our summary bodies start with the marker; matching only at the start keeps a marker
    // quoted inside another comment (or inside a finding text) from being taken for it.
    existing = comments.find(comment =>
      comment && comment.user && comment.user.type === 'Bot' &&
      typeof comment.body === 'string' && comment.body.startsWith(marker)
    ) || null;
    if (comments.length < 100) {
      break;
    }
  }

  if (existing) {
    ghApi(`${repoPath}/issues/comments/${existing.id}`, 'PATCH', { body });
    console.log(`Updated findings summary comment ${existing.id} for head ${headSha} (${findings.length} finding(s))`);
  } else {
    ghApi(`${repoPath}/issues/${context.issue.number}/comments`, 'POST', { body });
    console.log(`Created findings summary comment for head ${headSha} (${findings.length} finding(s))`);
  }
}

async function run() {
  let newFindings = [];
  try {
    // Read the findings
    try {
      const findingsData = fs.readFileSync('findings.json', 'utf8');
      newFindings = JSON.parse(findingsData);
    } catch (e) {
      console.log('Could not read findings file');
      return;
    }
    
    if (newFindings.length === 0) {
      return;
    }
    
    // Check if ClaudeCode comments should be silenced (no comments at all, summary included)
    const silenceClaudeCodeComments = process.env.SILENCE_CLAUDECODE_COMMENTS === 'true';
    
    if (silenceClaudeCodeComments) {
      console.log(`ClaudeCode comments silenced - excluding ${newFindings.length} findings from comments`);
      return;
    }
    
    // The summary comment goes first and fails closed: without it the PR may not show this head's findings
    upsertFindingsSummary(newFindings);
  } catch (error) {
    console.error('Failed to comment on PR:', error);
    process.exit(1);
    return;
  }
  
  // Inline review comments: best effort once the summary stands. An error here is logged
  // and does not fail the step.
  try {
    // Get the PR diff to map file lines to diff positions
    const prFiles = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/files?per_page=100`);
    
    // Create a map of file paths to their diff information
    const fileMap = {};
    prFiles.forEach(file => {
      fileMap[file.filename] = file;
    });
    
    // Prepare review comments
    const reviewComments = [];
    
    // Process findings synchronously (gh cli doesn't support async well)
    for (const finding of newFindings) {
      const file = finding.file || finding.path;
      const line = finding.line || (finding.start && finding.start.line) || 1;
      const message = finding.description || (finding.extra && finding.extra.message) || 'Security vulnerability detected';
      const severity = finding.severity || 'HIGH';
      const category = finding.category || 'security_issue';
      
      // Check if this file is part of the PR diff
      if (!fileMap[file]) {
        console.log(`File ${file} not in PR diff, skipping`);
        continue;
      }
      
      // Build the comment body
      let commentBody = `🤖 **Security Issue: ${message}**\n\n`;
      commentBody += `**Severity:** ${severity}\n`;
      commentBody += `**Category:** ${category}\n`;
      commentBody += `**Tool:** ClaudeCode AI Security Analysis\n`;
      
      // Add exploit scenario if available
      if (finding.exploit_scenario || (finding.extra && finding.extra.metadata && finding.extra.metadata.exploit_scenario)) {
        const exploitScenario = finding.exploit_scenario || finding.extra.metadata.exploit_scenario;
        commentBody += `\n**Exploit Scenario:** ${exploitScenario}\n`;
      }
      
      // Add recommendation if available
      if (finding.recommendation || (finding.extra && finding.extra.metadata && finding.extra.metadata.recommendation)) {
        const recommendation = finding.recommendation || finding.extra.metadata.recommendation;
        commentBody += `\n**Recommendation:** ${recommendation}\n`;
      }
      
      // Prepare the review comment
      const reviewComment = {
        path: file,
        line: line,
        side: 'RIGHT',
        body: commentBody
      };
      
      reviewComments.push(reviewComment);
    }
    
    if (reviewComments.length === 0) {
      console.log('No findings to comment on PR diff');
      return;
    }
    
    // Check for existing review comments to avoid duplicates (suppresses inline comments only, never the summary)
    const comments = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/comments`);
    
    // Check if we've already commented on these findings
    const existingSecurityComments = comments.filter(comment => 
      comment.user.type === 'Bot' && 
      comment.body && comment.body.includes('🤖 **Security Issue:')
    );
    
    if (existingSecurityComments.length > 0) {
      console.log(`Found ${existingSecurityComments.length} existing security comments, skipping to avoid duplicates`);
      return;
    }
        
    try {
      // Create a review with all the comments
      const reviewData = {
        commit_id: context.payload.pull_request.head.sha,
        event: 'COMMENT',
        comments: reviewComments
      };
      
      const reviewResponse = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/reviews`, 'POST', reviewData);
      
      console.log(`Created review with ${reviewComments.length} inline comments`);
      
      // Add reactions to the comments
      if (reviewResponse && reviewResponse.id) {
        addReactionsToReview(reviewResponse.id);
      }
    } catch (error) {
      console.error('Error creating review:', error);
      
      // Fallback: try to create individual comments if review fails
      // This might happen if line numbers are outside the diff context
      console.log('Attempting fallback with adjusted line numbers...');
      
      for (const comment of reviewComments) {
        try {
          // Try to create comment with the original line
          const commentData = {
            path: comment.path,
            line: comment.line,
            side: comment.side,
            body: comment.body,
            commit_id: context.payload.pull_request.head.sha
          };
          
          const commentResponse = ghApi(`/repos/${context.repo.owner}/${context.repo.repo}/pulls/${context.issue.number}/comments`, 'POST', commentData);
          
          // Add reactions to the individual comment
          if (commentResponse && commentResponse.id) {
            addReactionsToComment(commentResponse.id, true);
          }
        } catch (lineError) {
          console.log(`Could not comment on ${comment.path}:${comment.line} - line might not be in diff context`);
          // If the specific line fails, try to get the file's patch and find a suitable line
          const fileInfo = fileMap[comment.path];
          if (fileInfo && fileInfo.patch) {
            // This is a simplified approach - in production you'd want more sophisticated line mapping
            console.log(`File ${comment.path} has additions but line ${comment.line} is not in the diff`);
          }
        }
      }
    }
  } catch (error) {
    console.error('Failed to post inline review comments (the findings summary comment stands):', error);
  }
}

run();