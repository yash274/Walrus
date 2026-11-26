/**
 * @file code-reviewer.js
 * @module main/code-intel/code-reviewer
 * @description CodeRabbit-grade AI code reviewer and engineering intelligence engine.
 */

'use strict';

const { randomUUID } = require('crypto');
const { GitDiffEngine } = require('./git-diff-engine');
const { ContextEngine } = require('./context-engine');
const { BlastRadiusAnalyzer } = require('./blast-radius');

// Static security & quality heuristics for diff additions
const DIFF_HEURISTICS = [
  {
    id: 'SEC-SQLI',
    title: 'Potential SQL Injection',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE).*?\+\s*[a-zA-Z0-9_\$]+/i,
    severity: 'critical',
    explanation: 'String concatenation detected in SQL query string without parameterized queries.',
    recommendation: 'Use parameterized SQL queries or prepared statements.',
  },
  {
    id: 'SEC-EVAL',
    title: 'Unsafe Dynamic Code Execution',
    regex: /\b(?:eval|Function)\s*\(.*?\)/,
    severity: 'critical',
    explanation: 'Direct invocation of eval() or new Function() allows arbitrary code execution.',
    recommendation: 'Eliminate dynamic eval and use static parser methods.',
  },
  {
    id: 'QUAL-UNHANDLED',
    title: 'Empty Catch Block',
    regex: /catch\s*\([^\)]*\)\s*\{\s*\}/,
    severity: 'medium',
    explanation: 'Empty catch block silently suppresses runtime errors without logging.',
    recommendation: 'Log or handle the exception appropriately.',
  },
  {
    id: 'QUAL-CONSOLE',
    title: 'Debug Console Logging',
    regex: /console\.(?:log|debug)\s*\(/,
    severity: 'minor',
    explanation: 'Console logging detected in production code.',
    recommendation: 'Use structured logger or remove debug statement before merge.',
  },
];

class CodeReviewer {
  constructor({ repoRoot, database, orchestrator } = {}) {
    this.repoRoot = repoRoot || process.cwd();
    this.database = database || null;
    this.orchestrator = orchestrator || null;
    this.diffEngine = new GitDiffEngine(this.repoRoot);
    this.contextEngine = new ContextEngine(this.repoRoot);
    this.blastRadius = new BlastRadiusAnalyzer(this.contextEngine);
  }

  /**
   * Run a code review over a given scope.
   * @param {Object} [options]
   * @param {string} [options.scope='staged'] 'staged' | 'unstaged' | 'last-commit' | custom diff string
   * @param {string} [options.rawDiff] Explicit diff text override
   */
  async review({ scope = 'staged', rawDiff = null } = {}) {
    const diffText = rawDiff !== null ? rawDiff : this.diffEngine.getRawDiff(scope);
    const parsedFiles = this.diffEngine.parseDiff(diffText);
    const changedFilePaths = parsedFiles.map((f) => f.file);

    // 1. Analyze architectural impact & blast radius
    const impact = this.blastRadius.analyze(changedFilePaths);

    // 2. Deterministic line-level findings
    const findings = [];
    for (const file of parsedFiles) {
      for (const hunk of file.hunks) {
        for (const lineObj of hunk.lines) {
          if (lineObj.type === 'add') {
            for (const h of DIFF_HEURISTICS) {
              if (h.regex.test(lineObj.content)) {
                findings.push({
                  id: `rev-find-${randomUUID()}`,
                  file: file.file,
                  line: lineObj.line,
                  title: h.title,
                  severity: h.severity,
                  matchedSnippet: lineObj.content.trim(),
                  explanation: h.explanation,
                  recommendation: h.recommendation,
                });
              }
            }
          }
        }
      }
    }

    // 3. Formulate walkthrough
    const walkthrough = parsedFiles.map((f) => ({
      file: f.file,
      additions: f.additions,
      deletions: f.deletions,
      description: `Modified with ${f.additions} addition(s) and ${f.deletions} deletion(s).`,
    }));

    // 4. Formulate summary
    const summary =
      parsedFiles.length === 0
        ? 'No code changes detected in selected scope.'
        : `Reviewed ${parsedFiles.length} file(s) across scope '${scope}'. Found ${findings.length} issue(s). ${impact.summary}`;

    // 5. Generate suggested fixes for findings
    const suggestedFixes = findings.map((f) => ({
      findingId: f.id,
      file: f.file,
      line: f.line,
      patch: `// Remediation: ${f.recommendation}\n`,
    }));

    const reviewId = `rev-${randomUUID()}`;
    const report = {
      id: reviewId,
      repository_path: this.repoRoot,
      git_branch: this.diffEngine.getCurrentBranch(),
      commit_hash: this.diffEngine.getHeadCommit(),
      scope,
      summary,
      impact,
      walkthrough,
      findings,
      suggested_fixes: suggestedFixes,
      status: 'completed',
      created_at: new Date().toISOString(),
    };

    if (this.database) {
      this.database.insertCodeReview(report);
    }

    return report;
  }
}

module.exports = { CodeReviewer, DIFF_HEURISTICS };
