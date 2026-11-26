/**
 * @file git-diff-engine.js
 * @module main/code-intel/git-diff-engine
 * @description Extracts and parses Git diffs across staged, unstaged, branch, or commit scopes.
 */

'use strict';

const { execFileSync } = require('child_process');
const path = require('path');

class GitDiffEngine {
  constructor(repoRoot) {
    this.repoRoot = repoRoot || process.cwd();
  }

  /**
   * Execute git command safely without shell expansion.
   */
  _git(args) {
    try {
      const fs = require('fs');
      if (!fs.existsSync(path.join(this.repoRoot, '.git'))) {
        return '';
      }
      return execFileSync('git', args, {
        cwd: this.repoRoot,
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024,
        windowsHide: true,
      });
    } catch (err) {
      // In non-git repos or fresh dirs, return empty string
      return '';
    }
  }

  getCurrentBranch() {
    const out = this._git(['rev-parse', '--abbrev-ref', 'HEAD']);
    return out ? out.trim() : 'main';
  }

  getHeadCommit() {
    const out = this._git(['rev-parse', 'HEAD']);
    return out ? out.trim() : 'unknown';
  }

  /**
   * Get raw diff string by scope ('staged', 'unstaged', 'last-commit', or custom branch)
   */
  getRawDiff(scope = 'staged') {
    switch (scope) {
      case 'staged':
        return this._git(['diff', '--cached']);
      case 'unstaged':
        return this._git(['diff']);
      case 'last-commit':
        return this._git(['diff', 'HEAD~1', 'HEAD']);
      default:
        // Assume custom branch or commit range
        return this._git(['diff', scope]);
    }
  }

  /**
   * Parse a unified diff into structured file objects with hunks and lines.
   */
  parseDiff(diffText) {
    if (!diffText || typeof diffText !== 'string') return [];

    const files = [];
    const fileBlocks = diffText.split(/^diff --git /m).filter(Boolean);

    for (const block of fileBlocks) {
      const lines = block.split('\n');
      const headerLine = lines[0] || '';
      const match = headerLine.match(/a\/(.+?)\s+b\/(.+)/);
      const filePath = match ? match[2] : headerLine.split(' ')[0] || 'unknown';

      const fileObj = {
        file: filePath,
        hunks: [],
        additions: 0,
        deletions: 0,
      };

      let currentHunk = null;
      let currentLineNumber = 0;

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.startsWith('@@')) {
          const hunkMatch = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
          currentLineNumber = hunkMatch ? parseInt(hunkMatch[1], 10) : 1;
          currentHunk = {
            header: line,
            startLine: currentLineNumber,
            lines: [],
          };
          fileObj.hunks.push(currentHunk);
        } else if (currentHunk) {
          if (line.startsWith('+') && !line.startsWith('+++')) {
            fileObj.additions++;
            currentHunk.lines.push({ type: 'add', line: currentLineNumber++, content: line.slice(1) });
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            fileObj.deletions++;
            currentHunk.lines.push({ type: 'del', line: currentLineNumber, content: line.slice(1) });
          } else if (line.startsWith(' ')) {
            currentHunk.lines.push({ type: 'context', line: currentLineNumber++, content: line.slice(1) });
          }
        }
      }

      files.push(fileObj);
    }

    return files;
  }
}

module.exports = { GitDiffEngine };
