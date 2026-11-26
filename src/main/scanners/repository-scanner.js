/**
 * @file repository-scanner.js
 * @module main/scanners/repository-scanner
 * @description Scans Git repositories and directory structures for prompt injection,
 *   malicious agent instructions, credential leaks, and unsafe build configurations.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { BaseScanner } = require('./base-scanner');
const { InjectionDetector } = require('../security/injection-detector');

const SECRET_PATTERNS = [
  { name: 'GitHub Personal Access Token', regex: /ghp_[a-zA-Z0-9]{36}/, severity: 'critical' },
  { name: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9_\-]{40,}/, severity: 'critical' },
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{48}/, severity: 'critical' },
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, severity: 'high' },
  { name: 'Slack Bot Token', regex: /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/, severity: 'high' },
  { name: 'Private RSA/OpenSSH Key', regex: /-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----/, severity: 'critical' },
];

class RepositoryScanner extends BaseScanner {
  constructor() {
    super({
      id: 'repo-scanner',
      name: 'AEGIS Repository Security Scanner',
      version: '1.0.0',
      supportedArtifacts: ['repository', 'directory'],
    });
    this.detector = new InjectionDetector();
  }

  async scan(repoPath, options = {}, onProgress = null) {
    this.reportProgress(onProgress, 10, 'Initializing repository scan...');
    const findings = [];
    const scannedFiles = [];

    if (!fs.existsSync(repoPath)) {
      throw new Error(`Repository path does not exist: ${repoPath}`);
    }

    const maxFiles = options.maxFiles || 500;
    const filesToScan = [];
    this._collectFiles(repoPath, filesToScan, 0, maxFiles);

    this.reportProgress(onProgress, 30, `Discovered ${filesToScan.length} files to analyze.`);

    for (let i = 0; i < filesToScan.length; i++) {
      const file = filesToScan[i];
      scannedFiles.push(file);
      this._scanFile(file, repoPath, findings);
      const percent = Math.floor(30 + ((i + 1) / filesToScan.length) * 60);
      this.reportProgress(onProgress, percent, `Analyzing ${path.basename(file)}...`);
    }

    this.reportProgress(onProgress, 100, 'Repository scan completed.');

    return {
      scannerId: this.id,
      scannerVersion: this.version,
      repositoryPath: repoPath,
      scannedFilesCount: scannedFiles.length,
      findingsCount: findings.length,
      findings,
      scannedAt: new Date().toISOString(),
    };
  }

  _collectFiles(dir, list, depth, maxFiles) {
    if (depth > 6 || list.length >= maxFiles) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (list.length >= maxFiles) break;
        if (entry.isSymbolicLink()) continue; // Ignore symlinks to prevent loops
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          const ignoreDirs = ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor'];
          if (!ignoreDirs.includes(entry.name)) {
            this._collectFiles(fullPath, list, depth + 1, maxFiles);
          }
        } else if (entry.isFile()) {
          list.push(fullPath);
        }
      }
    } catch (_) {}
  }

  _scanFile(filePath, repoRoot, findings) {
    const relPath = path.relative(repoRoot, filePath).replace(/\\/g, '/');
    const ext = path.extname(filePath).toLowerCase();

    // Sensitive files committed to repository
    if (relPath.endsWith('.env') || relPath.includes('.env.local') || relPath.endsWith('id_rsa')) {
      findings.push({
        id: `find-${randomUUID()}`,
        title: 'Sensitive Credential File in Repository',
        description: `Sensitive file '${relPath}' committed directly to the repository.`,
        category: 'secret_leak',
        severity: 'critical',
        confidence: 0.99,
        artifact: relPath,
        explanation: 'Committing environment files or private keys allows unauthorized access.',
        recommended_action: 'Remove file from Git history and revoke exposed credentials.',
      });
    }

    // Only inspect text and code files
    const validExtensions = ['.md', '.txt', '.json', '.yaml', '.yml', '.js', '.ts', '.py', '.sh', '.ps1', '.toml', '.env'];
    if (!validExtensions.includes(ext) && !relPath.startsWith('.')) {
      return;
    }

    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 2 * 1024 * 1024) return; // Skip files > 2MB

      const content = fs.readFileSync(filePath, 'utf8');

      // 1. Scan for leaked secrets
      for (const secretRule of SECRET_PATTERNS) {
        const match = content.match(secretRule.regex);
        if (match) {
          findings.push({
            id: `find-${randomUUID()}`,
            title: `Exposed Secret: ${secretRule.name}`,
            description: `Found active secret pattern '${secretRule.name}' in '${relPath}'.`,
            category: 'secret_leak',
            severity: secretRule.severity,
            confidence: 0.95,
            artifact: relPath,
            evidence: { matchedSnippet: match[0].slice(0, 10) + '...' },
            explanation: 'Hardcoded secrets in source files lead to credential theft.',
            recommended_action: 'Revoke key immediately and move credentials to secure environment variables.',
          });
        }
      }

      // 2. Scan for malicious agent instructions or prompt injection
      const injectionThreats = this.detector.detect(content, { filePath: relPath });
      for (const threat of injectionThreats) {
        findings.push({
          id: `find-${randomUUID()}`,
          title: `Prompt Injection: ${threat.name}`,
          description: threat.description,
          category: threat.category,
          severity: threat.severity,
          confidence: threat.confidence,
          artifact: relPath,
          evidence: { matchedText: threat.matchedText, ruleId: threat.ruleId },
          explanation: `Repository file '${relPath}' contains instructions targeting AI agents.`,
          recommended_action: 'Inspect file origin and remove prompt injection directives.',
        });
      }
    } catch (_) {}
  }
}

module.exports = { RepositoryScanner, SECRET_PATTERNS };
