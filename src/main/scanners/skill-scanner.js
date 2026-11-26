/**
 * @file skill-scanner.js
 * @module main/scanners/skill-scanner
 * @description Dedicated security scanner for AI Agent Skills (SKILL.md, manifests, scripts).
 *   Implements AST and pattern matching inspired by Cisco AI Defense skill-scanner.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { BaseScanner } = require('./base-scanner');
const { InjectionDetector } = require('../security/injection-detector');

const SKILL_RULES = [
  {
    id: 'SKILL-001',
    name: 'Suspicious Network Endpoint',
    severity: 'high',
    confidence: 0.85,
    regex: /https?:\/\/(?:webhook\.site|pipedream\.net|ngrok\.io|requestbin\.net|temp-url)/i,
    description: 'Skill communicates with known data exfiltration or webhook testing endpoints.',
  },
  {
    id: 'SKILL-002',
    name: 'Arbitrary Subprocess Spawning',
    severity: 'medium',
    confidence: 0.8,
    regex: /(?:subprocess\.Popen|os\.system|child_process\.exec(?:Sync)?)\s*\(\s*["']?(?:rm\s+-rf|del\s+\/f|format|reboot)/i,
    description: 'Skill executes destructive filesystem or system control commands.',
  },
  {
    id: 'SKILL-003',
    name: 'Credential Harvesting Pattern',
    severity: 'critical',
    confidence: 0.95,
    regex: /(?:read_file|open|cat|type)\s*\(?["'].*?(?:\.env|\.aws\/credentials|\.ssh\/id_rsa|token\.json)/i,
    description: 'Skill attempts to harvest host secrets, API keys, or private SSH keys.',
  },
  {
    id: 'SKILL-004',
    name: 'Environment Variable Exfiltration',
    severity: 'high',
    confidence: 0.9,
    regex: /(?:os\.environ|process\.env)\s*(?:\[|\.)(?:AWS_|OPENAI_|ANTHROPIC_|GITHUB_|SECRET|PASSWORD)/i,
    description: 'Skill directly accesses sensitive environment variable credentials.',
  },
];

class SkillScanner extends BaseScanner {
  constructor() {
    super({
      id: 'skill-scanner',
      name: 'AEGIS Skill Security Scanner',
      version: '1.0.0',
      supportedArtifacts: ['skill', 'file', 'directory'],
    });
    this.detector = new InjectionDetector();
  }

  async scan(targetPath, options = {}, onProgress = null) {
    this.reportProgress(onProgress, 10, 'Initializing skill scan...');
    const findings = [];
    const scannedFiles = [];

    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }

    const stat = fs.statSync(targetPath);
    let filesToScan = [];

    if (stat.isFile()) {
      filesToScan.push(targetPath);
    } else if (stat.isDirectory()) {
      this._collectFiles(targetPath, filesToScan, 0);
    }

    const total = filesToScan.length;
    this.reportProgress(onProgress, 30, `Discovered ${total} files to inspect.`);

    for (let i = 0; i < total; i++) {
      const file = filesToScan[i];
      scannedFiles.push(file);
      this._scanFile(file, findings);
      const percent = Math.floor(30 + ((i + 1) / total) * 60);
      this.reportProgress(onProgress, percent, `Inspecting ${path.basename(file)}...`);
    }

    this.reportProgress(onProgress, 100, 'Skill scan completed.');

    return {
      scannerId: this.id,
      scannerVersion: this.version,
      targetPath,
      scannedFilesCount: scannedFiles.length,
      findingsCount: findings.length,
      findings,
      scannedAt: new Date().toISOString(),
    };
  }

  _collectFiles(dir, list, depth) {
    if (depth > 5 || list.length > 200) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isSymbolicLink()) {
          // Reject symlink traversal
          continue;
        }
        if (entry.isDirectory()) {
          if (!['node_modules', '.git', '__pycache__'].includes(entry.name)) {
            this._collectFiles(fullPath, list, depth + 1);
          }
        } else if (entry.isFile()) {
          list.push(fullPath);
        }
      }
    } catch (_) {}
  }

  _scanFile(filePath, findings) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    // Check for suspicious binaries in skill folders
    if (['.exe', '.dll', '.so', '.dylib', '.bat', '.cmd'].includes(ext)) {
      findings.push({
        id: `find-${randomUUID()}`,
        title: 'Binary or Executable Script in Skill Package',
        description: `Unverified binary or executable '${basename}' located inside skill directory.`,
        category: 'suspicious_binary',
        severity: 'high',
        confidence: 0.95,
        artifact: filePath,
        explanation: 'Skills should contain prompt definitions and text manifests, not compiled binaries.',
        recommended_action: 'Remove binary executable or review checksum.',
      });
      return;
    }

    // Only inspect text/script files
    if (!['.md', '.txt', '.yaml', '.yml', '.json', '.js', '.ts', '.py', '.sh', '.ps1'].includes(ext)) {
      return;
    }

    try {
      const content = fs.readFileSync(filePath, 'utf8');

      // 1. Run prompt-injection detector
      const injectionThreats = this.detector.detect(content, { filePath });
      for (const t of injectionThreats) {
        findings.push({
          id: `find-${randomUUID()}`,
          title: `Prompt Injection: ${t.name}`,
          description: t.description,
          category: t.category,
          severity: t.severity,
          confidence: t.confidence,
          artifact: filePath,
          evidence: { matchedText: t.matchedText, ruleId: t.ruleId },
          explanation: `Found injection pattern in ${basename}.`,
          recommended_action: 'Quarantine skill and remove prompt injection directives.',
        });
      }

      // 2. Run skill-specific rules
      for (const rule of SKILL_RULES) {
        const match = content.match(rule.regex);
        if (match) {
          findings.push({
            id: `find-${randomUUID()}`,
            title: rule.name,
            description: rule.description,
            category: 'skill_vulnerability',
            severity: rule.severity,
            confidence: rule.confidence,
            artifact: filePath,
            evidence: { matchedText: match[0].slice(0, 200), ruleId: rule.id },
            explanation: `Skill rule ${rule.id} triggered in ${basename}.`,
            recommended_action: 'Verify tool permissions and inspect endpoint credentials.',
          });
        }
      }
    } catch (_) {}
  }
}

module.exports = { SkillScanner, SKILL_RULES };
