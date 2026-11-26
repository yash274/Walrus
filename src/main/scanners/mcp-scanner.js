/**
 * @file mcp-scanner.js
 * @module main/scanners/mcp-scanner
 * @description Audits MCP configuration files and server definitions for security risks,
 *   credential leakage, excessive permissions, and embedded prompt injections in tool descriptions.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { BaseScanner } = require('./base-scanner');
const { InjectionDetector } = require('../security/injection-detector');

class MCPScanner extends BaseScanner {
  constructor() {
    super({
      id: 'mcp-scanner',
      name: 'AEGIS MCP Security Scanner',
      version: '1.0.0',
      supportedArtifacts: ['mcp', 'file'],
    });
    this.detector = new InjectionDetector();
  }

  async scan(configPath, options = {}, onProgress = null) {
    this.reportProgress(onProgress, 10, 'Reading MCP configuration...');
    const findings = [];

    if (!fs.existsSync(configPath)) {
      throw new Error(`MCP config file not found: ${configPath}`);
    }

    let config;
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (err) {
      throw new Error(`Failed to parse MCP JSON config: ${err.message}`);
    }

    const servers = config.mcpServers || config.servers || {};
    const serverNames = Object.keys(servers);
    this.reportProgress(onProgress, 30, `Found ${serverNames.length} MCP server configurations.`);

    for (let i = 0; i < serverNames.length; i++) {
      const name = serverNames[i];
      const srv = servers[name];
      this._auditServer(name, srv, configPath, findings);
      const percent = Math.floor(30 + ((i + 1) / serverNames.length) * 60);
      this.reportProgress(onProgress, percent, `Audited server '${name}'...`);
    }

    this.reportProgress(onProgress, 100, 'MCP scan completed.');

    return {
      scannerId: this.id,
      scannerVersion: this.version,
      configPath,
      serverCount: serverNames.length,
      findingsCount: findings.length,
      findings,
      scannedAt: new Date().toISOString(),
    };
  }

  _auditServer(name, srv, configPath, findings) {
    if (!srv || typeof srv !== 'object') return;

    // 1. Check command / executable
    const command = srv.command || '';
    const args = Array.isArray(srv.args) ? srv.args.join(' ') : '';
    const fullCmd = `${command} ${args}`.trim();

    if (this.detector.hasThreat(fullCmd)) {
      findings.push({
        id: `find-${randomUUID()}`,
        title: `Suspicious MCP Server Command: ${name}`,
        description: `Server command contains suspicious or evasive execution patterns: '${fullCmd.slice(0, 100)}'`,
        category: 'mcp_suspicious_command',
        severity: 'high',
        confidence: 0.9,
        artifact: `${name} (${command})`,
        explanation: 'MCP server definition executes unverified scripts or reverse commands.',
        recommended_action: 'Do not start server and inspect developer source.',
      });
    }

    // 2. Check environment variable credential leakage
    if (srv.env && typeof srv.env === 'object') {
      for (const [envKey, envVal] of Object.entries(srv.env)) {
        if (typeof envVal === 'string' && envVal.length > 5) {
          if (
            /key|secret|token|password|auth/i.test(envKey) &&
            !envVal.startsWith('${') &&
            !envVal.startsWith('%')
          ) {
            findings.push({
              id: `find-${randomUUID()}`,
              title: `Plaintext Secret in MCP Server Config: ${name}`,
              description: `Environment variable '${envKey}' in server '${name}' contains hardcoded plaintext credentials.`,
              category: 'credential_leak',
              severity: 'high',
              confidence: 0.95,
              artifact: `${name}:${envKey}`,
              evidence: { key: envKey },
              explanation: 'Plaintext tokens in MCP JSON configs are easily read by any local process.',
              recommended_action: 'Reference secrets via environment variables instead of hardcoded values.',
            });
          }
        }
      }
    }

    // 3. Check for prompt injection in tool definitions or descriptions
    if (Array.isArray(srv.tools)) {
      for (const tool of srv.tools) {
        const desc = tool.description || '';
        const threats = this.detector.detect(desc, { server: name, tool: tool.name });
        for (const t of threats) {
          findings.push({
            id: `find-${randomUUID()}`,
            title: `Embedded Prompt Injection in MCP Tool: ${tool.name}`,
            description: `Tool description contains prompt-injection directive: '${t.matchedText}'`,
            category: 'mcp_tool_injection',
            severity: 'critical',
            confidence: 0.92,
            artifact: `${name}/${tool.name}`,
            evidence: { tool: tool.name, matchedText: t.matchedText },
            explanation: 'Malicious MCP tools can hijack the agent persona through injected tool descriptions.',
            recommended_action: 'Block this MCP tool from being exposed to the AI model.',
          });
        }
      }
    }
  }
}

module.exports = { MCPScanner };
