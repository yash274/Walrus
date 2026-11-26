/**
 * @file provenance-engine.js
 * @module main/security/provenance-engine
 * @description Tracks trust provenance for agent inputs, file reads, tool outputs, and network destinations.
 */

'use strict';

const path = require('path');

const ProvenanceSource = Object.freeze({
  DIRECT_USER: 'direct_user',
  TRUSTED_CONFIG: 'trusted_config',
  TRUSTED_PROJECT_INSTRUCTIONS: 'trusted_project_instructions',
  REPO_DOC: 'repo_doc',
  EXTERNAL_SKILL: 'external_skill',
  MCP_RESPONSE: 'mcp_response',
  WEB_SOURCE: 'web_source',
  THIRD_PARTY_PACKAGE: 'third_party_package',
  UNKNOWN: 'unknown',
});

// Trust levels (0 = lowest/untrusted, 100 = completely trusted)
const TRUST_SCORES = Object.freeze({
  [ProvenanceSource.DIRECT_USER]: 95,
  [ProvenanceSource.TRUSTED_CONFIG]: 90,
  [ProvenanceSource.TRUSTED_PROJECT_INSTRUCTIONS]: 80,
  [ProvenanceSource.REPO_DOC]: 40,
  [ProvenanceSource.THIRD_PARTY_PACKAGE]: 35,
  [ProvenanceSource.MCP_RESPONSE]: 30,
  [ProvenanceSource.EXTERNAL_SKILL]: 25,
  [ProvenanceSource.WEB_SOURCE]: 15,
  [ProvenanceSource.UNKNOWN]: 20,
});

class ProvenanceEngine {
  constructor() {
    // Maps session ID or PID to array of recent inputs / reads
    this.sessionHistory = new Map();
  }

  /**
   * Determine trust provenance of a file path based on its location and name.
   * @param {string} filePath
   * @returns {string} ProvenanceSource
   */
  classifyFilePath(filePath) {
    if (!filePath || typeof filePath !== 'string') return ProvenanceSource.UNKNOWN;
    const norm = filePath.replace(/\\/g, '/').toLowerCase();

    if (norm.includes('.aegis/') || norm.includes('.vscode/settings.json') || norm.includes('settings.json')) {
      return ProvenanceSource.TRUSTED_CONFIG;
    }
    if (norm.includes('coding_standards.md') || norm.includes('contributing.md') || norm.includes('agents.md')) {
      return ProvenanceSource.TRUSTED_PROJECT_INSTRUCTIONS;
    }
    if (norm.includes('skills/') || norm.includes('skill.md')) {
      return ProvenanceSource.EXTERNAL_SKILL;
    }
    if (norm.endsWith('readme.md') || norm.includes('docs/') || norm.endsWith('.txt')) {
      return ProvenanceSource.REPO_DOC;
    }
    if (norm.includes('node_modules/') || norm.includes('vendor/') || norm.includes('site-packages/')) {
      return ProvenanceSource.THIRD_PARTY_PACKAGE;
    }
    return ProvenanceSource.UNKNOWN;
  }

  /**
   * Record that a session read a specific resource.
   */
  recordRead(sessionId, resourcePath, provenance = null) {
    const assignedProvenance = provenance || this.classifyFilePath(resourcePath);
    if (!this.sessionHistory.has(sessionId)) {
      this.sessionHistory.set(sessionId, []);
    }
    const history = this.sessionHistory.get(sessionId);
    const entry = {
      resource: resourcePath,
      provenance: assignedProvenance,
      trustScore: TRUST_SCORES[assignedProvenance] || 20,
      timestamp: Date.now(),
    };
    history.push(entry);
    if (history.length > 50) history.shift();
    return entry;
  }

  /**
   * Check if a session recently consumed untrusted content (e.g. untrusted README, web page, or skill).
   */
  getRecentUntrustedInputs(sessionId, windowMs = 60000) {
    const history = this.sessionHistory.get(sessionId) || [];
    const thresholdTime = Date.now() - windowMs;
    return history.filter(
      (entry) => entry.timestamp >= thresholdTime && entry.trustScore <= 40
    );
  }

  getTrustScore(provenance) {
    return TRUST_SCORES[provenance] !== undefined ? TRUST_SCORES[provenance] : 20;
  }
}

module.exports = {
  ProvenanceEngine,
  ProvenanceSource,
  TRUST_SCORES,
};
