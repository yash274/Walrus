/**
 * @file event-normalizer.js
 * @module main/events/event-normalizer
 * @description Event normalization, deduplication, and credential redaction engine.
 *   Produces standardized, schema-versioned telemetry events.
 */

'use strict';

const { randomUUID } = require('crypto');

const SCHEMA_VERSION = '2.0.0';

const VALID_EVENT_TYPES = new Set([
  'prompt',
  'response',
  'tool_call',
  'tool_result',
  'tool_failure',
  'tool_denial',
  'file_access',
  'file_read',
  'file_write',
  'file_delete',
  'net_access',
  'process_exec',
  'mcp_call',
  'policy_decision',
]);

const VALID_PROVENANCE = new Set([
  'direct_user',
  'trusted_config',
  'repo_doc',
  'external_skill',
  'mcp_response',
  'web_source',
  'third_party_package',
  'unknown',
]);

const VALID_COVERAGE = new Set(['FULL', 'PARTIAL', 'METADATA_ONLY', 'UNSUPPORTED']);

const VALID_SEVERITY = new Set(['info', 'low', 'medium', 'high', 'critical']);

// Patterns for sensitive keys/credentials to redact
const SENSITIVE_KEY_PATTERNS = [
  /api[_-]?key/i,
  /auth[_-]?token/i,
  /secret/i,
  /password/i,
  /bearer\s+[a-z0-9_.\-]+/i,
  /ghp_[a-zA-Z0-9]{36}/,
  /sk-ant-[a-zA-Z0-9_\-]{40,}/,
  /sk-[a-zA-Z0-9]{48}/,
  /xox[baprs]-[0-9a-zA-Z]{10,}/,
];

/**
 * Recursively sanitize objects or strings to redact secrets.
 */
function redactSecrets(obj, depth = 0) {
  if (depth > 6 || obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    let result = obj;
    // Redact recognized token signatures
    result = result.replace(/ghp_[a-zA-Z0-9]{36}/g, 'ghp_[REDACTED]');
    result = result.replace(/sk-ant-[a-zA-Z0-9_\-]{40,}/g, 'sk-ant-[REDACTED]');
    result = result.replace(/sk-[a-zA-Z0-9]{48}/g, 'sk-[REDACTED]');
    result = result.replace(/Bearer\s+[A-Za-z0-9_.\-]+/gi, 'Bearer [REDACTED]');
    return result;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => redactSecrets(item, depth + 1));
  }
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((pat) => pat.test(key));
      if (isSensitiveKey) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = redactSecrets(value, depth + 1);
      }
    }
    return sanitized;
  }
  return obj;
}

class EventNormalizer {
  constructor(options = {}) {
    this.maxDedupeSize = options.maxDedupeSize || 10000;
    this.seenEventHashes = new Set();
    this.dedupeQueue = [];
  }

  /**
   * Generates a deterministic signature hash for deduplication.
   */
  _computeEventHash(raw) {
    const timestamp = raw.timestamp ? Math.floor(new Date(raw.timestamp).getTime() / 1000) : 0;
    const parts = [
      raw.agent_id || raw.agentId || '',
      raw.event_type || raw.type || '',
      raw.tool_name || raw.toolName || '',
      raw.target_resource || raw.resource || '',
      raw.pid || '',
      timestamp,
    ];
    return parts.join('|');
  }

  _trackDedupe(hash) {
    if (this.seenEventHashes.has(hash)) return true;
    this.seenEventHashes.add(hash);
    this.dedupeQueue.push(hash);
    if (this.dedupeQueue.length > this.maxDedupeSize) {
      const oldest = this.dedupeQueue.shift();
      this.seenEventHashes.delete(oldest);
    }
    return false;
  }

  /**
   * Normalize an incoming event.
   * @param {Object} raw Raw event payload from connectors, sensors, or monitors.
   * @returns {Object|null} Normalized event object, or null if duplicate.
   */
  normalize(raw) {
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid raw event: must be an object');
    }

    const hash = this._computeEventHash(raw);
    if (raw.deduplicate !== false && this._trackDedupe(hash)) {
      return null; // Duplicate discarded
    }

    const eventType = raw.event_type || raw.type || 'tool_call';
    const validEventType = VALID_EVENT_TYPES.has(eventType) ? eventType : 'tool_call';

    const provenance = raw.trust_provenance || raw.provenance || 'unknown';
    const validProvenance = VALID_PROVENANCE.has(provenance) ? provenance : 'unknown';

    const coverage = raw.monitoring_coverage || raw.coverage || 'METADATA_ONLY';
    const validCoverage = VALID_COVERAGE.has(coverage) ? coverage : 'METADATA_ONLY';

    const severity = raw.risk_severity || raw.severity || 'info';
    const validSeverity = VALID_SEVERITY.has(severity) ? severity : 'info';

    const toolArgs = raw.tool_args || raw.toolArgs || null;
    const sanitizedArgs = toolArgs ? redactSecrets(toolArgs) : null;

    let timestamp;
    try {
      timestamp = raw.timestamp ? new Date(raw.timestamp).toISOString() : new Date().toISOString();
    } catch {
      timestamp = new Date().toISOString();
    }

    return {
      schemaVersion: SCHEMA_VERSION,
      id: raw.id || randomUUID(),
      timestamp,
      event_type: validEventType,
      agent_id: raw.agent_id || raw.agentId || 'agent-unknown',
      session_id: raw.session_id || raw.sessionId || null,
      workspace_id: raw.workspace_id || raw.workspaceId || raw.workspace || null,
      pid: Number.isSafeInteger(raw.pid) ? raw.pid : null,
      parent_pid: Number.isSafeInteger(raw.parent_pid || raw.parentPid) ? raw.parent_pid || raw.parentPid : null,
      tool_name: raw.tool_name || raw.toolName || null,
      tool_args: sanitizedArgs,
      target_resource: raw.target_resource || raw.resource || null,
      event_source: raw.event_source || raw.source || 'aegis-monitor',
      trust_provenance: validProvenance,
      monitoring_coverage: validCoverage,
      risk_severity: validSeverity,
      risk_score: typeof raw.risk_score === 'number' ? Math.max(0, Math.min(100, raw.risk_score)) : 0,
      policy_decision: raw.policy_decision || raw.policyDecision || 'observed',
      evidence: raw.evidence || null,
    };
  }
}

module.exports = {
  EventNormalizer,
  SCHEMA_VERSION,
  VALID_EVENT_TYPES,
  VALID_PROVENANCE,
  VALID_COVERAGE,
  VALID_SEVERITY,
  redactSecrets,
};
