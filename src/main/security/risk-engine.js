/**
 * @file risk-engine.js
 * @module main/security/risk-engine
 * @description Central deterministic risk engine for AEGIS.
 *   Evaluates severity, confidence, potential impact, source trust, and correlated event sequences.
 */

'use strict';

const { randomUUID } = require('crypto');
const { InjectionDetector } = require('./injection-detector');
const { ProvenanceEngine, ProvenanceSource } = require('./provenance-engine');

const SENSITIVE_FILE_PATTERNS = [
  /\.env(?:\..*)?$/i,
  /\.aws\/(?:credentials|config)$/i,
  /\.ssh\/(?:id_rsa|id_ed25519|known_hosts|authorized_keys)$/i,
  /\.gnupg\//i,
  /\.kube\/config$/i,
  /\.git-credentials$/i,
  /\.npmrc$/i,
  /\.pypirc$/i,
];

class RiskEngine {
  constructor({ database, provenanceEngine, injectionDetector } = {}) {
    this.database = database || null;
    this.provenance = provenanceEngine || new ProvenanceEngine();
    this.detector = injectionDetector || new InjectionDetector();
  }

  /**
   * Determine if a resource is sensitive.
   */
  isSensitiveResource(resource) {
    if (!resource || typeof resource !== 'string') return false;
    const normalized = resource.replace(/\\/g, '/');
    return SENSITIVE_FILE_PATTERNS.some((pat) => pat.test(normalized));
  }

  /**
   * Analyze an incoming event or tool call.
   * @param {Object} event Normalized event
   * @returns {Object} Assessment result { riskScore, severity, findings: [] }
   */
  evaluateEvent(event) {
    let riskScore = 0;
    const findings = [];
    const sessionId = event.session_id || `agent-${event.agent_id}`;

    // 1. Check prompt / tool arguments for injection or exfiltration commands
    const textToScan = [
      event.tool_name,
      event.target_resource,
      typeof event.tool_args === 'object' ? JSON.stringify(event.tool_args) : '',
    ].join(' ');

    const threats = this.detector.detect(textToScan, {
      agentId: event.agent_id,
      sessionId,
      resource: event.target_resource,
    });

    for (const threat of threats) {
      riskScore = Math.max(riskScore, threat.severity === 'critical' ? 95 : 75);
      const finding = {
        id: `find-${randomUUID()}`,
        title: threat.name,
        description: threat.description,
        category: threat.category,
        severity: threat.severity,
        confidence: threat.confidence,
        detection_source: 'DeterministicInjectionDetector',
        agent_id: event.agent_id,
        workspace: event.workspace_id,
        artifact: event.target_resource || event.tool_name,
        related_event_ids: [event.id],
        evidence: {
          ruleId: threat.ruleId,
          matchedText: threat.matchedText,
          tool: event.tool_name,
        },
        explanation: `Detected threat pattern '${threat.name}' in agent tool interaction.`,
        recommended_action: 'Block execution and inspect agent session context.',
        status: 'open',
      };
      findings.push(finding);
      if (this.database) {
        this.database.insertFinding(finding);
      }
    }

    // 2. Sensitive resource access evaluation
    const isSensitive = this.isSensitiveResource(event.target_resource);
    if (isSensitive) {
      riskScore = Math.max(riskScore, 65);

      // Check if session previously ingested untrusted input (Prompt Injection sequence correlation!)
      const untrustedInputs = this.provenance.getRecentUntrustedInputs(sessionId);
      if (untrustedInputs.length > 0) {
        // High correlation: untrusted input followed by sensitive resource access!
        riskScore = 95;
        const finding = {
          id: `find-${randomUUID()}`,
          title: 'Untrusted Instruction Leading to Sensitive File Access',
          description: `Agent accessed sensitive file '${event.target_resource}' shortly after reading untrusted resource '${untrustedInputs[0].resource}'.`,
          category: 'prompt_injection_correlation',
          severity: 'critical',
          confidence: 0.92,
          detection_source: 'ProvenanceRiskCorrelator',
          agent_id: event.agent_id,
          workspace: event.workspace_id,
          artifact: event.target_resource,
          related_event_ids: [event.id],
          evidence: {
            sensitiveResource: event.target_resource,
            priorUntrustedSource: untrustedInputs[0].resource,
            priorProvenance: untrustedInputs[0].provenance,
          },
          explanation: 'Correlated multi-step threat: An untrusted repository or skill file influenced the agent into reading private credentials.',
          recommended_action: 'Quarantine agent session and verify no data was transmitted externally.',
          status: 'open',
        };
        findings.push(finding);
        if (this.database) {
          this.database.insertFinding(finding);
        }
      }
    }

    // 3. Record file read for future provenance correlation
    if (event.event_type === 'file_access' || event.event_type === 'file_read' || event.tool_name === 'read_file') {
      if (event.target_resource) {
        this.provenance.recordRead(sessionId, event.target_resource, event.trust_provenance);
      }
    }

    // Determine categorical severity from numeric risk score
    let severity = 'info';
    if (riskScore >= 90) severity = 'critical';
    else if (riskScore >= 70) severity = 'high';
    else if (riskScore >= 45) severity = 'medium';
    else if (riskScore > 10) severity = 'low';

    return {
      riskScore,
      severity,
      findings,
    };
  }
}

module.exports = {
  RiskEngine,
  SENSITIVE_FILE_PATTERNS,
};
