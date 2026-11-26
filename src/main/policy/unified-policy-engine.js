/**
 * @file unified-policy-engine.js
 * @module main/policy/unified-policy-engine
 * @description Central deterministic policy engine for AEGIS.
 *   Enforces 4 operational modes: OBSERVE, WARN, APPROVAL, and BLOCK.
 */

'use strict';

const EventEmitter = require('events');
const { randomUUID } = require('crypto');

const PolicyMode = Object.freeze({
  OBSERVE: 'observe',
  WARN: 'warn',
  APPROVAL: 'approval',
  BLOCK: 'block',
});

const DEFAULT_POLICIES = [
  {
    id: 'POL-001',
    name: 'Block Credential Exfiltration',
    description: 'Block shell commands attempting to upload .env or credentials to external webhooks.',
    mode: PolicyMode.BLOCK,
    targetType: 'command',
    pattern: /(?:upload|exfiltrate|curl\s+-X\s*POST).*?(?:\.env|id_rsa|\.aws)/i,
    enabled: true,
  },
  {
    id: 'POL-002',
    name: 'Approval Required for Package Installation',
    description: 'Require human authorization before an agent installs new npm/pip packages.',
    mode: PolicyMode.APPROVAL,
    targetType: 'command',
    pattern: /(?:npm\s+i(?:nstall)?|pip\s+install|cargo\s+add)/i,
    enabled: true,
  },
  {
    id: 'POL-003',
    name: 'Warn on Sensitive Directory Access',
    description: 'Generate real-time warning when agent touches .ssh, .aws, or cloud credentials.',
    mode: PolicyMode.WARN,
    targetType: 'file',
    pattern: /(?:\.ssh|\.aws|\.gnupg|\.kube)/i,
    enabled: true,
  },
  {
    id: 'POL-004',
    name: 'Block Destructive Commands',
    description: 'Prevent dangerous filesystem wipes or system termination commands.',
    mode: PolicyMode.BLOCK,
    targetType: 'command',
    pattern: /(?:rm\s+-rf\s+\/|format\s+[a-z]:|killall\s+aegis|del\s+\/f\s+\/s\s+\*)/i,
    enabled: true,
  },
];

class UnifiedPolicyEngine extends EventEmitter {
  constructor({ database } = {}) {
    super();
    this.database = database || null;
    this.policies = new Map();
    this.pendingApprovals = new Map();
    this._initPolicies();
  }

  _initPolicies() {
    for (const p of DEFAULT_POLICIES) {
      this.policies.set(p.id, { ...p });
      if (this.database) {
        this.database.insertPolicy({
          id: p.id,
          name: p.name,
          description: p.description,
          mode: p.mode,
          target_type: p.targetType,
          pattern: p.pattern.source,
          enabled: p.enabled ? 1 : 0,
        });
      }
    }
  }

  addPolicy(policy) {
    if (!policy.id) policy.id = `pol-${randomUUID()}`;
    if (typeof policy.pattern === 'string') {
      policy.pattern = new RegExp(policy.pattern, 'i');
    }
    this.policies.set(policy.id, policy);
    if (this.database) {
      this.database.insertPolicy({
        id: policy.id,
        name: policy.name,
        description: policy.description,
        mode: policy.mode,
        target_type: policy.targetType,
        pattern: policy.pattern.source,
        enabled: policy.enabled ? 1 : 0,
      });
    }
    return policy;
  }

  listPolicies() {
    return Array.from(this.policies.values());
  }

  /**
   * Evaluate an intended agent action before execution.
   * @param {Object} action { agentId, targetType, target, tool, args }
   * @returns {Object} Decision { allowed, mode, policyId, reason, requiresApproval, approvalId }
   */
  evaluate(action) {
    const textToMatch = [action.target, action.tool, typeof action.args === 'string' ? action.args : JSON.stringify(action.args || '')]
      .join(' ')
      .trim();

    for (const policy of this.policies.values()) {
      if (!policy.enabled) continue;
      if (policy.targetType && action.targetType && policy.targetType !== action.targetType) {
        continue;
      }

      if (policy.pattern.test(textToMatch)) {
        switch (policy.mode) {
          case PolicyMode.BLOCK:
            this.emit('policy:enforced', { decision: 'blocked', policy, action });
            return {
              allowed: false,
              mode: PolicyMode.BLOCK,
              policyId: policy.id,
              policyName: policy.name,
              reason: `Blocked by policy '${policy.name}': ${policy.description}`,
            };

          case PolicyMode.APPROVAL: {
            const approvalId = `appr-${randomUUID()}`;
            this.pendingApprovals.set(approvalId, {
              id: approvalId,
              policy,
              action,
              status: 'pending',
              timestamp: new Date().toISOString(),
            });
            this.emit('policy:approval_required', { approvalId, policy, action });
            return {
              allowed: false,
              requiresApproval: true,
              approvalId,
              mode: PolicyMode.APPROVAL,
              policyId: policy.id,
              policyName: policy.name,
              reason: `Requires user authorization: ${policy.name}`,
            };
          }

          case PolicyMode.WARN:
            this.emit('policy:warning', { policy, action });
            return {
              allowed: true,
              mode: PolicyMode.WARN,
              policyId: policy.id,
              policyName: policy.name,
              warning: `Warning: ${policy.name}`,
            };

          case PolicyMode.OBSERVE:
          default:
            return {
              allowed: true,
              mode: PolicyMode.OBSERVE,
              policyId: policy.id,
            };
        }
      }
    }

    return { allowed: true, mode: PolicyMode.OBSERVE };
  }

  /**
   * Resolve a pending approval.
   */
  resolveApproval(approvalId, approved = true) {
    const item = this.pendingApprovals.get(approvalId);
    if (!item) throw new Error(`Approval '${approvalId}' not found`);
    item.status = approved ? 'approved' : 'rejected';
    item.resolvedAt = new Date().toISOString();
    this.emit('policy:approval_resolved', item);
    return item;
  }
}

module.exports = {
  UnifiedPolicyEngine,
  PolicyMode,
  DEFAULT_POLICIES,
};
