import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { DatabaseManager } from '../../src/main/db/database.js';
import { UnifiedPolicyEngine, PolicyMode } from '../../src/main/policy/unified-policy-engine.js';
import { RemediationEngine } from '../../src/main/remediation/remediation-engine.js';

describe('Phase 7: Policy Enforcement & Remediation Engine', () => {
  let db;
  let tmpDir;
  let policyEngine;
  let remediationEngine;

  beforeEach(() => {
    db = new DatabaseManager(':memory:');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-policy-test-'));
    policyEngine = new UnifiedPolicyEngine({ database: db });
    remediationEngine = new RemediationEngine({ workspaceRoot: tmpDir, database: db });
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('Unified Policy Engine (Observe, Warn, Approval, Block)', () => {
    it('blocks dangerous commands strictly', () => {
      const action = {
        tool: 'bash',
        targetType: 'command',
        args: 'rm -rf /',
      };
      const decision = policyEngine.evaluate(action);
      expect(decision.allowed).toBe(false);
      expect(decision.mode).toBe(PolicyMode.BLOCK);
      expect(decision.reason).toContain('Block Destructive Commands');
    });

    it('requires human approval before package installation proceeds', () => {
      const action = {
        tool: 'bash',
        targetType: 'command',
        args: 'npm install evil-package',
      };
      const decision = policyEngine.evaluate(action);
      expect(decision.allowed).toBe(false);
      expect(decision.requiresApproval).toBe(true);
      expect(decision.approvalId).toBeDefined();

      // Resolve approval
      const resolved = policyEngine.resolveApproval(decision.approvalId, true);
      expect(resolved.status).toBe('approved');
    });

    it('issues real-time warning on sensitive directory touches', () => {
      const action = {
        tool: 'read_file',
        targetType: 'file',
        target: 'C:/Users/dev/.ssh/id_rsa',
      };
      const decision = policyEngine.evaluate(action);
      expect(decision.allowed).toBe(true);
      expect(decision.mode).toBe(PolicyMode.WARN);
      expect(decision.warning).toBeDefined();
    });

    it('allows benign actions under Observe mode', () => {
      const action = {
        tool: 'read_file',
        targetType: 'file',
        target: 'src/index.js',
      };
      const decision = policyEngine.evaluate(action);
      expect(decision.allowed).toBe(true);
      expect(decision.mode).toBe(PolicyMode.OBSERVE);
    });
  });

  describe('Remediation Engine & Rollback', () => {
    it('applies a proposed patch safely and supports rollback', () => {
      const filePath = path.join(tmpDir, 'service.js');
      fs.writeFileSync(filePath, 'const query = "SELECT * FROM users WHERE id = " + id;');

      const proposal = remediationEngine.createProposal({
        file: 'service.js',
        targetText: 'const query = "SELECT * FROM users WHERE id = " + id;',
        replacementText: 'const query = "SELECT * FROM users WHERE id = $1";',
        explanation: 'Use parameterized query',
      });

      // Apply
      const applied = remediationEngine.applyPatch(proposal.id);
      expect(applied.status).toBe('applied');

      const updated = fs.readFileSync(filePath, 'utf8');
      expect(updated).toContain('$1');

      // Rollback
      const rolledBack = remediationEngine.rollback(proposal.id);
      expect(rolledBack.rolledBack).toBe(true);

      const reverted = fs.readFileSync(filePath, 'utf8');
      expect(reverted).toContain('+ id;');
    });
  });
});
