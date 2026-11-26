import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DatabaseManager } from '../../src/main/db/database.js';
import { EventNormalizer, redactSecrets } from '../../src/main/events/event-normalizer.js';

describe('Phase 1: Database & Event Normalization', () => {
  let db;
  let normalizer;

  beforeEach(() => {
    db = new DatabaseManager(':memory:');
    normalizer = new EventNormalizer();
  });

  afterEach(() => {
    db.close();
  });

  describe('Database Operations', () => {
    it('creates tables and schema migrations cleanly', () => {
      const migrations = db.db.prepare('SELECT * FROM schema_migrations').all();
      expect(migrations.length).toBeGreaterThan(0);
      expect(migrations[0].version).toBe(1);
    });

    it('upserts and retrieves agent records', () => {
      const agent = db.upsertAgent({
        id: 'agent-codex-1',
        name: 'OpenAI Codex',
        executable: 'codex.exe',
        process_id: 1234,
        coverage: 'FULL',
        workspace: '/projects/walrus',
      });
      expect(agent.name).toBe('OpenAI Codex');
      expect(agent.process_id).toBe(1234);
      expect(agent.coverage).toBe('FULL');

      const listed = db.listAgents();
      expect(listed.length).toBe(1);
      expect(listed[0].id).toBe('agent-codex-1');
    });

    it('inserts and filters events with json attributes', () => {
      const event = {
        id: 'evt-1',
        timestamp: new Date().toISOString(),
        event_type: 'tool_call',
        agent_id: 'agent-codex-1',
        tool_name: 'bash',
        tool_args: { command: 'cat .env' },
        risk_severity: 'high',
        risk_score: 85.5,
        trust_provenance: 'repo_doc',
      };
      db.insertEvent(event);

      const events = db.listEvents({ severity: 'high' });
      expect(events.length).toBe(1);
      expect(events[0].tool_name).toBe('bash');
      expect(events[0].tool_args.command).toBe('cat .env');
      expect(events[0].risk_score).toBe(85.5);
    });

    it('stores and updates findings and status', () => {
      db.insertFinding({
        id: 'find-1',
        title: 'Prompt Injection in README',
        category: 'prompt_injection',
        severity: 'critical',
        confidence: 0.95,
        detection_source: 'SkillScanner',
        status: 'open',
      });

      const findings = db.listFindings({ severity: 'critical' });
      expect(findings.length).toBe(1);
      expect(findings[0].title).toBe('Prompt Injection in README');

      db.updateFindingStatus('find-1', 'resolved');
      const resolved = db.listFindings({ status: 'resolved' });
      expect(resolved.length).toBe(1);
      expect(resolved[0].resolved_at).not.toBeNull();
    });

    it('stores and retrieves code review reports', () => {
      db.insertCodeReview({
        id: 'rev-1',
        repository_path: '/projects/walrus',
        git_branch: 'feature/security-layer',
        scope: 'staged',
        summary: 'Added database persistence and normalized event engine',
        walkthrough: [{ file: 'src/main/db/database.js', change: 'SQLite WAL store' }],
        findings: [{ severity: 'low', message: 'Consider adding index for session_id' }],
        suggested_fixes: [{ file: 'src/main/db/database.js', patch: '...' }],
      });

      const review = db.getCodeReview('rev-1');
      expect(review).toBeDefined();
      expect(review.summary).toContain('persistence');
      expect(review.walkthrough.length).toBe(1);
      expect(review.findings[0].severity).toBe('low');
    });
  });

  describe('Event Normalizer & Redaction', () => {
    it('normalizes raw events into versioned schema', () => {
      const raw = {
        type: 'file_read',
        agentId: 'claude-code-1',
        resource: 'D:/secrets/.env',
        provenance: 'repo_doc',
        severity: 'high',
        risk_score: 90,
      };
      const normalized = normalizer.normalize(raw);
      expect(normalized.schemaVersion).toBe('2.0.0');
      expect(normalized.event_type).toBe('file_read');
      expect(normalized.agent_id).toBe('claude-code-1');
      expect(normalized.target_resource).toBe('D:/secrets/.env');
      expect(normalized.trust_provenance).toBe('repo_doc');
      expect(normalized.risk_severity).toBe('high');
      expect(normalized.risk_score).toBe(90);
    });

    it('redacts API keys and secrets in tool arguments', () => {
      const secretArgs = {
        apiKey: 'sk-ant-123456789012345678901234567890123456789012',
        ghToken: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
        headers: {
          Authorization: 'Bearer my-secret-jwt-token-string',
        },
        regularParam: 'plain-text-query',
      };
      const sanitized = redactSecrets(secretArgs);
      expect(sanitized.apiKey).toBe('[REDACTED]');
      expect(sanitized.ghToken).toBe('ghp_[REDACTED]');
      expect(sanitized.headers.Authorization).toBe('Bearer [REDACTED]');
      expect(sanitized.regularParam).toBe('plain-text-query');
    });

    it('deduplicates identical burst events', () => {
      const event1 = {
        type: 'file_read',
        agentId: 'agent-1',
        resource: 'config.json',
        timestamp: '2026-11-25T12:00:00.000Z',
      };
      const event2 = {
        type: 'file_read',
        agentId: 'agent-1',
        resource: 'config.json',
        timestamp: '2026-11-25T12:00:00.100Z',
      };
      const res1 = normalizer.normalize(event1);
      const res2 = normalizer.normalize(event2);
      expect(res1).not.toBeNull();
      expect(res2).toBeNull(); // Deduplicated!
    });
  });
});
