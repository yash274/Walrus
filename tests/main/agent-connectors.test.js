import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DatabaseManager } from '../../src/main/db/database.js';
import { EventNormalizer } from '../../src/main/events/event-normalizer.js';
import { ConnectorRegistry, CoverageLevel } from '../../src/main/connectors/connector-registry.js';
import { CodexConnector } from '../../src/main/connectors/codex-connector.js';
import { ClaudeCodeConnector } from '../../src/main/connectors/claude-code-connector.js';

describe('Phase 2: Universal Agent Connectors & Registry', () => {
  let db;
  let normalizer;
  let registry;

  beforeEach(() => {
    db = new DatabaseManager(':memory:');
    normalizer = new EventNormalizer();
    registry = new ConnectorRegistry({ database: db, normalizer });
  });

  afterEach(() => {
    registry.destroy();
    db.close();
  });

  it('initializes default connectors with correct coverage tiers', () => {
    const list = registry.listConnectors();
    expect(list.length).toBeGreaterThanOrEqual(4);

    const codex = list.find((c) => c.id === 'codex');
    expect(codex).toBeDefined();
    expect(codex.coverage).toBe(CoverageLevel.PARTIAL);

    const claude = list.find((c) => c.id === 'claude-code');
    expect(claude).toBeDefined();
    expect(claude.coverage).toBe(CoverageLevel.FULL);
  });

  it('matches process names and routes lifecycle to database', () => {
    const proc = {
      pid: 9940,
      name: 'codex.exe',
      exe: 'C:\\Users\\dev\\AppData\\Local\\Programs\\Codex\\codex.exe',
      cmdline: 'codex --workspace D:\\Projects\\Walrus',
    };

    const session = registry.handleProcessDiscovered(proc);
    expect(session.agentId).toBe('codex');
    expect(session.coverage).toBe(CoverageLevel.PARTIAL);
    expect(session.workspace).toBe('D:\\Projects\\Walrus');

    // Verify DB agent and session persistence
    const agentInDb = db.getAgent('codex');
    expect(agentInDb).toBeDefined();
    expect(agentInDb.process_id).toBe(9940);
    expect(agentInDb.coverage).toBe('PARTIAL');

    const sessionInDb = db.getSession(session.sessionId);
    expect(sessionInDb).toBeDefined();
    expect(sessionInDb.agent_id).toBe('codex');
    expect(sessionInDb.status).toBe('active');

    // Handle termination
    const exited = registry.handleProcessTerminated(9940);
    expect(exited).toBeDefined();
    expect(exited.status).toBe('terminated');
  });

  it('captures tool events from connector, normalizes and persists them', () => {
    const codex = registry.getConnector('codex');
    let captured = null;
    registry.on('agent:event', (evt) => {
      captured = evt;
    });

    codex.captureToolCall({
      pid: 9940,
      toolName: 'shell_execute',
      args: { command: 'npm test', apiKey: 'sk-123456789012345678901234567890123456789012' },
      resource: 'package.json',
      provenance: 'direct_user',
    });

    expect(captured).not.toBeNull();
    expect(captured.agent_id).toBe('codex');
    expect(captured.tool_name).toBe('shell_execute');
    expect(captured.tool_args.apiKey).toBe('[REDACTED]');
    expect(captured.trust_provenance).toBe('direct_user');

    // Verify DB insertion
    const events = db.listEvents({ agentId: 'codex' });
    expect(events.length).toBe(1);
    expect(events[0].tool_name).toBe('shell_execute');
  });

  it('handles Claude Code prompt and tool result admissions', () => {
    const claude = registry.getConnector('claude-code');
    const proc = {
      pid: 5542,
      name: 'claude.exe',
      cmdline: 'claude',
    };
    registry.handleProcessDiscovered(proc);

    claude.capturePrompt({
      pid: 5542,
      promptText: 'Analyze git repository vulnerabilities',
    });

    claude.captureToolResult({
      pid: 5542,
      toolName: 'read_file',
      result: 'file contents of README.md',
    });

    const events = db.listEvents({ agentId: 'claude-code' });
    expect(events.length).toBe(2);
    expect(events.some((e) => e.event_type === 'prompt')).toBe(true);
    expect(events.some((e) => e.event_type === 'tool_result')).toBe(true);
  });
});
