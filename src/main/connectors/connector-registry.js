/**
 * @file connector-registry.js
 * @module main/connectors/connector-registry
 * @description Central registry for AI agent connectors.
 *   Dispatches process and telemetry events, manages coverage classifications,
 *   and pipes normalized events into database and security pipelines.
 */

'use strict';

const EventEmitter = require('events');
const { CodexConnector } = require('./codex-connector');
const { CursorConnector } = require('./cursor-connector');
const { ClaudeCodeConnector } = require('./claude-code-connector');
const { MCPConnector } = require('./mcp-connector');
const { CoverageLevel } = require('./base-connector');

class ConnectorRegistry extends EventEmitter {
  constructor({ database, normalizer } = {}) {
    super();
    this.database = database || null;
    this.normalizer = normalizer || null;
    this.connectors = new Map();
    this._initDefaultConnectors();
  }

  _initDefaultConnectors() {
    this.registerConnector(new CodexConnector());
    this.registerConnector(new CursorConnector());
    this.registerConnector(new ClaudeCodeConnector());
    this.registerConnector(new MCPConnector());
  }

  registerConnector(connector) {
    if (!connector || !connector.id) {
      throw new Error('Invalid connector: must have an id');
    }
    this.connectors.set(connector.id, connector);

    // Forward events
    connector.on('agent:started', (session) => {
      if (this.database) {
        this.database.upsertAgent({
          id: session.agentId,
          name: session.name,
          executable: session.executable,
          process_id: session.pid,
          parent_pid: session.parentPid,
          workspace: session.workspace,
          coverage: session.coverage,
          connector_id: connector.id,
          status: 'active',
        });
        this.database.createSession({
          id: session.sessionId,
          agent_id: session.agentId,
          workspace: session.workspace,
          started_at: session.startedAt,
          status: 'active',
        });
      }
      this.emit('agent:started', session);
    });

    connector.on('agent:terminated', (session) => {
      if (this.database) {
        this.database.upsertAgent({
          id: session.agentId,
          name: session.name,
          process_id: session.pid,
          status: 'inactive',
        });
      }
      this.emit('agent:terminated', session);
    });

    connector.on('agent:event', (rawEvent) => {
      let event = rawEvent;
      if (this.normalizer) {
        event = this.normalizer.normalize(rawEvent);
      }
      if (event) {
        if (this.database) {
          this.database.insertEvent(event);
        }
        this.emit('agent:event', event);
      }
    });

    return connector;
  }

  getConnector(id) {
    return this.connectors.get(id) || null;
  }

  listConnectors() {
    return Array.from(this.connectors.values()).map((c) => ({
      id: c.id,
      name: c.name,
      coverage: c.coverage,
      executableNames: c.executableNames,
      activeSessionCount: c.activeSessions.size,
    }));
  }

  /**
   * Match an OS process to an appropriate connector.
   * If none matches, returns a fallback metadata-only representation.
   */
  findConnectorForProcess(proc) {
    for (const connector of this.connectors.values()) {
      if (connector.matchesProcess(proc)) {
        return connector;
      }
    }
    return null;
  }

  /**
   * Called by process scanner when a process starts or is discovered.
   */
  handleProcessDiscovered(proc) {
    const connector = this.findConnectorForProcess(proc);
    if (connector) {
      return connector.onProcessStarted(proc);
    }
    // Unknown or generic agent process
    const fallbackSession = {
      sessionId: `sess-generic-${proc.pid}-${Date.now()}`,
      agentId: proc.name || 'generic-agent',
      name: proc.name || 'Generic Agent',
      pid: proc.pid,
      parentPid: proc.parentPid || null,
      executable: proc.exe || proc.name,
      workspace: proc.cwd || null,
      coverage: CoverageLevel.METADATA_ONLY,
      startedAt: new Date().toISOString(),
      status: 'active',
    };
    if (this.database) {
      this.database.upsertAgent({
        id: fallbackSession.agentId,
        name: fallbackSession.name,
        executable: fallbackSession.executable,
        process_id: fallbackSession.pid,
        coverage: CoverageLevel.METADATA_ONLY,
        status: 'active',
      });
    }
    this.emit('agent:started', fallbackSession);
    return fallbackSession;
  }

  /**
   * Called by process scanner when a process terminates.
   */
  handleProcessTerminated(pid) {
    for (const connector of this.connectors.values()) {
      const session = connector.onProcessExited(pid);
      if (session) return session;
    }
    return null;
  }

  destroy() {
    for (const connector of this.connectors.values()) {
      connector.destroy();
    }
    this.connectors.clear();
    this.removeAllListeners();
  }
}

module.exports = {
  ConnectorRegistry,
  CoverageLevel,
};
