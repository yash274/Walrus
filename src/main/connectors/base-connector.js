/**
 * @file base-connector.js
 * @module main/connectors/base-connector
 * @description Base class and interface for universal AI agent connectors.
 */

'use strict';

const EventEmitter = require('events');

/**
 * Monitoring coverage classification levels
 */
const CoverageLevel = Object.freeze({
  FULL: 'FULL',
  PARTIAL: 'PARTIAL',
  METADATA_ONLY: 'METADATA_ONLY',
  UNSUPPORTED: 'UNSUPPORTED',
});

class BaseAgentConnector extends EventEmitter {
  /**
   * @param {Object} options
   * @param {string} options.id Connector identifier (e.g. 'codex', 'cursor', 'claude-code')
   * @param {string} options.name Display name
   * @param {string} options.coverage Default coverage classification
   * @param {string[]} options.executableNames Executable names associated with this agent
   */
  constructor({ id, name, coverage = CoverageLevel.METADATA_ONLY, executableNames = [] }) {
    super();
    this.id = id;
    this.name = name;
    this.coverage = coverage;
    this.executableNames = executableNames.map((e) => e.toLowerCase());
    this.activeSessions = new Map();
    this.enabled = true;
  }

  /**
   * Check if a given process or metadata matches this connector.
   * @param {Object} proc Process info { pid, name, exe, cmdline }
   * @returns {boolean}
   */
  matchesProcess(proc) {
    if (!proc || !proc.name) return false;
    const nameLower = proc.name.toLowerCase();
    const exeLower = (proc.exe || '').toLowerCase();
    return this.executableNames.some((target) => nameLower.includes(target) || exeLower.includes(target));
  }

  /**
   * Return the coverage level for a specific instance.
   */
  getCoverage(proc) {
    return this.coverage;
  }

  /**
   * Extract or generate workspace path if observable.
   */
  extractWorkspace(proc) {
    return proc.cwd || null;
  }

  /**
   * Called when a matching process is detected.
   */
  onProcessStarted(proc) {
    const session = {
      sessionId: `sess-${this.id}-${proc.pid}-${Date.now()}`,
      agentId: this.id,
      name: this.name,
      pid: proc.pid,
      parentPid: proc.parentPid || proc.ppid || null,
      executable: proc.exe || proc.name,
      workspace: this.extractWorkspace(proc),
      coverage: this.getCoverage(proc),
      startedAt: new Date().toISOString(),
      status: 'active',
    };
    this.activeSessions.set(proc.pid, session);
    this.emit('agent:started', session);
    return session;
  }

  /**
   * Called when a matching process exits.
   */
  onProcessExited(pid) {
    const session = this.activeSessions.get(pid);
    if (session) {
      session.status = 'terminated';
      session.endedAt = new Date().toISOString();
      this.activeSessions.delete(pid);
      this.emit('agent:terminated', session);
      return session;
    }
    return null;
  }

  /**
   * Emit an observed tool or interaction event.
   */
  emitEvent(eventData) {
    const event = {
      agent_id: this.id,
      monitoring_coverage: this.coverage,
      timestamp: new Date().toISOString(),
      ...eventData,
    };
    this.emit('agent:event', event);
    return event;
  }

  /**
   * Lifecycle cleanup.
   */
  destroy() {
    this.activeSessions.clear();
    this.removeAllListeners();
  }
}

module.exports = {
  BaseAgentConnector,
  CoverageLevel,
};
