/**
 * @file cursor-connector.js
 * @module main/connectors/cursor-connector
 * @description Connector for Cursor IDE and Cursor Agent processes.
 */

'use strict';

const { BaseAgentConnector, CoverageLevel } = require('./base-connector');

class CursorConnector extends BaseAgentConnector {
  constructor() {
    super({
      id: 'cursor',
      name: 'Cursor',
      coverage: CoverageLevel.PARTIAL,
      executableNames: ['cursor', 'cursor.exe', 'cursor-agent'],
    });
  }

  getCoverage(proc) {
    if (proc && proc.cmdline && proc.cmdline.includes('--type=renderer')) {
      return CoverageLevel.METADATA_ONLY;
    }
    return CoverageLevel.PARTIAL;
  }

  extractWorkspace(proc) {
    if (proc && proc.cmdline) {
      const match = proc.cmdline.match(/(?:--folder-uri|--file-uri)\s+([^\s]+)/i);
      if (match && match[1]) return decodeURIComponent(match[1]);
    }
    return super.extractWorkspace(proc);
  }

  captureToolCall({ pid, toolName, args, resource, provenance = 'direct_user' }) {
    return this.emitEvent({
      event_type: 'tool_call',
      pid,
      tool_name: toolName,
      tool_args: args,
      target_resource: resource,
      trust_provenance: provenance,
      event_source: 'cursor-agent-bridge',
    });
  }
}

module.exports = { CursorConnector };
