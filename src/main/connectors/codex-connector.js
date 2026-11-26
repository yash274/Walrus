/**
 * @file codex-connector.js
 * @module main/connectors/codex-connector
 * @description Connector for OpenAI Codex CLI and desktop tools.
 */

'use strict';

const { BaseAgentConnector, CoverageLevel } = require('./base-connector');

class CodexConnector extends BaseAgentConnector {
  constructor() {
    super({
      id: 'codex',
      name: 'OpenAI Codex',
      coverage: CoverageLevel.PARTIAL,
      executableNames: ['codex', 'codex.exe', 'openai-codex'],
    });
  }

  getCoverage(proc) {
    if (proc && proc.hasHookBridge) {
      return CoverageLevel.FULL;
    }
    return CoverageLevel.PARTIAL;
  }

  extractWorkspace(proc) {
    if (proc && proc.cmdline) {
      const match = proc.cmdline.match(/(?:--cwd|--workspace|-w)\s+([^\s]+)/i);
      if (match && match[1]) return match[1];
    }
    return super.extractWorkspace(proc);
  }

  /**
   * Handle captured tool invocation from Codex hook or CLI wrapper.
   */
  captureToolCall({ pid, toolName, args, resource, provenance = 'direct_user' }) {
    return this.emitEvent({
      event_type: 'tool_call',
      pid,
      tool_name: toolName,
      tool_args: args,
      target_resource: resource,
      trust_provenance: provenance,
      event_source: 'codex-hook',
    });
  }

  /**
   * Handle prompt submission to Codex.
   */
  capturePrompt({ pid, promptText, provenance = 'direct_user' }) {
    return this.emitEvent({
      event_type: 'prompt',
      pid,
      tool_name: 'user_prompt',
      tool_args: { prompt: promptText },
      trust_provenance: provenance,
      event_source: 'codex-input',
    });
  }
}

module.exports = { CodexConnector };
