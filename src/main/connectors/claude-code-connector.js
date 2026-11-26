/**
 * @file claude-code-connector.js
 * @module main/connectors/claude-code-connector
 * @description Connector for Anthropic Claude Code CLI.
 */

'use strict';

const { BaseAgentConnector, CoverageLevel } = require('./base-connector');

class ClaudeCodeConnector extends BaseAgentConnector {
  constructor() {
    super({
      id: 'claude-code',
      name: 'Claude Code',
      coverage: CoverageLevel.FULL,
      executableNames: ['claude', 'claude.exe', 'claude-code'],
    });
  }

  matchesProcess(proc) {
    if (super.matchesProcess(proc)) return true;
    if (proc && proc.cmdline && proc.cmdline.includes('@anthropic-ai/claude-code')) {
      return true;
    }
    return false;
  }

  captureToolCall({ pid, toolName, args, resource, provenance = 'direct_user' }) {
    return this.emitEvent({
      event_type: 'tool_call',
      pid,
      tool_name: toolName,
      tool_args: args,
      target_resource: resource,
      trust_provenance: provenance,
      event_source: 'claude-guard',
    });
  }

  captureToolResult({ pid, toolName, result, error = null }) {
    return this.emitEvent({
      event_type: error ? 'tool_failure' : 'tool_result',
      pid,
      tool_name: toolName,
      tool_args: { result: typeof result === 'string' ? result.slice(0, 4000) : result, error },
      event_source: 'claude-guard',
    });
  }

  capturePrompt({ pid, promptText, provenance = 'direct_user' }) {
    return this.emitEvent({
      event_type: 'prompt',
      pid,
      tool_name: 'prompt_admission',
      tool_args: { prompt: promptText },
      trust_provenance: provenance,
      event_source: 'claude-guard',
    });
  }
}

module.exports = { ClaudeCodeConnector };
