/**
 * @file mcp-connector.js
 * @module main/connectors/mcp-connector
 * @description Connector for Model Context Protocol (MCP) clients and servers.
 */

'use strict';

const { BaseAgentConnector, CoverageLevel } = require('./base-connector');

class MCPConnector extends BaseAgentConnector {
  constructor() {
    super({
      id: 'mcp-agent',
      name: 'MCP Agent / Gateway',
      coverage: CoverageLevel.FULL,
      executableNames: ['mcp', 'mcp-server', 'npx @modelcontextprotocol'],
    });
  }

  captureToolCall({ pid, serverName, toolName, args, provenance = 'mcp_response' }) {
    return this.emitEvent({
      event_type: 'mcp_call',
      pid,
      tool_name: `${serverName || 'mcp'}/${toolName}`,
      tool_args: args,
      trust_provenance: provenance,
      event_source: 'mcp-gateway',
    });
  }

  capturePolicyDecision({ pid, toolName, decision, reason }) {
    return this.emitEvent({
      event_type: 'policy_decision',
      pid,
      tool_name: toolName,
      policy_decision: decision,
      evidence: { reason },
      event_source: 'mcp-gateway-policy',
    });
  }
}

module.exports = { MCPConnector };
