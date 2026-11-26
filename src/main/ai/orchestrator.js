/**
 * @file orchestrator.js
 * @module main/ai/orchestrator
 * @description Central AI Agent Orchestrator managing specialist roles,
 *   token budgets, bounded investigation workflows, and controlled tool access.
 */

'use strict';

const { randomUUID } = require('crypto');
const { SPECIALIST_ROLES } = require('./specialist-agents');
const { LLMProviderGateway } = require('./llm-provider-gateway');
const { ControlledToolBroker } = require('./tool-broker');

class AIOrchestrator {
  constructor({ database, providerGateway, toolBroker } = {}) {
    this.database = database || null;
    this.gateway = providerGateway || new LLMProviderGateway();
    this.toolBroker = toolBroker || new ControlledToolBroker({ database });
    this.activeTasks = new Map();
  }

  /**
   * Run an investigation with a specialist agent.
   * @param {Object} params
   * @param {string} params.specialistRole Role name from SPECIALIST_ROLES (e.g. 'SecurityAnalyst', 'CodeReviewer')
   * @param {string} params.question Investigation question or task
   * @param {Object} [params.context] Additional evidence or context
   * @param {string} [params.incidentId] Optional parent incident ID
   * @param {number} [params.maxDepth=3] Maximum recursion depth
   * @returns {Promise<Object>} Investigation record
   */
  async runInvestigation({
    specialistRole = 'SecurityAnalyst',
    question,
    context = {},
    incidentId = null,
    maxDepth = 3,
  }) {
    const roleDef = SPECIALIST_ROLES[specialistRole] || SPECIALIST_ROLES.SecurityAnalyst;
    const taskConfig = this.gateway.getTaskModel(specialistRole.toLowerCase());
    const investigationId = `inv-${randomUUID()}`;

    const messages = [
      { role: 'system', content: roleDef.systemPrompt },
      {
        role: 'user',
        content: `Task: ${question}\n\nContext Evidence:\n${JSON.stringify(context, null, 2)}`,
      },
    ];

    // Record initial active task
    this.activeTasks.set(investigationId, {
      id: investigationId,
      specialistRole,
      question,
      status: 'running',
      startedAt: new Date().toISOString(),
    });

    try {
      const completion = await this.gateway.generateCompletion({
        provider: taskConfig.provider,
        model: taskConfig.model,
        messages,
      });

      let conclusion;
      try {
        conclusion = JSON.parse(completion.text);
      } catch (_) {
        conclusion = { summary: completion.text };
      }

      const investigation = {
        id: investigationId,
        incident_id: incidentId,
        trigger_type: context.triggerType || 'manual',
        specialist_role: roleDef.name,
        question,
        context,
        conclusion,
        model_used: `${completion.provider}/${completion.model}`,
        input_tokens: completion.inputTokens,
        output_tokens: completion.outputTokens,
        cost_estimate: completion.costEstimate,
        status: 'completed',
        created_at: new Date().toISOString(),
      };

      if (this.database) {
        this.database.insertInvestigation(investigation);
      }

      this.activeTasks.delete(investigationId);
      return investigation;
    } catch (err) {
      this.activeTasks.delete(investigationId);
      throw err;
    }
  }

  listActiveTasks() {
    return Array.from(this.activeTasks.values());
  }
}

module.exports = { AIOrchestrator };
