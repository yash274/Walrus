/**
 * @file incident-manager.js
 * @module main/security/incident-manager
 * @description Correlates findings into actionable Security Incidents.
 */

'use strict';

const { randomUUID } = require('crypto');

class IncidentManager {
  constructor({ database } = {}) {
    this.database = database || null;
  }

  /**
   * Process a finding and escalate to an incident if high or critical.
   */
  processFinding(finding) {
    if (!finding) return null;
    if (finding.severity !== 'high' && finding.severity !== 'critical') {
      return null;
    }

    const incident = {
      id: `inc-${randomUUID()}`,
      title: `Security Incident: ${finding.title}`,
      severity: finding.severity,
      status: 'active',
      agent_id: finding.agent_id || 'unknown',
      workspace: finding.workspace || null,
      summary: finding.description || finding.explanation,
      primary_finding_id: finding.id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    if (this.database) {
      this.database.insertIncident(incident);
    }
    return incident;
  }

  listActiveIncidents() {
    if (!this.database) return [];
    return this.database.listIncidents();
  }
}

module.exports = { IncidentManager };
