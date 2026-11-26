/**
 * @file database.js
 * @module main/db/database
 * @description Local-first relational persistence layer for AEGIS using SQLite WAL mode.
 *   Provides structured persistence for agents, sessions, events, findings, incidents,
 *   scans, code reviews, AI investigations, and policies.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

class DatabaseManager {
  /**
   * @param {string} [dbPath] Path to SQLite file, defaults to in-memory if undefined.
   */
  constructor(dbPath) {
    this.dbPath = dbPath || ':memory:';
    if (this.dbPath !== ':memory:') {
      const dir = path.dirname(this.dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
    this.db = new DatabaseSync(this.dbPath);
    this._initPragmas();
    this._runMigrations();
  }

  _initPragmas() {
    if (this.dbPath !== ':memory:') {
      this.db.exec('PRAGMA journal_mode = WAL;');
      this.db.exec('PRAGMA synchronous = NORMAL;');
    }
    this.db.exec('PRAGMA foreign_keys = ON;');
  }

  _runMigrations() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
      );
    `);

    const currentVersionRow = this.db.prepare('SELECT MAX(version) as max_v FROM schema_migrations').get();
    const currentVersion = currentVersionRow && currentVersionRow.max_v ? Number(currentVersionRow.max_v) : 0;

    const migrations = [
      {
        version: 1,
        sql: `
          CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            executable TEXT,
            process_id INTEGER,
            parent_pid INTEGER,
            version TEXT,
            workspace TEXT,
            status TEXT DEFAULT 'active',
            coverage TEXT DEFAULT 'METADATA_ONLY',
            connector_id TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
          );

          CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            workspace TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT DEFAULT 'active',
            metadata_json TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
          );

          CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            agent_id TEXT,
            session_id TEXT,
            workspace_id TEXT,
            pid INTEGER,
            parent_pid INTEGER,
            tool_name TEXT,
            tool_args_json TEXT,
            target_resource TEXT,
            event_source TEXT,
            trust_provenance TEXT DEFAULT 'unknown',
            monitoring_coverage TEXT DEFAULT 'METADATA_ONLY',
            risk_severity TEXT DEFAULT 'info',
            risk_score REAL DEFAULT 0.0,
            policy_decision TEXT DEFAULT 'observed',
            evidence_json TEXT
          );
          CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);
          CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events (agent_id);
          CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
          CREATE INDEX IF NOT EXISTS idx_events_risk_severity ON events (risk_severity);

          CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            detection_source TEXT NOT NULL,
            agent_id TEXT,
            workspace TEXT,
            artifact TEXT,
            related_event_ids_json TEXT,
            evidence_json TEXT,
            explanation TEXT,
            recommended_action TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT NOT NULL,
            resolved_at TEXT
          );
          CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
          CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);

          CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            agent_id TEXT,
            workspace TEXT,
            summary TEXT,
            primary_finding_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
          );

          CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            scanner_id TEXT NOT NULL,
            scanner_version TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_path TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            findings_count INTEGER DEFAULT 0,
            results_json TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT
          );

          CREATE TABLE IF NOT EXISTS code_reviews (
            id TEXT PRIMARY KEY,
            repository_path TEXT NOT NULL,
            git_branch TEXT,
            commit_hash TEXT,
            scope TEXT NOT NULL,
            summary TEXT,
            walkthrough_json TEXT,
            findings_json TEXT,
            suggested_fixes_json TEXT,
            status TEXT DEFAULT 'completed',
            created_at TEXT NOT NULL
          );

          CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            mode TEXT NOT NULL DEFAULT 'observe',
            target_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
          );

          CREATE TABLE IF NOT EXISTS ai_investigations (
            id TEXT PRIMARY KEY,
            incident_id TEXT,
            trigger_type TEXT NOT NULL,
            specialist_role TEXT NOT NULL,
            question TEXT NOT NULL,
            context_json TEXT,
            conclusion_json TEXT,
            model_used TEXT NOT NULL,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cost_estimate REAL DEFAULT 0.0,
            status TEXT DEFAULT 'completed',
            created_at TEXT NOT NULL
          );
        `,
      },
    ];

    for (const migration of migrations) {
      if (migration.version > currentVersion) {
        this.db.exec(migration.sql);
        const insert = this.db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)');
        insert.run(migration.version, new Date().toISOString());
      }
    }
  }

  // ─── AGENTS ───
  upsertAgent(agent) {
    const stmt = this.db.prepare(`
      INSERT INTO agents (id, name, executable, process_id, parent_pid, version, workspace, status, coverage, connector_id, first_seen, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        executable = excluded.executable,
        process_id = excluded.process_id,
        parent_pid = excluded.parent_pid,
        version = excluded.version,
        workspace = excluded.workspace,
        status = excluded.status,
        coverage = excluded.coverage,
        connector_id = excluded.connector_id,
        last_seen = excluded.last_seen;
    `);
    const now = new Date().toISOString();
    stmt.run(
      agent.id,
      agent.name,
      agent.executable || null,
      agent.process_id !== undefined ? agent.process_id : null,
      agent.parent_pid !== undefined ? agent.parent_pid : null,
      agent.version || null,
      agent.workspace || null,
      agent.status || 'active',
      agent.coverage || 'METADATA_ONLY',
      agent.connector_id || null,
      agent.first_seen || now,
      agent.last_seen || now
    );
    return this.getAgent(agent.id);
  }

  getAgent(id) {
    return this.db.prepare('SELECT * FROM agents WHERE id = ?').get(id);
  }

  listAgents(limit = 100) {
    return this.db.prepare('SELECT * FROM agents ORDER BY last_seen DESC LIMIT ?').all(limit);
  }

  // ─── SESSIONS ───
  createSession(session) {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, agent_id, workspace, started_at, status, metadata_json)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      session.id,
      session.agent_id,
      session.workspace || null,
      session.started_at || new Date().toISOString(),
      session.status || 'active',
      session.metadata ? JSON.stringify(session.metadata) : null
    );
    return this.getSession(session.id);
  }

  getSession(id) {
    const row = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      metadata: row.metadata_json ? JSON.parse(row.metadata_json) : null,
    };
  }

  // ─── EVENTS ───
  insertEvent(event) {
    const stmt = this.db.prepare(`
      INSERT INTO events (
        id, timestamp, event_type, agent_id, session_id, workspace_id,
        pid, parent_pid, tool_name, tool_args_json, target_resource,
        event_source, trust_provenance, monitoring_coverage,
        risk_severity, risk_score, policy_decision, evidence_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      event.id,
      event.timestamp || new Date().toISOString(),
      event.event_type,
      event.agent_id || null,
      event.session_id || null,
      event.workspace_id || null,
      event.pid || null,
      event.parent_pid || null,
      event.tool_name || null,
      event.tool_args ? JSON.stringify(event.tool_args) : null,
      event.target_resource || null,
      event.event_source || null,
      event.trust_provenance || 'unknown',
      event.monitoring_coverage || 'METADATA_ONLY',
      event.risk_severity || 'info',
      event.risk_score || 0.0,
      event.policy_decision || 'observed',
      event.evidence ? JSON.stringify(event.evidence) : null
    );
    return event;
  }

  listEvents({ limit = 100, offset = 0, agentId, severity, eventType } = {}) {
    let query = 'SELECT * FROM events WHERE 1=1';
    const params = [];
    if (agentId) {
      query += ' AND agent_id = ?';
      params.push(agentId);
    }
    if (severity) {
      query += ' AND risk_severity = ?';
      params.push(severity);
    }
    if (eventType) {
      query += ' AND event_type = ?';
      params.push(eventType);
    }
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = this.db.prepare(query).all(...params);
    return rows.map((r) => ({
      ...r,
      tool_args: r.tool_args_json ? JSON.parse(r.tool_args_json) : null,
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : null,
    }));
  }

  // ─── FINDINGS ───
  insertFinding(finding) {
    const stmt = this.db.prepare(`
      INSERT INTO findings (
        id, title, description, category, severity, confidence,
        detection_source, agent_id, workspace, artifact,
        related_event_ids_json, evidence_json, explanation,
        recommended_action, status, created_at, resolved_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      finding.id,
      finding.title,
      finding.description || null,
      finding.category,
      finding.severity,
      finding.confidence || 1.0,
      finding.detection_source,
      finding.agent_id || null,
      finding.workspace || null,
      finding.artifact || null,
      finding.related_event_ids ? JSON.stringify(finding.related_event_ids) : null,
      finding.evidence ? JSON.stringify(finding.evidence) : null,
      finding.explanation || null,
      finding.recommended_action || null,
      finding.status || 'open',
      finding.created_at || new Date().toISOString(),
      finding.resolved_at || null
    );
    return finding;
  }

  listFindings({ limit = 100, status, severity } = {}) {
    let query = 'SELECT * FROM findings WHERE 1=1';
    const params = [];
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const rows = this.db.prepare(query).all(...params);
    return rows.map((r) => ({
      ...r,
      related_event_ids: r.related_event_ids_json ? JSON.parse(r.related_event_ids_json) : [],
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : null,
    }));
  }

  updateFindingStatus(id, status) {
    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null;
    this.db.prepare('UPDATE findings SET status = ?, resolved_at = ? WHERE id = ?').run(status, resolvedAt, id);
    return this.db.prepare('SELECT * FROM findings WHERE id = ?').get(id);
  }

  // ─── INCIDENTS ───
  insertIncident(incident) {
    const stmt = this.db.prepare(`
      INSERT INTO incidents (id, title, severity, status, agent_id, workspace, summary, primary_finding_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const now = new Date().toISOString();
    stmt.run(
      incident.id,
      incident.title,
      incident.severity,
      incident.status || 'active',
      incident.agent_id || null,
      incident.workspace || null,
      incident.summary || null,
      incident.primary_finding_id || null,
      incident.created_at || now,
      incident.updated_at || now
    );
    return incident;
  }

  listIncidents(limit = 50) {
    return this.db.prepare('SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?').all(limit);
  }

  // ─── SCANS ───
  insertScan(scan) {
    const stmt = this.db.prepare(`
      INSERT INTO scans (id, scanner_id, scanner_version, target_type, target_path, status, findings_count, results_json, started_at, completed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        status = excluded.status,
        findings_count = excluded.findings_count,
        results_json = excluded.results_json,
        completed_at = excluded.completed_at;
    `);
    stmt.run(
      scan.id,
      scan.scanner_id,
      scan.scanner_version,
      scan.target_type,
      scan.target_path,
      scan.status || 'completed',
      scan.findings_count || 0,
      scan.results ? JSON.stringify(scan.results) : null,
      scan.started_at || new Date().toISOString(),
      scan.completed_at || new Date().toISOString()
    );
    return scan;
  }

  listScans(limit = 50) {
    const rows = this.db.prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT ?').all(limit);
    return rows.map((r) => ({
      ...r,
      results: r.results_json ? JSON.parse(r.results_json) : null,
    }));
  }

  // ─── CODE REVIEWS ───
  insertCodeReview(review) {
    const stmt = this.db.prepare(`
      INSERT INTO code_reviews (id, repository_path, git_branch, commit_hash, scope, summary, walkthrough_json, findings_json, suggested_fixes_json, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      review.id,
      review.repository_path,
      review.git_branch || null,
      review.commit_hash || null,
      review.scope || 'staged',
      review.summary || null,
      review.walkthrough ? JSON.stringify(review.walkthrough) : null,
      review.findings ? JSON.stringify(review.findings) : null,
      review.suggested_fixes ? JSON.stringify(review.suggested_fixes) : null,
      review.status || 'completed',
      review.created_at || new Date().toISOString()
    );
    return review;
  }

  getCodeReview(id) {
    const r = this.db.prepare('SELECT * FROM code_reviews WHERE id = ?').get(id);
    if (!r) return null;
    return {
      ...r,
      walkthrough: r.walkthrough_json ? JSON.parse(r.walkthrough_json) : [],
      findings: r.findings_json ? JSON.parse(r.findings_json) : [],
      suggested_fixes: r.suggested_fixes_json ? JSON.parse(r.suggested_fixes_json) : [],
    };
  }

  listCodeReviews(limit = 50) {
    const rows = this.db.prepare('SELECT * FROM code_reviews ORDER BY created_at DESC LIMIT ?').all(limit);
    return rows.map((r) => ({
      ...r,
      walkthrough: r.walkthrough_json ? JSON.parse(r.walkthrough_json) : [],
      findings: r.findings_json ? JSON.parse(r.findings_json) : [],
      suggested_fixes: r.suggested_fixes_json ? JSON.parse(r.suggested_fixes_json) : [],
    }));
  }

  // ─── POLICIES ───
  insertPolicy(policy) {
    const stmt = this.db.prepare(`
      INSERT INTO policies (id, name, description, mode, target_type, pattern, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        mode = excluded.mode,
        target_type = excluded.target_type,
        pattern = excluded.pattern,
        enabled = excluded.enabled;
    `);
    stmt.run(
      policy.id,
      policy.name,
      policy.description || null,
      policy.mode || 'observe',
      policy.target_type,
      policy.pattern,
      policy.enabled !== undefined ? (policy.enabled ? 1 : 0) : 1,
      policy.created_at || new Date().toISOString()
    );
    return policy;
  }

  listPolicies() {
    return this.db.prepare('SELECT * FROM policies ORDER BY created_at ASC').all();
  }

  // ─── AI INVESTIGATIONS ───
  insertInvestigation(inv) {
    const stmt = this.db.prepare(`
      INSERT INTO ai_investigations (
        id, incident_id, trigger_type, specialist_role, question,
        context_json, conclusion_json, model_used, input_tokens,
        output_tokens, cost_estimate, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      inv.id,
      inv.incident_id || null,
      inv.trigger_type,
      inv.specialist_role,
      inv.question,
      inv.context ? JSON.stringify(inv.context) : null,
      inv.conclusion ? JSON.stringify(inv.conclusion) : null,
      inv.model_used,
      inv.input_tokens || 0,
      inv.output_tokens || 0,
      inv.cost_estimate || 0.0,
      inv.status || 'completed',
      inv.created_at || new Date().toISOString()
    );
    return inv;
  }

  listInvestigations(limit = 50) {
    const rows = this.db.prepare('SELECT * FROM ai_investigations ORDER BY created_at DESC LIMIT ?').all(limit);
    return rows.map((r) => ({
      ...r,
      context: r.context_json ? JSON.parse(r.context_json) : null,
      conclusion: r.conclusion_json ? JSON.parse(r.conclusion_json) : null,
    }));
  }

  close() {
    this.db.close();
  }
}

let _defaultInstance = null;

function getDatabase(customPath) {
  if (customPath) {
    return new DatabaseManager(customPath);
  }
  if (!_defaultInstance) {
    const defaultPath = path.join(process.cwd(), 'data', 'aegis-platform.db');
    _defaultInstance = new DatabaseManager(defaultPath);
  }
  return _defaultInstance;
}

module.exports = {
  DatabaseManager,
  getDatabase,
};
