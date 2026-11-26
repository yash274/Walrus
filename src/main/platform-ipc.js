/**
 * @file platform-ipc.js
 * @module main/platform-ipc
 * @description Registers IPC endpoints for the AI Agent Security, Intelligence & Engineering Control Platform.
 */

'use strict';

const { getDatabase } = require('./db/database');
const { EventNormalizer } = require('./events/event-normalizer');
const { ConnectorRegistry } = require('./connectors/connector-registry');
const { ProvenanceEngine } = require('./security/provenance-engine');
const { InjectionDetector } = require('./security/injection-detector');
const { RiskEngine } = require('./security/risk-engine');
const { IncidentManager } = require('./security/incident-manager');
const { ScannerRegistry } = require('./scanners/scanner-registry');
const { LLMProviderGateway } = require('./ai/llm-provider-gateway');
const { ControlledToolBroker } = require('./ai/tool-broker');
const { AIOrchestrator } = require('./ai/orchestrator');
const { CodeReviewer } = require('./code-intel/code-reviewer');
const { UnifiedPolicyEngine } = require('./policy/unified-policy-engine');
const { RemediationEngine } = require('./remediation/remediation-engine');

let electronIpcMain = null;
try {
  // Only access ipcMain if already in Electron runtime, avoiding fallback downloader
  if (process.versions && process.versions.electron) {
    electronIpcMain = require('electron').ipcMain;
  }
} catch (_) {}

let _initialized = false;
let _services = null;

function initPlatformServices(customWorkspace = null, customDb = null) {
  if (_services && !customWorkspace && !customDb) return _services;

  const db = customDb || getDatabase();
  const normalizer = new EventNormalizer();
  const connectors = new ConnectorRegistry({ database: db, normalizer });
  const provenance = new ProvenanceEngine();
  const detector = new InjectionDetector();
  const riskEngine = new RiskEngine({ database: db, provenanceEngine: provenance, injectionDetector: detector });
  const incidentManager = new IncidentManager({ database: db });
  const scanners = new ScannerRegistry({ database: db });
  const providerGateway = new LLMProviderGateway();
  const toolBroker = new ControlledToolBroker({ workspaceRoot: customWorkspace || process.cwd(), database: db });
  const orchestrator = new AIOrchestrator({ database: db, providerGateway, toolBroker });
  const codeReviewer = new CodeReviewer({ repoRoot: customWorkspace || process.cwd(), database: db, orchestrator });
  const policyEngine = new UnifiedPolicyEngine({ database: db });
  const remediation = new RemediationEngine({
    workspaceRoot: customWorkspace || process.cwd(),
    database: db,
    reviewer: codeReviewer,
  });

  const createdServices = {
    db,
    normalizer,
    connectors,
    provenance,
    detector,
    riskEngine,
    incidentManager,
    scanners,
    providerGateway,
    toolBroker,
    orchestrator,
    codeReviewer,
    policyEngine,
    remediation,
  };

  if (!customWorkspace && !customDb) {
    _services = createdServices;
  }
  return createdServices;
}

function registerPlatformIpc(services, customIpc = null) {
  const targetIpc = customIpc || electronIpcMain;
  if (!targetIpc || typeof targetIpc.handle !== 'function') return;
  if (_initialized && !customIpc) return;
  if (!customIpc) _initialized = true;

  const {
    db,
    connectors,
    incidentManager,
    scanners,
    orchestrator,
    codeReviewer,
    policyEngine,
    remediation,
  } = services;

  // 1. Overview & Stats
  targetIpc.handle('platform:overview', async () => {
    const agents = db.listAgents(50);
    const events = db.listEvents({ limit: 10 });
    const findings = db.listFindings({ limit: 10, status: 'open' });
    const incidents = db.listIncidents(10);
    const reviews = db.listCodeReviews(5);
    const scans = db.listScans(5);
    return {
      agentsCount: agents.length,
      activeAgents: agents.filter((a) => a.status === 'active'),
      recentEvents: events,
      openFindings: findings,
      incidents,
      recentReviews: reviews,
      recentScans: scans,
      connectors: connectors.listConnectors(),
    };
  });

  // 2. Connectors
  targetIpc.handle('connectors:list', async () => {
    return connectors.listConnectors();
  });

  // 3. Scanners
  targetIpc.handle('scanner:list', async () => {
    return scanners.listScanners();
  });

  targetIpc.handle('scanner:execute', async (_event, scannerId, targetPath, options) => {
    return scanners.executeScan(scannerId, targetPath, options);
  });

  targetIpc.handle('scanner:history', async (_event, limit) => {
    return db.listScans(limit || 50);
  });

  // 4. Code Intelligence & Review
  targetIpc.handle('code-review:run', async (_event, options) => {
    return codeReviewer.review(options || {});
  });

  targetIpc.handle('code-review:list', async (_event, limit) => {
    return db.listCodeReviews(limit || 50);
  });

  targetIpc.handle('code-review:get', async (_event, id) => {
    return db.getCodeReview(id);
  });

  // 5. AI Reasoning & Investigations
  targetIpc.handle('ai:investigate', async (_event, params) => {
    return orchestrator.runInvestigation(params);
  });

  targetIpc.handle('ai:investigations-list', async (_event, limit) => {
    return db.listInvestigations(limit || 50);
  });

  // 6. Incidents & Findings
  targetIpc.handle('incidents:list', async () => {
    return incidentManager.listActiveIncidents();
  });

  targetIpc.handle('findings:list', async (_event, filters) => {
    return db.listFindings(filters || {});
  });

  targetIpc.handle('findings:update-status', async (_event, findingId, status) => {
    return db.updateFindingStatus(findingId, status);
  });

  // 7. Policies
  targetIpc.handle('policies:list', async () => {
    return policyEngine.listPolicies();
  });

  targetIpc.handle('policies:add', async (_event, policy) => {
    return policyEngine.addPolicy(policy);
  });

  targetIpc.handle('policies:resolve-approval', async (_event, approvalId, approved) => {
    return policyEngine.resolveApproval(approvalId, approved);
  });

  // 8. Remediation
  targetIpc.handle('remediation:propose', async (_event, params) => {
    return remediation.createProposal(params);
  });

  targetIpc.handle('remediation:apply', async (_event, proposalId) => {
    return remediation.applyPatch(proposalId);
  });

  targetIpc.handle('remediation:rollback', async (_event, proposalId) => {
    return remediation.rollback(proposalId);
  });
}

module.exports = {
  initPlatformServices,
  registerPlatformIpc,
};
