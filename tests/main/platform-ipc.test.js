import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { DatabaseManager } from '../../src/main/db/database.js';
import { initPlatformServices, registerPlatformIpc } from '../../src/main/platform-ipc.js';

describe('Phase 8: Platform IPC & End-to-End Subsystem Integration', () => {
  let tmpDir;
  let services;
  let db;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-e2e-test-'));
    db = new DatabaseManager(':memory:');
    services = initPlatformServices(tmpDir, db);
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('initializes all platform services in a coherent unified system', () => {
    expect(services.db).toBeDefined();
    expect(services.connectors).toBeDefined();
    expect(services.scanners).toBeDefined();
    expect(services.orchestrator).toBeDefined();
    expect(services.codeReviewer).toBeDefined();
    expect(services.policyEngine).toBeDefined();
    expect(services.remediation).toBeDefined();
  });

  it('registers all IPC channels on mock IPC target and serves requests', async () => {
    const handlers = new Map();
    const mockIpc = {
      handle: (channel, fn) => handlers.set(channel, fn),
    };

    registerPlatformIpc(services, mockIpc);

    expect(handlers.has('platform:overview')).toBe(true);
    expect(handlers.has('code-review:run')).toBe(true);
    expect(handlers.has('scanner:execute')).toBe(true);
    expect(handlers.has('ai:investigate')).toBe(true);
    expect(handlers.has('policies:list')).toBe(true);
    expect(handlers.has('remediation:propose')).toBe(true);

    // Call platform:overview handler
    const overview = await handlers.get('platform:overview')();
    expect(overview).toBeDefined();
    expect(overview.connectors.length).toBeGreaterThanOrEqual(4);
  });

  it('runs complete lifecycle: scan -> finding -> policy evaluation -> code review -> fix', async () => {
    // 1. Create a project file with an issue
    const srcFile = path.join(tmpDir, 'auth.js');
    fs.writeFileSync(srcFile, 'const sql = "SELECT * FROM users WHERE token = " + token;\neval("unsafe();");');

    // 2. Code Review identifies the vulnerabilities
    const review = await services.codeReviewer.review({
      scope: 'staged',
      rawDiff: `diff --git a/auth.js b/auth.js
--- a/auth.js
+++ b/auth.js
@@ -1,2 +1,2 @@
+const sql = "SELECT * FROM users WHERE token = " + token;
+eval("unsafe();");
`,
    });

    expect(review.findings.length).toBe(2);
    expect(review.findings.some((f) => f.title === 'Potential SQL Injection')).toBe(true);

    // 3. Propose Remediation
    const fixProposal = services.remediation.createProposal({
      file: 'auth.js',
      targetText: 'const sql = "SELECT * FROM users WHERE token = " + token;',
      replacementText: 'const sql = "SELECT * FROM users WHERE token = $1";',
      explanation: 'Use parameterized SQL query',
    });
    expect(fixProposal.status).toBe('pending_approval');

    // 4. Policy evaluation for applying patch
    const policyDecision = services.policyEngine.evaluate({
      tool: 'remediation',
      targetType: 'file',
      target: 'auth.js',
    });
    expect(policyDecision.allowed).toBe(true);

    // 5. Apply Remediation patch
    const applied = services.remediation.applyPatch(fixProposal.id);
    expect(applied.status).toBe('applied');

    const patchedContent = fs.readFileSync(srcFile, 'utf8');
    expect(patchedContent).toContain('$1');

    // 6. Rollback Remediation
    const rolledBack = services.remediation.rollback(fixProposal.id);
    expect(rolledBack.rolledBack).toBe(true);

    const revertedContent = fs.readFileSync(srcFile, 'utf8');
    expect(revertedContent).toContain('+ token;');
  });
});
