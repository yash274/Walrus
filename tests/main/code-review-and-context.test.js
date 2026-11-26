import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { DatabaseManager } from '../../src/main/db/database.js';
import { GitDiffEngine } from '../../src/main/code-intel/git-diff-engine.js';
import { ContextEngine } from '../../src/main/code-intel/context-engine.js';
import { BlastRadiusAnalyzer } from '../../src/main/code-intel/blast-radius.js';
import { CodeReviewer } from '../../src/main/code-intel/code-reviewer.js';

describe('Phase 6: CodeRabbit-Style Engineering Intelligence & Context Engine', () => {
  let db;
  let tmpDir;
  let reviewer;

  beforeEach(() => {
    db = new DatabaseManager(':memory:');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-code-intel-'));
    reviewer = new CodeReviewer({ repoRoot: tmpDir, database: db });
  });

  afterEach(() => {
    db.close();
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  describe('Git Diff Parser', () => {
    it('parses unified diff text into structured files, hunks, and line numbers', () => {
      const sampleDiff = `diff --git a/src/auth.js b/src/auth.js
index 123456..789abc 100644
--- a/src/auth.js
+++ b/src/auth.js
@@ -10,3 +10,4 @@ function login(user) {
   const query = "SELECT * FROM users WHERE id = " + user.id;
   return db.execute(query);
+  console.log("Logged in user: " + user.name);
 }
`;
      const diffEngine = new GitDiffEngine();
      const files = diffEngine.parseDiff(sampleDiff);

      expect(files.length).toBe(1);
      expect(files[0].file).toBe('src/auth.js');
      expect(files[0].additions).toBe(1);
      expect(files[0].hunks.length).toBe(1);
      expect(files[0].hunks[0].lines.length).toBe(4);
      expect(files[0].hunks[0].lines[2].type).toBe('add');
      expect(files[0].hunks[0].lines[2].line).toBe(12);
    });
  });

  describe('Context Engine & Blast Radius', () => {
    it('indexes imports and computes blast radius across dependent files', () => {
      // Create mock module hierarchy
      const srcDir = path.join(tmpDir, 'src');
      const testDir = path.join(tmpDir, 'tests');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.mkdirSync(testDir, { recursive: true });

      // Core service
      fs.writeFileSync(path.join(srcDir, 'auth-service.js'), 'export function verify() {}');

      // Consumer module
      fs.writeFileSync(
        path.join(srcDir, 'api-handler.js'),
        'const { verify } = require("./auth-service");\nexport function handle() { verify(); }'
      );

      // Test file
      fs.writeFileSync(
        path.join(testDir, 'auth.test.js'),
        'const { verify } = require("../src/auth-service");'
      );

      const context = new ContextEngine(tmpDir);
      const stats = context.indexProject();
      expect(stats.totalFiles).toBeGreaterThanOrEqual(3);

      const blast = new BlastRadiusAnalyzer(context);
      const impact = blast.analyze(['src/auth-service.js']);

      expect(impact.directCallersCount).toBeGreaterThanOrEqual(1);
      expect(impact.affectedTestsCount).toBeGreaterThanOrEqual(1);
      expect(impact.affectedTests.some((t) => t.includes('auth.test.js'))).toBe(true);
    });
  });

  describe('Code Review Workflow', () => {
    it('identifies security vulnerabilities, produces line-level findings and saves review', async () => {
      const mockDiff = `diff --git a/src/db.js b/src/db.js
--- a/src/db.js
+++ b/src/db.js
@@ -5,3 +5,4 @@
+  const sql = "SELECT * FROM users WHERE name = " + req.query.name;
+  eval("var a = 1;");
+  try { run(); } catch (err) {}
+  console.log("query executed");
`;
      const report = await reviewer.review({ scope: 'staged', rawDiff: mockDiff });

      expect(report.id).toBeDefined();
      expect(report.findings.length).toBe(4);

      // Verify specific line findings
      const sqli = report.findings.find((f) => f.title === 'Potential SQL Injection');
      expect(sqli).toBeDefined();
      expect(sqli.severity).toBe('critical');
      expect(sqli.line).toBe(5);

      const evalIssue = report.findings.find((f) => f.title === 'Unsafe Dynamic Code Execution');
      expect(evalIssue).toBeDefined();
      expect(evalIssue.severity).toBe('critical');

      const catchIssue = report.findings.find((f) => f.title === 'Empty Catch Block');
      expect(catchIssue).toBeDefined();
      expect(catchIssue.severity).toBe('medium');

      // Verify DB persistence
      const savedReview = db.getCodeReview(report.id);
      expect(savedReview).toBeDefined();
      expect(savedReview.findings.length).toBe(4);
      expect(savedReview.walkthrough.length).toBe(1);
    });
  });
});
