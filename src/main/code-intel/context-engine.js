/**
 * @file context-engine.js
 * @module main/code-intel/context-engine
 * @description Context Engine analyzing project architecture, module imports,
 *   entry points, and coding conventions.
 */

'use strict';

const fs = require('fs');
const path = require('path');

class ContextEngine {
  constructor(projectRoot) {
    this.projectRoot = projectRoot || process.cwd();
    this.fileImports = new Map(); // file -> [importedFiles]
    this.reverseImports = new Map(); // file -> [importers]
    this.entryPoints = [];
    this.isIndexed = false;
  }

  /**
   * Build the project dependency map.
   */
  indexProject() {
    this.fileImports.clear();
    this.reverseImports.clear();
    this.entryPoints = [];

    const files = [];
    this._scanFiles(this.projectRoot, files, 0);

    for (const file of files) {
      const relPath = path.relative(this.projectRoot, file).replace(/\\/g, '/');
      const ext = path.extname(file).toLowerCase();

      if (['.js', '.ts', '.mjs', '.svelte'].includes(ext)) {
        this._extractJsImports(file, relPath);
      } else if (ext === '.py') {
        this._extractPythonImports(file, relPath);
      }

      if (
        relPath === 'package.json' ||
        relPath.includes('main.js') ||
        relPath.includes('entry.ts') ||
        relPath.includes('index.js')
      ) {
        this.entryPoints.push(relPath);
      }
    }

    this.isIndexed = true;
    return {
      totalFiles: files.length,
      entryPoints: this.entryPoints,
      modulesCount: this.fileImports.size,
    };
  }

  _scanFiles(dir, list, depth) {
    if (depth > 6 || list.length > 500) return;
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'].includes(entry.name)) {
            this._scanFiles(fullPath, list, depth + 1);
          }
        } else if (entry.isFile()) {
          list.push(fullPath);
        }
      }
    } catch (_) {}
  }

  _extractJsImports(fullPath, relPath) {
    try {
      const content = fs.readFileSync(fullPath, 'utf8');
      const imported = new Set();

      // Match require('./...') or from './...'
      const requireRegex = /(?:require\s*\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"])/g;
      let match;
      while ((match = requireRegex.exec(content)) !== null) {
        const importTarget = match[1] || match[2];
        if (importTarget && importTarget.startsWith('.')) {
          const resolved = path
            .normalize(path.join(path.dirname(relPath), importTarget))
            .replace(/\\/g, '/');
          imported.add(resolved);
        }
      }

      this.fileImports.set(relPath, Array.from(imported));
      for (const dep of imported) {
        if (!this.reverseImports.has(dep)) this.reverseImports.set(dep, []);
        this.reverseImports.get(dep).push(relPath);
      }
    } catch (_) {}
  }

  _extractPythonImports(fullPath, relPath) {
    try {
      const content = fs.readFileSync(fullPath, 'utf8');
      const imported = new Set();
      const pyRegex = /(?:from\s+([a-zA-Z0-9_\.]+)\s+import|import\s+([a-zA-Z0-9_\.]+))/g;
      let match;
      while ((match = pyRegex.exec(content)) !== null) {
        const mod = match[1] || match[2];
        if (mod && mod.startsWith('.')) {
          imported.add(mod);
        }
      }
      this.fileImports.set(relPath, Array.from(imported));
    } catch (_) {}
  }

  /**
   * Return callers / dependent files that import the target file.
   */
  getImporters(filePath) {
    const norm = filePath.replace(/\\/g, '/').replace(/\.[^/.]+$/, '');
    const results = new Set();
    for (const [dep, callers] of this.reverseImports.entries()) {
      if (dep.includes(norm) || norm.includes(dep)) {
        for (const c of callers) results.add(c);
      }
    }
    return Array.from(results);
  }
}

module.exports = { ContextEngine };
