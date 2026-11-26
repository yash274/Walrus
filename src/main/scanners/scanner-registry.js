/**
 * @file scanner-registry.js
 * @module main/scanners/scanner-registry
 * @description Central registry and runner for all AEGIS security scanners.
 */

'use strict';

const EventEmitter = require('events');
const { randomUUID } = require('crypto');
const { SkillScanner } = require('./skill-scanner');
const { RepositoryScanner } = require('./repository-scanner');
const { DependencyScanner } = require('./dependency-scanner');
const { MCPScanner } = require('./mcp-scanner');

class ScannerRegistry extends EventEmitter {
  constructor({ database } = {}) {
    super();
    this.database = database || null;
    this.scanners = new Map();
    this._initDefaultScanners();
  }

  _initDefaultScanners() {
    this.registerScanner(new SkillScanner());
    this.registerScanner(new RepositoryScanner());
    this.registerScanner(new DependencyScanner());
    this.registerScanner(new MCPScanner());
  }

  registerScanner(scanner) {
    if (!scanner || !scanner.id) {
      throw new Error('Invalid scanner');
    }
    this.scanners.set(scanner.id, scanner);
    return scanner;
  }

  getScanner(id) {
    return this.scanners.get(id) || null;
  }

  listScanners() {
    return Array.from(this.scanners.values()).map((s) => ({
      id: s.id,
      name: s.name,
      version: s.version,
      supportedArtifacts: s.supportedArtifacts,
    }));
  }

  /**
   * Execute a scan using a registered scanner.
   */
  async executeScan(scannerId, targetPath, options = {}, onProgress = null) {
    const scanner = this.getScanner(scannerId);
    if (!scanner) {
      throw new Error(`Scanner '${scannerId}' is not registered.`);
    }

    const scanId = `scan-${randomUUID()}`;
    const startedAt = new Date().toISOString();

    if (this.database) {
      this.database.insertScan({
        id: scanId,
        scanner_id: scanner.id,
        scanner_version: scanner.version,
        target_type: scanner.supportedArtifacts[0] || 'artifact',
        target_path: targetPath,
        status: 'running',
        findings_count: 0,
        started_at: startedAt,
      });
    }

    try {
      const result = await scanner.scan(targetPath, options, onProgress);
      result.id = scanId;

      if (this.database) {
        // Save individual findings
        for (const finding of result.findings || []) {
          this.database.insertFinding({
            ...finding,
            detection_source: scanner.name,
            workspace: targetPath,
          });
        }

        // Update scan record
        this.database.insertScan({
          id: scanId,
          scanner_id: scanner.id,
          scanner_version: scanner.version,
          target_type: scanner.supportedArtifacts[0] || 'artifact',
          target_path: targetPath,
          status: 'completed',
          findings_count: result.findingsCount,
          results: result,
          started_at: startedAt,
          completed_at: new Date().toISOString(),
        });
      }

      this.emit('scan:completed', result);
      return result;
    } catch (err) {
      if (this.database) {
        this.database.insertScan({
          id: scanId,
          scanner_id: scanner.id,
          scanner_version: scanner.version,
          target_type: scanner.supportedArtifacts[0] || 'artifact',
          target_path: targetPath,
          status: 'failed',
          findings_count: 0,
          results: { error: err.message },
          started_at: startedAt,
          completed_at: new Date().toISOString(),
        });
      }
      this.emit('scan:failed', { id: scanId, error: err.message });
      throw err;
    }
  }
}

module.exports = { ScannerRegistry };
