/**
 * @file base-scanner.js
 * @module main/scanners/base-scanner
 * @description Base interface for AEGIS security scanners.
 */

'use strict';

const EventEmitter = require('events');

class BaseScanner extends EventEmitter {
  /**
   * @param {Object} options
   * @param {string} options.id Unique scanner identifier
   * @param {string} options.name Display name
   * @param {string} options.version Semantic version
   * @param {string[]} options.supportedArtifacts Target types (e.g. 'skill', 'repository', 'dependency', 'mcp')
   */
  constructor({ id, name, version = '1.0.0', supportedArtifacts = [] }) {
    super();
    this.id = id;
    this.name = name;
    this.version = version;
    this.supportedArtifacts = supportedArtifacts;
  }

  /**
   * Core scan method to be implemented by subclasses.
   * @param {string} targetPath File path, directory, or URL
   * @param {Object} [options]
   * @param {Function} [onProgress] Optional callback (percent, statusMessage)
   * @returns {Promise<Object>} Scan report { scannerId, target, findings: [], stats: {} }
   */
  async scan(targetPath, options = {}, onProgress = null) {
    throw new Error(`Scan not implemented for scanner: ${this.id}`);
  }

  /**
   * Safe progress emitter helper
   */
  reportProgress(onProgress, percent, status) {
    if (typeof onProgress === 'function') {
      try {
        onProgress(percent, status);
      } catch (_) {}
    }
    this.emit('progress', { percent, status });
  }
}

module.exports = { BaseScanner };
