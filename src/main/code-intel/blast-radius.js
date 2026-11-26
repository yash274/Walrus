/**
 * @file blast-radius.js
 * @module main/code-intel/blast-radius
 * @description Computes upstream/downstream impact analysis and blast radius for code changes.
 */

'use strict';

class BlastRadiusAnalyzer {
  constructor(contextEngine) {
    this.context = contextEngine;
  }

  /**
   * Analyze blast radius for a list of modified files.
   * @param {string[]} changedFiles Array of relative file paths
   * @returns {Object} Impact assessment
   */
  analyze(changedFiles = []) {
    if (!this.context.isIndexed) {
      this.context.indexProject();
    }

    const directCallers = new Set();
    const affectedTests = new Set();
    const affectedModules = new Set();

    for (const file of changedFiles) {
      const importers = this.context.getImporters(file);
      for (const caller of importers) {
        directCallers.add(caller);
        affectedModules.add(caller);
        if (caller.includes('test') || caller.includes('spec')) {
          affectedTests.add(caller);
        }
      }
    }

    const totalImpacted = directCallers.size;
    let impactTier = 'low';
    if (totalImpacted > 15) impactTier = 'critical';
    else if (totalImpacted > 6) impactTier = 'high';
    else if (totalImpacted > 1) impactTier = 'medium';

    return {
      changedFiles,
      impactTier,
      directCallersCount: directCallers.size,
      directCallers: Array.from(directCallers),
      affectedTestsCount: affectedTests.size,
      affectedTests: Array.from(affectedTests),
      summary: `Change affects ${changedFiles.length} file(s), directly imported by ${directCallers.size} module(s) and ${affectedTests.size} test suite(s).`,
    };
  }
}

module.exports = { BlastRadiusAnalyzer };
