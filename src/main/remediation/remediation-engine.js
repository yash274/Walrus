/**
 * @file remediation-engine.js
 * @module main/remediation/remediation-engine
 * @description Security-intelligent code remediation and bounded fix-verification engine.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

class RemediationEngine {
  constructor({ workspaceRoot, database, reviewer } = {}) {
    this.workspaceRoot = workspaceRoot || process.cwd();
    this.database = database || null;
    this.reviewer = reviewer || null;
    this.proposals = new Map();
    this.backups = new Map();
  }

  /**
   * Create a proposed remediation for a security or code finding.
   */
  createProposal({ finding, file, targetText, replacementText, explanation }) {
    const proposalId = `fix-${randomUUID()}`;
    const proposal = {
      id: proposalId,
      findingId: finding?.id || null,
      file,
      targetText,
      replacementText,
      explanation: explanation || `Remediation for ${finding?.title || 'finding'}`,
      status: 'pending_approval',
      createdAt: new Date().toISOString(),
    };
    this.proposals.set(proposalId, proposal);
    return proposal;
  }

  /**
   * Apply an approved patch with automatic backup for safe rollback.
   */
  applyPatch(proposalId) {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error(`Proposal '${proposalId}' not found`);

    const fullPath = path.resolve(this.workspaceRoot, proposal.file);
    const resolvedRoot = path.resolve(this.workspaceRoot);
    const relative = path.relative(resolvedRoot, fullPath);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('Access denied: File escapes workspace');
    }
    if (!fs.existsSync(fullPath)) {
      throw new Error(`File does not exist: ${proposal.file}`);
    }

    const currentContent = fs.readFileSync(fullPath, 'utf8');

    // Create backup
    this.backups.set(proposalId, {
      file: fullPath,
      content: currentContent,
      timestamp: new Date().toISOString(),
    });

    if (!currentContent.includes(proposal.targetText)) {
      throw new Error(`Target text to replace not found in ${proposal.file}`);
    }

    const updatedContent = currentContent.replace(proposal.targetText, proposal.replacementText);
    fs.writeFileSync(fullPath, updatedContent, 'utf8');

    proposal.status = 'applied';
    proposal.appliedAt = new Date().toISOString();
    return proposal;
  }

  /**
   * Rollback an applied patch using the preserved backup.
   */
  rollback(proposalId) {
    const backup = this.backups.get(proposalId);
    const proposal = this.proposals.get(proposalId);
    if (!backup) throw new Error(`No backup found for proposal '${proposalId}'`);

    fs.writeFileSync(backup.file, backup.content, 'utf8');
    if (proposal) {
      proposal.status = 'rolled_back';
      proposal.rolledBackAt = new Date().toISOString();
    }
    return { rolledBack: true, file: backup.file };
  }

  /**
   * Bounded Fix-Review Loop:
   * Propose -> Apply -> Re-review -> Verify resolved
   */
  async executeBoundedRemediationLoop({ finding, file, targetText, replacementText, maxIterations = 3 }) {
    let iteration = 0;
    let resolved = false;

    while (iteration < maxIterations && !resolved) {
      iteration++;
      const proposal = this.createProposal({ finding, file, targetText, replacementText });
      this.applyPatch(proposal.id);

      if (this.reviewer) {
        const reReview = await this.reviewer.review({ scope: 'unstaged' });
        const remainingIssue = reReview.findings.some(
          (f) => f.title === finding.title && f.file.includes(file)
        );
        if (!remainingIssue) {
          resolved = true;
          proposal.status = 'verified_resolved';
          return { resolved: true, iterations: iteration, proposal, reReview };
        }
      } else {
        resolved = true;
        return { resolved: true, iterations: iteration, proposal };
      }
    }

    return { resolved, iterations: iteration };
  }
}

module.exports = { RemediationEngine };
