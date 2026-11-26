/**
 * @file tool-broker.js
 * @module main/ai/tool-broker
 * @description Controlled tool broker enforcing security boundaries for AI reasoning agents.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ToolPermissionTier = Object.freeze({
  READ_ONLY: 'READ_ONLY',
  RESTRICTED: 'RESTRICTED',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  BLOCKED: 'BLOCKED',
});

const TOOL_REGISTRY = {
  read_file: { tier: ToolPermissionTier.READ_ONLY, description: 'Read selected project file' },
  inspect_git_diff: { tier: ToolPermissionTier.READ_ONLY, description: 'Inspect Git diff' },
  query_event_history: { tier: ToolPermissionTier.READ_ONLY, description: 'Query events database' },
  read_scan_results: { tier: ToolPermissionTier.READ_ONLY, description: 'Read scanner findings' },
  inspect_process_metadata: { tier: ToolPermissionTier.READ_ONLY, description: 'Inspect process list' },

  execute_static_analyzer: { tier: ToolPermissionTier.RESTRICTED, description: 'Run static security analyzer' },
  generate_patch: { tier: ToolPermissionTier.RESTRICTED, description: 'Produce proposed unified diff patch' },
  run_selected_tests: { tier: ToolPermissionTier.RESTRICTED, description: 'Execute bounded test command' },

  apply_patch: { tier: ToolPermissionTier.APPROVAL_REQUIRED, description: 'Modify source files on disk' },
  install_package: { tier: ToolPermissionTier.APPROVAL_REQUIRED, description: 'Install dependency package' },
  run_shell_command: { tier: ToolPermissionTier.APPROVAL_REQUIRED, description: 'Run arbitrary shell command' },

  extract_credentials: { tier: ToolPermissionTier.BLOCKED, description: 'Extract host credentials' },
  disable_monitoring: { tier: ToolPermissionTier.BLOCKED, description: 'Disable security monitoring' },
  modify_security_policy: { tier: ToolPermissionTier.BLOCKED, description: 'Modify or bypass policy' },
};

class ControlledToolBroker {
  constructor({ workspaceRoot, database } = {}) {
    this.workspaceRoot = workspaceRoot || process.cwd();
    this.database = database || null;
    this.pendingApprovals = new Map();
  }

  /**
   * Check if an agent is allowed to execute a tool.
   */
  canExecute(toolName, agentRole) {
    const meta = TOOL_REGISTRY[toolName];
    if (!meta) return { allowed: false, tier: ToolPermissionTier.BLOCKED, reason: 'Unknown tool' };
    if (meta.tier === ToolPermissionTier.BLOCKED) {
      return { allowed: false, tier: ToolPermissionTier.BLOCKED, reason: 'Prohibited security action' };
    }
    if (meta.tier === ToolPermissionTier.APPROVAL_REQUIRED) {
      return { allowed: false, requiresApproval: true, tier: ToolPermissionTier.APPROVAL_REQUIRED };
    }
    return { allowed: true, tier: meta.tier };
  }

  /**
   * Robust workspace containment validation.
   * Resolves canonical real paths, prevents symlink/junction escapes,
   * blocks sibling-prefix traversal, handles drive mismatches, and walks
   * nonexistent ancestor trees safely.
   *
   * @param {string} targetPath File or directory path to validate
   * @param {Object} [options]
   * @param {boolean} [options.mustExist=false] If true, target must physically exist
   * @returns {string} The canonical resolved safe path
   */
  validatePath(targetPath, { mustExist = false } = {}) {
    if (!targetPath || typeof targetPath !== 'string') {
      throw new Error('Invalid path: Target path must be a non-empty string.');
    }

    // Block null bytes and control characters
    if (targetPath.includes('\0')) {
      throw new Error(`Access denied: Null byte detected in path '${targetPath}'.`);
    }

    // Block raw Windows device namespaces unless workspaceRoot itself is inside one
    const isWindows = process.platform === 'win32';
    if (isWindows && (/^\\\\\.\\/i.test(targetPath) || /^\\\\\?\\/i.test(targetPath))) {
      throw new Error(`Access denied: Device namespace paths are prohibited: '${targetPath}'.`);
    }

    // 1. Resolve canonical workspace root
    let realRoot;
    try {
      realRoot = fs.realpathSync.native ? fs.realpathSync.native(this.workspaceRoot) : fs.realpathSync(this.workspaceRoot);
    } catch (_) {
      realRoot = path.resolve(this.workspaceRoot);
    }

    // 2. Resolve candidate path against realRoot
    const candidate = path.isAbsolute(targetPath)
      ? path.normalize(targetPath)
      : path.resolve(realRoot, targetPath);

    // 3. Resolve real path resolving symlinks and junctions
    let realCandidate;
    let targetExists = fs.existsSync(candidate);

    if (targetExists) {
      try {
        realCandidate = fs.realpathSync.native ? fs.realpathSync.native(candidate) : fs.realpathSync(candidate);
      } catch (err) {
        throw new Error(`Access denied: Failed to resolve real path for '${targetPath}': ${err.message}`);
      }
    } else {
      // Nonexistent path: walk up to deepest existing ancestor
      let current = candidate;
      const tail = [];
      while (current && current !== path.dirname(current) && !fs.existsSync(current)) {
        tail.unshift(path.basename(current));
        current = path.dirname(current);
      }
      let realAncestor;
      try {
        realAncestor = fs.realpathSync.native ? fs.realpathSync.native(current) : fs.realpathSync(current);
      } catch (_) {
        realAncestor = path.resolve(current);
      }
      realCandidate = path.join(realAncestor, ...tail);
    }

    // 4. Component-based containment check (MUST precede existence check for security)
    const checkRoot = isWindows ? realRoot.toLowerCase() : realRoot;
    const checkTarget = isWindows ? realCandidate.toLowerCase() : realCandidate;
    const rel = path.relative(checkRoot, checkTarget);

    // If rel is absolute, targets are on different roots/drives (Windows)
    if (path.isAbsolute(rel)) {
      throw new Error(`Access denied: Path '${targetPath}' escapes workspace boundary to a different root or volume.`);
    }

    // Check traversal prefixes and components
    if (rel === '..' || rel.startsWith(`..${path.sep}`) || rel.startsWith('../') || rel.startsWith('..\\')) {
      throw new Error(`Access denied: Path '${targetPath}' escapes workspace boundary.`);
    }

    const segments = rel.split(/[\\/]/);
    if (segments.includes('..')) {
      throw new Error(`Access denied: Path '${targetPath}' escapes workspace boundary via parent segment.`);
    }

    // 5. If mustExist is specified, verify file physically exists within workspace
    if (mustExist && !targetExists) {
      throw new Error(`File not found: ${targetPath}`);
    }

    return realCandidate;
  }

  /**
   * Safe read of project files (strictly within workspace boundary).
   */
  async readFile(relPath) {
    const safePath = this.validatePath(relPath, { mustExist: true });
    const stat = fs.statSync(safePath);
    if (stat.isDirectory()) {
      throw new Error(`Cannot read directory as file: ${relPath}`);
    }
    if (stat.size > 1024 * 1024) {
      throw new Error(`File oversize: ${relPath} exceeds 1MB limit`);
    }
    return fs.readFileSync(safePath, 'utf8');
  }

  /**
   * Safe execution of registered read-only tools.
   */
  async executeTool(toolName, args, agentRole = 'SecurityAnalyst') {
    const check = this.canExecute(toolName, agentRole);
    if (!check.allowed) {
      throw new Error(`Tool execution denied for ${toolName}: ${check.reason || 'Requires approval'}`);
    }

    switch (toolName) {
      case 'read_file':
        return this.readFile(args.path);
      case 'query_event_history':
        if (this.database) {
          return this.database.listEvents(args || {});
        }
        return [];
      case 'read_scan_results':
        if (this.database) {
          return this.database.listScans(args?.limit || 10);
        }
        return [];
      default:
        throw new Error(`Unsupported tool handler: ${toolName}`);
    }
  }
}

module.exports = {
  ControlledToolBroker,
  ToolPermissionTier,
  TOOL_REGISTRY,
};
