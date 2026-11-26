import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ControlledToolBroker, ToolPermissionTier } from '../../src/main/ai/tool-broker.js';

describe('P0 Security: Tool Broker Workspace Containment & Adversarial Path Testing', () => {
  let baseDir;
  let workspaceDir;
  let siblingDir;
  let outsideDir;
  let broker;

  beforeEach(() => {
    // Create base temp tree:
    // baseDir/
    //   workspace/
    //     sub/
    //       nested.txt
    //     hello.txt
    //   workspace-sibling/
    //     secret.txt
    //   outside/
    //     external.txt
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'walrus-broker-sec-'));
    workspaceDir = path.join(baseDir, 'workspace');
    siblingDir = path.join(baseDir, 'workspace-sibling');
    outsideDir = path.join(baseDir, 'outside');

    fs.mkdirSync(path.join(workspaceDir, 'sub'), { recursive: true });
    fs.mkdirSync(siblingDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });

    fs.writeFileSync(path.join(workspaceDir, 'hello.txt'), 'Hello safe world');
    fs.writeFileSync(path.join(workspaceDir, 'sub', 'nested.txt'), 'Nested content');
    fs.writeFileSync(path.join(siblingDir, 'secret.txt'), 'SIBLING_SECRET_KEY');
    fs.writeFileSync(path.join(outsideDir, 'external.txt'), 'OUTSIDE_ROOT_PASSWORD');

    broker = new ControlledToolBroker({ workspaceRoot: workspaceDir });
  });

  afterEach(() => {
    try {
      if (fs.existsSync(baseDir)) {
        fs.rmSync(baseDir, { recursive: true, force: true });
      }
    } catch (_) {}
  });

  describe('Legitimate Access Within Workspace', () => {
    it('reads top-level files correctly', async () => {
      const content = await broker.readFile('hello.txt');
      expect(content).toBe('Hello safe world');
    });

    it('reads nested subdirectory files correctly', async () => {
      const content = await broker.readFile('sub/nested.txt');
      expect(content).toBe('Nested content');
    });

    it('resolves relative path with current directory notation (.)', async () => {
      const content = await broker.readFile('./hello.txt');
      expect(content).toBe('Hello safe world');
    });

    it('permits validating nonexistent path within workspace for future writes', () => {
      const safePath = broker.validatePath('sub/new-output.json', { mustExist: false });
      expect(safePath).toContain('new-output.json');
      expect(safePath.toLowerCase()).toContain(workspaceDir.toLowerCase());
    });
  });

  describe('Adversarial Traversal & Prefix Bypasses', () => {
    it('blocks classic .. traversal out of workspace', async () => {
      await expect(
        broker.readFile('../outside/external.txt')
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('blocks deep .. traversal attempts', async () => {
      await expect(
        broker.readFile('sub/../../outside/external.txt')
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('CRITICAL: blocks sibling directory prefix bypass (e.g. workspace-sibling)', async () => {
      // workspaceDir is ".../workspace"
      // siblingDir is ".../workspace-sibling"
      // An unsafe startsWith check on ".../workspace" matches ".../workspace-sibling"
      const siblingRelative = '../workspace-sibling/secret.txt';
      await expect(
        broker.readFile(siblingRelative)
      ).rejects.toThrow(/escapes workspace boundary/i);

      // Also verify direct validatePath
      expect(() => {
        broker.validatePath(siblingRelative, { mustExist: false });
      }).toThrow(/escapes workspace boundary/i);
    });

    it('blocks absolute paths pointing outside workspace', async () => {
      const absoluteOutside = path.resolve(outsideDir, 'external.txt');
      await expect(
        broker.readFile(absoluteOutside)
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('blocks null byte injection in paths', async () => {
      await expect(
        broker.readFile('hello.txt\0/../outside/external.txt')
      ).rejects.toThrow(/null byte detected/i);
    });

    it('blocks Windows device namespaces', () => {
      expect(() => {
        broker.validatePath('\\\\.\\PhysicalDrive0');
      }).toThrow(/device namespace paths are prohibited/i);

      expect(() => {
        broker.validatePath('\\\\?\\C:\\Windows\\System32');
      }).toThrow(/device namespace paths are prohibited/i);
    });
  });

  describe('Symlink and Junction Escapes', () => {
    it('blocks reading a symlink pointing to a file outside workspace', async () => {
      const symlinkFile = path.join(workspaceDir, 'symlink-leak.txt');
      try {
        fs.symlinkSync(path.join(outsideDir, 'external.txt'), symlinkFile, 'file');
      } catch (err) {
        // Windows unprivileged accounts might throw EPERM for symlinks without Developer Mode
        return;
      }

      await expect(
        broker.readFile('symlink-leak.txt')
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('blocks reading through a directory symlink pointing outside workspace', async () => {
      const symlinkDir = path.join(workspaceDir, 'symlink-folder');
      try {
        fs.symlinkSync(outsideDir, symlinkDir, 'junction');
      } catch (err) {
        try {
          fs.symlinkSync(outsideDir, symlinkDir, 'dir');
        } catch (_) {
          return;
        }
      }

      await expect(
        broker.readFile('symlink-folder/external.txt')
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('blocks nonexistent file target inside an escaping symlink folder', () => {
      const symlinkDir = path.join(workspaceDir, 'escape-folder');
      try {
        fs.symlinkSync(outsideDir, symlinkDir, 'junction');
      } catch (err) {
        try {
          fs.symlinkSync(outsideDir, symlinkDir, 'dir');
        } catch (_) {
          return;
        }
      }

      // File does not exist, but ancestor symlink points outside
      expect(() => {
        broker.validatePath('escape-folder/nonexistent-target.txt', { mustExist: false });
      }).toThrow(/escapes workspace boundary/i);
    });
  });

  describe('Nonexistent File Handling & Boundary Validation', () => {
    it('validates a nonexistent file in an existing directory within workspace', () => {
      const safePath = broker.validatePath('sub/does-not-exist.txt', { mustExist: false });
      expect(safePath.toLowerCase()).toContain(path.join(workspaceDir, 'sub').toLowerCase());
    });

    it('validates a nonexistent file in multiple nonexistent subdirectories within workspace', () => {
      const safePath = broker.validatePath('new/deep/dirs/file.txt', { mustExist: false });
      expect(safePath.toLowerCase()).toContain(workspaceDir.toLowerCase());
    });

    it('blocks a nonexistent file when parent traversal escapes workspace', () => {
      expect(() => {
        broker.validatePath('../../nonexistent-ancestor/file.txt', { mustExist: false });
      }).toThrow(/escapes workspace boundary/i);
    });

    it('throws File not found when mustExist is true for nonexistent file', async () => {
      await expect(
        broker.readFile('does-not-exist.txt')
      ).rejects.toThrow(/file not found/i);
    });
  });
});
