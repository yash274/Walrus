/**
 * Launch Electron with ELECTRON_RUN_AS_NODE unset.
 *
 * IDE terminals (VS Code, Cursor, Antigravity) set ELECTRON_RUN_AS_NODE=1
 * which forces Electron to run as plain Node.js instead of a full app.
 * cross-env can only set vars to empty string — Electron's native code
 * checks for the variable's existence, so empty string still triggers
 * Node mode. We must `delete` it from the env before spawning Electron.
 *
 * @since 0.2.0-alpha
 */
const path = require('path');
const { spawn } = require('child_process');
const electron = require('electron');

delete process.env.ELECTRON_RUN_AS_NODE;

const appPath = path.resolve(__dirname, '..');
const child = spawn(electron, [appPath, ...process.argv.slice(2)], {
  stdio: 'inherit',
  cwd: appPath,
});
child.on('exit', (code) => process.exit(code ?? 0));
