# Contributing to Project Walrus

Thank you for your interest in contributing to **Project Walrus**, the open-source AI agent security, monitoring, and engineering control platform maintained by [BlueIce](https://blueice.one).

## Getting Started

1. **Fork the Repository:** Create a personal fork and clone it to your local machine.
2. **Branching:** Create a descriptive branch from `main` (e.g. `feature/ebpf-sensor` or `fix/tool-broker-symlink`).
3. **Environment Setup:**
   ```bash
   npm install
   npm run frontend:build
   ```

## Development Guidelines

- **Security Boundaries:** Any file system interaction must use canonical path validation (`fs.realpathSync.native`) and component-based relative containment (`path.relative`) to eliminate path traversal vulnerabilities.
- **Frontend Code:** All UI code in `frontend/observatory` must use Svelte 5 Runes and adhere to the `unslop` design tokens (dark slate palette, 4px grid, tabular numbers).
- **Testing:** Add reproducible unit/integration tests under `tests/main/`. All new features must have test coverage.
- **Run Tests:**
  ```powershell
  $env:AEGIS_SKIP_ELECTRON_PREPARE="1"; $env:AEGIS_ALLOW_NODE_OVERRIDE="1"; npx vitest run
  ```

## Submitting Pull Requests

1. Ensure the code builds cleanly with zero errors (`npm run frontend:build`).
2. Verify all platform and security tests pass.
3. Push your branch to your fork and submit a Pull Request to `main`.
4. Provide a clear description of the problem solved, architectural changes made, and test evidence.

For questions, join the [BlueIce Builders Community](https://blueice.one#builders-community).
