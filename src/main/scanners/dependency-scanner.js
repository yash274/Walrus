/**
 * @file dependency-scanner.js
 * @module main/scanners/dependency-scanner
 * @description Advanced dependency vulnerability intelligence scanner.
 *   Integrates Google OSV (Open Source Vulnerabilities) batch resolution,
 *   supports optional osv-scanner CLI binary, and provides offline advisory fallback.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');
const { randomUUID } = require('crypto');
const semver = require('semver');
const { BaseScanner } = require('./base-scanner');

// Built-in curated supplementary advisory database for zero-network environments
const KNOWN_ADVISORIES = [
  {
    ecosystem: 'npm',
    package: 'lodash',
    vulnerableRange: '<4.17.21',
    cve: 'CVE-2021-23337',
    ghsa: 'GHSA-35jh-r3h4-6jhm',
    severity: 'high',
    title: 'Command Injection in lodash template',
    fixedVersion: '4.17.21',
  },
  {
    ecosystem: 'npm',
    package: 'axios',
    vulnerableRange: '<0.21.2',
    cve: 'CVE-2021-3749',
    ghsa: 'GHSA-cph5-m8f7-6c5x',
    severity: 'high',
    title: 'Server-Side Request Forgery in axios',
    fixedVersion: '0.21.2',
  },
  {
    ecosystem: 'npm',
    package: 'tar',
    vulnerableRange: '<6.1.11',
    cve: 'CVE-2021-37712',
    ghsa: 'GHSA-5955-9wpr-37jh',
    severity: 'high',
    title: 'Arbitrary File Overwrite in tar',
    fixedVersion: '6.1.11',
  },
  {
    ecosystem: 'npm',
    package: 'jsonwebtoken',
    vulnerableRange: '<9.0.0',
    cve: 'CVE-2022-23529',
    ghsa: 'GHSA-qwph-4952-7xr6',
    severity: 'high',
    title: 'Insecure key handling in jsonwebtoken verify',
    fixedVersion: '9.0.0',
  },
  {
    ecosystem: 'pypi',
    package: 'urllib3',
    vulnerableRange: '<1.26.18',
    cve: 'CVE-2023-45803',
    ghsa: 'GHSA-g4mx-q9vg-27p4',
    severity: 'medium',
    title: 'Request body leak on redirect',
    fixedVersion: '1.26.18',
  },
  {
    ecosystem: 'pypi',
    package: 'requests',
    vulnerableRange: '<2.31.0',
    cve: 'CVE-2023-32681',
    ghsa: 'GHSA-j8r2-6x86-q33q',
    severity: 'medium',
    title: 'Unintended leak of Proxy-Authorization header',
    fixedVersion: '2.31.0',
  },
];

class DependencyScanner extends BaseScanner {
  constructor({ osvEndpoint = 'https://api.osv.dev/v1/querybatch', timeoutMs = 8000 } = {}) {
    super({
      id: 'dependency-scanner',
      name: 'WALRUS OSV Dependency Vulnerability Intelligence Scanner',
      version: '2.0.0',
      supportedArtifacts: ['dependency', 'repository'],
    });
    this.osvEndpoint = osvEndpoint;
    this.timeoutMs = timeoutMs;
  }

  async scan(projectDir, options = {}, onProgress = null) {
    this.reportProgress(onProgress, 10, 'Detecting project dependency manifests...');
    const findings = [];
    const detectedEcosystems = [];
    const packagesToQuery = [];

    if (!fs.existsSync(projectDir)) {
      throw new Error(`Directory does not exist: ${projectDir}`);
    }

    // 1. Detect npm ecosystem
    const packageJsonPath = path.join(projectDir, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      detectedEcosystems.push('npm');
      this.reportProgress(onProgress, 25, 'Parsing npm package manifests...');
      this._extractNpmPackages(packageJsonPath, projectDir, packagesToQuery);
    }

    // 2. Detect Python ecosystem
    const reqsPath = path.join(projectDir, 'requirements.txt');
    if (fs.existsSync(reqsPath)) {
      detectedEcosystems.push('pypi');
      this.reportProgress(onProgress, 40, 'Parsing Python requirements...');
      this._extractPythonPackages(reqsPath, packagesToQuery);
    }

    // 3. Detect Rust Cargo
    const cargoLockPath = path.join(projectDir, 'Cargo.lock');
    if (fs.existsSync(cargoLockPath)) {
      detectedEcosystems.push('crates.io');
    }

    // 4. Detect Go
    const goModPath = path.join(projectDir, 'go.mod');
    if (fs.existsSync(goModPath)) {
      detectedEcosystems.push('Go');
    }

    if (detectedEcosystems.length === 0) {
      return {
        scannerId: this.id,
        scannerVersion: this.version,
        projectDir,
        detectedEcosystems: [],
        status: 'no_supported_manifests',
        findingsCount: 0,
        findings: [],
        scannedAt: new Date().toISOString(),
        message: 'No supported dependency manifests (package.json, requirements.txt, Cargo.lock, go.mod) found.',
      };
    }

    // 5. Check if native osv-scanner binary is installed on system
    const hasOsvBinary = this._checkOsvScannerCli();
    let databaseStatus = 'offline_database';

    if (hasOsvBinary && !options.forceOffline) {
      this.reportProgress(onProgress, 60, 'Executing OSV-Scanner binary...');
      try {
        const cliFindings = this._runOsvScannerCli(projectDir);
        if (cliFindings && cliFindings.length > 0) {
          findings.push(...cliFindings);
          databaseStatus = 'osv_scanner_binary';
        }
      } catch (_) {
        // Fall back to batch query API
      }
    }

    // 6. Query OSV API if binary was not used or returned no findings
    if (findings.length === 0 && packagesToQuery.length > 0 && !options.forceOffline) {
      this.reportProgress(onProgress, 70, `Querying OSV vulnerability database for ${packagesToQuery.length} dependencies...`);
      try {
        const onlineFindings = await this._queryOsvBatch(packagesToQuery);
        if (onlineFindings && onlineFindings.length > 0) {
          findings.push(...onlineFindings);
          databaseStatus = 'online_osv_api';
        } else {
          databaseStatus = 'online_osv_api_clean';
        }
      } catch (err) {
        // Network timeout or offline -> fallback to local advisory database
        databaseStatus = 'offline_fallback';
      }
    }

    // 7. Supplementary local advisory check (handles offline or known curated advisories)
    if (packagesToQuery.length > 0) {
      this.reportProgress(onProgress, 90, 'Applying local advisory heuristics...');
      this._applyLocalAdvisories(packagesToQuery, findings);
    }

    this.reportProgress(onProgress, 100, 'Dependency vulnerability scan completed.');

    return {
      scannerId: this.id,
      scannerVersion: this.version,
      projectDir,
      detectedEcosystems,
      databaseStatus,
      totalDependenciesScanned: packagesToQuery.length,
      findingsCount: findings.length,
      findings,
      scannedAt: new Date().toISOString(),
    };
  }

  _checkOsvScannerCli() {
    try {
      execFileSync('osv-scanner', ['--version'], { stdio: 'ignore', timeout: 2000 });
      return true;
    } catch (_) {
      return false;
    }
  }

  _runOsvScannerCli(projectDir) {
    try {
      const output = execFileSync('osv-scanner', ['--json', '-r', projectDir], {
        encoding: 'utf8',
        timeout: 15000,
      });
      const data = JSON.parse(output);
      const findings = [];
      if (data.results) {
        for (const res of data.results) {
          for (const pkg of res.packages || []) {
            for (const v of pkg.vulnerabilities || []) {
              const cve = (v.aliases || []).find((a) => a.startsWith('CVE-')) || v.id;
              const ghsa = (v.aliases || []).find((a) => a.startsWith('GHSA-'));
              findings.push({
                id: `find-${randomUUID()}`,
                title: `Vulnerable Dependency: ${pkg.package.name}@${pkg.package.version} (${cve})`,
                description: v.summary || v.details || 'Known open source vulnerability identified by OSV.',
                category: 'dependency_vulnerability',
                severity: this._normalizeSeverity(v),
                confidence: 0.99,
                artifact: `${pkg.package.name}@${pkg.package.version}`,
                evidence: {
                  package: pkg.package.name,
                  installedVersion: pkg.package.version,
                  osvId: v.id,
                  cve,
                  ghsa,
                  source: 'osv-scanner',
                },
                explanation: `OSV recorded advisory ${v.id} for ${pkg.package.name}.`,
                recommended_action: 'Upgrade package to resolved version.',
              });
            }
          }
        }
      }
      return findings;
    } catch (_) {
      return [];
    }
  }

  async _queryOsvBatch(packages) {
    if (!packages || packages.length === 0) return [];

    const queries = packages.slice(0, 100).map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    }));

    const payload = JSON.stringify({ queries });

    return new Promise((resolve, reject) => {
      const url = new URL(this.osvEndpoint);
      const req = https.request(
        {
          hostname: url.hostname,
          port: 443,
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': 'WALRUS-Security-Scanner/2.0',
          },
          timeout: this.timeoutMs,
        },
        (res) => {
          if (res.statusCode !== 200) {
            return reject(new Error(`OSV API returned status ${res.statusCode}`));
          }
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              const findings = [];
              if (json.results && Array.isArray(json.results)) {
                for (let i = 0; i < json.results.length; i++) {
                  const result = json.results[i];
                  const pkgInfo = packages[i];
                  if (result && result.vulns && Array.isArray(result.vulns)) {
                    for (const v of result.vulns) {
                      const aliases = Array.isArray(v.aliases) ? v.aliases : [];
                      const known = KNOWN_ADVISORIES.find((k) => k.ghsa === v.id || k.cve === v.id);
                      const cve = known?.cve || aliases.find((a) => a.startsWith('CVE-')) || (v.id && v.id.startsWith('CVE-') ? v.id : (v.related || []).find((r) => r.startsWith('CVE-')) || v.id);
                      const ghsa = known?.ghsa || aliases.find((a) => a.startsWith('GHSA-')) || (v.id && v.id.startsWith('GHSA-') ? v.id : (v.related || []).find((r) => r.startsWith('GHSA-')));
                      findings.push({
                        id: `find-${randomUUID()}`,
                        title: `Vulnerable Dependency: ${pkgInfo.name}@${pkgInfo.version} (${cve})`,
                        description: v.summary || v.details || 'Known open source vulnerability reported by OSV database.',
                        category: 'dependency_vulnerability',
                        severity: this._normalizeSeverity(v),
                        confidence: 0.99,
                        artifact: `${pkgInfo.name}@${pkgInfo.version}`,
                        evidence: {
                          package: pkgInfo.name,
                          installedVersion: pkgInfo.version,
                          osvId: v.id,
                          cve,
                          ghsa,
                          source: 'osv_api',
                        },
                        explanation: `OSV recorded advisory ${v.id} for ${pkgInfo.name}.`,
                        recommended_action: 'Upgrade package to an unaffected version.',
                      });
                    }
                  }
                }
              }
              resolve(findings);
            } catch (err) {
              reject(err);
            }
          });
        }
      );

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('OSV query timed out'));
      });
      req.write(payload);
      req.end();
    });
  }

  _normalizeSeverity(v) {
    if (!v) return 'medium';
    if (v.database_specific && v.database_specific.severity) {
      const s = String(v.database_specific.severity).toLowerCase();
      if (['critical', 'high', 'medium', 'low'].includes(s)) return s;
    }
    if (v.severity && Array.isArray(v.severity)) {
      const cvss = v.severity.find((s) => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
      if (cvss && cvss.score) {
        // e.g. CVSS:3.1/AV:N/...
        return 'high';
      }
    }
    return 'high';
  }

  _extractNpmPackages(packageJsonPath, projectDir, list) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

      const lockPath = path.join(projectDir, 'package-lock.json');
      let lockPackages = {};
      if (fs.existsSync(lockPath)) {
        try {
          const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
          if (lock.packages) {
            for (const [pKey, pVal] of Object.entries(lock.packages)) {
              const name = pKey.replace(/^node_modules\//, '');
              if (pVal.version) lockPackages[name] = pVal.version;
            }
          }
        } catch (_) {}
      }

      for (const [depName, declaredVersion] of Object.entries(deps)) {
        const rawVersion = lockPackages[depName] || declaredVersion.replace(/^[\^~]/, '');
        const clean = semver.coerce(rawVersion);
        if (clean) {
          list.push({
            ecosystem: 'npm',
            name: depName,
            version: clean.version,
          });
        }
      }
    } catch (_) {}
  }

  _extractPythonPackages(reqsPath, list) {
    try {
      const lines = fs.readFileSync(reqsPath, 'utf8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const match = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*==\s*([0-9a-zA-Z_\.\-]+)/);
        if (match) {
          const [, name, version] = match;
          list.push({
            ecosystem: 'PyPI',
            name,
            version,
          });
        }
      }
    } catch (_) {}
  }

  _applyLocalAdvisories(packages, findings) {
    const existingKeys = new Set(findings.map((f) => f.artifact));

    for (const pkg of packages) {
      if (existingKeys.has(`${pkg.name}@${pkg.version}`)) continue;

      for (const adv of KNOWN_ADVISORIES) {
        if (adv.ecosystem.toLowerCase() === pkg.ecosystem.toLowerCase() && adv.package.toLowerCase() === pkg.name.toLowerCase()) {
          try {
            const cleanVersion = semver.coerce(pkg.version);
            if (cleanVersion && semver.satisfies(cleanVersion, adv.vulnerableRange)) {
              findings.push({
                id: `find-${randomUUID()}`,
                title: `Vulnerable Dependency: ${pkg.name}@${pkg.version} (${adv.cve})`,
                description: `${adv.title}. Installed version ${pkg.version} satisfies vulnerable range ${adv.vulnerableRange}.`,
                category: 'dependency_vulnerability',
                severity: adv.severity,
                confidence: 0.98,
                artifact: `${pkg.name}@${pkg.version}`,
                evidence: {
                  package: pkg.name,
                  installedVersion: pkg.version,
                  vulnerableRange: adv.vulnerableRange,
                  fixedVersion: adv.fixedVersion,
                  cve: adv.cve,
                  ghsa: adv.ghsa,
                  source: 'local_advisory_database',
                },
                explanation: `Known security advisory ${adv.cve} exists for package ${pkg.name}.`,
                recommended_action: `Upgrade ${pkg.name} to version ${adv.fixedVersion} or higher.`,
              });
              existingKeys.add(`${pkg.name}@${pkg.version}`);
            }
          } catch (_) {}
        }
      }
    }
  }
}

module.exports = { DependencyScanner, KNOWN_ADVISORIES };
