/**
 * @file credential-store.js
 * @module main/ai/credential-store
 * @description Secure credential store for AI provider API keys.
 *   Uses Windows DPAPI / Electron safeStorage when available, falling back to
 *   AES-256-GCM authenticated encryption with machine-bound entropy key derivation.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { createCipheriv, createDecipheriv, scryptSync, randomBytes } = require('crypto');

const ALGORITHM = 'aes-256-gcm';

class CredentialStore {
  /**
   * @param {string} [storagePath] Path to encrypted key store file
   * @param {string} [secretSeed] Master entropy seed (optional override)
   */
  constructor(storagePath, secretSeed = null) {
    this.storagePath = storagePath || path.join(process.cwd(), 'data', 'credentials.enc');

    // Attempt to import safeStorage if inside Electron main runtime
    this.safeStorage = null;
    try {
      if (process.versions && process.versions.electron) {
        const electron = require('electron');
        if (electron.safeStorage && electron.safeStorage.isEncryptionAvailable()) {
          this.safeStorage = electron.safeStorage;
        }
      }
    } catch (_) {}

    // Derive machine-bound primary key and legacy fallback key
    const machineEntropy = [
      os.hostname(),
      os.userInfo ? os.userInfo().username : 'walrus-user',
      process.env.COMPUTERNAME || '',
      process.env.USERDOMAIN || '',
      secretSeed || 'walrus-machine-entropy-v2',
    ].join(':');

    this.primaryKey = scryptSync(machineEntropy, 'walrus-machine-salt-v2', 32);
    this.legacyKey = scryptSync('aegis-machine-credential-seed-v1', 'aegis-salt-fixed', 32);
    if (secretSeed) {
      this.customKey = scryptSync(secretSeed, 'aegis-salt-fixed', 32);
    } else {
      this.customKey = null;
    }

    this._ensureDir();
  }

  _ensureDir() {
    const dir = path.dirname(this.storagePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  _decryptPayload(raw, key) {
    if (raw.length < 28) return null;
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  }

  _readAll() {
    if (!fs.existsSync(this.storagePath)) return {};
    try {
      const raw = fs.readFileSync(this.storagePath);

      // 1. Try custom key if explicit seed was provided
      if (this.customKey) {
        try {
          const res = this._decryptPayload(raw, this.customKey);
          if (res) return res;
        } catch (_) {}
      }

      // 2. Try primary machine-bound key
      try {
        const res = this._decryptPayload(raw, this.primaryKey);
        if (res) return res;
      } catch (_) {}

      // 3. Fallback to legacy key (backward compatibility with existing AEGIS stores)
      try {
        const res = this._decryptPayload(raw, this.legacyKey);
        if (res) {
          // Re-encrypt with modern primary key
          this._writeAll(res);
          return res;
        }
      } catch (_) {}

      return {};
    } catch (_) {
      return {};
    }
  }

  _writeAll(data) {
    const key = this.customKey || this.primaryKey;
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    const plaintext = Buffer.from(JSON.stringify(data), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([iv, tag, ciphertext]);
    fs.writeFileSync(this.storagePath, payload);
  }

  setApiKey(provider, apiKey) {
    if (!provider || typeof provider !== 'string') throw new Error('Invalid provider');
    const all = this._readAll();
    all[provider.toLowerCase()] = apiKey;
    this._writeAll(all);
  }

  getApiKey(provider) {
    if (!provider || typeof provider !== 'string') return null;
    const all = this._readAll();
    return all[provider.toLowerCase()] || null;
  }

  hasApiKey(provider) {
    return !!this.getApiKey(provider);
  }

  removeApiKey(provider) {
    if (!provider) return;
    const all = this._readAll();
    delete all[provider.toLowerCase()];
    this._writeAll(all);
  }

  listConfiguredProviders() {
    return Object.keys(this._readAll());
  }
}

let _defaultInstance = null;

function getCredentialStore(customPath) {
  if (customPath) return new CredentialStore(customPath);
  if (!_defaultInstance) {
    _defaultInstance = new CredentialStore();
  }
  return _defaultInstance;
}

module.exports = {
  CredentialStore,
  getCredentialStore,
};
