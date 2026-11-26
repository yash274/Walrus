/**
 * @file injection-detector.js
 * @module main/security/injection-detector
 * @description Deterministic rule-based prompt-injection, instruction override,
 *   malicious command detector, and Unicode obfuscation / homoglyph evasion analyzer.
 */

'use strict';

const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u2060\u180E]/g;
const ZERO_WIDTH_INSIDE_WORD_REGEX = /\w[\u200B-\u200D\uFEFF\u2060\u180E]+\w/u;
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

// Homoglyphs commonly used in Latin command / directive spoofing
const HOMOGLYPH_MAP = {
  // Cyrillic
  '\u0430': 'a', '\u0410': 'A',
  '\u0441': 'c', '\u0421': 'C',
  '\u0435': 'e', '\u0415': 'E',
  '\u043E': 'o', '\u041E': 'O',
  '\u0440': 'p', '\u0420': 'P',
  '\u0445': 'x', '\u0425': 'X',
  '\u0443': 'y', '\u0423': 'Y',
  '\u0456': 'i', '\u0406': 'I',
  '\u0458': 'j', '\u0408': 'J',
  '\u0455': 's', '\u0405': 'S',
  // Greek
  '\u03BF': 'o', '\u039F': 'O',
  '\u03C1': 'p', '\u03A1': 'P',
  '\u03BD': 'v', '\u03BA': 'k',
  '\u039A': 'K', '\u03B9': 'i',
  '\u0399': 'I', '\u03C4': 't',
  '\u03A4': 'T',
};

const INJECTION_RULES = [
  {
    id: 'INJ-001',
    name: 'Instruction Override Attempt',
    category: 'prompt_injection',
    severity: 'critical',
    confidence: 0.95,
    regex: /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|directives|rules)/i,
    description: 'Attempts to override existing system instructions or security guardrails.',
  },
  {
    id: 'INJ-002',
    name: 'System Prompt Hijack',
    category: 'prompt_injection',
    severity: 'critical',
    confidence: 0.9,
    regex: /(?:new\s+system\s+(?:instruction|prompt)|system\s+prompt\s+override|system\s+update:\s+you\s+are\s+now|developer\s+mode\s+enabled|jailbreak\s+activated)/i,
    description: 'Attempts to re-declare the core agent persona or disable guardrails.',
  },
  {
    id: 'INJ-003',
    name: 'Credential Exfiltration Request',
    category: 'credential_harvesting',
    severity: 'critical',
    confidence: 0.95,
    regex: /(?:upload|exfiltrate|send|post|transmit|curl\s+-X\s*POST).*?(?:\.env|\.aws\/credentials|id_rsa|id_ed25519|api[_-]?key|secret_key)/i,
    description: 'Explicit instruction to transmit secret keys or authentication credentials externally.',
  },
  {
    id: 'INJ-004',
    name: 'Encoded / Hidden Payload',
    category: 'obfuscation',
    severity: 'high',
    confidence: 0.85,
    regex: /(?:base64\s+-d|powershell\s+(?:-[eE](?:nc(?:odedcommand)?)?)\s+[A-Za-z0-9+/=]{20,}|certutil\s+-decode)/i,
    description: 'Execution of encoded or obfuscated payloads commonly used in evasion.',
  },
  {
    id: 'INJ-005',
    name: 'Reverse Shell Ingestion',
    category: 'command_injection',
    severity: 'critical',
    confidence: 0.98,
    regex: /(?:bash\s+-i\s+>&|\/dev\/tcp\/\d+|nc\s+-e\s+\/bin\/(?:ba)?sh|socat\s+exec:)/i,
    description: 'Direct interactive reverse shell command string detected.',
  },
  {
    id: 'INJ-006',
    name: 'Defense Evasion / Monitor Tampering',
    category: 'defense_evasion',
    severity: 'high',
    confidence: 0.9,
    regex: /(?:killall\s+(?:aegis|walrus)|pkill\s+-9\s+(?:aegis|walrus)|taskkill\s+\/f\s+\/im\s+(?:aegis|walrus)\.exe|rm\s+-rf\s+.*(?:aegis|walrus))/i,
    description: 'Attempt to terminate monitoring services or delete telemetry logs.',
  },
  {
    id: 'INJ-007',
    name: 'Download & Execute Pattern',
    category: 'command_injection',
    severity: 'high',
    confidence: 0.88,
    regex: /(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|python|perl|powershell)|(?:iwr|invoke-webrequest)\s+.*\|\s*iex/i,
    description: 'Unverified download-and-pipe-to-shell execution pattern.',
  },
];

class InjectionDetector {
  /**
   * Safely normalize text while detecting obfuscation attempts.
   * Preserves legitimate multilingual text while de-cloaking zero-width,
   * bidi, and homoglyph disguises.
   *
   * @param {string} text Raw input string
   * @returns {{
   *   normalized: string,
   *   hasZeroWidthInsideWord: boolean,
   *   hasBidiOverride: boolean,
   *   hasHomoglyphs: boolean,
   *   zeroWidthCount: number,
   *   bidiCount: number
   * }}
   */
  normalizeText(text) {
    if (!text || typeof text !== 'string') {
      return {
        normalized: '',
        hasZeroWidthInsideWord: false,
        hasBidiOverride: false,
        hasHomoglyphs: false,
        zeroWidthCount: 0,
        bidiCount: 0,
      };
    }

    const zeroWidthMatches = text.match(ZERO_WIDTH_REGEX);
    const zeroWidthCount = zeroWidthMatches ? zeroWidthMatches.length : 0;
    const hasZeroWidthInsideWord = ZERO_WIDTH_INSIDE_WORD_REGEX.test(text);

    const bidiMatches = text.match(BIDI_REGEX);
    const bidiCount = bidiMatches ? bidiMatches.length : 0;
    const hasBidiOverride = bidiCount > 0;

    // 1. Strip zero-width & bidi characters
    let cleaned = text.replace(ZERO_WIDTH_REGEX, '').replace(BIDI_REGEX, '');

    // 2. Normalize compatibility forms (e.g. Fullwidth ａｂｃ -> abc, ligatures)
    cleaned = cleaned.normalize('NFKC');

    // 3. Map common confusable characters (homoglyphs) to Latin
    let hasHomoglyphs = false;
    let homoglyphCleaned = '';
    for (const char of cleaned) {
      if (HOMOGLYPH_MAP[char]) {
        homoglyphCleaned += HOMOGLYPH_MAP[char];
        hasHomoglyphs = true;
      } else {
        homoglyphCleaned += char;
      }
    }

    return {
      normalized: homoglyphCleaned,
      hasZeroWidthInsideWord,
      hasBidiOverride,
      hasHomoglyphs,
      zeroWidthCount,
      bidiCount,
    };
  }

  /**
   * Scan text (prompt, tool args, file content, or markdown) for security threats.
   * Analyzes both raw text and normalized representation to defeat evasion.
   *
   * @param {string} text Content to scan
   * @param {Object} [metadata] Context (filePath, source, etc.)
   * @returns {Array<Object>} List of matched threat indicators
   */
  detect(text, metadata = {}) {
    if (!text || typeof text !== 'string') return [];

    const matches = [];
    const matchedRuleIds = new Set();

    // 1. Check for Unicode evasion indicators
    const {
      normalized,
      hasZeroWidthInsideWord,
      hasBidiOverride,
      hasHomoglyphs,
      zeroWidthCount,
      bidiCount,
    } = this.normalizeText(text);

    if (hasZeroWidthInsideWord) {
      matches.push({
        ruleId: 'EVASION-001',
        name: 'Zero-Width Character Concealment',
        category: 'obfuscation',
        severity: 'high',
        confidence: 0.92,
        description: `Text contains ${zeroWidthCount} hidden zero-width characters embedded inside words to evade security filters.`,
        matchedText: text.slice(0, 150),
        context: metadata,
      });
      matchedRuleIds.add('EVASION-001');
    }

    if (hasBidiOverride) {
      matches.push({
        ruleId: 'EVASION-002',
        name: 'Bidirectional Text Override (Trojan Source)',
        category: 'obfuscation',
        severity: 'critical',
        confidence: 0.96,
        description: `Text contains ${bidiCount} directional override control characters that disguise executable logic or commands.`,
        matchedText: text.slice(0, 150),
        context: metadata,
      });
      matchedRuleIds.add('EVASION-002');
    }

    // 2. Scan raw text against injection rules
    for (const rule of INJECTION_RULES) {
      const match = text.match(rule.regex);
      if (match) {
        matches.push({
          ruleId: rule.id,
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          description: rule.description,
          matchedText: match[0].slice(0, 200),
          context: metadata,
        });
        matchedRuleIds.add(rule.id);
      }
    }

    // 3. Scan normalized text to unmask hidden/homoglyph/zero-width injections
    if (normalized !== text) {
      for (const rule of INJECTION_RULES) {
        if (!matchedRuleIds.has(rule.id)) {
          const normMatch = normalized.match(rule.regex);
          if (normMatch) {
            matches.push({
              ruleId: rule.id,
              name: `${rule.name} (Unmasked via Unicode Normalization)`,
              category: rule.category,
              severity: rule.severity,
              confidence: rule.confidence,
              description: `${rule.description} [De-cloaked from Unicode/homoglyph obfuscation]`,
              matchedText: normMatch[0].slice(0, 200),
              context: { ...metadata, deobfuscated: true },
            });
            matchedRuleIds.add(rule.id);

            if (hasHomoglyphs && !matchedRuleIds.has('EVASION-003')) {
              matches.push({
                ruleId: 'EVASION-003',
                name: 'Mixed-Script Homoglyph Command Spoofing',
                category: 'obfuscation',
                severity: 'high',
                confidence: 0.90,
                description: 'Adversary substituted lookalike characters from Cyrillic or Greek into security commands.',
                matchedText: text.slice(0, 150),
                context: metadata,
              });
              matchedRuleIds.add('EVASION-003');
            }
          }
        }
      }
    }

    return matches;
  }

  /**
   * Fast boolean check.
   */
  hasThreat(text) {
    if (!text || typeof text !== 'string') return false;
    const threats = this.detect(text);
    return threats.length > 0;
  }
}

module.exports = {
  InjectionDetector,
  INJECTION_RULES,
  HOMOGLYPH_MAP,
};
