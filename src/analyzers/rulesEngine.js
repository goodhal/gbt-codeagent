/**
 * 规则引擎
 * 负责加载和管理 YAML 配置的检测规则
 */

import { promises as fs } from 'node:fs';
import path from 'path';
import yaml from 'yaml';

export class RulesEngine {
  constructor() {
    this.rules = null;
    this._cache = new Map();
    this._initialized = false;
  }

  async initialize(configPath = null) {
    if (this._initialized && this.rules) {
      return this.rules;
    }

    if (configPath) {
      await this.loadFromFile(configPath);
    } else {
      this._createDefaultRules();
    }

    this._initialized = true;
    return this.rules;
  }

  async loadFromFile(filepath) {
    try {
      const content = await fs.readFile(filepath, 'utf-8');
      this.rules = yaml.parse(content);
      this._buildIndex();
      return this.rules;
    } catch (error) {
      console.error(`[RulesEngine] Failed to load rules from ${filepath}:`, error);
      this._createDefaultRules();
      return this.rules;
    }
  }

  _createDefaultRules() {
    this.rules = {
      taintTracking: {
        sources: {},
        sinks: {},
        sanitizers: {}
      },
      detectionRules: {},
      frameworkRules: {},
      severityLevels: {
        CRITICAL: { score: 9.5 },
        HIGH: { score: 7.5 },
        MEDIUM: { score: 5.0 },
        LOW: { score: 2.5 }
      }
    };
  }

  _buildIndex() {
    this._sourceIndex = new Map();
    this._sinkIndex = new Map();
    this._sanitizerIndex = new Map();
    this._ruleIndex = new Map();

    for (const [lang, sources] of Object.entries(this.rules.taintTracking?.sources || {})) {
      for (const source of sources) {
        for (const pattern of source.patterns || []) {
          const key = this._normalizePattern(pattern);
          this._sourceIndex.set(key, { lang, ...source });
        }
      }
    }

    for (const [lang, sinks] of Object.entries(this.rules.taintTracking?.sinks || {})) {
      for (const sink of sinks) {
        for (const pattern of sink.patterns || []) {
          const key = this._normalizePattern(pattern);
          this._sinkIndex.set(key, { lang, ...sink });
        }
      }
    }

    for (const [lang, sanitizers] of Object.entries(this.rules.taintTracking?.sanitizers || {})) {
      for (const sanitizer of sanitizers) {
        for (const pattern of sanitizer.patterns || []) {
          const key = this._normalizePattern(pattern);
          this._sanitizerIndex.set(key, { lang, ...sanitizer });
        }
      }
    }

    for (const [ruleId, rule] of Object.entries(this.rules.detectionRules || {})) {
      this._ruleIndex.set(ruleId, rule);
    }
  }

  _normalizePattern(pattern) {
    if (pattern instanceof RegExp) {
      return pattern.source;
    }
    return pattern;
  }

  getSupportedLanguages() {
    return this.rules?.supportedLanguages || [];
  }

  getRulesForLanguage(language) {
    const lang = language.toLowerCase();
    const rules = [];

    for (const [ruleId, rule] of this._ruleIndex) {
      if (rule.languages && rule.languages[lang]) {
        rules.push({
          id: ruleId,
          ...rule,
          languageRules: rule.languages[lang]
        });
      }
    }

    return rules;
  }

  getTaintSources(language) {
    const lang = language.toLowerCase();
    return this.rules?.taintTracking?.sources?.[lang] || [];
  }

  getTaintSinks(language) {
    const lang = language.toLowerCase();
    return this.rules?.taintTracking?.sinks?.[lang] || [];
  }

  getSanitizers(language) {
    const lang = language.toLowerCase();
    return this.rules?.taintTracking?.sanitizers?.[lang] || [];
  }

  matchSources(code, language) {
    const lang = language.toLowerCase();
    const sources = this.getTaintSources(lang);
    const matches = [];

    for (const source of sources) {
      for (const pattern of source.patterns || []) {
        const regex = this._createRegex(pattern);
        let match;
        while ((match = regex.exec(code)) !== null) {
          matches.push({
            ...source,
            pattern,
            match: match[0],
            index: match.index,
            line: this._getLineNumber(code, match.index)
          });
        }
      }
    }

    return matches;
  }

  matchSinks(code, language) {
    const lang = language.toLowerCase();
    const sinks = this.getTaintSinks(lang);
    const matches = [];

    for (const sink of sinks) {
      for (const pattern of sink.patterns || []) {
        const regex = this._createRegex(pattern);
        let match;
        while ((match = regex.exec(code)) !== null) {
          matches.push({
            ...sink,
            pattern,
            match: match[0],
            index: match.index,
            line: this._getLineNumber(code, match.index)
          });
        }
      }
    }

    return matches;
  }

  matchSanitizers(code, language) {
    const lang = language.toLowerCase();
    const sanitizers = this.getSanitizers(lang);
    const matches = [];

    for (const sanitizer of sanitizers) {
      for (const pattern of sanitizer.patterns || []) {
        const regex = this._createRegex(pattern);
        let match;
        while ((match = regex.exec(code)) !== null) {
          matches.push({
            ...sanitizer,
            pattern,
            match: match[0],
            index: match.index,
            line: this._getLineNumber(code, match.index)
          });
        }
      }
    }

    return matches;
  }

  matchVulnerability(code, ruleId, language) {
    const lang = language.toLowerCase();
    const rule = this._ruleIndex.get(ruleId);
    if (!rule || !rule.languages || !rule.languages[lang]) {
      return [];
    }

    const langRule = rule.languages[lang];
    const matches = [];

    for (const patternDef of langRule.riskPatterns || []) {
      const pattern = typeof patternDef === 'string' ? patternDef : patternDef.pattern;
      const regex = this._createRegex(pattern);
      let match;

      while ((match = regex.exec(code)) !== null) {
        if (this._isSafeMatch(code, match, langRule.safePatterns, lang)) {
          continue;
        }

        matches.push({
          ruleId,
          description: rule.description || patternDef.description || '',
          cwe: rule.cwe,
          gbt: rule.gbt,
          severity: langRule.severity || rule.severity || 'MEDIUM',
          remediation: langRule.remediation || rule.remediation,
          pattern,
          match: match[0],
          index: match.index,
          line: this._getLineNumber(code, match.index)
        });
      }
    }

    return matches;
  }

  _isSafeMatch(code, match, safePatterns, language) {
    if (!safePatterns || safePatterns.length === 0) {
      return false;
    }

    const contextStart = Math.max(0, match.index - 100);
    const contextEnd = Math.min(code.length, match.index + match[0].length + 100);
    const context = code.substring(contextStart, contextEnd);

    for (const safeDef of safePatterns) {
      const safePattern = typeof safeDef === 'string' ? safeDef : safeDef.pattern;
      const regex = this._createRegex(safePattern);
      if (regex.test(context)) {
        return true;
      }
    }

    return false;
  }

  _createRegex(pattern) {
    try {
      return new RegExp(pattern, 'gi');
    } catch {
      return null;
    }
  }

  _getLineNumber(code, index) {
    return code.substring(0, index).split('\n').length;
  }

  getSeverityScore(severity) {
    const level = this.rules?.severityLevels?.[severity.toUpperCase()];
    return level?.score || 5.0;
  }

  getFrameworkRules(frameworkName, language) {
    const frameworks = this.rules?.frameworkRules || {};
    for (const [name, framework] of Object.entries(frameworks)) {
      if (name.toLowerCase() === frameworkName.toLowerCase()) {
        if (!language || framework.languages?.includes(language.toLowerCase())) {
          return framework;
        }
      }
    }
    return null;
  }

  clearCache() {
    this._cache.clear();
  }
}

let globalRulesEngine = null;

export async function getRulesEngine(configPath = null) {
  if (!globalRulesEngine) {
    globalRulesEngine = new RulesEngine();
    await globalRulesEngine.initialize(configPath);
  }
  return globalRulesEngine;
}

export function resetRulesEngine() {
  globalRulesEngine = null;
}
