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
    this._regexCache = new Map();
    this._patternStats = new Map();
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
    this._labelIndex = new Map();
    this._guidelineIndex = new Map();
    this._profileIndex = new Map();

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

        if (sink.id) {
          this._labelIndex.set(sink.id, sink);
          for (const profile of sink.profiles || []) {
            if (!this._profileIndex.has(profile)) {
              this._profileIndex.set(profile, []);
            }
            this._profileIndex.get(profile).push(sink);
          }
          for (const [glType, glValues] of Object.entries(sink.guidelines || {})) {
            for (const glValue of glValues) {
              const glKey = `${glType}:${glValue}`;
              if (!this._guidelineIndex.has(glKey)) {
                this._guidelineIndex.set(glKey, []);
              }
              this._guidelineIndex.get(glKey).push(sink);
            }
          }
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
    if (this._regexCache.has(pattern)) {
      return this._regexCache.get(pattern);
    }
    
    try {
      const regex = new RegExp(pattern, 'gi');
      this._regexCache.set(pattern, regex);
      return regex;
    } catch {
      return null;
    }
  }

  _getLineNumber(code, index) {
    return code.substring(0, index).split('\n').length;
  }

  _getLineContent(code, lineNumber) {
    const lines = code.split('\n');
    return lines[lineNumber - 1] || '';
  }

  matchWithContext(code, language, options = {}) {
    const lang = language.toLowerCase();
    const contextWindow = options.contextWindow || 3;
    const results = [];

    const sources = this.getTaintSources(lang);
    const sinks = this.getTaintSinks(lang);

    for (const source of sources) {
      for (const pattern of source.patterns || []) {
        const regex = this._createRegex(pattern);
        let match;
        while ((match = regex.exec(code)) !== null) {
          const line = this._getLineNumber(code, match.index);
          const context = this._getSurroundingContext(code, line, contextWindow);
          
          results.push({
            type: 'source',
            ...source,
            pattern,
            match: match[0],
            index: match.index,
            line,
            context,
            confidence: this._calculateConfidence(source, context)
          });
        }
      }
    }

    for (const sink of sinks) {
      for (const pattern of sink.patterns || []) {
        const regex = this._createRegex(pattern);
        let match;
        while ((match = regex.exec(code)) !== null) {
          const line = this._getLineNumber(code, match.index);
          const context = this._getSurroundingContext(code, line, contextWindow);
          
          results.push({
            type: 'sink',
            ...sink,
            pattern,
            match: match[0],
            index: match.index,
            line,
            context,
            confidence: this._calculateConfidence(sink, context)
          });
        }
      }
    }

    return results.sort((a, b) => b.confidence - a.confidence);
  }

  _getSurroundingContext(code, lineNumber, contextWindow) {
    const lines = code.split('\n');
    const start = Math.max(0, lineNumber - contextWindow - 1);
    const end = Math.min(lines.length, lineNumber + contextWindow);
    
    const context = [];
    for (let i = start; i < end; i++) {
      context.push({
        line: i + 1,
        content: lines[i] || '',
        isTarget: i + 1 === lineNumber
      });
    }
    
    return context;
  }

  _calculateConfidence(patternDef, context) {
    let confidence = 0.7;
    
    if (patternDef.confidenceBoost) {
      confidence += patternDef.confidenceBoost;
    }
    
    const targetLine = context.find(c => c.isTarget);
    if (targetLine) {
      if (targetLine.content.trim().length > 0) {
        confidence += 0.1;
      }
    }
    
    return Math.min(1.0, Math.max(0.0, confidence));
  }

  filterFalsePositives(findings, options = {}) {
    const minConfidence = options.minConfidence || 0.5;
    const enableHeuristic = options.enableHeuristic !== false;
    
    let filtered = findings.filter(f => f.confidence >= minConfidence);
    
    if (enableHeuristic) {
      filtered = filtered.filter(f => !this._isHeuristicFalsePositive(f));
    }
    
    return filtered;
  }

  _isHeuristicFalsePositive(finding) {
    if (!finding.context || !finding.match) {
      return false;
    }
    
    const targetLine = finding.context.find(c => c.isTarget);
    if (!targetLine) {
      return false;
    }
    
    const lineContent = targetLine.content.toLowerCase();
    
    const falsePositivePatterns = [
      /test/i,
      /mock/i,
      /example/i,
      /sample/i,
      /demo/i,
      /stub/i,
      /placeholder/i,
      /dummy/i
    ];
    
    return falsePositivePatterns.some(pattern => pattern.test(lineContent));
  }

  clusterFindings(findings, options = {}) {
    const threshold = options.similarityThreshold || 0.8;
    const clusters = [];
    const visited = new Set();
    
    for (let i = 0; i < findings.length; i++) {
      if (visited.has(i)) continue;
      
      const cluster = [findings[i]];
      visited.add(i);
      
      for (let j = i + 1; j < findings.length; j++) {
        if (visited.has(j)) continue;
        
        if (this._isSimilar(findings[i], findings[j], threshold)) {
          cluster.push(findings[j]);
          visited.add(j);
        }
      }
      
      if (cluster.length > 1) {
        clusters.push({
          representative: cluster[0],
          members: cluster,
          count: cluster.length
        });
      }
    }
    
    return clusters;
  }

  _isSimilar(finding1, finding2, threshold) {
    if (finding1.ruleId !== finding2.ruleId) return false;
    
    const str1 = finding1.match || '';
    const str2 = finding2.match || '';
    
    const similarity = this._levenshteinDistance(str1, str2) / Math.max(str1.length, str2.length);
    return 1 - similarity >= threshold;
  }

  _levenshteinDistance(s1, s2) {
    if (s1.length === 0) return s2.length;
    if (s2.length === 0) return s1.length;
    
    const dp = Array(s1.length + 1).fill(null).map(() => Array(s2.length + 1).fill(0));
    
    for (let i = 0; i <= s1.length; i++) dp[i][0] = i;
    for (let j = 0; j <= s2.length; j++) dp[0][j] = j;
    
    for (let i = 1; i <= s1.length; i++) {
      for (let j = 1; j <= s2.length; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost
        );
      }
    }
    
    return dp[s1.length][s2.length];
  }

  detectOWASPTop10(code, language) {
    const lang = language.toLowerCase();
    const findings = [];
    
    const owaspRules = this.findByLabels(['owasp:top10'], lang);
    
    for (const rule of owaspRules) {
      const matches = this.matchVulnerability(code, rule.id, lang);
      findings.push(...matches.map(m => ({
        ...m,
        category: 'OWASP Top 10',
        owaspId: rule.guidelines?.owasp?.[0]
      })));
    }
    
    return findings;
  }

  detectGBTStandards(code, language) {
    const lang = language.toLowerCase();
    const findings = [];
    
    const gbtRules = this.findByLabels(['guideline:gbt'], lang);
    
    for (const rule of gbtRules) {
      const matches = this.matchVulnerability(code, rule.id, lang);
      findings.push(...matches.map(m => ({
        ...m,
        category: 'GB/T Standard',
        gbtId: rule.guidelines?.gbt?.[0]
      })));
    }
    
    return findings;
  }

  analyzeCode(code, language, options = {}) {
    const results = {
      vulnerabilities: [],
      sources: [],
      sinks: [],
      clusters: [],
      summary: {
        totalFindings: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        byCategory: {}
      }
    };

    results.vulnerabilities = this.matchWithContext(code, language, options);
    results.sources = this.matchSources(code, language);
    results.sinks = this.matchSinks(code, language);
    
    const allFindings = [...results.vulnerabilities];
    results.clusters = this.clusterFindings(allFindings, options);
    
    results.summary.totalFindings = allFindings.length;
    for (const finding of allFindings) {
      const severity = finding.severity?.toUpperCase() || 'MEDIUM';
      results.summary.bySeverity[severity] = (results.summary.bySeverity[severity] || 0) + 1;
      
      const category = finding.category || 'Other';
      results.summary.byCategory[category] = (results.summary.byCategory[category] || 0) + 1;
    }
    
    return results;
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

  static splitLabelKV(keyValue) {
    const colonIndex = keyValue.indexOf(':');
    if (colonIndex === -1) {
      return [keyValue.trim(), ''];
    }
    return [keyValue.substring(0, colonIndex).trim(), keyValue.substring(colonIndex + 1).trim()];
  }

  findByLabels(filterLabels, language = null) {
    if (!filterLabels || filterLabels.length === 0) {
      return [];
    }

    const labelSet = new Set(filterLabels.map(l => RulesEngine.splitLabelKV(l).map(part => part.toLowerCase())).flat());

    const results = [];

    for (const [ruleId, rule] of this._labelIndex) {
      if (language && rule.language && rule.language !== language.toLowerCase()) {
        continue;
      }

      const ruleLabels = new Set();
      if (rule.severity) {
        ruleLabels.add(`severity:${rule.severity.toLowerCase()}`);
      }
      if (rule.category) {
        ruleLabels.add(`category:${rule.category.toLowerCase()}`);
      }
      for (const profile of rule.profiles || []) {
        ruleLabels.add(`profile:${profile.toLowerCase()}`);
      }
      for (const [glType, glValues] of Object.entries(rule.guidelines || {})) {
        for (const glValue of glValues) {
          ruleLabels.add(`${glType.toLowerCase()}:${glValue.toLowerCase()}`);
        }
      }

      const intersection = [...labelSet].filter(label => ruleLabels.has(label));
      if (intersection.length > 0) {
        results.push({
          ...rule,
          matchedLabels: intersection
        });
      }
    }

    return results;
  }

  getRuleById(ruleId) {
    return this._labelIndex.get(ruleId) || null;
  }

  getRulesByProfile(profile) {
    return this._profileIndex.get(profile) || [];
  }

  getRulesByGuideline(guidelineType, guidelineValue) {
    const glKey = `${guidelineType.toLowerCase()}:${guidelineValue.toLowerCase()}`;
    return this._guidelineIndex.get(glKey) || [];
  }

  getRulesByCWE(cweId) {
    return this.getRulesByGuideline('cwe', cweId);
  }

  getRulesByOWASP(owaspId) {
    return this.getRulesByGuideline('owasp', owaspId);
  }

  getRulesByGBT(gbtId) {
    return this.getRulesByGuideline('gbt', gbtId);
  }

  getLabelDescriptions() {
    return this.rules?.labelDescriptions || {};
  }

  getProfileDescription(profile) {
    return this.rules?.labelDescriptions?.profile?.[profile] || null;
  }

  getSeverityDescription(severity) {
    return this.rules?.labelDescriptions?.severity?.[severity.toUpperCase()] || null;
  }

  getGuidelineDescription(guideline) {
    return this.rules?.labelDescriptions?.guideline?.[guideline] || null;
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
