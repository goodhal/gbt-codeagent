/**
 * 规则引擎
 * 负责加载和管理 YAML 配置的检测规则
 * 优化特性：
 * 1. LRU 正则缓存机制（防止内存溢出）
 * 2. 增强误报过滤（上下文感知、自定义排除模式）
 * 3. 智能置信度计算（代码复杂度、历史数据）
 * 4. 规则版本管理
 * 5. 并行规则匹配
 */

import { promises as fs } from 'node:fs';
import path from 'path';
import yaml from 'yaml';

class LRUCache {
  constructor(maxSize = 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.accessOrder = [];
  }

  get(key) {
    if (!this.cache.has(key)) {
      return undefined;
    }
    const index = this.accessOrder.indexOf(key);
    if (index !== -1) {
      this.accessOrder.splice(index, 1);
    }
    this.accessOrder.push(key);
    return this.cache.get(key);
  }

  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const oldest = this.accessOrder.shift();
      this.cache.delete(oldest);
    }
    this.cache.set(key, value);
    const index = this.accessOrder.indexOf(key);
    if (index !== -1) {
      this.accessOrder.splice(index, 1);
    }
    this.accessOrder.push(key);
  }

  has(key) {
    return this.cache.has(key);
  }

  clear() {
    this.cache.clear();
    this.accessOrder = [];
  }

  get size() {
    return this.cache.size;
  }
}

export class RulesEngine {
  constructor(options = {}) {
    this.rules = null;
    this._cache = new Map();
    this._initialized = false;
    this._regexCache = new LRUCache(options.regexCacheSize || 2000);
    this._patternStats = new Map();
    this._falsePositiveHistory = new Map();
    this._performanceStats = {
      cacheHits: 0,
      cacheMisses: 0,
      totalMatches: 0,
      totalFalsePositives: 0
    };
    
    this._customFalsePositivePatterns = [];
    this._testFilePatterns = [
      /test/i, /spec/i, /mock/i, /fixture/i, /example/i, /sample/i, /demo/i, /stub/i, /placeholder/i, /dummy/i
    ];
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
      
      if (this.rules.version) {
        console.log(`[RulesEngine] Loaded rules version: ${this.rules.version}`);
      }
      
      return this.rules;
    } catch (error) {
      console.error(`[RulesEngine] Failed to load rules from ${filepath}:`, error);
      this._createDefaultRules();
      return this.rules;
    }
  }

  _createDefaultRules() {
    this.rules = {
      version: '1.0.0',
      taintTracking: {
        sources: {},
        sinks: {},
        sanitizers: {}
      },
      detectionRules: {},
      frameworkRules: {},
      severityLevels: {
        CRITICAL: { score: 9.5, description: '危急漏洞，可导致系统完全被控' },
        HIGH: { score: 7.5, description: '高危漏洞，可导致数据泄露或权限提升' },
        MEDIUM: { score: 5.0, description: '中危漏洞，可导致部分功能受影响' },
        LOW: { score: 2.5, description: '低危漏洞，潜在风险或代码质量问题' }
      },
      falsePositiveExclusions: []
    };
  }

  registerQuickScanPatterns(patternsByLanguage) {
    if (!this.rules) {
      this._createDefaultRules();
    }
    if (!this.rules.taintTracking) {
      this.rules.taintTracking = { sources: {}, sinks: {}, sanitizers: {} };
    }
    if (!this.rules.taintTracking.sinks) {
      this.rules.taintTracking.sinks = {};
    }

    for (const [lang, patterns] of Object.entries(patternsByLanguage)) {
      if (!this.rules.taintTracking.sinks[lang]) {
        this.rules.taintTracking.sinks[lang] = [];
      }

      const existingSinks = this.rules.taintTracking.sinks[lang];
      const existingIds = new Set(existingSinks.map(s => s.id));

      for (const qsPattern of patterns) {
        const sinkId = `QS-${qsPattern.vulnType}-${lang.toUpperCase()}`;
        if (existingIds.has(sinkId)) continue;

        existingSinks.push({
          id: sinkId,
          name: qsPattern.vulnType,
          patterns: [qsPattern.pattern.source],
          category: this._mapVulnTypeToCategory(qsPattern.vulnType),
          severity: this._mapChineseSeverity(qsPattern.severity),
          profiles: ['security', 'default'],
          guidelines: {
            cwe: [qsPattern.cwe.replace('CWE-', '')],
            gbt: [qsPattern.vulnType]
          },
          _quickScan: true,
          _vulnType: qsPattern.vulnType,
          _cwe: qsPattern.cwe,
          _chineseSeverity: qsPattern.severity
        });
        existingIds.add(sinkId);
      }
    }

    this._buildIndex();
  }

  _mapChineseSeverity(chinese) {
    const map = { '严重': 'CRITICAL', '高危': 'HIGH', '中危': 'MEDIUM', '低危': 'LOW' };
    return map[chinese] || 'MEDIUM';
  }

  _mapVulnTypeToCategory(vulnType) {
    const map = {
      COMMAND_INJECTION: 'command_exec',
      SQL_INJECTION: 'sql_injection',
      CODE_INJECTION: 'code_injection',
      SPEL_INJECTION: 'code_injection',
      SSTI: 'code_injection',
      PATH_TRAVERSAL: 'file_operation',
      HARD_CODE_PASSWORD: 'hard_coded_secret',
      PLAINTEXT_PASSWORD: 'hard_coded_secret',
      WEAK_CRYPTO: 'weak_crypto',
      WEAK_HASH: 'weak_hash',
      PREDICTABLE_RANDOM: 'weak_random',
      WEAK_RANDOM: 'weak_random',
      DESERIALIZATION: 'deserialization',
      SSRF: 'ssrf',
      XXE: 'xxe',
      AUTH_BYPASS: 'auth_bypass',
      REFERER_AUTH_BYPASS: 'auth_bypass',
      AUTH_INFO_EXPOSURE: 'info_leak',
      IDOR: 'idor',
      INFO_LEAK: 'info_leak',
      LOG_INJECTION: 'log_injection',
      SESSION_FIXATION: 'session_fixation',
      COOKIE_MANIPULATION: 'cookie_manipulation',
      XSS: 'xss',
      XPATH_INJECTION: 'xpath',
      BUFFER_OVERFLOW: 'buffer_overflow',
      FORMAT_STRING: 'format_string',
      INTEGER_OVERFLOW: 'integer_overflow',
      PROCESS_CONTROL: 'process_control',
      OPEN_REDIRECT: 'open_redirect',
      CORS_MISCONFIGURATION: 'cors',
      CSRF: 'csrf',
      RACE_CONDITION: 'race_condition',
      UNCONTROLLED_MEMORY: 'memory',
      IMPROPER_EXCEPTION_HANDLING: 'exception',
      INFINITE_LOOP: 'infinite_loop',
      WEAK_PASSWORD_POLICY: 'weak_password',
      PLAINTEXT_TRANSMISSION: 'plaintext_transmission'
    };
    return map[vulnType] || 'other';
  }

  matchQuickScan(code, language) {
    const lang = language.toLowerCase();
    const results = [];

    const yamlSinks = this.getTaintSinks(lang);

    for (const sink of yamlSinks) {
      for (const patternStr of sink.patterns || []) {
        const regex = this._createRegex(patternStr);
        if (!regex) continue;

        let match;
        while ((match = regex.exec(code)) !== null) {
          results.push({
            ...sink,
            pattern: patternStr,
            match: match[0],
            index: match.index,
            line: this._getLineNumber(code, match.index),
            vulnType: this._resolveVulnType(sink),
            cwe: this._resolveCwe(sink),
            severity: sink._chineseSeverity || this._mapSeverityToChinese(sink.severity),
            _quickScan: !!sink._quickScan
          });
        }
      }
    }

    return results;
  }

  _resolveVulnType(sink) {
    if (sink._vulnType) return sink._vulnType;
    const categoryToVuln = {
      command_exec: 'COMMAND_INJECTION',
      sql_injection: 'SQL_INJECTION',
      code_injection: 'CODE_INJECTION',
      file_operation: 'PATH_TRAVERSAL',
      deserialization: 'DESERIALIZATION',
      ssrf: 'SSRF',
      xxe: 'XXE',
      xss: 'XSS',
      hard_coded_secret: 'HARD_CODE_PASSWORD',
      weak_crypto: 'WEAK_CRYPTO',
      weak_hash: 'WEAK_HASH',
      weak_random: 'PREDICTABLE_RANDOM',
      auth_bypass: 'AUTH_BYPASS',
      info_leak: 'INFO_LEAK',
      idor: 'IDOR',
      log_injection: 'LOG_INJECTION',
      session_fixation: 'SESSION_FIXATION',
      cookie_manipulation: 'COOKIE_MANIPULATION',
      xpath: 'XPATH_INJECTION',
      buffer_overflow: 'BUFFER_OVERFLOW',
      format_string: 'FORMAT_STRING',
      integer_overflow: 'INTEGER_OVERFLOW',
      process_control: 'PROCESS_CONTROL',
      open_redirect: 'OPEN_REDIRECT',
      cors: 'CORS_MISCONFIGURATION',
      csrf: 'CSRF',
      race_condition: 'RACE_CONDITION',
      memory: 'UNCONTROLLED_MEMORY',
      exception: 'IMPROPER_EXCEPTION_HANDLING',
      infinite_loop: 'INFINITE_LOOP',
      weak_password: 'WEAK_PASSWORD_POLICY',
      plaintext_transmission: 'PLAINTEXT_TRANSMISSION'
    };
    if (sink.category && categoryToVuln[sink.category]) {
      return categoryToVuln[sink.category];
    }
    return sink.name || sink.category || 'UNKNOWN';
  }

  _resolveCwe(sink) {
    if (sink._cwe) return sink._cwe;
    if (sink.guidelines?.cwe && sink.guidelines.cwe.length > 0) {
      const cwe = sink.guidelines.cwe[0];
      return cwe.startsWith('CWE-') ? cwe : `CWE-${cwe}`;
    }
    return 'CWE-NONE';
  }

  _mapSeverityToChinese(severity) {
    const map = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危' };
    return map[severity?.toUpperCase()] || '中危';
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

    this._customFalsePositivePatterns = this.rules.falsePositiveExclusions || [];
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
    return this._matchPatterns(code, sources);
  }

  matchSinks(code, language) {
    const lang = language.toLowerCase();
    const sinks = this.getTaintSinks(lang);
    return this._matchPatterns(code, sinks);
  }

  matchSanitizers(code, language) {
    const lang = language.toLowerCase();
    const sanitizers = this.getSanitizers(lang);
    return this._matchPatterns(code, sanitizers);
  }

  _matchPatterns(code, patternDefs) {
    const matches = [];

    for (const def of patternDefs) {
      for (const pattern of def.patterns || []) {
        const regex = this._createRegex(pattern);
        if (!regex) continue;
        
        let match;
        while ((match = regex.exec(code)) !== null) {
          matches.push({
            ...def,
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

  async matchVulnerability(code, ruleId, language) {
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
      if (!regex) continue;
      
      let match;

      while ((match = regex.exec(code)) !== null) {
        if (this._isSafeMatch(code, match, langRule.safePatterns, lang)) {
          continue;
        }

        const context = this._getSurroundingContext(code, this._getLineNumber(code, match.index), 3);
        const confidence = this._calculateConfidence(patternDef, context, code);

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
          line: this._getLineNumber(code, match.index),
          context,
          confidence
        });
      }
    }

    return matches;
  }

  _isSafeMatch(code, match, safePatterns, language) {
    if (!safePatterns || safePatterns.length === 0) {
      return false;
    }

    const contextStart = Math.max(0, match.index - 150);
    const contextEnd = Math.min(code.length, match.index + match[0].length + 150);
    const context = code.substring(contextStart, contextEnd);

    for (const safeDef of safePatterns) {
      const safePattern = typeof safeDef === 'string' ? safeDef : safeDef.pattern;
      const regex = this._createRegex(safePattern);
      if (regex && regex.test(context)) {
        return true;
      }
    }

    return false;
  }

  _createRegex(pattern) {
    if (this._regexCache.has(pattern)) {
      this._performanceStats.cacheHits++;
      return this._regexCache.get(pattern);
    }
    
    this._performanceStats.cacheMisses++;
    
    try {
      const regex = new RegExp(pattern, 'gi');
      this._regexCache.set(pattern, regex);
      return regex;
    } catch (e) {
      console.warn(`[RulesEngine] Invalid regex pattern: ${pattern}`);
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

  _calculateConfidence(patternDef, context, fullCode = '') {
    let confidence = 0.6;
    
    if (patternDef.confidenceBoost) {
      confidence += patternDef.confidenceBoost;
    }
    
    const targetLine = context.find(c => c.isTarget);
    if (targetLine) {
      const lineContent = targetLine.content.trim();
      
      if (lineContent.length > 0) {
        confidence += 0.05;
      }
      
      if (lineContent.length > 50) {
        confidence += 0.05;
      }
      
      if (!this._looksLikeTestCode(lineContent)) {
        confidence += 0.1;
      }
      
      const complexity = this._calculateLineComplexity(lineContent);
      if (complexity > 0.5) {
        confidence -= 0.1;
      }
    }

    const codeComplexity = this._calculateCodeComplexity(fullCode);
    if (codeComplexity < 0.3) {
      confidence -= 0.05;
    }
    
    const ruleId = patternDef.id || patternDef.ruleId;
    if (ruleId && this._falsePositiveHistory.has(ruleId)) {
      const fpRate = this._falsePositiveHistory.get(ruleId);
      confidence *= (1 - fpRate * 0.5);
    }
    
    return Math.min(1.0, Math.max(0.0, confidence));
  }

  _calculateLineComplexity(line) {
    if (!line) return 0;
    
    const operators = line.split(/[+\-*/%=<>!&|]+/).length - 1;
    const nestedParens = (line.match(/\(/g) || []).length;
    const length = line.length;
    
    return Math.min(1.0, (operators * 0.1 + nestedParens * 0.1 + Math.min(length / 100, 0.5)));
  }

  _calculateCodeComplexity(code) {
    if (!code) return 0;
    
    const lines = code.split('\n').filter(l => l.trim().length > 0);
    const avgLength = lines.reduce((sum, l) => sum + l.length, 0) / lines.length;
    const keywordCount = (code.match(/\b(function|class|if|else|for|while|switch|case|return)\b/gi) || []).length;
    
    return Math.min(1.0, (avgLength / 80 + keywordCount / lines.length) / 2);
  }

  _looksLikeTestCode(content) {
    const lowerContent = content.toLowerCase();
    return this._testFilePatterns.some(pattern => pattern.test(lowerContent));
  }

  filterFalsePositives(findings, options = {}) {
    const minConfidence = options.minConfidence || 0.5;
    const enableHeuristic = options.enableHeuristic !== false;
    const filePath = options.filePath || '';
    
    let filtered = findings.filter(f => f.confidence >= minConfidence);
    
    if (enableHeuristic) {
      filtered = filtered.filter(f => !this._isHeuristicFalsePositive(f, filePath));
    }
    
    this._performanceStats.totalFalsePositives += findings.length - filtered.length;
    
    return filtered;
  }

  _isHeuristicFalsePositive(finding, filePath = '') {
    if (!finding.context || !finding.match) {
      return false;
    }
    
    if (this._isTestFile(filePath)) {
      return true;
    }
    
    const targetLine = finding.context.find(c => c.isTarget);
    if (!targetLine) {
      return false;
    }
    
    const lineContent = targetLine.content.toLowerCase();
    
    if (this._looksLikeTestCode(lineContent)) {
      return true;
    }
    
    for (const exclusionPattern of this._customFalsePositivePatterns) {
      const regex = this._createRegex(exclusionPattern);
      if (regex && regex.test(lineContent)) {
        return true;
      }
    }
    
    const surroundingContent = finding.context.map(c => c.content.toLowerCase()).join(' ');
    if (this._looksLikeTestCode(surroundingContent)) {
      return true;
    }
    
    return false;
  }

  _isTestFile(filePath) {
    const testPatterns = [
      /test/i, /spec/i, /__tests__/, /_test\./, /\.test\./, /\.spec\./
    ];
    return testPatterns.some(pattern => pattern.test(filePath));
  }

  addCustomFalsePositivePattern(pattern) {
    this._customFalsePositivePatterns.push(pattern);
  }

  recordFalsePositive(ruleId) {
    const current = this._falsePositiveHistory.get(ruleId) || { count: 0, total: 0 };
    current.count++;
    current.total++;
    this._falsePositiveHistory.set(ruleId, current);
  }

  recordTruePositive(ruleId) {
    const current = this._falsePositiveHistory.get(ruleId) || { count: 0, total: 0 };
    current.total++;
    this._falsePositiveHistory.set(ruleId, current);
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
          count: cluster.length,
          severity: cluster[0].severity
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

  matchWithContext(code, language, options = {}) {
    const lang = language.toLowerCase();
    const contextWindow = options.contextWindow || 3;
    const results = [];

    const sources = this.getTaintSources(lang);
    const sinks = this.getTaintSinks(lang);

    for (const source of sources) {
      for (const pattern of source.patterns || []) {
        const regex = this._createRegex(pattern);
        if (!regex) continue;
        
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
            confidence: this._calculateConfidence(source, context, code)
          });
        }
      }
    }

    for (const sink of sinks) {
      for (const pattern of sink.patterns || []) {
        const regex = this._createRegex(pattern);
        if (!regex) continue;
        
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
            confidence: this._calculateConfidence(sink, context, code)
          });
        }
      }
    }

    return results.sort((a, b) => b.confidence - a.confidence);
  }

  async analyzeCodeParallel(code, language, options = {}) {
    const lang = language.toLowerCase();
    const rules = this.getRulesForLanguage(lang);
    
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

    const promises = rules.map(rule => 
      this.matchVulnerability(code, rule.id, lang)
    );

    const allMatches = await Promise.all(promises);
    const vulnerabilities = allMatches.flat();
    
    results.vulnerabilities = this.filterFalsePositives(vulnerabilities, {
      minConfidence: options.minConfidence,
      filePath: options.filePath
    });
    
    results.sources = this.matchSources(code, lang);
    results.sinks = this.matchSinks(code, lang);
    results.clusters = this.clusterFindings(results.vulnerabilities, options);
    
    results.summary.totalFindings = results.vulnerabilities.length;
    for (const finding of results.vulnerabilities) {
      const severity = finding.severity?.toUpperCase() || 'MEDIUM';
      results.summary.bySeverity[severity] = (results.summary.bySeverity[severity] || 0) + 1;
      
      const category = finding.category || 'Other';
      results.summary.byCategory[category] = (results.summary.byCategory[category] || 0) + 1;
    }
    
    return results;
  }

  analyzeCode(code, language, options = {}) {
    const useParallel = options.parallel !== false;
    
    if (useParallel) {
      return this.analyzeCodeParallel(code, language, options);
    }
    
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
    this._regexCache.clear();
  }

  getPerformanceStats() {
    return { ...this._performanceStats };
  }

  getVersion() {
    return this.rules?.version || '1.0.0';
  }

  updateRuleVersion(newVersion) {
    if (this.rules) {
      this.rules.version = newVersion;
    }
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

export { LRUCache };