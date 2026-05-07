/**
 * 基础分析器类
 * 定义分析器的通用接口和工具方法
 */

import { Semaphore } from '../utils/semaphore.js';

export class BaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    this.rulesEngine = rulesEngine;
    this.options = {
      maxLineLength: options.maxLineLength || 10000,
      timeout: options.timeout || 30000,
      cacheEnabled: options.cacheEnabled !== undefined ? options.cacheEnabled : true,
      cacheTTL: options.cacheTTL || 3600000, // 1小时
      incrementalEnabled: options.incrementalEnabled !== undefined ? options.incrementalEnabled : true,
      ...options
    };
    this._cache = new Map();
    this._cacheTimestamps = new Map();
    this._analysisStats = {
      totalAnalyses: 0,
      cacheHits: 0,
      cacheMisses: 0,
      incrementalSkips: 0,
      avgAnalysisTime: 0,
      totalAnalysisTime: 0
    };
  }

  get language() {
    return this._language;
  }

  setLanguage(language) {
    this._language = language;
    return this;
  }

  async analyze(code, context = {}) {
    throw new Error('analyze() must be implemented by subclass');
  }

  async analyzeWithIncremental(code, context = {}) {
    const startTime = Date.now();
    this._analysisStats.totalAnalyses++;

    if (this.options.incrementalEnabled && context?.diffInfo) {
      const skipReason = this._checkIncrementalSkip(code, context);
      if (skipReason) {
        this._analysisStats.incrementalSkips++;
        return { findings: [], skipped: true, reason: skipReason };
      }
    }

    const cacheKey = this._getCacheKey(code, context);
    if (this.options.cacheEnabled) {
      const cachedResult = this._getCachedResult(cacheKey);
      if (cachedResult) {
        this._analysisStats.cacheHits++;
        return cachedResult;
      }
    }

    this._analysisStats.cacheMisses++;
    const result = await this.analyze(code, context);
    
    if (this.options.cacheEnabled) {
      this._cacheResult(cacheKey, result);
    }

    const analysisTime = Date.now() - startTime;
    this._analysisStats.totalAnalysisTime += analysisTime;
    this._analysisStats.avgAnalysisTime = 
      this._analysisStats.totalAnalysisTime / this._analysisStats.totalAnalyses;

    return result;
  }

  async analyzeWithContext(code, context = {}) {
    const startTime = Date.now();
    
    const options = {
      contextWindow: context.contextWindow || 3,
      minConfidence: context.minConfidence || 0.5,
      similarityThreshold: context.similarityThreshold || 0.8
    };

    const result = await this.analyze(code, context);
    
    if (this._rulesEngine) {
      const filtered = this._rulesEngine.filterFalsePositives(
        result.findings || [],
        options
      );
      const clusters = this._rulesEngine.clusterFindings(filtered, options);
      
      return {
        ...result,
        findings: filtered,
        clusters,
        filteredCount: result.findings?.length - filtered.length || 0,
        analysisTime: Date.now() - startTime
      };
    }

    return {
      ...result,
      analysisTime: Date.now() - startTime
    };
  }

  async detectOWASPTop10(code, context = {}) {
    if (!this._rulesEngine) {
      return { findings: [], category: 'OWASP Top 10' };
    }

    const language = context.language || this._defaultLanguage || 'javascript';
    const findings = this._rulesEngine.detectOWASPTop10(code, language);
    
    return {
      findings,
      category: 'OWASP Top 10',
      count: findings.length
    };
  }

  async detectGBTStandards(code, context = {}) {
    if (!this._rulesEngine) {
      return { findings: [], category: 'GB/T Standard' };
    }

    const language = context.language || this._defaultLanguage || 'javascript';
    const findings = this._rulesEngine.detectGBTStandards(code, language);
    
    return {
      findings,
      category: 'GB/T Standard',
      count: findings.length
    };
  }

  async comprehensiveAnalysis(code, context = {}) {
    const startTime = Date.now();
    
    const results = await Promise.all([
      this.analyzeWithContext(code, context),
      this.detectOWASPTop10(code, context),
      this.detectGBTStandards(code, context)
    ]);

    const mainResult = results[0];
    const owaspResult = results[1];
    const gbtResult = results[2];

    const allFindings = [
      ...mainResult.findings,
      ...owaspResult.findings,
      ...gbtResult.findings
    ];

    const clusters = this._rulesEngine?.clusterFindings(allFindings, {
      similarityThreshold: context.similarityThreshold || 0.8
    }) || [];

    const summary = this._generateSummary(allFindings);

    return {
      findings: allFindings,
      clusters,
      summary,
      breakdown: {
        standard: mainResult,
        owasp: owaspResult,
        gbt: gbtResult
      },
      totalAnalysisTime: Date.now() - startTime
    };
  }

  _generateSummary(findings) {
    const summary = {
      total: findings.length,
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      byCategory: {},
      byConfidence: { high: 0, medium: 0, low: 0 }
    };

    for (const finding of findings) {
      const severity = finding.severity?.toUpperCase() || 'MEDIUM';
      summary.bySeverity[severity] = (summary.bySeverity[severity] || 0) + 1;

      const category = finding.category || 'Other';
      summary.byCategory[category] = (summary.byCategory[category] || 0) + 1;

      const confidence = finding.confidence || 0.7;
      if (confidence >= 0.8) summary.byConfidence.high++;
      else if (confidence >= 0.5) summary.byConfidence.medium++;
      else summary.byConfidence.low++;
    }

    return summary;
  }

  _checkIncrementalSkip(code, context) {
    const { diffInfo } = context;
    if (!diffInfo?.changedLines) {
      return null;
    }

    const codeLines = code.split('\n');
    const hasChangedLines = diffInfo.changedLines.some(lineNum => 
      lineNum > 0 && lineNum <= codeLines.length
    );

    if (!hasChangedLines) {
      return 'No changed lines in analyzed code';
    }

    if (diffInfo.onlyWhitespace && !this._hasNonWhitespaceChanges(code, diffInfo.changedLines)) {
      return 'Only whitespace changes';
    }

    return null;
  }

  _hasNonWhitespaceChanges(code, changedLines) {
    const lines = code.split('\n');
    return changedLines.some(lineNum => {
      const line = lines[lineNum - 1];
      return line && line.trim().length > 0;
    });
  }

  _getCachedResult(cacheKey) {
    const timestamp = this._cacheTimestamps.get(cacheKey);
    if (!timestamp) {
      return null;
    }

    if (Date.now() - timestamp > this.options.cacheTTL) {
      this._cache.delete(cacheKey);
      this._cacheTimestamps.delete(cacheKey);
      return null;
    }

    return this._cache.get(cacheKey);
  }

  _cacheResult(cacheKey, result) {
    this._cache.set(cacheKey, result);
    this._cacheTimestamps.set(cacheKey, Date.now());
    this._trimCache();
  }

  _trimCache(maxEntries = 1000) {
    if (this._cache.size <= maxEntries) {
      return;
    }

    const oldestKeys = [...this._cacheTimestamps.entries()]
      .sort((a, b) => a[1] - b[1])
      .map(([key]) => key)
      .slice(0, this._cache.size - maxEntries);

    for (const key of oldestKeys) {
      this._cache.delete(key);
      this._cacheTimestamps.delete(key);
    }
  }

  getAnalysisStats() {
    return { ...this._analysisStats };
  }

  canAnalyze(language) {
    const supportedLanguages = this.getSupportedLanguages();
    return supportedLanguages.includes(language.toLowerCase());
  }

  getSupportedLanguages() {
    return [];
  }

  clearCache() {
    this._cache.clear();
    this._cacheTimestamps.clear();
  }

  _getCacheKey(code, context) {
    const codeHash = this._hashCode(code);
    const contextHash = JSON.stringify(context);
    return `${codeHash}:${contextHash}`;
  }

  _hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  _createVulnerability(type, severity, location, description, evidence, remediation, metadata = {}) {
    return {
      type,
      severity: severity.toUpperCase(),
      location,
      description,
      evidence,
      remediation,
      metadata: {
        analyzer: this.constructor.name,
        language: this._language,
        ...metadata
      }
    };
  }

  _extractLineNumber(code, matchIndex) {
    const lines = code.substring(0, matchIndex).split('\n');
    return lines.length;
  }

  _getLineContext(code, lineNumber, contextLines = 3) {
    const lines = code.split('\n');
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);

    return {
      before: lines.slice(start, lineNumber - 1),
      line: lines[lineNumber - 1],
      after: lines.slice(lineNumber, end),
      full: lines.slice(start, end).join('\n')
    };
  }

  _validateCode(code) {
    if (!code || typeof code !== 'string') {
      throw new Error('Code must be a non-empty string');
    }
    if (code.length > this.options.maxLineLength * 1000) {
      throw new Error(`Code too large: ${code.length} bytes`);
    }
    return true;
  }
}

export class AsyncBaseAnalyzer extends BaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);
    this._semaphore = null;
    this._maxConcurrency = options.maxConcurrency || 5;
  }

  async analyzeWithTimeout(code, context = {}, timeout = null) {
    const timeoutMs = timeout || this.options.timeout;

    return Promise.race([
      this.analyze(code, context),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Analysis timeout')), timeoutMs)
      )
    ]);
  }

  async analyzeBatch(codes, context = {}) {
    const results = [];
    const semaphore = new Semaphore(this._maxConcurrency);

    const tasks = codes.map((code, index) =>
      semaphore.acquire().then(async () => {
        try {
          const result = await this.analyze(code, { ...context, index });
          results[index] = result;
        } catch (error) {
          results[index] = { success: false, error: error.message };
        } finally {
          semaphore.release();
        }
      })
    );

    await Promise.all(tasks);
    return results;
  }

  _inferLanguage(filePath) {
    const ext = filePath.match(/\.[^.]+$/)?.[0] || '';
    const map = {
      '.py': 'python',
      '.js': 'javascript',
      '.ts': 'typescript',
      '.jsx': 'javascript',
      '.tsx': 'typescript',
      '.java': 'java',
      '.php': 'php',
      '.go': 'go',
      '.rb': 'ruby',
      '.rs': 'rust',
      '.c': 'c',
      '.cpp': 'cpp',
      '.cs': 'csharp'
    };
    return map[ext] || 'unknown';
  }
}
