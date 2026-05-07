/**
 * 静态分析器
 * 综合多种分析技术的静态代码分析器
 */

import { AsyncBaseAnalyzer } from './baseAnalyzer.js';
import { PatternAnalyzer } from './patternAnalyzer.js';
import { TaintAnalyzer } from './taintAnalyzer.js';
import { Semaphore } from '../utils/semaphore.js';

export class StaticAnalyzer extends AsyncBaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);

    this.patternAnalyzer = new PatternAnalyzer(rulesEngine, options);
    this.taintAnalyzer = new TaintAnalyzer(rulesEngine, options);

    this.options = {
      enablePatternAnalysis: options.enablePatternAnalysis !== false,
      enableTaintAnalysis: options.enableTaintAnalysis !== false,
      ...options
    };
  }

  getSupportedLanguages() {
    return this.rulesEngine?.getSupportedLanguages() || [];
  }

  async analyze(code, context = {}) {
    const language = context.language || this._language || 'unknown';
    this.setLanguage(language);

    this._validateCode(code);

    const results = {
      success: true,
      language,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        byType: {}
      },
      analysisDetails: {}
    };

    const analysisPromises = [];

    if (this.options.enablePatternAnalysis) {
      analysisPromises.push(
        this._runPatternAnalysis(code, language, context)
          .then(r => { results.analysisDetails.pattern = r; })
      );
    }

    if (this.options.enableTaintAnalysis) {
      analysisPromises.push(
        this._runTaintAnalysis(code, language, context)
          .then(r => { results.analysisDetails.taint = r; })
      );
    }

    await Promise.all(analysisPromises);

    this._mergeResults(results);

    return results;
  }

  async _runPatternAnalysis(code, language, context) {
    try {
      return await this.patternAnalyzer.analyze(code, { language, ...context });
    } catch (error) {
      console.error('[StaticAnalyzer] Pattern analysis failed:', error);
      return { vulnerabilities: [], summary: {} };
    }
  }

  async _runTaintAnalysis(code, language, context) {
    try {
      return await this.taintAnalyzer.analyze(code, { language, ...context });
    } catch (error) {
      console.error('[StaticAnalyzer] Taint analysis failed:', error);
      return { vulnerabilities: [], taintSources: [], taintSinks: [] };
    }
  }

  _mergeResults(results) {
    const allVulnerabilities = [];

    if (results.analysisDetails.pattern?.vulnerabilities) {
      for (const vuln of results.analysisDetails.pattern.vulnerabilities) {
        allVulnerabilities.push({
          ...vuln,
          source: 'pattern'
        });
      }
    }

    if (results.analysisDetails.taint?.vulnerabilities) {
      for (const vuln of results.analysisDetails.taint.vulnerabilities) {
        allVulnerabilities.push({
          ...vuln,
          source: 'taint'
        });
      }
    }

    results.vulnerabilities = this._deduplicateVulnerabilities(allVulnerabilities);

    for (const vuln of results.vulnerabilities) {
      results.summary.total++;
      const severity = vuln.severity?.toLowerCase() || 'medium';
      if (['critical', 'high', 'medium', 'low'].includes(severity)) {
        results.summary[severity]++;
      }

      const type = vuln.type;
      results.summary.byType[type] = (results.summary.byType[type] || 0) + 1;
    }
  }

  _deduplicateVulnerabilities(vulnerabilities) {
    const seen = new Map();

    for (const vuln of vulnerabilities) {
      const key = `${vuln.type}:${vuln.location?.line || 0}:${vuln.evidence || ''}`;

      if (seen.has(key)) {
        const existing = seen.get(key);
        if (this._isBetterSeverity(vuln.severity, existing.severity)) {
          seen.set(key, vuln);
        }
      } else {
        seen.set(key, vuln);
      }
    }

    return Array.from(seen.values());
  }

  _isBetterSeverity(newSeverity, existingSeverity) {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    const newOrder = order[newSeverity?.toLowerCase()] || 0;
    const existingOrder = order[existingSeverity?.toLowerCase()] || 0;
    return newOrder > existingOrder;
  }

  async analyzeMultiple(files, options = {}) {
    const results = [];
    const { concurrency = 3 } = options;

    const semaphore = new Semaphore(concurrency);

    const tasks = files.map(async (file) => {
      await semaphore.acquire();
      try {
        const result = await this.analyze(file.code, {
          language: file.language || this._detectLanguage(file.path),
          path: file.path
        });
        return {
          ...result,
          path: file.path
        };
      } finally {
        semaphore.release();
      }
    });

    return Promise.all(tasks);
  }

  _detectLanguage(filePath) {
    return this._inferLanguage(filePath);
  }
}
