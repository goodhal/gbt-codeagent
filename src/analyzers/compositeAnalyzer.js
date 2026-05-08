/**
 * 组合分析器
 * 组合多种分析器进行综合分析
 */

import { StaticAnalyzer } from './staticAnalyzer.js';
import { TaintAnalyzer } from './taintAnalyzer.js';
import { PatternAnalyzer } from './patternAnalyzer.js';
import { BaseAnalyzer } from './baseAnalyzer.js';
import { Semaphore } from '../utils/semaphore.js';

export class CompositeAnalyzer extends BaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);
    this.rulesEngine = rulesEngine;
    this.options = options;

    this.analyzers = new Map();
    this._initializeAnalyzers(options);
  }

  _initializeAnalyzers(options) {
    if (options.enableStatic !== false) {
      this.analyzers.set('static', new StaticAnalyzer(this.rulesEngine, options));
    }

    if (options.enableTaint !== false) {
      this.analyzers.set('taint', new TaintAnalyzer(options));
    }

    if (options.enablePattern !== false) {
      this.analyzers.set('pattern', new PatternAnalyzer(this.rulesEngine, options));
    }
  }

  getAnalyzer(name) {
    return this.analyzers.get(name);
  }

  addAnalyzer(name, analyzer) {
    this.analyzers.set(name, analyzer);
  }

  removeAnalyzer(name) {
    this.analyzers.delete(name);
  }

  async analyze(code, context = {}) {
    const results = {
      success: true,
      timestamp: new Date().toISOString(),
      analyzers: [],
      vulnerabilities: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        byAnalyzer: {},
        byType: {}
      }
    };

    const analyzerResults = await Promise.all(
      Array.from(this.analyzers.entries()).map(async ([name, analyzer]) => {
        try {
          const result = await analyzer.analyze(code, context);
          return { name, result, success: true };
        } catch (error) {
          console.error(`[CompositeAnalyzer] ${name} failed:`, error);
          return { name, result: null, success: false, error: error.message };
        }
      })
    );

    for (const { name, result, success } of analyzerResults) {
      results.analyzers.push({
        name,
        success,
        error: result?.error || null
      });

      if (success && result) {
        this._mergeAnalyzerResult(results, name, result);
      }
    }

    return results;
  }

  _mergeAnalyzerResult(results, analyzerName, analyzerResult) {
    const vulnerabilities = analyzerResult.vulnerabilities || [];

    for (const vuln of vulnerabilities) {
      results.vulnerabilities.push({
        ...vuln,
        analyzer: analyzerName
      });

      const severity = vuln.severity?.toLowerCase() || 'medium';
      results.summary.byAnalyzer[analyzerName] = (results.summary.byAnalyzer[analyzerName] || 0) + 1;

      if (['critical', 'high', 'medium', 'low'].includes(severity)) {
        results.summary[severity]++;
      }

      const type = vuln.type;
      results.summary.byType[type] = (results.summary.byType[type] || 0) + 1;
    }

    results.summary.total = results.vulnerabilities.length;
  }

  async analyzeMultiple(files, options = {}) {
    const { concurrency = 3 } = options;
    const results = [];

    const semaphore = new Semaphore(concurrency);

    const tasks = files.map(async (file) => {
      await semaphore.acquire();
      try {
        const result = await this.analyze(file.code, {
          language: file.language,
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

  async analyzeProject(files, options = {}) {
    const { minSeverity = 'LOW', maxIssuesPerFile = 50 } = options;

    const results = await this.analyzeMultiple(files, options);

    const filtered = results.filter(r => {
      r.vulnerabilities = r.vulnerabilities
        .filter(v => this._meetsSeverityThreshold(v.severity, minSeverity))
        .slice(0, maxIssuesPerFile);
      return r.vulnerabilities.length > 0;
    });

    const summary = this._aggregateProjectSummary(filtered);

    return {
      success: true,
      filesAnalyzed: results.length,
      filesWithVulnerabilities: filtered.length,
      summary,
      results: filtered
    };
  }

  _meetsSeverityThreshold(severity, threshold) {
    const order = { low: 1, medium: 2, high: 3, critical: 4 };
    const severityLevel = order[severity?.toLowerCase()] || 0;
    const thresholdLevel = order[threshold?.toLowerCase()] || 0;
    return severityLevel >= thresholdLevel;
  }

  _aggregateProjectSummary(results) {
    const summary = {
      totalFiles: results.length,
      filesWithVulnerabilities: 0,
      totalVulnerabilities: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      byType: {},
      byAnalyzer: {}
    };

    for (const result of results) {
      if (result.vulnerabilities.length > 0) {
        summary.filesWithVulnerabilities++;
      }

      for (const vuln of result.vulnerabilities) {
        summary.totalVulnerabilities++;

        const severity = vuln.severity?.toLowerCase() || 'medium';
        if (['critical', 'high', 'medium', 'low'].includes(severity)) {
          summary[severity]++;
        }

        summary.byType[vuln.type] = (summary.byType[vuln.type] || 0) + 1;
        summary.byAnalyzer[vuln.analyzer] = (summary.byAnalyzer[vuln.analyzer] || 0) + 1;
      }
    }

    return summary;
  }

  clearCache() {
    for (const analyzer of this.analyzers.values()) {
      if (typeof analyzer.clearCache === 'function') {
        analyzer.clearCache();
      }
    }
  }
}
