/**
 * 模式匹配分析器
 * 基于规则引擎中的模式进行漏洞检测
 */

import { AsyncBaseAnalyzer } from './baseAnalyzer.js';
import { Semaphore } from '../utils/semaphore.js';

export class PatternAnalyzer extends AsyncBaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);
  }

  getSupportedLanguages() {
    return this.rulesEngine?.getSupportedLanguages() || [];
  }

  async analyze(code, context = {}) {
    const language = context.language || this._language || 'unknown';
    this.setLanguage(language);

    this._validateCode(code);

    const cacheKey = this._getCacheKey(code, { language });
    if (this._cache.has(cacheKey)) {
      return this._cache.get(cacheKey);
    }

    const results = {
      success: true,
      language,
      vulnerabilities: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
    };

    const rules = this.rulesEngine.getRulesForLanguage(language);

    for (const rule of (rules || [])) {
      const matches = this.rulesEngine.matchVulnerability(code, rule.id, language);

      if (!matches || !matches[Symbol.iterator]) continue;

      for (const match of matches) {
        const vuln = this._createVulnerabilityFromMatch(match, rule);
        results.vulnerabilities.push(vuln);

        const severity = match.severity?.toLowerCase() || 'medium';
        results.summary[severity]++;
      }
    }

    this._cache.set(cacheKey, results);
    return results;
  }

  _createVulnerabilityFromMatch(match, rule) {
    return {
      type: match.ruleId || rule.id,
      severity: match.severity,
      location: {
        line: match.line,
        column: match.index
      },
      description: match.description || rule.description,
      evidence: match.match,
      cwe: match.cwe || rule.cwe,
      gbt: match.gbt,
      pattern: match.pattern,
      remediation: match.remediation || rule.remediation
    };
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
