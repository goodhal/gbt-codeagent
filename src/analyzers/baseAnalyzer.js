/**
 * 基础分析器类
 * 定义分析器的通用接口和工具方法
 */

export class BaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    this.rulesEngine = rulesEngine;
    this.options = {
      maxLineLength: options.maxLineLength || 10000,
      timeout: options.timeout || 30000,
      ...options
    };
    this._cache = new Map();
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

  canAnalyze(language) {
    const supportedLanguages = this.getSupportedLanguages();
    return supportedLanguages.includes(language.toLowerCase());
  }

  getSupportedLanguages() {
    return [];
  }

  clearCache() {
    this._cache.clear();
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
}

class Semaphore {
  constructor(max) {
    this.max = max;
    this.current = 0;
    this.waiting = [];
  }

  async acquire() {
    if (this.current < this.max) {
      this.current++;
      return;
    }

    return new Promise(resolve => {
      this.waiting.push(resolve);
    });
  }

  release() {
    this.current--;
    if (this.waiting.length > 0) {
      this.current++;
      const resolve = this.waiting.shift();
      resolve();
    }
  }
}
