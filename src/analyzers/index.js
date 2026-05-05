/**
 * 分析器模块入口
 * 统一的分析器接口，支持多语言、多类型分析
 */

import { StaticAnalyzer } from './staticAnalyzer.js';
import { TaintAnalyzer } from './taintAnalyzer.js';
import { PatternAnalyzer } from './patternAnalyzer.js';
import { CompositeAnalyzer } from './compositeAnalyzer.js';
import { RulesEngine, getRulesEngine } from './rulesEngine.js';

export {
  StaticAnalyzer,
  TaintAnalyzer,
  PatternAnalyzer,
  CompositeAnalyzer,
  RulesEngine,
  getRulesEngine
};

export class AnalyzerFactory {
  constructor(rulesEngine) {
    this.rulesEngine = rulesEngine;
    this._analyzers = new Map();
  }

  createAnalyzer(type, options = {}) {
    switch (type) {
      case 'static':
        if (!this._analyzers.has('static')) {
          this._analyzers.set('static', new StaticAnalyzer(this.rulesEngine, options));
        }
        return this._analyzers.get('static');

      case 'taint':
        if (!this._analyzers.has('taint')) {
          this._analyzers.set('taint', new TaintAnalyzer(this.rulesEngine, options));
        }
        return this._analyzers.get('taint');

      case 'pattern':
        if (!this._analyzers.has('pattern')) {
          this._analyzers.set('pattern', new PatternAnalyzer(this.rulesEngine, options));
        }
        return this._analyzers.get('pattern');

      case 'composite':
        return new CompositeAnalyzer(this.rulesEngine, options);

      default:
        throw new Error(`Unknown analyzer type: ${type}`);
    }
  }

  clearCache() {
    this._analyzers.clear();
  }
}
