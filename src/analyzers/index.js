/**
 * 分析器模块入口
 * 统一的分析器接口，支持多语言、多类型分析
 */

import { StaticAnalyzer } from './staticAnalyzer.js';
import { TaintAnalyzer } from './taintAnalyzer.js';
import { PatternAnalyzer } from './patternAnalyzer.js';
import { CompositeAnalyzer } from './compositeAnalyzer.js';
import { BaseAnalyzer } from './baseAnalyzer.js';
import { RulesEngine, getRulesEngine, resetRulesEngine } from './rulesEngine.js';

export {
  StaticAnalyzer,
  TaintAnalyzer,
  PatternAnalyzer,
  CompositeAnalyzer,
  BaseAnalyzer,
  RulesEngine,
  getRulesEngine,
  resetRulesEngine
};
