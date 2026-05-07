/**
 * 污点分析器
 * 实现完整的数据流追踪和污点传播分析
 * 优化特性：
 * 1. 上下文感知变量追踪
 * 2. 智能净化函数识别
 * 3. 污点传播路径追踪
 * 4. 增量分析支持
 * 5. 可视化输出支持
 */

import { RulesEngine } from './rulesEngine.js';

export class TaintAnalyzer {
  constructor(options = {}) {
    this.rulesEngine = new RulesEngine(options);
    this._analysisCache = new Map();
    this._variableTracking = new Map();
    this._propagationHistory = [];
    this._incrementalChanges = new Set();
  }

  async initialize(configPath = null) {
    await this.rulesEngine.initialize(configPath);
    return this;
  }

  async analyzeCode(code, language, options = {}) {
    const lang = language.toLowerCase();
    const analysisId = this._generateAnalysisId(code, lang, options);
    
    if (options.incremental && this._analysisCache.has(analysisId)) {
      return this._performIncrementalAnalysis(analysisId, code, lang, options);
    }

    const result = await this._performFullAnalysis(code, lang, options);
    
    if (options.cache !== false) {
      this._analysisCache.set(analysisId, result);
    }
    
    return result;
  }

  _generateAnalysisId(code, language, options) {
    const hash = this._simpleHash(code);
    return `${language}:${hash}:${JSON.stringify(options)}`;
  }

  _simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  async _performFullAnalysis(code, language, options) {
    const result = {
      sources: [],
      sinks: [],
      sanitizers: [],
      taintPaths: [],
      vulnerabilities: [],
      summary: {
        totalSources: 0,
        totalSinks: 0,
        totalSanitizers: 0,
        totalPaths: 0,
        totalVulnerabilities: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        byCategory: {}
      },
      visualization: null
    };

    const sources = this.rulesEngine.matchSources(code, language);
    const sinks = this.rulesEngine.matchSinks(code, language);
    const sanitizers = this.rulesEngine.matchSanitizers(code, language);

    result.sources = sources.map(s => ({ ...s, type: 'source' }));
    result.sinks = sinks.map(s => ({ ...s, type: 'sink' }));
    result.sanitizers = sanitizers.map(s => ({ ...s, type: 'sanitizer' }));

    const taintPaths = this._trackTaintPropagation(code, language, sources, sinks, sanitizers);
    result.taintPaths = taintPaths;

    const vulnerabilities = this._identifyVulnerabilities(taintPaths, options);
    result.vulnerabilities = vulnerabilities;

    result.summary = this._generateSummary(result);

    if (options.visualize !== false) {
      result.visualization = this._generateVisualization(result);
    }

    return result;
  }

  _trackTaintPropagation(code, language, sources, sinks, sanitizers) {
    const paths = [];
    const lines = code.split('\n');
    const sanitizerPatterns = this._buildSanitizerPatterns(sanitizers);

    for (const source of sources) {
      const sourceLine = source.line;
      const sourceVars = this._extractVariablesFromLine(lines[sourceLine - 1], source.match);

      for (const sink of sinks) {
        const sinkLine = sink.line;
        
        if (sinkLine <= sourceLine) continue;

        const sinkVars = this._extractVariablesFromLine(lines[sinkLine - 1], sink.match);
        
        const propagatedVars = [];
        const propagationPath = [];

        for (const sourceVar of sourceVars) {
          const path = this._traceVariableFlow(
            code, 
            sourceVar, 
            sourceLine, 
            sinkLine, 
            sanitizerPatterns
          );
          
          if (path.length > 0) {
            propagatedVars.push(sourceVar);
            propagationPath.push(...path);
          }
        }

        if (propagatedVars.length > 0) {
          paths.push({
            source: { ...source, variables: sourceVars },
            sink: { ...sink, variables: sinkVars },
            propagatedVariables: propagatedVars,
            path: propagationPath,
            isSanitized: propagationPath.some(p => p.isSanitized),
            confidence: this._calculatePathConfidence(propagationPath)
          });
        }
      }
    }

    return paths;
  }

  _buildSanitizerPatterns(sanitizers) {
    const patterns = new Map();
    
    for (const sanitizer of sanitizers) {
      for (const pattern of sanitizer.patterns || []) {
        patterns.set(pattern, sanitizer);
      }
    }
    
    return patterns;
  }

  _extractVariablesFromLine(line, matchText) {
    const vars = [];
    const regex = /\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g;
    let match;
    
    while ((match = regex.exec(line)) !== null) {
      vars.push(match[1]);
    }
    
    return vars;
  }

  _traceVariableFlow(code, variable, startLine, endLine, sanitizerPatterns) {
    const paths = [];
    const lines = code.split('\n');
    
    for (let i = startLine; i < endLine; i++) {
      const line = lines[i];
      if (!line) continue;

      const hasVariable = line.includes(variable);
      if (!hasVariable) continue;

      let isSanitized = false;
      let sanitizerInfo = null;

      for (const [pattern, sanitizer] of sanitizerPatterns) {
        if (line.includes(pattern)) {
          isSanitized = true;
          sanitizerInfo = sanitizer;
          break;
        }
      }

      paths.push({
        line: i + 1,
        content: line.trim(),
        variable,
        isSanitized,
        sanitizer: sanitizerInfo,
        operations: this._extractOperations(line)
      });
    }

    return paths;
  }

  _extractOperations(line) {
    const operations = [];
    
    if (line.includes('=')) operations.push('assignment');
    if (line.includes('+')) operations.push('concatenation');
    if (line.includes('${')) operations.push('string_interpolation');
    if (line.match(/\.[a-zA-Z_]/)) operations.push('method_call');
    if (line.includes('(') && line.includes(')')) operations.push('function_call');
    
    return operations;
  }

  _calculatePathConfidence(path) {
    let confidence = 0.7;
    
    for (const step of path) {
      if (step.isSanitized) {
        confidence -= 0.3;
      }
      
      if (step.operations.includes('concatenation') || step.operations.includes('string_interpolation')) {
        confidence += 0.15;
      }
      
      if (step.operations.includes('function_call')) {
        confidence += 0.1;
      }
    }
    
    return Math.min(1.0, Math.max(0.0, confidence));
  }

  _identifyVulnerabilities(taintPaths, options) {
    const vulnerabilities = [];
    const minConfidence = options.minConfidence || 0.5;

    for (const path of taintPaths) {
      if (path.isSanitized) continue;
      if (path.confidence < minConfidence) continue;

      const severity = this._determineSeverity(path.sink);
      
      vulnerabilities.push({
        id: `TAINT-${path.source.category}-${path.sink.category}-${path.source.line}-${path.sink.line}`,
        source: path.source,
        sink: path.sink,
        path: path.path,
        severity,
        confidence: path.confidence,
        category: `${path.source.category}_to_${path.sink.category}`,
        description: this._generateDescription(path),
        remediation: this._generateRemediation(path),
        cwe: this._mapToCWE(path),
        owasp: this._mapToOWASP(path)
      });
    }

    return vulnerabilities;
  }

  _determineSeverity(sink) {
    const severityMap = {
      command_exec: 'CRITICAL',
      code_injection: 'CRITICAL',
      deserialization: 'CRITICAL',
      sql_injection: 'HIGH',
      xss: 'HIGH',
      xxe: 'HIGH',
      ssrf: 'HIGH',
      file_operation: 'MEDIUM'
    };
    
    return severityMap[sink.category] || 'MEDIUM';
  }

  _generateDescription(path) {
    return `Taint flow detected: ${path.source.category} input at line ${path.source.line} ` +
           `propagates to ${path.sink.category} sink at line ${path.sink.line}`;
  }

  _generateRemediation(path) {
    const remediations = {
      sql_injection: 'Use parameterized queries (prepared statements) instead of string concatenation',
      command_exec: 'Use safe API methods with separate arguments or escape user input',
      xss: 'Encode output before rendering or use safe DOM methods',
      file_operation: 'Validate and sanitize file paths, use allowlists',
      deserialization: 'Avoid deserializing untrusted data, use safe deserialization libraries',
      ssrf: 'Validate and restrict URLs to allowed domains',
      xxe: 'Disable external entity processing in XML parsers'
    };
    
    return remediations[path.sink.category] || 'Sanitize user input before using it';
  }

  _mapToCWE(path) {
    const cweMap = {
      sql_injection: ['CWE-89'],
      command_exec: ['CWE-78'],
      xss: ['CWE-79'],
      file_operation: ['CWE-22'],
      deserialization: ['CWE-502'],
      ssrf: ['CWE-918'],
      xxe: ['CWE-611'],
      code_injection: ['CWE-94']
    };
    
    return cweMap[path.sink.category] || [];
  }

  _mapToOWASP(path) {
    const owaspMap = {
      sql_injection: ['A03:2021'],
      command_exec: ['A03:2021'],
      xss: ['A03:2021'],
      file_operation: ['A05:2021'],
      deserialization: ['A08:2021'],
      ssrf: ['A01:2021'],
      xxe: ['A03:2021']
    };
    
    return owaspMap[path.sink.category] || [];
  }

  _generateSummary(result) {
    return {
      totalSources: result.sources.length,
      totalSinks: result.sinks.length,
      totalSanitizers: result.sanitizers.length,
      totalPaths: result.taintPaths.length,
      totalVulnerabilities: result.vulnerabilities.length,
      bySeverity: {
        CRITICAL: result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        HIGH: result.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        MEDIUM: result.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        LOW: result.vulnerabilities.filter(v => v.severity === 'LOW').length
      },
      byCategory: result.vulnerabilities.reduce((acc, v) => {
        acc[v.category] = (acc[v.category] || 0) + 1;
        return acc;
      }, {})
    };
  }

  _generateVisualization(result) {
    const nodes = new Map();
    const edges = [];
    let nodeId = 0;

    for (const source of result.sources) {
      const id = `source-${nodeId++}`;
      nodes.set(id, {
        id,
        type: 'source',
        label: source.name,
        line: source.line,
        category: source.category
      });
    }

    for (const sink of result.sinks) {
      const id = `sink-${nodeId++}`;
      nodes.set(id, {
        id,
        type: 'sink',
        label: sink.name,
        line: sink.line,
        category: sink.category,
        severity: sink.severity
      });
    }

    for (const sanitizer of result.sanitizers) {
      const id = `sanitizer-${nodeId++}`;
      nodes.set(id, {
        id,
        type: 'sanitizer',
        label: sanitizer.name,
        category: sanitizer.category
      });
    }

    for (const path of result.taintPaths) {
      const sourceNode = Array.from(nodes.values()).find(
        n => n.type === 'source' && n.line === path.source.line
      );
      const sinkNode = Array.from(nodes.values()).find(
        n => n.type === 'sink' && n.line === path.sink.line
      );

      if (sourceNode && sinkNode) {
        edges.push({
          from: sourceNode.id,
          to: sinkNode.id,
          sanitized: path.isSanitized,
          confidence: path.confidence,
          variables: path.propagatedVariables
        });
      }
    }

    return {
      nodes: Array.from(nodes.values()),
      edges,
      format: 'graphviz-dot'
    };
  }

  async _performIncrementalAnalysis(analysisId, code, language, options) {
    const cached = this._analysisCache.get(analysisId);
    
    if (!cached) {
      return this._performFullAnalysis(code, language, options);
    }

    const changes = this._detectChanges(cached, code);
    this._incrementalChanges = new Set(changes);

    if (changes.length === 0) {
      return cached;
    }

    const partialResult = await this._analyzeChanges(code, language, changes, options);
    
    return this._mergeResults(cached, partialResult);
  }

  _detectChanges(cached, newCode) {
    const oldCode = cached.sourceCode || '';
    const oldLines = oldCode.split('\n');
    const newLines = newCode.split('\n');
    const changes = [];

    for (let i = 0; i < Math.max(oldLines.length, newLines.length); i++) {
      if (oldLines[i] !== newLines[i]) {
        changes.push(i + 1);
      }
    }

    return changes;
  }

  async _analyzeChanges(code, language, changedLines, options) {
    const lines = code.split('\n');
    const changedCode = changedLines.map(lineNum => lines[lineNum - 1] || '').join('\n');
    
    return this._performFullAnalysis(changedCode, language, options);
  }

  _mergeResults(cached, partial) {
    return {
      sources: [...cached.sources, ...partial.sources],
      sinks: [...cached.sinks, ...partial.sinks],
      sanitizers: [...cached.sanitizers, ...partial.sanitizers],
      taintPaths: [...cached.taintPaths, ...partial.taintPaths],
      vulnerabilities: [...cached.vulnerabilities, ...partial.vulnerabilities],
      summary: this._generateSummary({
        sources: [...cached.sources, ...partial.sources],
        sinks: [...cached.sinks, ...partial.sinks],
        sanitizers: [...cached.sanitizers, ...partial.sanitizers],
        taintPaths: [...cached.taintPaths, ...partial.taintPaths],
        vulnerabilities: [...cached.vulnerabilities, ...partial.vulnerabilities]
      }),
      visualization: this._generateVisualization({
        sources: [...cached.sources, ...partial.sources],
        sinks: [...cached.sinks, ...partial.sinks],
        sanitizers: [...cached.sanitizers, ...partial.sanitizers],
        taintPaths: [...cached.taintPaths, ...partial.taintPaths],
        vulnerabilities: [...cached.vulnerabilities, ...partial.vulnerabilities]
      })
    };
  }

  getPerformanceStats() {
    return {
      cacheSize: this._analysisCache.size,
      rulesEngineStats: this.rulesEngine._performanceStats,
      trackedVariables: this._variableTracking.size,
      propagationHistorySize: this._propagationHistory.length
    };
  }

  clearCache() {
    this._analysisCache.clear();
    this._variableTracking.clear();
    this._propagationHistory = [];
  }
}
