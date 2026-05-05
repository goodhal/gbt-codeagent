/**
 * 污点追踪分析器
 * 实现数据流分析，跟踪用户输入到危险函数的传播路径
 */

import { AsyncBaseAnalyzer } from './baseAnalyzer.js';

export class TaintAnalyzer extends AsyncBaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);
    this._variableMap = new Map();
    this._callStack = [];
  }

  getSupportedLanguages() {
    return this.rulesEngine?.getSupportedLanguages() || [];
  }

  async analyze(code, context = {}) {
    const language = context.language || this._language || 'unknown';
    this.setLanguage(language);

    this._validateCode(code);
    this._resetState();

    const results = {
      success: true,
      language,
      taintSources: [],
      taintSinks: [],
      sanitizers: [],
      vulnerabilities: [],
      dataFlows: []
    };

    const sources = this.rulesEngine.matchSources(code, language);
    const sinks = this.rulesEngine.matchSinks(code, language);
    const sanitizers = this.rulesEngine.matchSanitizers(code, language);

    results.taintSources = sources;
    results.taintSinks = sinks;
    results.sanitizers = sanitizers;

    for (const sink of sinks) {
      const vuln = this._analyzeTaintPath(code, sink, sources, sanitizers, language);
      if (vuln) {
        results.vulnerabilities.push(vuln);
        results.dataFlows.push(...vuln.dataFlow);
      }
    }

    delete results.dataFlows;
    return results;
  }

  _resetState() {
    this._variableMap.clear();
    this._callStack = [];
  }

  _analyzeTaintPath(code, sink, sources, sanitizers, language) {
    const sinkLine = sink.line;
    const nearbySources = sources.filter(s => Math.abs(s.line - sinkLine) <= 20);

    if (nearbySources.length === 0) {
      return null;
    }

    const hasSanitizer = sanitizers.some(s =>
      s.line > nearbySources[0].line && s.line < sinkLine
    );

    if (hasSanitizer) {
      return null;
    }

    const dataFlow = this._traceDataFlow(code, nearbySources[0], sink, language);

    return {
      type: `TAINT:${sink.category || 'unknown'}`,
      severity: sink.severity || 'HIGH',
      location: {
        file: 'unknown',
        line: sink.line,
        column: 0
      },
      description: `污点从 ${nearbySources[0].name} 传播到危险函数 ${sink.name}`,
      evidence: this._getEvidence(code, sink.line),
      remediation: this._getRemediation(sink),
      sink: {
        name: sink.name,
        category: sink.category,
        pattern: sink.pattern
      },
      source: {
        name: nearbySources[0].name,
        category: nearbySources[0].category,
        pattern: nearbySources[0].pattern
      },
      dataFlow: dataFlow.map(d => ({
        type: d.type,
        description: d.description
      }))
    };
  }

  _traceDataFlow(code, source, sink, language) {
    const flow = [];
    const lines = code.split('\n');

    const sourceLine = source.line - 1;
    const sinkLine = sink.line - 1;

    flow.push({
      type: 'source',
      description: `第 ${source.line} 行: ${source.name} (${source.match})`
    });

    for (let i = sourceLine + 1; i < sinkLine; i++) {
      const line = lines[i];

      if (this._isVariableAssignment(line, language)) {
        const assignment = this._parseAssignment(line);
        if (assignment) {
          flow.push({
            type: 'propagation',
            description: `第 ${i + 1} 行: 变量赋值 ${assignment.variable} = ${assignment.value}`
          });
        }
      }

      if (this._isFunctionCall(line, language)) {
        const func = this._parseFunctionCall(line);
        if (func) {
          flow.push({
            type: 'function_call',
            description: `第 ${i + 1} 行: 函数调用 ${func.name}(${func.args})`
          });
        }
      }
    }

    flow.push({
      type: 'sink',
      description: `第 ${sink.line} 行: ${sink.name} (${sink.match})`
    });

    return flow;
  }

  _isVariableAssignment(line, language) {
    const patterns = {
      python: /^\s*(\w+)\s*=\s*.+$/,
      javascript: /^\s*(const|let|var)?\s*(\w+)\s*=\s*.+$/,
      java: /^\s*[\w<>]+\s+(\w+)\s*=\s*.+$/
    };

    const pattern = patterns[language] || patterns.python;
    return pattern.test(line.trim());
  }

  _parseAssignment(line) {
    const match = line.match(/^\s*(\w+)\s*=\s*(.+)$/);
    if (match) {
      return {
        variable: match[1],
        value: match[2].trim()
      };
    }
    return null;
  }

  _isFunctionCall(line, language) {
    const callPatterns = [
      /\w+\s*\([^)]*\)/,
      /\$\w+\s*\([^)]*\)/,
      /this\.\w+\s*\([^)]*\)/
    ];

    return callPatterns.some(p => p.test(line.trim()));
  }

  _parseFunctionCall(line) {
    const match = line.match(/(\w+)\s*\(([^)]*)\)/);
    if (match) {
      return {
        name: match[1],
        args: match[2]
      };
    }
    return null;
  }

  _getEvidence(code, lineNumber) {
    const lines = code.split('\n');
    const start = Math.max(0, lineNumber - 3);
    const end = Math.min(lines.length, lineNumber + 2);

    return lines.slice(start, end).map((l, i) => ({
      lineNumber: start + i + 1,
      content: l,
      marker: i + 1 === lineNumber - start ? '>>>' : '   '
    }));
  }

  _getRemediation(sink) {
    const remediations = {
      command_exec: '使用安全的 API 替代 shell 命令，避免字符串拼接',
      sql_injection: '使用参数化查询或 ORM',
      code_injection: '避免使用 eval/exec，对输入进行严格验证',
      xss: '对输出进行 HTML 编码，使用 textContent 替代 innerHTML',
      file_operation: '验证文件路径，使用 path.resolve() 规范化',
      deserialization: '使用安全的序列化格式如 JSON',
      ssrf: '验证和限制 URL，禁用重定向跟随'
    };

    return remediations[sink.category] || '对用户输入进行严格验证和过滤';
  }
}
