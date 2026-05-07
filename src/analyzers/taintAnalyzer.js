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
    this._propagationDepth = options.propagationDepth || 50;
    this._enableTaintPropagation = options.enableTaintPropagation !== false;
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
      dataFlows: [],
      propagationPaths: []
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
        if (vuln.propagationPath) {
          results.propagationPaths.push(vuln.propagationPath);
        }
      }
    }

    delete results.dataFlows;
    delete results.propagationPaths;
    return results;
  }

  _resetState() {
    this._variableMap.clear();
    this._callStack = [];
  }

  _analyzeTaintPath(code, sink, sources, sanitizers, language) {
    const sinkLine = sink.line;
    const nearbySources = sources.filter(s => Math.abs(s.line - sinkLine) <= this._propagationDepth);

    if (nearbySources.length === 0) {
      return null;
    }

    const sanitizersBetween = sanitizers.filter(s =>
      s.line > Math.min(...nearbySources.map(src => src.line)) && s.line < sinkLine
    );

    const activeSanitizers = this._findActiveSanitizers(sanitizersBetween, code, language);

    if (activeSanitizers.length > 0 && !this._isSanitizerBypassed(activeSanitizers, nearbySources, sink)) {
      return null;
    }

    const bestSource = this._findBestSource(nearbySources, sink, sanitizers);
    if (!bestSource) {
      return null;
    }

    const dataFlow = this._traceDataFlow(code, bestSource, sink, language);
    const propagationPath = this._buildPropagationPath(code, bestSource, sink, dataFlow, language);

    return {
      type: `TAINT:${sink.category || 'unknown'}`,
      severity: sink.severity || 'HIGH',
      location: {
        file: 'unknown',
        line: sink.line,
        column: 0
      },
      description: `污点从 ${bestSource.name} 传播到危险函数 ${sink.name}`,
      evidence: this._getEvidence(code, sink.line),
      remediation: this._getRemediation(sink),
      confidence: this._calculateConfidence(bestSource, sink, sanitizers, dataFlow),
      sink: {
        name: sink.name,
        category: sink.category,
        pattern: sink.pattern,
        id: sink.id
      },
      source: {
        name: bestSource.name,
        category: bestSource.category,
        pattern: bestSource.pattern
      },
      dataFlow: dataFlow.map(d => ({
        type: d.type,
        description: d.description
      })),
      propagationPath
    };
  }

  _findBestSource(sources, sink, sanitizers) {
    let bestSource = null;
    let minDistance = Infinity;

    for (const source of sources) {
      const distance = sink.line - source.line;
      if (distance > 0 && distance < minDistance) {
        minDistance = distance;
        bestSource = source;
      }
    }

    return bestSource;
  }

  _findActiveSanitizers(sanitizers, code, language) {
    const active = [];
    for (const sanitizer of sanitizers) {
      if (this._isSanitizerEffective(sanitizer, code, language)) {
        active.push(sanitizer);
      }
    }
    return active;
  }

  _isSanitizerEffective(sanitizer, code, language) {
    const lineContent = code.split('\n')[sanitizer.line - 1] || '';

    const ineffectivePatterns = [
      /\/\/\s*todo/i,
      /\/\/\s*fixme/i,
      /\/\/\s*xxx/i,
      /#\s*todo/i,
      /#\s*fixme/i
    ];

    return !ineffectivePatterns.some(p => p.test(lineContent));
  }

  _isSanitizerBypassed(activeSanitizers, sources, sink) {
    if (activeSanitizers.length === 0) return false;

    for (const sanitizer of activeSanitizers) {
      for (const source of sources) {
        const sanitizerLine = sanitizer.line;
        const sourceLine = source.line;
        const sinkLine = sink.line;

        if (sanitizerLine > sourceLine && sanitizerLine < sinkLine) {
          const sourceVar = this._extractVariableFromPattern(source.pattern);
          const sinkVar = this._extractVariableFromPattern(sink.pattern);

          if (sourceVar && sinkVar && sourceVar !== sinkVar) {
            return true;
          }
        }
      }
    }

    return false;
  }

  _extractVariableFromPattern(pattern) {
    const match = pattern.match(/(\w+)/);
    return match ? match[1] : null;
  }

  _traceDataFlow(code, source, sink, language) {
    const flow = [];
    const lines = code.split('\n');

    const sourceLine = source.line - 1;
    const sinkLine = sink.line - 1;

    flow.push({
      type: 'source',
      description: `第 ${source.line} 行: ${source.name} (${source.match})`,
      line: source.line
    });

    for (let i = sourceLine + 1; i < sinkLine; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      if (this._isVariableAssignment(line, language)) {
        const assignment = this._parseAssignment(line);
        if (assignment) {
          flow.push({
            type: 'propagation',
            description: `第 ${lineNumber} 行: 变量赋值 ${assignment.variable} = ${assignment.value}`,
            line: lineNumber,
            variable: assignment.variable,
            value: assignment.value
          });
          this._variableMap.set(assignment.variable, { line: lineNumber, value: assignment.value });
        }
      }

      if (this._isFunctionCall(line, language)) {
        const func = this._parseFunctionCall(line);
        if (func) {
          flow.push({
            type: 'function_call',
            description: `第 ${lineNumber} 行: 函数调用 ${func.name}(${func.args})`,
            line: lineNumber,
            function: func.name,
            args: func.args
          });
        }
      }

      if (this._isStringConcat(line, language)) {
        const concat = this._parseStringConcat(line);
        if (concat) {
          flow.push({
            type: 'string_concat',
            description: `第 ${lineNumber} 行: 字符串拼接可能引入污点`,
            line: lineNumber,
            expression: concat.expression
          });
        }
      }

      if (this._isReturnStatement(line, language)) {
        const retVar = this._parseReturn(line);
        if (retVar) {
          flow.push({
            type: 'return',
            description: `第 ${lineNumber} 行: 返回变量 ${retVar}`,
            line: lineNumber,
            variable: retVar
          });
        }
      }
    }

    flow.push({
      type: 'sink',
      description: `第 ${sink.line} 行: ${sink.name} (${sink.match})`,
      line: sink.line
    });

    return flow;
  }

  _buildPropagationPath(code, source, sink, dataFlow, language) {
    const path = {
      source: {
        line: source.line,
        name: source.name,
        match: source.match
      },
      sink: {
        line: sink.line,
        name: sink.name,
        match: sink.match
      },
      steps: [],
      riskLevel: 'HIGH'
    };

    for (const step of dataFlow) {
      path.steps.push({
        line: step.line,
        type: step.type,
        description: step.description
      });

      if (step.type === 'string_concat' || step.type === 'function_call') {
        path.riskLevel = 'CRITICAL';
      }
    }

    path.summary = `污点从第 ${source.line} 行传播到第 ${sink.line} 行，经过 ${dataFlow.length} 个步骤`;

    return path;
  }

  _calculateConfidence(source, sink, sanitizers, dataFlow) {
    let confidence = 0.8;

    const distance = sink.line - source.line;
    if (distance > 30) {
      confidence -= 0.2;
    } else if (distance <= 10) {
      confidence += 0.1;
    }

    if (sanitizers.length > 0) {
      confidence -= 0.3 * sanitizers.length;
    }

    const hasStringConcat = dataFlow.some(d => d.type === 'string_concat');
    if (hasStringConcat) {
      confidence += 0.15;
    }

    const hasFunctionCall = dataFlow.some(d => d.type === 'function_call');
    if (hasFunctionCall) {
      confidence -= 0.1;
    }

    return Math.min(1.0, Math.max(0.0, confidence));
  }

  _isVariableAssignment(line, language) {
    const patterns = {
      python: /^\s*(\w+)\s*=\s*.+$/,
      javascript: /^\s*(const|let|var)?\s*(\w+)\s*=\s*.+$/,
      java: /^\s*[\w<>]+\s+(\w+)\s*=\s*.+$/,
      php: /^\s*\$(\w+)\s*=\s*.+$/,
      go: /^\s*(\w+)\s*:=\s*.+$|^\s*\w+\s*=\s*.+$/,
      ruby: /^\s*(\w+)\s*=\s*.+$/
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
      /this\.\w+\s*\([^)]*\)/,
      /self\.\w+\s*\([^)]*\)/
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

  _isStringConcat(line, language) {
    const concatPatterns = {
      python: /\+['"']|['"']\+|%\s*|_format\(/,
      javascript: /\+['"']|['"']\+|template\s+string/,
      java: /\+['"']|String\.format\(|MessageFormat\.format\(/,
      php: /\.\s*['"']|['"']\s*\./,
      go: /\+.*['"']|fmt\.Sprintf\(|strings\.Join\(/,
      ruby: /\+['"']|['"']\+|#\{[^}]+\}/
    };

    const pattern = concatPatterns[language] || concatPatterns.python;
    return pattern.test(line);
  }

  _parseStringConcat(line) {
    const match = line.match(/(.+)/);
    if (match) {
      return {
        expression: match[1].trim()
      };
    }
    return null;
  }

  _isReturnStatement(line, language) {
    const patterns = {
      python: /^\s*return\s+/,
      javascript: /^\s*return\s+/,
      java: /^\s*return\s+/,
      php: /^\s*return\s+/,
      go: /^\s*return\s+/,
      ruby: /^\s*return\s+/
    };

    const pattern = patterns[language] || patterns.python;
    return pattern.test(line.trim());
  }

  _parseReturn(line) {
    const match = line.match(/return\s+(\w+)/);
    return match ? match[1] : null;
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
      command_exec: '使用安全的 API 替代 shell 命令，避免字符串拼接。使用 subprocess.run() 并传入 args 数组而非 shell 字符串。',
      sql_injection: '使用参数化查询或 ORM。避免字符串拼接构建 SQL 语句。',
      code_injection: '避免使用 eval/exec，对输入进行严格验证和白名单过滤。',
      xss: '对输出进行 HTML 编码，使用 textContent 替代 innerHTML，使用 React/Vue 的默认转义。',
      file_operation: '验证文件路径，使用 path.resolve() 规范化，避免用户控制文件名。',
      deserialization: '使用安全的序列化格式如 JSON，避免 pickle/yaml 的不安全加载。',
      ssrf: '验证和限制 URL，禁用重定向跟随，使用 requests.Session() 并设置允许的域名列表。',
      path_traversal: '使用 path.normalize() 和 path.resolve() 规范化路径，验证文件在允许的目录内。',
      eval: '避免使用 eval()，使用 JSON.parse() 替代 JSON 字符串解析。',
      exec: '使用 subprocess.run() 传入列表参数而非 shell=True。'
    };

    return remediations[sink.category] || '对用户输入进行严格验证、过滤和边界检查';
  }
}
