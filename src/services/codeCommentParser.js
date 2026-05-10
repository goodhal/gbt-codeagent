/**
 * 代码注释解析服务
 * 用于解析代码中的注释和抑制规则
 */

import { SUPPRESSION_PATTERNS } from "../config/auditConfig.js";

export class CodeCommentParser {
  constructor() {
    this.singleLinePatterns = {
      'javascript': /\/\/(.*)$/,
      'typescript': /\/\/(.*)$/,
      'java': /\/\/(.*)$/,
      'c': /\/\/(.*)$/,
      'cpp': /\/\/(.*)$/,
      'csharp': /\/\/(.*)$/,
      'go': /\/\/(.*)$/,
      'rust': /\/\/(.*)$/,
      'python': /#(.*)$/,
      'ruby': /#(.*)$/,
      'php': /#(.*)$/,
      'shell': /#(.*)$/,
      'yaml': /#(.*)$/,
      'yml': /#(.*)$/,
      'xml': /<!--(.*)$/,
      'html': /<!--(.*)$/,
      'sql': /--(.*)$/
    };

    this.multiLinePatterns = {
      'javascript': { start: /\/\*/, end: /\*\// },
      'typescript': { start: /\/\*/, end: /\*\// },
      'java': { start: /\/\*/, end: /\*\// },
      'c': { start: /\/\*/, end: /\*\// },
      'cpp': { start: /\/\*/, end: /\*\// },
      'csharp': { start: /\/\*/, end: /\*\// },
      'go': { start: /\/\*/, end: /\*\// },
      'rust': { start: /\/\*/, end: /\*\// },
      'xml': { start: /<!--/, end: /-->/ },
      'html': { start: /<!--/, end: /-->/ }
    };
  }

  _getSingleLineCommentPattern(language) {
    return this.singleLinePatterns[language.toLowerCase()] || /\/\/(.*)$/;
  }

  _getMultiLineCommentPattern(language) {
    return this.multiLinePatterns[language.toLowerCase()] || null;
  }

  _extractSuppressions(text) {
    const suppressions = [];
    for (const pattern of SUPPRESSION_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        suppressions.push(match[1].toUpperCase());
      }
    }
    return suppressions;
  }

  /**
   * 解析代码中的注释
   * @param {string} code - 代码内容
   * @param {string} language - 语言标识
   * @returns {Object} 注释解析结果
   */
  parseCodeComments(code, language = 'javascript') {
    const comments = {
      singleLine: [],
      multiLine: [],
      suppressedRules: []
    };

    const lines = code.split('\n');
    let inMultiLine = false;
    let multiLineStart = -1;
    let multiLineContent = [];

    const singleLinePattern = this._getSingleLineCommentPattern(language);
    const multiLinePattern = this._getMultiLineCommentPattern(language);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      if (multiLinePattern) {
        const startMatch = line.match(multiLinePattern.start);
        const endMatch = line.match(multiLinePattern.end);

        if (inMultiLine) {
          multiLineContent.push({ line: lineNum, content: line });
          if (endMatch) {
            comments.multiLine.push({
              startLine: multiLineStart,
              endLine: lineNum,
              content: multiLineContent,
              suppressions: this._extractSuppressions(multiLineContent.map(c => c.content).join('\n'))
            });
            inMultiLine = false;
            multiLineContent = [];
          }
        } else if (startMatch) {
          inMultiLine = true;
          multiLineStart = lineNum;
          multiLineContent.push({ line: lineNum, content: line });
          if (endMatch) {
            comments.multiLine.push({
              startLine: multiLineStart,
              endLine: lineNum,
              content: multiLineContent,
              suppressions: this._extractSuppressions(line)
            });
            inMultiLine = false;
            multiLineContent = [];
          }
        }
      }

      if (!inMultiLine && singleLinePattern) {
        const match = line.match(singleLinePattern);
        if (match) {
          const commentContent = line.substring(line.indexOf(match[1]) + match[1].length);
          comments.singleLine.push({
            line: lineNum,
            content: commentContent.trim(),
            suppressions: this._extractSuppressions(commentContent)
          });
        }
      }
    }

    if (inMultiLine && multiLineContent.length > 0) {
      comments.multiLine.push({
        startLine: multiLineStart,
        endLine: lines.length,
        content: multiLineContent,
        suppressions: [],
        unclosed: true
      });
    }

    return comments;
  }

  /**
   * 检查某行是否被抑制
   * @param {number} lineNumber - 行号
   * @param {Object} comments - 注释解析结果
   * @returns {Object} 抑制检查结果
   */
  isLineSuppressed(lineNumber, comments) {
    for (const comment of comments.singleLine) {
      if (comment.line === lineNumber && comment.suppressions.length > 0) {
        return {
          suppressed: true,
          rules: comment.suppressions,
          source: 'singleLine',
          line: comment.line
        };
      }
    }

    for (const comment of comments.multiLine) {
      if (lineNumber >= comment.startLine && lineNumber <= comment.endLine) {
        return {
          suppressed: comment.suppressions.length > 0,
          rules: comment.suppressions,
          source: 'multiLine',
          startLine: comment.startLine,
          endLine: comment.endLine
        };
      }
    }

    return { suppressed: false };
  }

  /**
   * 检查漏洞发现是否被抑制
   * @param {Object} finding - 漏洞发现
   * @param {Object} comments - 注释解析结果
   * @returns {boolean} 是否被抑制
   */
  isFindingSuppressed(finding, comments) {
    const line = finding.line || parseInt(finding.location?.split(':')[1], 10) || 1;
    const ruleId = (finding.vulnType || finding.id || '').toUpperCase();

    const suppressionResult = this.isLineSuppressed(line, comments);

    if (!suppressionResult.suppressed) {
      return false;
    }

    if (suppressionResult.rules.length === 0) {
      return true;
    }

    return suppressionResult.rules.some(rule =>
      rule === ruleId ||
      rule === 'ALL' ||
      rule.includes('*')
    );
  }

  /**
   * 获取所有被抑制的规则
   * @param {Object} comments - 注释解析结果
   * @returns {Array} 被抑制的规则列表
   */
  getSuppressedRules(comments) {
    const allRules = new Set();
    for (const comment of comments.singleLine) {
      for (const rule of comment.suppressions) {
        allRules.add(rule);
      }
    }
    for (const comment of comments.multiLine) {
      for (const rule of comment.suppressions) {
        allRules.add(rule);
      }
    }
    return Array.from(allRules);
  }

  /**
   * 过滤被抑制的漏洞发现
   * @param {Array} findings - 漏洞发现列表
   * @param {Object} comments - 注释解析结果
   * @returns {Object} 过滤结果
   */
  filterSuppressedFindings(findings, comments) {
    const result = {
      suppressed: [],
      active: []
    };

    for (const finding of findings) {
      if (this.isFindingSuppressed(finding, comments)) {
        result.suppressed.push({
          ...finding,
          suppressedBy: 'code_comment'
        });
      } else {
        result.active.push(finding);
      }
    }

    return result;
  }

  /**
   * 获取注释范围
   * @param {string} code - 代码内容
   * @param {string} language - 语言标识
   * @returns {Array} 注释范围列表
   */
  getCommentRanges(code, language = 'javascript') {
    const comments = this.parseCodeComments(code, language);
    const ranges = [];

    for (const comment of comments.singleLine) {
      ranges.push({
        type: 'singleLine',
        startLine: comment.line,
        endLine: comment.line,
        suppressions: comment.suppressions
      });
    }

    for (const comment of comments.multiLine) {
      ranges.push({
        type: 'multiLine',
        startLine: comment.startLine,
        endLine: comment.endLine,
        suppressions: comment.suppressions
      });
    }

    return ranges.sort((a, b) => a.startLine - b.startLine);
  }
}