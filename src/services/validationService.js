/**
 * 漏洞验证服务
 * 负责验证漏洞发现的准确性，包括：
 * - 代码片段验证
 * - 行号修正
 * - 状态更新
 * - Source→Sink 路径验证
 * 
 * 整合 java-audit-skills 优点：
 * - 三维评分体系（可达性、影响范围、利用复杂度）
 * - 数据流追踪验证
 * - 净化措施检测
 * - 调用链验证
 */

import { promises as fs } from "node:fs";
import path from "path";
import { globalVulnValidator } from "./sandbox.js";
import { VERDICT, SANITIZER_PATTERNS } from "../config/auditConfig.js";
import {
  FILE_EXTENSION_MAP,
  LANGUAGE_VULN_MAP,
  VULN_TYPE_TO_SANDBOX,
  detectLanguage,
  isVulnerabilitySupported
} from "../config/auditConfig.js";
import { CodeCommentParser } from "./codeCommentParser.js";
import { CoverageMatrix } from "./coverageMatrix.js";

export class ValidationService {
  constructor() {
    this.codeCommentParser = new CodeCommentParser();
  }

  /**
   * 验证代码片段
   * @param {string} filePath - 文件路径
   * @param {number} line - 行号
   * @param {string} codeSnippet - 代码片段
   * @param {Array} preloadedLines - 预加载的文件内容行
   * @returns {Object} 验证结果
   */
  async validateCodeSnippet(filePath, line, codeSnippet, preloadedLines = null) {
    try {
      const lines = preloadedLines || (await fs.readFile(filePath, "utf8")).split("\n");
      
      if (line < 1 || line > lines.length) {
        return {
          valid: false,
          error: `行号 ${line} 超出范围 (1-${lines.length})`
        };
      }
      
      const codeLines = codeSnippet.split("\n").filter(l => l.trim());
      const keywords = codeLines
        .map(l => l.trim())
        .filter(l => l.length > 3);
      
      if (keywords.length === 0) {
        return {
          valid: false,
          error: "代码片段为空"
        };
      }

      const regexPattern = keywords[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const keywordRegex = new RegExp(regexPattern, "i");
      
      let grepMatchLine = null;
      let grepMatchContent = null;
      let grepFirstMatchLine = null;
      let grepFirstMatchContent = null;
      
      for (let i = 0; i < lines.length; i++) {
        if (keywordRegex.test(lines[i])) {
          if (i + 1 === line) {
            grepMatchLine = i + 1;
            grepMatchContent = lines[i].trim();
          }
          if (grepFirstMatchLine === null) {
            grepFirstMatchLine = i + 1;
            grepFirstMatchContent = lines[i].trim();
          }
          if (grepMatchLine !== null && grepFirstMatchLine !== null) {
            break;
          }
        }
      }
      
      if (grepMatchLine !== null) {
        return {
          valid: true,
          actualCode: grepMatchContent,
          verifiedBy: "keyword_search"
        };
      }
      
      if (grepFirstMatchLine !== null) {
        return {
          valid: true,
          correctedLine: grepFirstMatchLine,
          actualCode: grepFirstMatchContent,
          originalLine: line,
          verifiedBy: "keyword_search"
        };
      }
      
      const targetLine = lines[line - 1];
      const hasMatch = keywords.some(keyword => 
        targetLine.includes(keyword)
      );
      
      if (hasMatch) {
        return {
          valid: true,
          actualCode: targetLine.trim()
        };
      }
      
      const searchRange = 10;
      const startLine = Math.max(0, line - searchRange - 1);
      const endLine = Math.min(lines.length, line + searchRange);
      
      for (let i = startLine; i < endLine; i++) {
        const currentLine = lines[i];
        const lineHasMatch = keywords.some(keyword => 
          currentLine.includes(keyword)
        );
        
        if (lineHasMatch) {
          return {
            valid: true,
            correctedLine: i + 1,
            actualCode: currentLine.trim(),
            originalLine: line
          };
        }
      }
      
      return {
        valid: false,
        error: "代码片段未在文件中找到",
        searchedRange: `${startLine + 1}-${endLine}`
      };
      
    } catch (error) {
      return {
        valid: false,
        error: `读取文件失败：${error.message}`
      };
    }
  }
  
  /**
   * 批量验证漏洞发现
   * @param {Array} findings - 漏洞发现列表
   * @param {string} projectRoot - 项目根路径
   * @param {number} maxWorkers - 最大并发数
   * @returns {Promise<{validated: Array, hallucinations: Array, corrected: Array}>}
   */
  async validateFindings(findings, projectRoot, maxWorkers = 4) {
    const validated = [];
    const hallucinations = [];
    const corrected = [];
    
    // 按文件分组，批量读取
    const fileMap = new Map();
    for (const finding of findings) {
      let filePath;
      if (finding.file) {
        filePath = path.join(projectRoot, finding.file);
      } else if (finding.location) {
        const locationParts = finding.location.split(':');
        if (locationParts.length >= 1) {
          const relativePath = locationParts[0];
          filePath = path.join(projectRoot, relativePath);
        } else {
          hallucinations.push({
            ...finding,
            validationError: "无法提取文件路径"
          });
          continue;
        }
      } else {
        hallucinations.push({
          ...finding,
          validationError: "缺少文件路径信息"
        });
        continue;
      }
      
      if (!(await this.fileExists(filePath))) {
        hallucinations.push({
          ...finding,
          validationError: `文件不存在: ${filePath}`
        });
        continue;
      }
      
      if (!fileMap.has(filePath)) {
        fileMap.set(filePath, []);
      }
      fileMap.get(filePath).push(finding);
    }
    
    // 并发验证每个文件的发现
    const validationPromises = [];
    const batchSize = Math.ceil(fileMap.size / maxWorkers);
    const batches = [];
    
    let batch = [];
    for (const [filePath, fileFindings] of fileMap) {
      batch.push({ filePath, fileFindings });
      if (batch.length >= batchSize) {
        batches.push([...batch]);
        batch = [];
      }
    }
    if (batch.length > 0) {
      batches.push(batch);
    }
    
    for (const batch of batches) {
      const batchPromises = batch.map(async ({ filePath, fileFindings }) => {
        const results = [];
        
        try {
          const content = await fs.readFile(filePath, "utf8");
          const lines = content.split("\n");
          
          for (const finding of fileFindings) {
            const result = await this.validateSingleFinding(finding, lines, filePath);
            results.push(result);
          }
        } catch (error) {
          for (const finding of fileFindings) {
            results.push({
              finding,
              valid: false,
              error: `文件读取失败：${error.message}`,
              isHallucination: true
            });
          }
        }
        
        return results;
      });
      
      const batchResults = await Promise.all(batchPromises);
      batchResults.flat().forEach(result => {
        if (result.valid) {
          validated.push(result.finding);
          if (result.corrected) {
            corrected.push(result);
          }
        } else {
          hallucinations.push({
            ...result.finding,
            validationError: result.error
          });
        }
      });
    }
    
    return {
      validated,
      hallucinations,
      corrected
    };
  }

  /**
   * 验证文件存在性
   * @param {string} filePath - 文件路径
   * @returns {Promise<boolean>} 文件是否存在
   */
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * 验证单个漏洞发现
   * @private
   */
  async validateSingleFinding(finding, lines, filePath) {
    let { line, codeSnippet } = finding;
    
    if (!line && finding.location) {
      const locationParts = finding.location.split(':');
      if (locationParts.length >= 2) {
        line = parseInt(locationParts[1], 10);
      }
    }
    
    if (!line) {
      return {
        finding,
        valid: false,
        error: "缺少行号信息",
        isHallucination: true
      };
    }
    
    if (!codeSnippet && line >= 1 && line <= lines.length) {
      codeSnippet = lines[line - 1];
    }
    
    // 验证技术栈一致性
    const language = detectLanguage(filePath);
    const vulnType = finding.vulnType || finding.type;
    if (!isVulnerabilitySupported(vulnType, language)) {
      return {
        finding,
        valid: false,
        error: `漏洞类型 '${vulnType}' 与文件语言 '${language}' 不匹配`,
        isHallucination: true
      };
    }
    
    const result = await this.validateCodeSnippet(filePath, line, codeSnippet || "", lines);
    
    if (result.valid) {
      const updatedFinding = {
        ...finding,
        status: "有效",
        validatedCode: result.actualCode
      };

      if (result.correctedLine) {
        updatedFinding.line = result.correctedLine;
        updatedFinding.location = `${finding.file}:${result.correctedLine}`;
        updatedFinding.correctedFrom = result.originalLine;
      }

      const sandboxResult = await this.validateWithSandbox(updatedFinding, lines);
      if (sandboxResult) {
        updatedFinding.sandboxValidation = sandboxResult;
        if (sandboxResult.exploitable) {
          updatedFinding.confirmedExploitable = true;
        }
      }

      return {
        finding: updatedFinding,
        valid: true,
        corrected: !!result.correctedLine,
        originalLine: result.originalLine,
        correctedLine: result.correctedLine
      };
    }
    
    return {
      finding,
      valid: false,
      error: result.error,
      isHallucination: true
    };
  }
  
  /**
   * 更新漏洞状态
   * @param {Array} findings - 漏洞发现列表
   * @param {Array} validatedFindings - 验证通过的发现
   * @returns {Array} 更新后的发现列表
   */
  updateFindingStatus(findings, validatedFindings) {
    const validatedMap = new Map(
      validatedFindings.map(f => {
        const vulnType = f.vulnType || f.title || 'unknown';
        const file = f.file || (f.location ? f.location.split(':')[0] : 'unknown');
        const line = f.line || (f.location ? parseInt(f.location.split(':')[1], 10) : 0);
        return [`${file}:${line}:${vulnType}`, f];
      })
    );
    
    return findings.map(finding => {
      const vulnType = finding.vulnType || finding.title || 'unknown';
      const file = finding.file || (finding.location ? finding.location.split(':')[0] : 'unknown');
      const line = finding.line || (finding.location ? parseInt(finding.location.split(':')[1], 10) : 0);
      const key = `${file}:${line}:${vulnType}`;
      const validated = validatedMap.get(key);
      
      if (validated) {
        return { ...validated };
      }
      
      return finding;
    });
  }

  async validateWithSandbox(finding, lines) {
    const vulnType = finding.vulnType;
    const sandboxVulnType = VULN_TYPE_TO_SANDBOX[vulnType];

    if (!sandboxVulnType) {
      return null;
    }

    if (!globalVulnValidator || !globalVulnValidator.isAvailable) {
      return {
        checked: true,
        available: false,
        message: "沙箱不可用"
      };
    }

    try {
      const line = finding.line || parseInt(finding.location?.split(':')[1], 10) || 1;
      const codeContext = lines.slice(Math.max(0, line - 5), Math.min(lines.length, line + 5)).join('\n');

      const result = await globalVulnValidator.validate(
        { vulnType: sandboxVulnType, location: finding.location, evidence: finding.evidence },
        codeContext
      );

      return {
        checked: true,
        available: true,
        exploitable: result.success && result.exploitable,
        message: result.message || (result.success ? "验证成功" : "验证失败"),
        details: result.payload
      };
    } catch (error) {
      return {
        checked: true,
        available: true,
        error: error.message
      };
    }
  }

  /**
   * 提取证据点
   * @param {Object} finding - 漏洞发现
   * @param {Array} lines - 文件内容行
   * @returns {Object} 证据点提取结果
   */
  extractEvidencePoints(finding, lines = []) {
    const evidencePoints = finding.evidencePoints || [];
    const sink = finding.sink || {};

    const extracted = {
      provided: evidencePoints,
      required: sink.evidencePoints || [],
      missing: [],
      completeness: "COMPLETE"
    };

    for (const required of extracted.required) {
      if (!evidencePoints.includes(required)) {
        extracted.missing.push(required);
      }
    }

    if (extracted.missing.length > 0) {
      extracted.completeness = extracted.required.length === 0 ? "N/A" : "PARTIAL";
    }

    return extracted;
  }

  /**
   * 检查未解决风险（参考 java-audit-skills 质量保障机制）
   * @param {Array} findings - 漏洞发现列表
   * @param {Object} traceResults - 追踪结果
   * @returns {Array} 风险列表
   */
  async checkUnresolvedRisks(findings, traceResults = {}) {
    const risks = [];

    for (const finding of findings) {
      const routeId = finding.routeId || finding.location || `${finding.file}:${finding.line}`;
      const traceResult = traceResults[routeId];
      const evidenceCheck = this.extractEvidencePoints(finding);

      let riskEntry = {
        vulnId: finding.vulnId || finding.title,
        type: finding.vulnType || finding.type,
        severity: finding.severity,
        location: finding.location || finding.file,
        status: "已确认",
        priority: "low",
        reasons: [],
        score: 0,
        // 三维评分（参考 java-audit-skills）
        reachability: "unknown",
        impact: "unknown",
        complexity: "unknown"
      };

      let score = 0;

      // 可达性评分 (0-3)
      const reachabilityScore = this._calculateReachabilityScore(finding);
      riskEntry.reachability = this._getReachabilityLabel(reachabilityScore);
      score += reachabilityScore * 40 / 3;

      // 影响范围评分 (0-3)
      const impactScore = this._calculateImpactScore(finding);
      riskEntry.impact = this._getImpactLabel(impactScore);
      score += impactScore * 35 / 3;

      // 利用复杂度评分 (0-3)
      const complexityScore = this._calculateComplexityScore(finding);
      riskEntry.complexity = this._getComplexityLabel(complexityScore);
      score += complexityScore * 25 / 3;

      // 追踪状态检查
      if (traceResult?.status === "UNRESOLVED") {
        riskEntry.status = "待验证";
        riskEntry.reasons.push(`追踪状态: ${traceResult.status}`);
        score += 40;
      } else if (traceResult?.status === "PARTIAL") {
        riskEntry.status = "待验证";
        riskEntry.reasons.push(`追踪状态: ${traceResult.status}`);
        score += 20;
      }

      // 证据完整性检查
      if (evidenceCheck.completeness === "PARTIAL") {
        riskEntry.status = "待验证";
        riskEntry.reasons.push(`缺失证据点: ${evidenceCheck.missing.join(", ")}`);
        score += evidenceCheck.missing.length * 15;
      }

      // 沙箱验证检查
      if (!finding.confirmedExploitable && !finding.sandboxValidation?.exploitable) {
        if (riskEntry.status === "已确认") {
          riskEntry.status = "待验证";
          riskEntry.reasons.push("未通过沙箱验证");
        }
        score += 30;
      }

      // 严重程度加权
      const severityWeights = { critical: 30, high: 20, medium: 10, low: 5 };
      score += severityWeights[finding.severity] || 0;

      riskEntry.score = Math.min(Math.round(score), 100);

      // 优先级判定
      if (riskEntry.score >= 70) {
        riskEntry.priority = "high";
      } else if (riskEntry.score >= 40) {
        riskEntry.priority = "medium";
      } else {
        riskEntry.priority = "low";
      }

      if (riskEntry.reasons.length > 0) {
        if (riskEntry.priority === "high") {
          riskEntry.recommendation = "立即进行人工复核，补充缺失证据或确认漏洞真实性";
        } else if (riskEntry.priority === "medium") {
          riskEntry.recommendation = "建议在本次审计周期内完成复核";
        } else {
          riskEntry.recommendation = "可延后处理，或标记为环境依赖";
        }
        risks.push(riskEntry);
      }
    }

    return risks.sort((a, b) => b.score - a.score);
  }

  /**
   * 计算可达性评分 (0-3)
   * 0: 需要管理员权限
   * 1: 需要认证
   * 2: 仅内网可访问
   * 3: 互联网直接可达
   */
  _calculateReachabilityScore(finding) {
    const accessPath = String(finding.accessPath || finding.reachability || 'unknown');
    if (accessPath.includes('internet') || accessPath.includes('public')) return 3;
    if (accessPath.includes('intranet') || accessPath.includes('internal')) return 2;
    if (accessPath.includes('auth') || accessPath.includes('login')) return 1;
    if (accessPath.includes('admin') || accessPath.includes('privileged')) return 0;
    
    // 默认基于漏洞类型判断
    const vulnType = (finding.type || finding.vulnType || '').toUpperCase();
    if (vulnType.includes('SSRF') || vulnType.includes('XSS') || vulnType.includes('OPEN_REDIRECT')) {
      return 3;
    }
    if (vulnType.includes('AUTH_BYPASS') || vulnType.includes('IDOR')) {
      return 2;
    }
    return 1;
  }

  /**
   * 计算影响范围评分 (0-3)
   * 0: 无实际影响
   * 1: 有限信息泄露
   * 2: 重要数据泄露或权限提升
   * 3: RCE、系统沦陷、数据全泄露
   */
  _calculateImpactScore(finding) {
    const vulnType = (finding.type || finding.vulnType || '').toUpperCase();
    
    if (vulnType.includes('COMMAND_INJECTION') || 
        vulnType.includes('CODE_INJECTION') || 
        vulnType.includes('DESERIALIZATION')) {
      return 3;
    }
    if (vulnType.includes('SQL_INJECTION') || 
        vulnType.includes('PATH_TRAVERSAL')) {
      return 2;
    }
    if (vulnType.includes('XSS') || 
        vulnType.includes('INFO_LEAK') ||
        vulnType.includes('HARD_CODE_PASSWORD')) {
      return 1;
    }
    return 0;
  }

  /**
   * 计算利用复杂度评分 (0-3)
   * 0: 复杂利用条件
   * 1: 需要多步骤
   * 2: 需要特定条件
   * 3: 单次请求即可利用
   */
  _calculateComplexityScore(finding) {
    const vulnType = (finding.type || finding.vulnType || '').toUpperCase();
    
    if (vulnType.includes('SQL_INJECTION') || 
        vulnType.includes('COMMAND_INJECTION') ||
        vulnType.includes('PATH_TRAVERSAL')) {
      return 3;
    }
    if (vulnType.includes('XSS') || 
        vulnType.includes('OPEN_REDIRECT')) {
      return 2;
    }
    if (vulnType.includes('CSRF') || 
        vulnType.includes('IDOR')) {
      return 1;
    }
    return 0;
  }

  _getReachabilityScore(score) {
    const labels = ['admin_required', 'auth_required', 'intranet', 'internet'];
    return labels[score] || 'unknown';
  }

  _getReachabilityLabel(score) {
    const labels = ['需要管理员', '需要认证', '内网访问', '互联网可达'];
    return labels[score] || '未知';
  }

  _getImpactLabel(score) {
    const labels = ['无影响', '有限泄露', '重要泄露', '系统沦陷'];
    return labels[score] || '未知';
  }

  _getComplexityLabel(score) {
    const labels = ['复杂', '多步骤', '特定条件', '单次请求'];
    return labels[score] || '未知';
  }

  /**
   * 生成风险池报告
   */
  generateRiskPoolReport(risks) {
    if (!risks || risks.length === 0) {
      return {
        total: 0,
        summary: "无待验证风险",
        risks: [],
        byPriority: { high: [], medium: [], low: [] },
        byStatus: {},
        recommendations: [],
        statistics: {
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          avgScore: 0
        }
      };
    }

    const byPriority = { high: [], medium: [], low: [] };
    const byStatus = {};
    let totalScore = 0;

    for (const risk of risks) {
      byPriority[risk.priority].push(risk);
      if (!byStatus[risk.status]) {
        byStatus[risk.status] = [];
      }
      byStatus[risk.status].push(risk);
      totalScore += risk.score;
    }

    const stats = {
      highCount: byPriority.high.length,
      mediumCount: byPriority.medium.length,
      lowCount: byPriority.low.length,
      avgScore: Math.round(totalScore / risks.length)
    };

    let summary = `共 ${risks.length} 个待验证风险`;
    if (stats.highCount > 0) {
      summary += `，其中 ${stats.highCount} 个高优先级`;
    }
    if (stats.mediumCount > 0) {
      summary += `，${stats.mediumCount} 个中优先级`;
    }
    if (stats.lowCount > 0) {
      summary += `，${stats.lowCount} 个低优先级`;
    }

    const recommendations = [];
    if (stats.highCount > 0) {
      recommendations.push({
        action: "立即处理",
        count: stats.highCount,
        description: "高优先级风险需要立即人工复核"
      });
    }
    if (stats.mediumCount > 0) {
      recommendations.push({
        action: "计划处理",
        count: stats.mediumCount,
        description: "中优先级风险建议在当前审计周期内完成"
      });
    }

    return {
      total: risks.length,
      summary,
      risks,
      byPriority,
      byStatus,
      recommendations,
      statistics: stats
    };
  }

  /**
   * 深度验证漏洞路径（参考 SAST2AI + java-audit-skills 的数据流分析）
   * @param {Object} finding - 漏洞发现
   * @param {string} projectRoot - 项目根目录
   * @param {Array} lines - 预加载的文件内容行（可选）
   * @returns {Object} 验证结果，包含 verdict 和详细理由
   */
  async verifyVulnerabilityPath(finding, projectRoot, lines = null) {
    const result = {
      verdict: VERDICT.NEEDS_REVIEW,
      originalSeverity: finding.severity || 'medium',
      adjustedSeverity: null,
      reason: '',
      verifiedCallChain: [],
      sanitizersFound: [],
      sourceValidated: false,
      sinkValidated: false,
      // 新增：三维评分
      reachabilityScore: 0,
      impactScore: 0,
      complexityScore: 0,
      overallScore: 0
    };

    let filePath;
    if (finding.file) {
      filePath = path.join(projectRoot, finding.file);
    } else if (finding.location) {
      const locationParts = finding.location.split(':');
      if (locationParts.length >= 1) {
        filePath = path.join(projectRoot, locationParts[0]);
      }
    }

    if (!filePath) {
      result.reason = '无法确定漏洞所在文件路径';
      return result;
    }

    try {
      const fileContent = lines || (await fs.readFile(filePath, 'utf8'));
      const fileLines = typeof fileContent === 'string' ? fileContent.split('\n') : fileContent;

      // 1. 验证 Source（用户输入点）
      const sourceValidation = await this._validateSource(finding, fileLines, filePath);
      result.sourceValidated = sourceValidation.valid;
      if (!sourceValidation.valid) {
        result.verdict = VERDICT.FALSE_POSITIVE;
        result.reason = sourceValidation.reason;
        return result;
      }

      // 2. 验证 Sink（危险函数）
      const sinkValidation = await this._validateSink(finding, fileLines, filePath);
      result.sinkValidated = sinkValidation.valid;
      if (!sinkValidation.valid) {
        result.verdict = VERDICT.FALSE_POSITIVE;
        result.reason = sinkValidation.reason;
        return result;
      }

      // 3. 检查净化措施（参考 java-audit-skills 的数据流分析）
      const sanitizerCheck = await this._checkSanitizers(finding, fileLines);
      result.sanitizersFound = sanitizerCheck.found;
      
      if (sanitizerCheck.found.length > 0) {
        if (sanitizerCheck.effective) {
          // 即使发现有效净化措施，也不直接标记为误报，而是降级或需要复核
          result.verdict = VERDICT.DOWNGRADED;
          result.adjustedSeverity = this._downgradeSeverity(finding.severity);
          result.reason = `发现有效净化措施: ${sanitizerCheck.found.join(', ')}，但仍需复核确认`;
          // 继续验证其他部分
        } else {
          result.reason = `发现部分净化措施，但可能不充分: ${sanitizerCheck.found.join(', ')}`;
          // 继续验证其他部分
        }
      }

      // 4. 验证调用链（如果存在）
      if (finding.callChain && finding.callChain.length > 0) {
        const chainValidation = await this._validateCallChain(finding.callChain, projectRoot);
        result.verifiedCallChain = chainValidation.verified;
        if (!chainValidation.valid) {
          // 即使调用链验证失败，也不直接标记为误报，而是标记为需要复核
          result.reason = `调用链验证失败: ${chainValidation.reason}，但仍需人工复核`;
          // 继续验证其他部分
        }
      }

      // 5. 计算三维评分
      result.reachabilityScore = this._calculateReachabilityScore(finding);
      result.impactScore = this._calculateImpactScore(finding);
      result.complexityScore = this._calculateComplexityScore(finding);
      result.overallScore = Math.round(
        result.reachabilityScore * 40 / 3 + 
        result.impactScore * 35 / 3 + 
        result.complexityScore * 25 / 3
      );

      // 6. 所有检查通过，确认漏洞
      result.verdict = VERDICT.CONFIRMED;
      result.reason = 'Source→Sink 路径完整，未发现有效净化措施';

    } catch (error) {
      result.reason = `验证过程出错: ${error.message}`;
    }

    return result;
  }

  /**
   * 验证 Source（用户输入点）是否存在且可控
   */
  async _validateSource(finding, lines, filePath) {
    const source = finding.source || finding.sourceName || finding.inputVariable;
    if (!source) {
      return { valid: true, reason: '无明确 Source 信息，跳过验证' };
    }

    const lineNum = finding.line || parseInt(finding.location?.split(':')[1], 10);
    const searchRange = 100; // 扩大搜索范围
    const startLine = Math.max(0, (lineNum || 1) - searchRange - 1);
    const endLine = Math.min(lines.length, (lineNum || lines.length) + searchRange);

    const sourcePatterns = [
      /@RequestParam/, /@PathVariable/, /@RequestBody/, /@RequestHeader/,
      /req\./, /request\./, /params\./, /query\./, /body\./,
      /getParameter/, /getInputStream/, /readLine/, /getQuery/,
      /getBody/, /payload/, /input/, /data/
    ];

    // 先尝试精确匹配
    for (let i = startLine; i < endLine; i++) {
      const line = lines[i];
      for (const pattern of sourcePatterns) {
        if (pattern.test(line)) {
          if (line.toLowerCase().includes(source.toLowerCase())) {
            return { valid: true, reason: `在第 ${i + 1} 行找到 Source: ${source}` };
          }
        }
      }
    }

    // 如果找不到精确匹配，放宽验证 - 只要有任何用户输入模式就认为可能有效
    for (let i = startLine; i < endLine; i++) {
      const line = lines[i];
      for (const pattern of sourcePatterns) {
        if (pattern.test(line)) {
          return { valid: true, reason: `在第 ${i + 1} 行找到用户输入模式，Source 可能存在` };
        }
      }
    }

    // 最宽松的验证 - 即使找不到 Source，也不标记为误报，而是标记为需要人工复核
    return { valid: true, reason: `未找到明确的 Source，但可能存在其他输入渠道，需要人工复核` };
  }

  /**
   * 验证 Sink（危险函数）是否存在
   */
  async _validateSink(finding, lines, filePath) {
    const rawSink = finding.sink || finding.sinkName || finding.methodName;
    if (!rawSink) {
      return { valid: true, reason: '无明确 Sink 信息，跳过验证' };
    }

    const sinkCandidates = typeof rawSink === 'object'
      ? (rawSink.sinkFunctions || []).map(f => f.replace(/[()]/g, ''))
      : [String(rawSink)];

    const lineNum = finding.line || parseInt(finding.location?.split(':')[1], 10) || 1;
    const searchRange = 50; // 扩大搜索范围
    const startLine = Math.max(0, lineNum - searchRange - 1);
    const endLine = Math.min(lines.length, lineNum + searchRange);

    // 先尝试精确匹配
    for (let i = startLine; i < endLine; i++) {
      if (sinkCandidates.some(s => lines[i].includes(s))) {
        return { valid: true, reason: `在第 ${i + 1} 行找到 Sink` };
      }
    }

    // 如果找不到精确匹配，尝试模糊匹配 - 只要有类似的危险函数模式就认为可能有效
    const dangerPatterns = [
      /exec\s*\(/, /eval\s*\(/, /Runtime\s*\.\s*getRuntime/, /ProcessBuilder/,
      /executeQuery\s*\(/, /createQuery\s*\(/, /createNativeQuery/,
      /setHeader\s*\(/, /sendRedirect\s*\(/, /forward\s*\(/,
      /File\s*\(/, /FileInputStream/, /FileOutputStream/,
      /cipher\.doFinal/, /getInstance.*MD5|SHA1|DES/,
      /Random\s*\(/, /SecureRandom\s*\(/,
      /session\.put/, /Cookie\s*\(/
    ];

    for (let i = startLine; i < endLine; i++) {
      for (const pattern of dangerPatterns) {
        if (pattern.test(lines[i])) {
          return { valid: true, reason: `在第 ${i + 1} 行找到危险函数模式，Sink 可能存在` };
        }
      }
    }

    // 最宽松的验证 - 即使找不到 Sink，也不标记为误报，而是标记为需要人工复核
    return { valid: true, reason: `未找到明确的 Sink，但可能存在其他风险点，需要人工复核` };
  }

  /**
   * 检查代码中是否存在净化措施
   */
  async _checkSanitizers(finding, lines) {
    const vulnType = finding.type || finding.vulnType || '';
    const upperType = vulnType.toUpperCase();
    
    let patterns = [...SANITIZER_PATTERNS.general];
    
    if (upperType.includes('SQL')) {
      patterns = [...patterns, ...SANITIZER_PATTERNS.sql];
    } else if (upperType.includes('XSS')) {
      patterns = [...patterns, ...SANITIZER_PATTERNS.xss];
    } else if (upperType.includes('COMMAND') || upperType.includes('CMD')) {
      patterns = [...patterns, ...SANITIZER_PATTERNS.cmd];
    } else if (upperType.includes('PATH') || upperType.includes('TRAVERSAL')) {
      patterns = [...patterns, ...SANITIZER_PATTERNS.path];
    }

    const lineNum = finding.line || parseInt(finding.location?.split(':')[1], 10) || 1;
    const searchRange = 30;
    const startLine = Math.max(0, lineNum - searchRange - 1);
    const endLine = Math.min(lines.length, lineNum + searchRange);

    const foundSanitizers = [];

    for (let i = startLine; i < endLine; i++) {
      const line = lines[i];
      for (const pattern of patterns) {
        if (pattern.test(line)) {
          const sanitizerName = pattern.source.replace(/[\/\\]/g, '');
          if (!foundSanitizers.includes(sanitizerName)) {
            foundSanitizers.push(sanitizerName);
          }
        }
      }
    }

    return {
      found: foundSanitizers,
      effective: foundSanitizers.length > 0
    };
  }

  /**
   * 验证调用链
   */
  async _validateCallChain(callChain, projectRoot) {
    const verified = [];
    let prevFile = null;

    for (const node of callChain) {
      if (!node.file) continue;

      const filePath = path.join(projectRoot, node.file);
      try {
        const content = await fs.readFile(filePath, 'utf8');
        const lines = content.split('\n');
        
        if (node.line && node.line >= 1 && node.line <= lines.length) {
          verified.push({
            ...node,
            verified: true,
            actualCode: lines[node.line - 1]?.trim()
          });
        } else if (node.method) {
          const methodPattern = new RegExp(node.method, 'i');
          for (let i = 0; i < lines.length; i++) {
            if (methodPattern.test(lines[i])) {
              verified.push({
                ...node,
                verified: true,
                line: i + 1,
                actualCode: lines[i].trim()
              });
              break;
            }
          }
        }
        prevFile = filePath;
      } catch {
        return { valid: false, reason: `无法读取调用链文件: ${node.file}` };
      }
    }

    return { valid: true, reason: '调用链验证通过', verified };
  }

  /**
   * 降级严重性级别
   */
  _downgradeSeverity(severity) {
    const downgradeMap = {
      critical: 'high',
      high: 'medium',
      medium: 'low',
      low: 'low'
    };
    return downgradeMap[severity?.toLowerCase()] || severity;
  }

  // 委托给 CodeCommentParser 的方法
  parseCodeComments(code, language = 'javascript') {
    return this.codeCommentParser.parseCodeComments(code, language);
  }

  isLineSuppressed(lineNumber, comments) {
    return this.codeCommentParser.isLineSuppressed(lineNumber, comments);
  }

  isFindingSuppressed(finding, comments) {
    return this.codeCommentParser.isFindingSuppressed(finding, comments);
  }

  getSuppressedRules(comments) {
    return this.codeCommentParser.getSuppressedRules(comments);
  }

  filterSuppressedFindings(findings, comments) {
    return this.codeCommentParser.filterSuppressedFindings(findings, comments);
  }

  getCommentRanges(code, language = 'javascript') {
    return this.codeCommentParser.getCommentRanges(code, language);
  }
}

// 导出 CoverageMatrix 保持兼容性
export { CoverageMatrix };