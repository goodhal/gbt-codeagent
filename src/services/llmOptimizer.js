/**
 * LLM审计服务优化模块
 *
 * 优化内容：
 * 1. 结果缓存 - 基于文件hash避免重复审计
 * 2. 增量审计 - 只审计变更文件
 * 3. Token预算控制 - 智能上下文管理
 * 4. 发现能力提升 - 增强漏洞检测提示
 * 5. 防误报机制 - 多维度验证
 */

import crypto from 'crypto';
import { promises as fs } from 'node:fs';
import path from 'path';

export class LLMOptimizer {
  constructor(options = {}) {
    this.cacheDir = options.cacheDir || path.join(process.cwd(), 'data', 'llm_cache');
    this.cache = new Map();
    this.auditHistory = new Map();
    this.tokenBudget = {
      maxTokens: options.maxTokens || 120000,
      usedTokens: 0,
      warningThreshold: 0.8
    };
    this.falsePositivePatterns = this._initFalsePositivePatterns();
    this.confidenceThresholds = {
      critical: 0.7,
      high: 0.75,
      medium: 0.8,
      low: 0.85
    };
  }

  _initFalsePositivePatterns() {
    return {
      testPatterns: [
        /test/i, /spec/i, /mock/i, /fixture/i, /example/i,
        /demo/i, /stub/i, /placeholder/i, /dummy/i, /__tests__/,
        /\.test\./, /\.spec\./, /_test\.js/, /_spec\.js/
      ],
      frameworkPatterns: [
        /node_modules/, /vendor/, /\.git/, /dist/, /build/,
        /coverage/, /\.next/, /\.nuxt/, /__pycache__/
      ],
      safePatterns: [
        /logger\.(error|warn|info|debug)/,
        /console\.(log|debug|info)/,
        /throw new Error.*test/i,
        /skip/i, /todo/i, / FIXME /i, / XXX /i
      ]
    };
  }

  async initialize() {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      await this._loadCache();
      console.log('[LLM优化] 缓存加载完成，已缓存', this.cache.size, '条记录');
    } catch (error) {
      console.warn('[LLM优化] 缓存初始化失败:', error.message);
    }
  }

  async _loadCache() {
    try {
      const cacheFile = path.join(this.cacheDir, 'audit_cache.json');
      const data = await fs.readFile(cacheFile, 'utf8');
      const parsed = JSON.parse(data);
      this.cache = new Map(parsed.entries || []);
      this.auditHistory = new Map(parsed.history || []);
    } catch (error) {
      this.cache = new Map();
      this.auditHistory = new Map();
    }
  }

  async _saveCache() {
    try {
      const cacheFile = path.join(this.cacheDir, 'audit_cache.json');
      const data = JSON.stringify({
        entries: Array.from(this.cache.entries()),
        history: Array.from(this.auditHistory.entries()),
        savedAt: new Date().toISOString()
      }, null, 2);
      await fs.writeFile(cacheFile, data, 'utf8');
    } catch (error) {
      console.warn('[LLM优化] 缓存保存失败:', error.message);
    }
  }

  computeFileHash(content) {
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }

  computeProjectHash(files) {
    const fileHashes = files
      .map(f => `${f.relativePath}:${this.computeFileHash(f.content)}`)
      .sort()
      .join('|');
    return crypto.createHash('sha256').update(fileHashes).digest('hex').substring(0, 32);
  }

  getCachedResults(projectHash, files) {
    const cached = this.cache.get(projectHash);
    if (!cached) return null;

    const cachedFileHashes = new Set(cached.fileHashes || []);
    const currentFileHashes = files.map(f => ({
      path: f.relativePath,
      hash: this.computeFileHash(f.content)
    }));

    const unchangedFiles = currentFileHashes.filter(f => cachedFileHashes.has(`${f.path}:${f.hash}`));
    const changedFiles = currentFileHashes.filter(f => !cachedFileHashes.has(`${f.path}:${f.hash}`));

    return {
      cachedFindings: cached.findings || [],
      unchangedCount: unchangedFiles.length,
      changedFiles: changedFiles.map(f => f.path),
      isCacheHit: changedFiles.length === 0
    };
  }

  cacheResults(projectHash, files, findings) {
    const fileHashes = files.map(f => `${f.relativePath}:${this.computeFileHash(f.content)}`);
    const entry = {
      projectHash,
      fileHashes,
      findings,
      cachedAt: new Date().toISOString(),
      version: '1.0'
    };
    this.cache.set(projectHash, entry);
    this._saveCache();
  }

  filterUnchangedFiles(files, changedFiles) {
    if (!changedFiles || changedFiles.length === 0) return files;
    const changedSet = new Set(changedFiles);
    return files.filter(f => changedSet.has(f.relativePath));
  }

  calculateTokenBudget(files, priorityFiles = []) {
    const totalChars = files.reduce((sum, f) => sum + f.content.length, 0);
    const estimatedTokens = Math.ceil(totalChars / 4);

    const prioritySet = new Set(priorityFiles);
    const priorityFilesList = files.filter(f => prioritySet.has(f.relativePath));
    const priorityTokens = Math.ceil(priorityFilesList.reduce((sum, f) => sum + f.content.length, 0) / 4);

    const remainingBudget = this.tokenBudget.maxTokens - this.tokenBudget.usedTokens;
    const safeBudget = Math.floor(remainingBudget * 0.9);

    return {
      totalEstimated: estimatedTokens,
      priorityTokens,
      remainingBudget,
      safeBudget,
      needsCompression: estimatedTokens > safeBudget,
      compressionRatio: safeBudget / Math.max(estimatedTokens, 1)
    };
  }

  prioritizeFiles(files, heuristicFindings = []) {
    const scored = files.map(file => {
      let score = 0;

      const fileName = file.relativePath.toLowerCase();
      if (/auth|login|user|permission|role|admin|security/.test(fileName)) score += 10;
      if (/api|controller|handler|service/.test(fileName)) score += 8;
      if (/config|settings|env/.test(fileName)) score += 6;
      if (/\.(java|py|js|ts)$/.test(fileName)) score += 5;
      if (/test|spec|mock/.test(fileName)) score -= 20;
      if (/node_modules|vendor/.test(fileName)) score -= 30;

      const relatedFindings = heuristicFindings.filter(f =>
        f.location && f.location.includes(file.relativePath)
      );
      score += relatedFindings.length * 3;

      if (file.content.length > 1000 && file.content.length < 50000) score += 3;

      return { file, score };
    });

    return scored
      .sort((a, b) => b.score - a.score)
      .map(s => s.file);
  }

  isFalsePositive(finding, context = {}) {
    const { filePath = '', code = '' } = context;

    if (this.falsePositivePatterns.testPatterns.some(p => p.test(filePath))) {
      return { isFP: true, reason: 'test_file', confidence: 0.9 };
    }

    if (this.falsePositivePatterns.frameworkPatterns.some(p => p.test(filePath))) {
      return { isFP: true, reason: 'framework_code', confidence: 0.95 };
    }

    if (this.falsePositivePatterns.safePatterns.some(p => p.test(code))) {
      return { isFP: true, reason: 'safe_pattern', confidence: 0.8 };
    }

    if (this._isCommentLine(code)) {
      return { isFP: true, reason: 'comment_line', confidence: 0.95 };
    }

    if (this._isImportOnly(finding, code)) {
      return { isFP: true, reason: 'import_only', confidence: 0.85 };
    }

    if (this._isTestAssertion(finding, code)) {
      return { isFP: true, reason: 'test_assertion', confidence: 0.9 };
    }

    return { isFP: false, confidence: 1.0 };
  }

  _isCommentLine(code) {
    const trimmed = code.trim();
    return /^\/\/|^\/\*|^\*|#|<!--/.test(trimmed);
  }

  _isImportOnly(finding, code) {
    if (!finding.vulnType) return false;
    const importPatterns = [
      /import\s+.*from\s+['"]/, /require\s*\(/,
      /using\s+.*;/, /include\s*</
    ];
    return importPatterns.some(p => p.test(code)) && !code.includes('(');
  }

  _isTestAssertion(finding, code) {
    return /assert|expect|should\.be|should\.eq|jest\.fn|sinon/.test(code);
  }

  validateFinding(finding) {
    const issues = [];

    if (!finding.location) {
      issues.push('missing_location');
    } else {
      const parts = finding.location.split(':');
      if (parts.length < 1 || !parts[0]) {
        issues.push('invalid_location_format');
      }
      if (parts.length === 2 && isNaN(parseInt(parts[1]))) {
        issues.push('invalid_line_number');
      }
    }

    if (!finding.evidence || finding.evidence.length < 20) {
      issues.push('evidence_too_short');
    }

    if (!finding.remediation || finding.remediation.length < 30) {
      issues.push('remediation_too_short');
    }

    if (!finding.confidence || finding.confidence < 0.3) {
      issues.push('low_confidence');
    }

    const severity = (finding.severity || '').toLowerCase();
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
      issues.push('invalid_severity');
    }

    return {
      isValid: issues.length === 0,
      issues,
      isActionable: issues.filter(i => !['low_confidence'].includes(i)).length === 0
    };
  }

  enhanceFindingWithContext(finding, projectContext = {}) {
    const enhanced = { ...finding };

    if (!enhanced.cvssScore && enhanced.severity) {
      enhanced.cvssScore = this._severityToCVSS(enhanced.severity);
    }

    if (!enhanced.confidence) {
      enhanced.confidence = this._estimateConfidence(finding);
    }

    if (projectContext.language) {
      enhanced.language = projectContext.language;
    }

    if (!enhanced.gbtMapping && enhanced.cwe) {
      enhanced.gbtMapping = this._mapCWEToGBT(enhanced.cwe);
    }

    return enhanced;
  }

  _severityToCVSS(severity) {
    const map = {
      "严重": 9.5,
      critical: 9.5,
      "高危": 7.5,
      high: 7.5,
      "中危": 5.0,
      medium: 5.0,
      "低危": 2.5,
      low: 2.5,
      info: 0.1
    };
    const key = (severity || "").toLowerCase();
    return map[key] || map[severity] || 5.0;
  }

  _estimateConfidence(finding) {
    let confidence = 0.6;

    if (finding.evidence && finding.evidence.length > 100) confidence += 0.1;
    if (finding.remediation && finding.remediation.includes('具体')) confidence += 0.1;
    if (finding.location && finding.location.includes(':')) confidence += 0.1;

    const fpCheck = this.isFalsePositive(finding);
    if (fpCheck.isFP) confidence *= 0.3;

    return Math.min(1., Math.max(0, confidence));
  }

  _mapCWEToGBT(cwe) {
    const map = {
      'CWE-78': 'GB/T34944-6.1.1.6 命令注入',
      'CWE-79': 'GB/T34944-6.1.1.2 XSS',
      'CWE-89': 'GB/T34944-6.1.1.1 SQL注入',
      'CWE-287': 'GB/T34944-6.3.1.2 身份认证绕过',
      'CWE-502': 'GB/T34944-6.1.1.7 不安全反序列化',
      'CWE-22': 'GB/T34944-6.1.1.4 路径遍历',
      'CWE-94': 'GB/T34944-6.1.1.3 代码注入',
      'CWE-918': 'GB/T39412-6.4.1 SSRF'
    };
    return map[cwe] || 'GB/T39412-2020 通用要求';
  }

  deduplicateFindings(findings) {
    const seen = new Map();
    const deduped = [];

    for (const finding of findings) {
      const key = this._generateFindingKey(finding);
      if (seen.has(key)) {
        const existing = seen.get(key);
        if (finding.confidence > existing.confidence) {
          seen.set(key, finding);
        }
      } else {
        seen.set(key, finding);
      }
    }

    return Array.from(seen.values());
  }

  _generateFindingKey(finding) {
    const parts = [
      finding.title || '',
      finding.cwe || '',
      finding.vulnType || '',
      finding.location || ''
    ];
    return crypto.createHash('md5').update(parts.join('|')).digest('hex');
  }

  filterByConfidence(findings, threshold = 0.5) {
    return findings.filter(f => f.confidence >= threshold);
  }

  rankFindings(findings) {
    return findings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

      const sevDiff = (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
      if (sevDiff !== 0) return sevDiff;

      const confDiff = (b.confidence || 0) - (a.confidence || 0);
      if (confDiff !== 0) return confDiff;

      const cvssDiff = (b.cvssScore || 0) - (a.cvssScore || 0);
      return cvssDiff;
    });
  }

  getAuditStats() {
    return {
      cacheSize: this.cache.size,
      historySize: this.auditHistory.size,
      tokenBudget: { ...this.tokenBudget },
      falsePositiveRate: this._calculateFPRate()
    };
  }

  async recordAuditResult(projectId, findings, success) {
    const entry = {
      projectId,
      findingsCount: findings.length,
      success,
      timestamp: new Date().toISOString()
    };
    this.auditHistory.set(projectId, entry);
    await this._saveCache();
  }

  _calculateFPRate() {
    let total = 0;
    let fp = 0;
    for (const entry of this.auditHistory.values()) {
      total++;
      if (!entry.success) fp++;
    }
    return total > 0 ? fp / total : 0;
  }

  generateAuditReport(optimizationResult) {
    return {
      cachedFindings: optimizationResult.cachedFindings?.length || 0,
      incrementalFiles: optimizationResult.changedFiles?.length || 0,
      tokenBudgetUsed: this.tokenBudget.usedTokens,
      deduplicatedCount: optimizationResult.findings?.length || 0,
      stats: this.getAuditStats()
    };
  }
}

export function createEnhancedPrompt(options = {}) {
  const {
    includeContextAnalysis = true,
    includeBusinessLogic = true,
    includeAttackChain = true,
    strictMode = true
  } = options;

  const enhancements = [];

  if (includeContextAnalysis) {
    enhancements.push(`
【上下文分析要求】
- 分析数据流：从用户输入到危险函数的完整路径
- 识别安全边界：信任边界、输入验证点、输出编码
- 评估验证有效性：验证是否充分、是否存在绕过
`);
  }

  if (includeBusinessLogic) {
    enhancements.push(`
【业务逻辑漏洞检测】
- 状态机漏洞：订单状态、支付流程、权限状态
- 条件竞争：并发场景下的状态不一致
- 水平越权：用户间数据访问
- 垂直越权：普通用户访问管理功能
`);
  }

  if (includeAttackChain) {
    enhancements.push(`
【攻击链分析】
- 单一漏洞利用链：入口点 → 传播路径 → 最终影响
- 组合漏洞：多个低危漏洞组合成高危攻击
- 攻击复杂度：利用难度、所需权限、影响范围
`);
  }

  if (strictMode) {
    enhancements.push(`
【严格模式】
- 每发现必须包含具体代码行号
- evidence 必须包含问题代码片段
- remediation 必须包含可执行的修复代码
- 禁止报告未经验证的猜测
`);
  }

  return enhancements.join('\n');
}

export function createIncrementalAuditPrompt(changedFiles) {
  return `
【增量审计任务】
仅审计以下变更文件：
${changedFiles.map(f => `- ${f}`).join('\n')}

变更文件需要重点关注：
1. 新增的危险函数调用
2. 修改的认证/授权逻辑
3. 变化的数据验证流程
4. 新的外部输入处理

其他文件如有严重问题会通过上下文分析被发现。
`;
}
