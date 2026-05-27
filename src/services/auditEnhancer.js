/**
 * 审计增强器
 * 整合来自 AiCodeAudit 的多项优化：
 * - 本地 Token 预检：请求前检查 token 预算，避免浪费 API 调用
 * - Agent 输出校验：验证 LLM 输出的有效性和合理性
 * - 失败率保护：跟踪 LLM 失败率，标记审计不完整
 * - 依赖上下文增强：构建上下游安全上下文
 */

import { estimateTokens, getModelMaxTokens } from "../utils/contextManager.js";
import { getSecurityHintProfile } from "./securityHintProfile.js";

const DEFAULT_FAILURE_THRESHOLD = 0.3;

export class AuditFailureTracker {
  constructor(threshold = DEFAULT_FAILURE_THRESHOLD) {
    this.threshold = threshold;
    this.reset();
  }

  reset() {
    this.totalTasks = 0;
    this.failedTasks = 0;
    this.successTasks = 0;
    this.errors = [];
  }

  recordSuccess() {
    this.totalTasks++;
    this.successTasks++;
  }

  recordFailure(errorMsg = "") {
    this.totalTasks++;
    this.failedTasks++;
    if (errorMsg) {
      this.errors.push({ time: new Date().toISOString(), message: errorMsg });
    }
  }

  get failureRate() {
    return this.totalTasks > 0 ? this.failedTasks / this.totalTasks : 0;
  }

  isAboveThreshold() {
    return this.failureRate >= this.threshold;
  }

  buildIncompleteReport() {
    return {
      conclusion: "审计不完整",
      totalTasks: this.totalTasks,
      failedTasks: this.failedTasks,
      failureRate: `${(this.failureRate * 100).toFixed(1)}%`,
      threshold: `${(this.threshold * 100).toFixed(0)}%`,
      message:
        "本次审计阶段存在较高比例的 LLM 请求失败，当前结果不应视为\"审计通过\"。" +
        "建议检查网络连通性、API 服务稳定性或降低并发后重新执行审计。",
    };
  }

  getStats() {
    return {
      totalTasks: this.totalTasks,
      failedTasks: this.failedTasks,
      successTasks: this.successTasks,
      failureRate: this.failureRate,
      aboveThreshold: this.isAboveThreshold(),
      recentErrors: this.errors.slice(-5),
    };
  }
}

export class TokenPreChecker {
  constructor(options = {}) {
    this.overheadTokens = options.overheadTokens || 512;
    this.safetyMargin = options.safetyMargin || 0.85;
  }

  /**
   * 检查消息是否超过模型 token 上限
   * 返回 { ok, currentTokens, maxTokens, usagePercent }
   */
  check(messages, model) {
    const maxTokens = getModelMaxTokens(model);
    const effectiveMax = Math.floor(maxTokens * this.safetyMargin);

    let totalTokens = this.overheadTokens;
    for (const msg of messages) {
      const content = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
      totalTokens += estimateTokens(content) + 4;
    }

    const usagePercent = ((totalTokens / effectiveMax) * 100).toFixed(1);

    if (totalTokens > effectiveMax) {
      return {
        ok: false,
        currentTokens: totalTokens,
        maxTokens: effectiveMax,
        modelLimit: maxTokens,
        usagePercent,
        error: `请求消息过大: 当前约 ${totalTokens} tokens，模型 ${model} 有效上限 ${effectiveMax} tokens (${usagePercent}%)。请减少输入内容。`,
      };
    }

    return {
      ok: true,
      currentTokens: totalTokens,
      maxTokens: effectiveMax,
      modelLimit: maxTokens,
      usagePercent,
    };
  }

  /**
   * 计算给定 system + user prompt 的 token 使用情况
   */
  checkPrompts(systemPrompt, userPrompt, model, overheadTokens = 0) {
    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ];
    const result = this.check(messages, model);
    result.systemTokens = estimateTokens(systemPrompt);
    result.userTokens = estimateTokens(userPrompt);
    result.overhead = overheadTokens || this.overheadTokens;
    return result;
  }
}


export class AgentOutputValidator {
  /**
   * 验证单个 LLM finding 是否有效
   * 过滤：
   * - 空 title / 无意义的标题
   * - 缺少 severity 或 location
   * - 带有自然语言解释而非实际漏洞的项
   */
  validateFinding(finding) {
    const issues = [];
    const warnings = [];

    if (!finding || typeof finding !== "object") {
      return { isValid: false, issues: ["finding 不是有效对象"], warnings: [] };
    }

    const title = finding.title || "";
    if (!title.trim()) {
      issues.push("title 为空");
    }

    if (!finding.severity || !finding.severity.toString().trim()) {
      issues.push("severity 缺失");
    }

    if (!finding.location && !finding.filePath && !finding.line) {
      issues.push("location/filePath 缺失");
    }

    // evidence/description 缺失 → 软告警而非硬拒绝：降置信度后保留
    if (!finding.evidence && !finding.description) {
      warnings.push("evidence/description 缺失（已降级保留）");
      // 设置通过 normalizeFindings 门槛的最低置信度
      if (finding.confidence === undefined || finding.confidence < 0.55) {
        finding.confidence = 0.55;
      }
    }

    if (title.length > 200) {
      warnings.push("title 过长 (" + title.length + " 字符)");
    }

    const isValid = issues.length === 0;
    return { isValid, issues, warnings };
  }

  /**
   * 批量验证并过滤
   */
  validateFindings(findings) {
    const valid = [];
    const invalid = [];

    for (const finding of findings) {
      const validation = this.validateFinding(finding);
      if (validation.warnings && validation.warnings.length > 0) {
        console.warn(`[LLM审计]   软告警: ${validation.warnings.join('; ')}`);
      }
      if (validation.isValid) {
        valid.push(finding);
      } else {
        invalid.push({ finding, issues: validation.issues });
      }
    }

    return { valid, invalid, totalIn: findings.length, totalValid: valid.length, totalInvalid: invalid.length };
  }
}

export function buildDependencyContext(finding, codeGraph, options = {}) {
  const { maxDepth = 2, maxNodes = 12 } = options;
  const context = {
    upstreamBranches: [],
    downstreamBranches: [],
    focusPaths: [],
    inputSources: [],
    dangerousSinks: [],
    validationSignals: [],
    safetySignals: [],
    hasInputPath: false,
    hasSinkPath: false,
    combinedRisk: false,
  };

  if (!codeGraph || !finding) return context;

  const nodeQN =
    finding.qualifiedName ||
    (typeof finding.location === "object" ? finding.location.qualifiedName : null) ||
    finding.title;

  if (!nodeQN) return context;

  const upstream = codeGraph.getUpstreamNodes ? codeGraph.getUpstreamNodes(nodeQN, maxDepth) : [];
  const downstream = codeGraph.getDownstreamNodes ? codeGraph.getDownstreamNodes(nodeQN, maxDepth) : [];

  for (const node of upstream.slice(0, maxNodes)) {
    const code = node.sourceCode || "";
    const ext = node.extension || _inferExtension(node);
    const profile = getSecurityHintProfile(code, ext);
    context.upstreamBranches.push({
      name: node.name || node.qualifiedName,
      path: node.filePath,
      lineStart: node.lineStart,
      lineEnd: node.lineEnd,
      hasInput: profile.hasInput,
      hasSink: profile.hasSink,
    });
    if (profile.hasInput) context.inputSources.push(node.qualifiedName);
    if (profile.hasSink) context.dangerousSinks.push(node.qualifiedName);
    if (profile.hasValidation) context.validationSignals.push(node.qualifiedName);
    if (profile.hasSafety) context.safetySignals.push(node.qualifiedName);
  }

  for (const node of downstream.slice(0, maxNodes)) {
    const code = node.sourceCode || "";
    const ext = node.extension || _inferExtension(node);
    const profile = getSecurityHintProfile(code, ext);
    context.downstreamBranches.push({
      name: node.name || node.qualifiedName,
      path: node.filePath,
      lineStart: node.lineStart,
      lineEnd: node.lineEnd,
      hasInput: profile.hasInput,
      hasSink: profile.hasSink,
    });
    if (profile.hasInput) context.inputSources.push(node.qualifiedName);
    if (profile.hasSink) context.dangerousSinks.push(node.qualifiedName);
    if (profile.hasValidation) context.validationSignals.push(node.qualifiedName);
    if (profile.hasSafety) context.safetySignals.push(node.qualifiedName);
  }

  context.hasInputPath = context.upstreamBranches.some((n) => n.hasInput);
  context.hasSinkPath = context.downstreamBranches.some((n) => n.hasSink);
  context.combinedRisk =
    (context.hasInputPath && context.hasSinkPath) ||
    (context.inputSources.length > 0 && context.dangerousSinks.length > 0);

  return context;
}

/**
 * 将依赖上下文格式化为 LLM 可消费的文本
 */
export function formatDependencyContextText(ctx) {
  if (!ctx || (!ctx.upstreamBranches?.length && !ctx.downstreamBranches?.length)) {
    return "";
  }

  const parts = [];

  if (ctx.upstreamBranches.length > 0) {
    parts.push("【上游输入分支】");
    for (const branch of ctx.upstreamBranches) {
      parts.push(`  → ${branch.name} (${branch.path}:${branch.lineStart})${branch.hasInput ? " [外部输入]" : ""}${branch.hasSink ? " [危险操作]" : ""}`);
    }
  }

  if (ctx.downstreamBranches.length > 0) {
    parts.push("【下游危险分支】");
    for (const branch of ctx.downstreamBranches) {
      parts.push(`  → ${branch.name} (${branch.path}:${branch.lineStart})${branch.hasSink ? " [危险操作]" : ""}`);
    }
  }

  if (ctx.combinedRisk) {
    parts.unshift("⚠️ 存在输入源到危险点的组合风险路径");
  }

  return parts.join("\n");
}

function _inferExtension(node) {
  if (node.language === "python") return ".py";
  if (node.language === "javascript") return ".js";
  if (node.language === "typescript") return ".ts";
  if (node.language === "java") return ".java";
  if (node.language === "go") return ".go";
  if (node.language === "php") return ".php";
  if (node.language === "csharp") return ".cs";
  if (node.language === "cpp") return ".cpp";
  if (node.language === "c") return ".c";
  return "";
}
