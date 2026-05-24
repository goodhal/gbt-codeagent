/**
 * AdversarialValidateService — 对抗性验证服务
 * 参考: E:\code\audit\audit\stages\validate.py
 *
 * 核心设计：使用与主审计不同的模型/温度参数，以对抗性视角重新审查每个发现。
 * 提示词明确指示："你的报酬按驳回的发现计算"。
 * 此阶段存在是为了在报告生成前过滤 LLM 幻觉和低质量发现。
 */

import { callLLM, parseJsonResponse, clampNumber } from "./llmFactory.js";
import { Semaphore } from "../utils/semaphore.js";
import {
  ADVERSARIAL_VALIDATION_PROMPT,
  ADVERSARIAL_VALIDATION_USER_PROMPT,
} from "../config/llmPrompts.js";

/**
 * @param {object} llmConfig - LLM配置（建议与主审计使用不同模型）
 * @param {string} repoPath - 项目根目录
 * @param {object[]} findings - 待验证的发现列表
 * @param {object} [options]
 * @param {number} [options.maxFindings=30] - 最大验证发现数
 * @param {number} [options.temperature=0.2] - 对抗性验证用稍高温度以产生批判性思维
 * @param {Function} [options.onProgress] - 进度回调
 * @returns {Promise<object>} { validatedFindings, stats }
 */
export async function adversarialValidate(llmConfig, repoPath, findings, options = {}) {
  const { maxFindings = 30, temperature = 0.2, onProgress } = options;

  if (!llmConfig?.apiKey || !findings?.length) {
    return {
      validatedFindings: findings.map(f => ({ ...f, _advValidation: { verdict: "skipped", reason: "no-llm-or-no-findings" } })),
      stats: { confirmed: 0, rejected: 0, needsMoreInfo: 0, skipped: findings.length },
    };
  }

  const candidates = findings
    .filter(f => {
      // 只验证 LLM 来源的发现（规则层的确定性发现不需要对抗性验证）
      const isLlmSourced = f.source === "llm" || f.source === "react";
      // 只验证 critical/high/medium
      const isHighValue = f.severity === "critical" || f.severity === "high" || f.severity === "medium";
      return isLlmSourced && isHighValue;
    })
    .slice(0, maxFindings);

  if (candidates.length === 0) {
    console.log("[对抗验证] 无 LLM 来源的中高危候选发现需要对抗性验证");
    return {
      validatedFindings: findings.map(f => ({ ...f, _advValidation: { verdict: "skipped", reason: "not-llm-sourced-or-low-severity" } })),
      stats: { confirmed: 0, rejected: 0, needsMoreInfo: 0, skipped: findings.length },
    };
  }

  console.log(`[对抗验证] 开始对抗性验证 ${candidates.length}/${findings.length} 条发现 (温度=${temperature})`);

  const stats = { confirmed: 0, rejected: 0, needsMoreInfo: 0, skipped: findings.length - candidates.length };
  const validationResults = new Map();

  const semaphore = new Semaphore(3); // 限并发

  await Promise.all(candidates.map(async (finding, i) => {
    await semaphore.acquire();
    try {
      onProgress?.({
        stage: "adversarial-validate",
        current: i + 1,
        total: candidates.length,
        findingId: finding.finding_id || finding.title,
        label: `对抗性验证: ${i + 1}/${candidates.length}`,
      });

      const result = await validateOneFinding(llmConfig, finding, repoPath, temperature);
      validationResults.set(finding.finding_id || `${finding.location}:${finding.title}`, result);

      if (result.verdict === "confirmed") stats.confirmed++;
      else if (result.verdict === "rejected") stats.rejected++;
      else stats.needsMoreInfo++;

      console.log(`[对抗验证] ${finding.finding_id || finding.title}: ${result.verdict} (confidence: ${result.validatorConfidence})`);
    } catch (error) {
      console.warn(`[对抗验证] 验证失败 ${finding.finding_id || finding.title}: ${error.message}`);
      validationResults.set(finding.finding_id || `${finding.location}:${finding.title}`, {
        verdict: "needs_more_info",
        rationale: `验证器失败: ${error.message}`,
        alternativeExplanation: "",
        validatorConfidence: 0,
      });
      stats.needsMoreInfo++;
    } finally {
      semaphore.release();
    }
  }));

  // 应用验证结果到发现
  const validatedFindings = findings.map(f => {
    const key = f.finding_id || `${f.location}:${f.title}`;
    const validation = validationResults.get(key);
    if (!validation) {
      return {
        ...f,
        _advValidation: { verdict: "skipped", reason: "not-in-validation-scope" },
      };
    }

    // 被驳回的发现：标记为 false_positive
    if (validation.verdict === "rejected") {
      return {
        ...f,
        verdict: "false_positive",
        verificationReason: `[对抗性验证驳回] ${validation.rationale || ""}`,
        _advValidation: validation,
      };
    }

    // 需要更多信息的发现：降级并标记
    if (validation.verdict === "needs_more_info") {
      return {
        ...f,
        confidence: Math.min(f.confidence || 0.8, 0.6),
        _advValidation: validation,
        verificationReason: `[对抗性验证: 需更多信息] ${validation.rationale || ""}`,
      };
    }

    // 确认的发现：保持原样并附验证记录
    return {
      ...f,
      _advValidation: validation,
    };
  });

  return { validatedFindings, stats };
}

async function validateOneFinding(llmConfig, finding, repoPath, temperature) {
  const evidence = (finding.evidence || finding.description || "").substring(0, 3000);
  const description = (finding.description || finding.title || "").substring(0, 500);

  const userPrompt = ADVERSARIAL_VALIDATION_USER_PROMPT
    .replace(/\{finding_id\}/g, finding.finding_id || finding.title || "unknown")
    .replace(/\{attack_class\}/g, finding.vulnType || finding.vuln_class || "unknown")
    .replace(/\{file\}/g, finding.location || finding.file || "unknown")
    .replace(/\{line_start\}/g, String(finding.line_start || "0"))
    .replace(/\{line_end\}/g, String(finding.line_end || "0"))
    .replace(/\{severity\}/g, finding.severity || "unknown")
    .replace(/\{description\}/g, description)
    .replace(/\{evidence_snippet\}/g, evidence)
    .replace(/\{confidence\}/g, String(finding.confidence || 0))
    .replace(/\{scope_hint\}/g, (finding.location || finding.file || ""))
    .replace(/\{rationale\}/g, (finding.type || finding.attackVector || ""));

  const responseText = await callLLM(llmConfig, ADVERSARIAL_VALIDATION_PROMPT, userPrompt, temperature);
  const parsed = parseJsonResponse(responseText);

  return {
    verdict: ["confirmed", "rejected", "needs_more_info"].includes(parsed.verdict)
      ? parsed.verdict : "needs_more_info",
    rationale: parsed.rationale || "",
    alternativeExplanation: parsed.alternative_explanation || "",
    missingPreconditions: Array.isArray(parsed.missing_preconditions) ? parsed.missing_preconditions : [],
    validatorConfidence: clampNumber(parsed.validator_confidence, 0, 1),
  };
}

