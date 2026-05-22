/**
 * 风险候选预筛选服务
 * 从 AiCodeAudit 引入：对审计候选进行安全线索评分，过滤低风险项
 * 只将高风险候选送入 LLM 深度审计，降低 LLM 调用成本，提升效率
 */

import { getSecurityHintProfile, securityHintScore } from "./securityHintProfile.js";
import { severityScore } from "../utils/findingsUtils.js";

const DEFAULT_CONFIG = {
  candidateScoreThreshold: 12,
  maxInputCodeScore: 6,
  minHighRiskScore: 20,
  enableCodeGraphScoring: true,
  strictMode: true,
};

export class AuditCandidateFilter {
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this._stats = {
      totalCandidates: 0,
      filtered: 0,
      passed: 0,
      byPriority: { high: 0, medium: 0, low: 0 },
    };
  }

  resetStats() {
    this._stats = {
      totalCandidates: 0,
      filtered: 0,
      passed: 0,
      byPriority: { high: 0, medium: 0, low: 0 },
    };
  }

  getStats() {
    return { ...this._stats };
  }

  /**
   * 为单个 finding 计算风险评分
   * 评分维度：
   *  - 已有 heuristic 严重程度基础分
   *  - 文件扩展名对应的安全线索画像
   *  - 代码内容中的安全信号
   *  - evidence / location 中的安全关键路径
   */
  scoreCandidate(finding, codeGraphContext) {
    let score = 0;
    const severity = severityScore(finding.severity || finding.level);
    score += severity * 5;

    const ext = this._inferExtension(finding);
    if (finding.evidence) {
      const { profile } = this._profileCode(finding.evidence, ext);
      score += securityHintScore(profile);
      if (profile.hasInput) score += 25;
      if (profile.hasSink) score += 35;
      if (profile.hasInput && profile.hasSink) score += 200;
      if (profile.hasInput && profile.hasSink && !profile.hasValidation && !profile.hasSafety) score += 150;
    }

    if (finding.location) {
      const locationStr = typeof finding.location === "string"
        ? finding.location
        : JSON.stringify(finding.location);
      const inputPatterns = [/\b(api|auth|admin|login|upload|download|user|password|token|secret)\b/i];
      for (const p of inputPatterns) {
        if (p.test(locationStr)) score += 8;
      }
    }

    if (codeGraphContext && this.config.enableCodeGraphScoring) {
      const nodeQN = finding.qualifiedName || finding.location?.qualifiedName;
      if (nodeQN && codeGraphContext?.inDegree) {
        const inDegree = codeGraphContext.inDegree(nodeQN) || 0;
        const outDegree = codeGraphContext.outDegree(nodeQN) || 0;
        score += inDegree * 2 + outDegree * 3;
      }
    }

    return score;
  }

  /**
   * 筛选候选：只保留高分候选送入 LLM
   * 返回筛选后的候选列表 + 统计信息
   */
  filterCandidates(findings, codeGraphContext) {
    this.resetStats();
    this._stats.totalCandidates = findings.length;

    const scored = findings.map((finding) => ({
      finding,
      score: this.scoreCandidate(finding, codeGraphContext),
    }));

    const threshold = this.config.candidateScoreThreshold;
    const passed = [];
    const filtered = [];

    for (const item of scored) {
      const priority = this._classifyPriority(item.score);
      item.priority = priority;

      if (item.score >= threshold) {
        passed.push({ ...item.finding, _auditScore: item.score, _auditPriority: priority });
        this._stats.passed++;
        this._stats.byPriority[priority]++;
      } else {
        filtered.push({ ...item.finding, _auditScore: item.score, _auditPriority: priority });
        this._stats.filtered++;
      }
    }

    passed.sort((a, b) => (b._auditScore || 0) - (a._auditScore || 0));

    return {
      passed,
      filtered,
      stats: this.getStats(),
      threshold,
    };
  }

  /**
   * 宽松模式：高风险必过，中风险看阈值，低风险排除
   */
  filterCandidatesLenient(findings, codeGraphContext) {
    this.resetStats();
    this._stats.totalCandidates = findings.length;

    const scored = findings.map((finding) => ({
      finding,
      score: this.scoreCandidate(finding, codeGraphContext),
    }));

    const threshold = this.config.candidateScoreThreshold;
    const passed = [];
    const filtered = [];

    for (const item of scored) {
      const priority = this._classifyPriority(item.score);
      item.priority = priority;

      let shouldPass = false;
      if (priority === "high") shouldPass = true;
      else if (priority === "medium" && item.score >= threshold) shouldPass = true;
      else if (item.score >= this.config.minHighRiskScore) shouldPass = true;

      if (shouldPass) {
        passed.push({ ...item.finding, _auditScore: item.score, _auditPriority: priority });
        this._stats.passed++;
        this._stats.byPriority[priority]++;
      } else {
        filtered.push({ ...item.finding, _auditScore: item.score, _auditPriority: priority });
        this._stats.filtered++;
      }
    }

    passed.sort((a, b) => (b._auditScore || 0) - (a._auditScore || 0));

    return {
      passed,
      filtered,
      stats: this.getStats(),
      threshold,
    };
  }

  _classifyPriority(score) {
    if (score >= 50) return "high";
    if (score >= 20) return "medium";
    return "low";
  }

  _inferExtension(finding) {
    if (finding.language === "python") return ".py";
    if (finding.language === "javascript") return ".js";
    if (finding.language === "typescript") return ".ts";
    if (finding.language === "java") return ".java";
    if (finding.language === "go" || finding.language === "golang") return ".go";
    if (finding.language === "php") return ".php";
    if (finding.language === "csharp" || finding.language === "c#") return ".cs";
    if (finding.language === "cpp" || finding.language === "c++") return ".cpp";
    if (finding.language === "c") return ".c";
    const loc = finding.filePath || finding.location?.filePath || "";
    const dotIdx = loc.lastIndexOf(".");
    if (dotIdx >= 0) return loc.slice(dotIdx).toLowerCase();
    return "";
  }

  _profileCode(code, extension) {
    const profile = getSecurityHintProfile(code, extension);
    const score = securityHintScore(profile);
    return { profile, score };
  }
}

let _globalFilter = null;

export function getAuditCandidateFilter(config) {
  if (!_globalFilter) {
    _globalFilter = new AuditCandidateFilter(config);
  }
  return _globalFilter;
}

export function resetAuditCandidateFilter() {
  _globalFilter = null;
}
