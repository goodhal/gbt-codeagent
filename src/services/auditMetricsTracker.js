/**
 * 审计效果追踪服务
 * 记录审计耗时、统计发现准确率、收集反馈
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';

export class AuditMetricsTracker {
  constructor() {
    this.metricsStore = {};
    this.feedbackStore = [];
    this.statistics = {
      totalAudits: 0,
      totalFindings: 0,
      avgDuration: 0,
      avgFindingsPerAudit: 0,
      falsePositiveRate: 0,
      severityDistribution: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      sourceDistribution: {}
    };
  }

  /**
   * 开始审计追踪
   */
  startAudit(auditId, options = {}) {
    this.metricsStore[auditId] = {
      startTime: Date.now(),
      status: 'running',
      findings: [],
      rounds: [],
      options
    };
  }

  /**
   * 记录轮次结果
   */
  recordRound(auditId, roundId, result) {
    if (!this.metricsStore[auditId]) return;

    this.metricsStore[auditId].rounds.push({
      roundId,
      startTime: result.startTime || Date.now(),
      endTime: Date.now(),
      findings: result.findings?.length || 0,
      tokensUsed: result.tokensUsed || 0,
      duration: result.duration || 0
    });
  }

  /**
   * 完成审计
   */
  completeAudit(auditId, findings = []) {
    if (!this.metricsStore[auditId]) return null;

    const audit = this.metricsStore[auditId];
    audit.endTime = Date.now();
    audit.status = 'completed';
    audit.findings = findings;

    // 更新统计
    this._updateStatistics(audit);

    return this._generateReport(audit);
  }

  /**
   * 更新统计数据
   */
  _updateStatistics(audit) {
    this.statistics.totalAudits++;
    this.statistics.totalFindings += audit.findings.length;
    
    // 更新平均时长
    const totalDuration = this.statistics.avgDuration * (this.statistics.totalAudits - 1);
    this.statistics.avgDuration = (totalDuration + (audit.endTime - audit.startTime)) / this.statistics.totalAudits;
    
    // 更新平均发现数
    this.statistics.avgFindingsPerAudit = this.statistics.totalFindings / this.statistics.totalAudits;
    
    // 更新严重程度分布
    audit.findings.forEach(finding => {
      const severity = finding.severity || 'medium';
      if (this.statistics.severityDistribution[severity]) {
        this.statistics.severityDistribution[severity]++;
      }
    });
    
    // 更新来源分布
    const source = audit.options.source || 'unknown';
    if (!this.statistics.sourceDistribution[source]) {
      this.statistics.sourceDistribution[source] = 0;
    }
    this.statistics.sourceDistribution[source]++;
  }

  /**
   * 生成审计报告
   */
  _generateReport(audit) {
    const duration = audit.endTime - audit.startTime;
    const findingsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    
    audit.findings.forEach(finding => {
      const severity = finding.severity || 'medium';
      findingsBySeverity[severity]++;
    });

    return {
      auditId: audit.options.auditId || auditId,
      projectName: audit.options.projectName || 'unknown',
      startTime: new Date(audit.startTime).toISOString(),
      endTime: new Date(audit.endTime).toISOString(),
      duration,
      durationFormatted: this._formatDuration(duration),
      findings: audit.findings.length,
      findingsBySeverity,
      rounds: audit.rounds.length,
      totalTokens: audit.rounds.reduce((sum, r) => sum + (r.tokensUsed || 0), 0),
      avgConfidence: audit.findings.length > 0 
        ? audit.findings.reduce((sum, f) => sum + (f.confidence || 0.5), 0) / audit.findings.length
        : 0
    };
  }

  /**
   * 格式化时长
   */
  _formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    if (minutes > 0) {
      return `${minutes}分${remainingSeconds}秒`;
    }
    return `${remainingSeconds}秒`;
  }

  /**
   * 记录反馈
   */
  recordFeedback(findingId, feedback) {
    this.feedbackStore.push({
      findingId,
      timestamp: Date.now(),
      ...feedback
    });

    // 更新误报率统计
    this._updateFalsePositiveRate();
  }

  /**
   * 更新误报率
   */
  _updateFalsePositiveRate() {
    const totalFeedback = this.feedbackStore.length;
    const falsePositives = this.feedbackStore.filter(f => f.type === 'false_positive').length;
    
    if (totalFeedback > 0) {
      this.statistics.falsePositiveRate = falsePositives / totalFeedback;
    }
  }

  /**
   * 获取统计摘要
   */
  getStatistics() {
    return {
      ...this.statistics,
      avgDurationFormatted: this._formatDuration(this.statistics.avgDuration),
      feedbackCount: this.feedbackStore.length
    };
  }

  /**
   * 获取审计历史
   */
  getAuditHistory() {
    return Object.values(this.metricsStore)
      .filter(a => a.status === 'completed')
      .map(a => this._generateReport(a))
      .sort((a, b) => new Date(b.endTime) - new Date(a.endTime));
  }

  /**
   * 获取最近反馈
   */
  getRecentFeedback(count = 10) {
    return [...this.feedbackStore]
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, count);
  }

  /**
   * 导出统计数据
   */
  async exportStatistics(outputPath) {
    const data = {
      statistics: this.getStatistics(),
      auditHistory: this.getAuditHistory(),
      recentFeedback: this.getRecentFeedback(50),
      exportedAt: new Date().toISOString()
    };

    await fs.writeFile(outputPath, JSON.stringify(data, null, 2), 'utf8');
    return { success: true, filePath: outputPath };
  }

  /**
   * 生成统计报告（Markdown）
   */
  generateStatisticsReport() {
    const stats = this.getStatistics();
    
    let report = `# 审计效果统计报告\n\n`;
    report += `**生成时间**: ${new Date().toLocaleString('zh-CN')}\n\n`;
    
    report += `## 概览\n\n`;
    report += `- 总审计次数: ${stats.totalAudits}\n`;
    report += `- 总发现数: ${stats.totalFindings}\n`;
    report += `- 平均审计时长: ${stats.avgDurationFormatted}\n`;
    report += `- 平均每审计发现数: ${stats.avgFindingsPerAudit.toFixed(1)}\n`;
    report += `- 误报率: ${(stats.falsePositiveRate * 100).toFixed(1)}%\n\n`;

    report += `## 严重程度分布\n\n`;
    report += `| 严重程度 | 数量 | 占比 |\n`;
    report += `|---------|------|------|\n`;
    
    const total = stats.totalFindings || 1;
    for (const [severity, count] of Object.entries(stats.severityDistribution)) {
      report += `| ${this._severityLabel(severity)} | ${count} | ${((count / total) * 100).toFixed(1)}% |\n`;
    }
    report += '\n';

    report += `## 来源分布\n\n`;
    for (const [source, count] of Object.entries(stats.sourceDistribution)) {
      report += `- ${source}: ${count}次 (${((count / stats.totalAudits) * 100).toFixed(1)}%)\n`;
    }
    report += '\n';

    report += `## 反馈统计\n\n`;
    report += `- 总反馈数: ${stats.feedbackCount}\n`;
    
    const falsePositives = this.feedbackStore.filter(f => f.type === 'false_positive').length;
    const truePositives = this.feedbackStore.filter(f => f.type === 'true_positive').length;
    const improvements = this.feedbackStore.filter(f => f.type === 'improvement').length;
    
    report += `- 确认为误报: ${falsePositives}\n`;
    report += `- 确认为真实: ${truePositives}\n`;
    report += `- 改进建议: ${improvements}\n`;

    return report;
  }

  /**
   * 严重程度标签
   */
  _severityLabel(severity) {
    const mapping = {
      'critical': '严重',
      'high': '高危',
      'medium': '中危',
      'low': '低危'
    };
    return mapping[severity] || severity;
  }

  /**
   * 重置统计
   */
  reset() {
    this.metricsStore = {};
    this.feedbackStore = [];
    this.statistics = {
      totalAudits: 0,
      totalFindings: 0,
      avgDuration: 0,
      avgFindingsPerAudit: 0,
      falsePositiveRate: 0,
      severityDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
      sourceDistribution: {}
    };
  }
}

export const auditMetricsTracker = new AuditMetricsTracker();