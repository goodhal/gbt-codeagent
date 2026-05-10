/**
 * Findings 工具函数
 * 提供问题发现的通用操作方法
 */

import {
  VULN_TYPE_CODES,
  SEVERITY_PREFIX,
  VERDICT,
  SANITIZER_PATTERNS,
  DKTSS_BASE_SCORES,
  DKTSS_FRICTION,
  DKTSS_WEAPON,
  getVulnTypeCode,
  getSeverityPrefix,
  calculateDKTSS as configCalculateDKTSS,
  getDktssSeverity as configGetDktssSeverity
} from "../config/auditConfig.js";

/**
 * 为漏洞列表批量生成编号
 * @param {Array} findings - 漏洞列表
 * @returns {Array} 带 vulnId 的漏洞列表
 */
export function assignVulnIds(findings) {
  const assigned = [];
  const counted = {};
  for (const finding of findings) {
    const severity = getSeverityPrefix(finding.severity);
    const typeCode = getVulnTypeCode(finding.type);
    const key = `${severity}-${typeCode}`;
    counted[key] = (counted[key] || 0) + 1;
    assigned.push({
      ...finding,
      vulnId: `${key}-${counted[key].toString().padStart(3, '0')}`
    });
  }
  return assigned;
}

/**
 * 去重 findings
 * @param {Array} findings - findings 数组
 * @param {Object} options - 选项
 * @param {string} options.keyType - key 生成类型: 'title-location', 'type-location', 'type-location-line'
 * @returns {Array} 去重后的 findings
 */
export function deduplicateFindings(findings, options = {}) {
  const { keyType = 'type-location-line' } = options;
  const seen = new Set();
  const deduped = [];

  for (const finding of findings) {
    let key;
    switch (keyType) {
      case 'title-location':
        key = `${finding.title}::${finding.location}`;
        break;
      case 'type-location':
        key = `${finding.vulnType || finding.type}::${finding.location}`;
        break;
      case 'type-location-line':
      default:
        const line = finding.location?.line || finding.line || 0;
        key = `${finding.vulnType || finding.type}::${finding.location}::${line}`;
        break;
    }

    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(finding);
    }
  }

  return deduped;
}

/**
 * 按严重程度排序
 * @param {Array} findings - findings 数组
 * @returns {Array} 排序后的 findings
 */
export function sortBySeverity(findings) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  return [...findings].sort((a, b) => {
    const severityA = severityOrder[a.severity?.toLowerCase()] || 0;
    const severityB = severityOrder[b.severity?.toLowerCase()] || 0;
    if (severityB !== severityA) {
      return severityB - severityA;
    }
    return (b.confidence || 0) - (a.confidence || 0);
  });
}

/**
 * 去重并排序
 * @param {Array} findings - findings 数组
 * @param {Object} options - 选项
 * @returns {Array} 去重并排序后的 findings
 */
export function deduplicateAndSort(findings, options = {}) {
  const deduped = deduplicateFindings(findings, options);
  return sortBySeverity(deduped);
}

/**
 * 严重程度评分
 * @param {string} value - 严重程度值
 * @returns {number} 评分值
 */
export function severityScore(value) {
  return value === "high" || value === "严重" ? 3 : value === "medium" || value === "中危" ? 2 : 1;
}

/**
 * 计算 DKTSS 评分（导出为保持兼容性）
 */
export function calculateDKTSS(finding) {
  return configCalculateDKTSS(finding);
}

/**
 * 获取 DKTSS 严重程度（导出为保持兼容性）
 */
export function getDktSSSeverity(dktssScore) {
  return configGetDktssSeverity(dktssScore);
}

// 导出 VERDICT 和 SANITIZER_PATTERNS 保持兼容性
export { VERDICT, SANITIZER_PATTERNS };