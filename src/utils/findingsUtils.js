/**
 * Findings 工具函数
 * 提供问题发现的通用操作方法
 */

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