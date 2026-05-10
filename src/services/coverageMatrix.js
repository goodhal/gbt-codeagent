/**
 * 覆盖率矩阵服务
 * 用于追踪审计覆盖范围和进度
 */

import path from "path";

export class CoverageMatrix {
  constructor() {
    this.modules = new Map();
    this.auditedFiles = new Map();
    this.auditRecords = [];
  }

  addModule(modulePath, stats = {}) {
    this.modules.set(modulePath, {
      path: modulePath,
      loc: stats.loc || 0,
      controllerCount: stats.controllerCount || 0,
      riskLevel: stats.riskLevel || 'MEDIUM',
      status: 'pending',
      tierCounts: { T1: 0, T2: 0, T3: 0 },
      auditState: null,
      auditTime: null,
      findings: 0
    });
  }

  trackFile(filePath, tier, status = 'audited') {
    const normalizedPath = path.normalize(filePath);
    this.auditedFiles.set(normalizedPath, {
      file: normalizedPath,
      tier,
      status,
      auditedAt: status === 'audited' ? Date.now() : null
    });

    if (tier) {
      const module = this._findModule(filePath);
      if (module) {
        module.tierCounts[tier]++;
      }
    }
  }

  markSkipped(filePath, reason = 'third_party') {
    const normalizedPath = path.normalize(filePath);
    this.auditedFiles.set(normalizedPath, {
      file: normalizedPath,
      tier: null,
      status: `skipped:${reason}`
    });
  }

  markAudited(filePath, tier, findings = 0) {
    this.trackFile(filePath, tier, 'audited');
    const module = this._findModule(filePath);
    if (module) {
      module.findings += findings;
      if (module.status === 'pending') {
        module.status = 'audited';
        module.auditTime = Date.now();
      }
    }
    this.auditRecords.push({
      file: path.normalize(filePath),
      tier,
      findings,
      timestamp: Date.now()
    });
  }

  _findModule(filePath) {
    const normalized = path.normalize(filePath);
    for (const [modulePath, module] of this.modules) {
      if (normalized.includes(modulePath) || modulePath.includes(normalized.split(path.sep)[0])) {
        return module;
      }
    }
    return null;
  }

  getCoverageReport() {
    const allFiles = Array.from(this.auditedFiles.values());
    const auditedCount = allFiles.filter(f => f.status === 'audited').length;
    const skippedCount = allFiles.filter(f => f.status.startsWith('skipped')).length;
    const totalCount = allFiles.length;
    const coveragePercent = totalCount > 0 ? Math.round((auditedCount / totalCount) * 100) : 0;

    const tierStats = { T1: { total: 0, audited: 0 }, T2: { total: 0, audited: 0 }, T3: { total: 0, audited: 0 } };
    for (const file of allFiles) {
      if (file.tier && tierStats[file.tier]) {
        tierStats[file.tier].total++;
        if (file.status === 'audited') tierStats[file.tier].audited++;
      }
    }

    return {
      total: totalCount,
      audited: auditedCount,
      skipped: skippedCount,
      coveragePercent,
      tierStats,
      isComplete: coveragePercent >= 100,
      moduleStats: Array.from(this.modules.values()),
      recentRecords: this.auditRecords.slice(-20)
    };
  }

  isCoverageComplete(minPercent = 100) {
    const report = this.getCoverageReport();
    return report.coveragePercent >= minPercent;
  }

  getUnauditedFiles() {
    return Array.from(this.auditedFiles.values())
      .filter(f => f.status !== 'audited' && !f.status.startsWith('skipped'))
      .map(f => f.file);
  }

  exportToJson() {
    return {
      generatedAt: new Date().toISOString(),
      modules: Array.from(this.modules.entries()),
      files: Array.from(this.auditedFiles.entries()),
      records: this.auditRecords
    };
  }
}