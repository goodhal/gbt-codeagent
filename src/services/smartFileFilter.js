import { promises as fs } from 'node:fs';
import path from 'path';

const LOW_RISK_EXTENSIONS = [
  '.md', '.txt', '.json', '.yaml', '.yml', '.xml',
  '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico',
  '.css', '.scss', '.less',
  '.lock', '.gitignore', '.dockerignore',
  '.md5', '.sha256',
  '.log', '.tmp', '.bak'
];

const HIGH_RISK_EXTENSIONS = [
  '.java', '.py', '.js', '.ts', '.tsx', '.jsx',
  '.php', '.go', '.rs', '.rb',
  '.cpp', '.c', '.cxx', '.h', '.hpp',
  '.cs', '.vb', '.asp', '.aspx',
  '.sql', '.pl', '.pm', '.tpl'
];

const HIGH_RISK_PATTERNS = [
  /controller/i,
  /service/i,
  /handler/i,
  /api/i,
  /auth/i,
  /security/i,
  /login/i,
  /admin/i,
  /payment/i,
  /encrypt/i,
  /decrypt/i,
  /config/i,
  /secret/i,
  /token/i,
  /session/i,
  /jdbc/i,
  /orm/i,
  /dto/i,
  /entity/i,
  /model/i
];

const LOW_RISK_PATTERNS = [
  /test/i,
  /spec/i,
  /mock/i,
  /fixture/i,
  /sample/i,
  /example/i,
  /demo/i,
  /doc/i,
  /docs/i,
  /readme/i,
  /changelog/i,
  /license/i
];

const TIER_PATTERNS = {
  T1: [
    /controller/i, /filter/i, /interceptor/i, /gateway/i,
    /securityconfig/i, /webconfig/i, /route/i, /router/i,
    /DispatchServlet/i, /DispatchFilter/i, /MvcConfig/i,
    /AuthFilter/i, /CorsFilter/i, /RateLimitFilter/i
  ],
  T2: [
    /service/i, /dao/i, /mapper/i, /repository/i,
    /util/i, /helper/i, /manager/i, /handler/i,
    /config/i, /properties/i, /application/i,
    /business/i, /core/i, /common/i
  ],
  T3: [
    /entity/i, /dto/i, /vo/i, /pojo/i, /model/i,
    /domain/i, /bean/i, /object/i,
    /request/i, /response/i, /param/i
  ]
};

const EALOC_WEIGHTS = {
  T1: 1.0,
  T2: 0.5,
  T3: 0.1
};

export class SmartFileFilter {
  constructor() {
    this.cache = new Map();
    this.cacheTtl = 300000;
  }

  shouldAuditFile(filePath, options = {}) {
    const cacheKey = filePath;
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() < cached.expires) {
      return cached.result;
    }

    const result = this._evaluateFile(filePath, options);
    
    this.cache.set(cacheKey, {
      result,
      expires: Date.now() + this.cacheTtl
    });

    return result;
  }

  _evaluateFile(filePath, options) {
    const basename = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();
    const dirname = path.dirname(filePath).toLowerCase();

    if (LOW_RISK_EXTENSIONS.includes(ext)) {
      return { shouldAudit: false, reason: 'low_risk_extension', confidence: 0.9 };
    }

    if (options.skipTests && LOW_RISK_PATTERNS.some(p => p.test(basename))) {
      return { shouldAudit: false, reason: 'test_file', confidence: 0.85 };
    }

    if (options.skipTests && (dirname.includes('/test/') || dirname.includes('/tests/') || dirname.includes('/spec/'))) {
      return { shouldAudit: false, reason: 'test_directory', confidence: 0.9 };
    }

    if (dirname.includes('/node_modules/') || dirname.includes('/vendor/') || dirname.includes('/dist/') || dirname.includes('/build/')) {
      return { shouldAudit: false, reason: 'third_party_code', confidence: 0.95 };
    }

    if (dirname.includes('/docs/') || dirname.includes('/documentation/')) {
      return { shouldAudit: false, reason: 'documentation', confidence: 0.95 };
    }

    let score = 0.5;

    if (HIGH_RISK_EXTENSIONS.includes(ext)) {
      score += 0.3;
    }

    if (HIGH_RISK_PATTERNS.some(p => p.test(basename))) {
      score += 0.2;
    }

    if (HIGH_RISK_PATTERNS.some(p => p.test(dirname))) {
      score += 0.1;
    }

    score = Math.min(score, 0.95);

    return {
      shouldAudit: score >= options.minScore || 0.6,
      reason: score >= 0.8 ? 'high_risk' : score >= 0.6 ? 'medium_risk' : 'low_risk',
      confidence: score,
      riskScore: score
    };
  }

  filterFiles(files, options = {}) {
    const result = {
      toAudit: [],
      skipped: [],
      stats: {
        total: files.length,
        toAudit: 0,
        skipped: 0,
        avgRiskScore: 0
      }
    };

    let totalRiskScore = 0;

    for (const file of files) {
      const filePath = file.path || file.fullPath || file;
      const evaluation = this.shouldAuditFile(filePath, options);
      const entry = typeof file === 'string' ? { path: file, fullPath: file } : { ...file };

      if (evaluation.shouldAudit) {
        result.toAudit.push({ ...entry, riskScore: evaluation.riskScore });
        totalRiskScore += evaluation.riskScore;
      } else {
        result.skipped.push({ ...entry, skipReason: evaluation.reason });
      }
    }

    result.toAudit.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

    result.stats.toAudit = result.toAudit.length;
    result.stats.skipped = result.skipped.length;
    result.stats.avgRiskScore = result.toAudit.length > 0
      ? Math.round((totalRiskScore / result.toAudit.length) * 100) / 100
      : 0;

    return result;
  }

  estimateAuditTime(files, options = {}) {
    const filtered = this.filterFiles(files, options);
    const avgTimePerFile = options.avgTimePerFile || 3000;
    const batchOverhead = options.batchOverhead || 1000;
    const batchSize = options.batchSize || 5;

    const batches = Math.ceil(filtered.stats.toAudit / batchSize);
    const totalTime = (filtered.stats.toAudit * avgTimePerFile) + (batches * batchOverhead);

    return {
      ...filtered.stats,
      estimatedMs: totalTime,
      estimatedSeconds: Math.round(totalTime / 1000),
      estimatedMinutes: Math.round(totalTime / 60000),
      batches
    };
  }

  clearCache() {
    this.cache.clear();
  }

  getCacheStats() {
    return {
      entries: this.cache.size,
      ttl: this.cacheTtl
    };
  }

  getTier(filePath) {
    const basename = path.basename(filePath).toLowerCase();
    const dirname = path.dirname(filePath).toLowerCase();

    for (const pattern of TIER_PATTERNS.T1) {
      if (pattern.test(basename) || pattern.test(dirname)) return 'T1';
    }
    for (const pattern of TIER_PATTERNS.T2) {
      if (pattern.test(basename) || pattern.test(dirname)) return 'T2';
    }
    for (const pattern of TIER_PATTERNS.T3) {
      if (pattern.test(basename) || pattern.test(dirname)) return 'T3';
    }
    return 'T2';
  }

  classifyByTier(files) {
    const classified = { T1: [], T2: [], T3: [], unknown: [] };
    for (const file of files) {
      const filePath = file.path || file.fullPath || file;
      const tier = this.getTier(filePath);
      const entry = typeof file === 'string' ? { path: file, fullPath: file } : { ...file };
      classified[tier].push({ ...entry, tier });
    }
    return classified;
  }

  calculateEALOC(tierCounts) {
    const t1Loc = tierCounts.T1 || 0;
    const t2Loc = tierCounts.T2 || 0;
    const t3Loc = tierCounts.T3 || 0;
    return Math.ceil(
      t1Loc * EALOC_WEIGHTS.T1 +
      t2Loc * EALOC_WEIGHTS.T2 +
      t3Loc * EALOC_WEIGHTS.T3
    );
  }

  estimateAgentCount(tierCounts, budgetPerAgent = 15000) {
    const ealoc = this.calculateEALOC(tierCounts);
    return Math.ceil(ealoc / budgetPerAgent);
  }

  filterFilesWithTier(files, options = {}) {
    const result = this.filterFiles(files, options);
    result.tierCounts = { T1: 0, T2: 0, T3: 0 };
    result.ealoc = 0;

    for (const file of result.toAudit) {
      const tier = file.tier || this.getTier(file.path || file.fullPath);
      file.tier = tier;
      result.tierCounts[tier]++;
    }
    result.ealoc = this.calculateEALOC(result.tierCounts);
    result.estimatedAgents = Math.ceil(result.ealoc / 15000);

    return result;
  }
}

const ANALYSIS_CACHE = new Map();

export class AnalysisCache {
  static get(key) {
    const entry = ANALYSIS_CACHE.get(key);
    if (entry && Date.now() < entry.expires) {
      return entry.data;
    }
    return null;
  }

  static set(key, data, ttl = 3600000) {
    ANALYSIS_CACHE.set(key, {
      data,
      expires: Date.now() + ttl,
      createdAt: Date.now()
    });
  }

  static has(key) {
    const entry = ANALYSIS_CACHE.get(key);
    return entry && Date.now() < entry.expires;
  }

  static delete(key) {
    ANALYSIS_CACHE.delete(key);
  }

  static clear() {
    ANALYSIS_CACHE.clear();
  }

  static prune() {
    const now = Date.now();
    for (const [key, entry] of ANALYSIS_CACHE) {
      if (now >= entry.expires) {
        ANALYSIS_CACHE.delete(key);
      }
    }
  }

  static getStats() {
    let size = 0;
    for (const entry of ANALYSIS_CACHE.values()) {
      size += JSON.stringify(entry.data).length;
    }
    return {
      entries: ANALYSIS_CACHE.size,
      approximateSize: size,
      approximateSizeKB: Math.round(size / 1024)
    };
  }
}

export async function calculateFileRiskScore(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    const lines = content.split('\n');
    
    let score = 0.5;
    const features = {
      hasExec: /\b(exec|system|shell_exec|subprocess|ProcessBuilder)\b/.test(content),
      hasSql: /\b(query|execute|Statement|raw.*sql)\b/i.test(content),
      hasAuth: /\b(authenticate|login|password|token|jwt|session)\b/i.test(content),
      hasCrypto: /\b(encrypt|decrypt|md5|sha1|base64|secret)\b/i.test(content),
      hasFile: /\b(readFile|writeFile|open|fs\.)/i.test(content),
      hasNetwork: /\b(fetch|axios|http\.get|request|socket)\b/i.test(content),
      hasEval: /\b(eval|new Function)\b/.test(content),
      hasDeserialize: /\b(pickle|unserialize|JSON\.parse|yaml\.load)\b/i.test(content)
    };

    if (features.hasExec) score += 0.15;
    if (features.hasSql) score += 0.1;
    if (features.hasAuth) score += 0.1;
    if (features.hasCrypto) score += 0.08;
    if (features.hasFile) score += 0.05;
    if (features.hasNetwork) score += 0.05;
    if (features.hasEval) score += 0.1;
    if (features.hasDeserialize) score += 0.1;

    const complexity = Math.min(lines.length / 1000, 1);
    score += complexity * 0.05;

    return Math.min(Math.round(score * 100) / 100, 1.0);
  } catch {
    return 0.5;
  }
}

export const smartFileFilter = new SmartFileFilter();