const SEVERITY_LEVEL = {
  BLOCKER: 'blocker',
  MAJOR: 'major',
  MINOR: 'minor',
  INFO: 'info'
};

const SCORE_WEIGHTS = {
  blocker: 25,
  major: 5,
  minor: 1
};

const DEFAULT_GATE_CONFIG = {
  threshold: 70,
  maxMajor: 3,
  maxBlocker: 0
};

function mapSeverity(severity) {
  const key = String(severity || '').toLowerCase();
  if (key === 'critical' || key === '严重' || key === 'blocker') return SEVERITY_LEVEL.BLOCKER;
  if (key === 'high' || key === '高危' || key === 'major') return SEVERITY_LEVEL.MAJOR;
  if (key === 'medium' || key === '中危' || key === 'minor') return SEVERITY_LEVEL.MINOR;
  return SEVERITY_LEVEL.INFO;
}

function calcScore(counts) {
  const infoPenalty = Math.min(3, Math.max(0, (counts.info || 0) - 5));
  return Math.max(0, 100
    - (counts.blocker || 0) * SCORE_WEIGHTS.blocker
    - (counts.major || 0) * SCORE_WEIGHTS.major
    - (counts.minor || 0) * SCORE_WEIGHTS.minor
    - infoPenalty
  );
}

function evaluateGate(counts, score, gateConfig) {
  const config = { ...DEFAULT_GATE_CONFIG, ...gateConfig };
  const reasons = [];
  if ((counts.blocker || 0) > config.maxBlocker) {
    reasons.push(`blocker:${counts.blocker}>${config.maxBlocker}`);
  }
  if ((counts.major || 0) > config.maxMajor) {
    reasons.push(`major:${counts.major}>${config.maxMajor}`);
  }
  if (score < config.threshold) {
    reasons.push(`score:${score}<${config.threshold}`);
  }
  return { passed: reasons.length === 0, reasons };
}

export function scoreFindings(findings, gateConfig = {}) {
  const items = Array.isArray(findings) ? findings : [];
  const counts = { blocker: 0, major: 0, minor: 0, info: 0 };

  for (const finding of items) {
    const level = mapSeverity(finding.severity);
    counts[level] = (counts[level] || 0) + 1;
  }

  const score = calcScore(counts);
  const gate = evaluateGate(counts, score, gateConfig);

  return {
    score,
    counts,
    gate,
    findingsCount: items.length,
    rating: score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'D'
  };
}

export function scoreBySource(findings, gateConfig = {}) {
  const items = Array.isArray(findings) ? findings : [];
  const quickScan = items.filter(f => f.source === 'heuristic' || f.source === 'quick-scan');
  const llm = items.filter(f => f.source === 'llm');
  const react = items.filter(f => f.source === 'react');

  return {
    overall: scoreFindings(items, gateConfig),
    quickScan: scoreFindings(quickScan, gateConfig),
    llm: scoreFindings(llm, gateConfig),
    react: scoreFindings(react, gateConfig)
  };
}


