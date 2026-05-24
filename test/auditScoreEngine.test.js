/**
 * 审计评分引擎单元测试
 */
import { expect } from 'chai';
import {
  scoreFindings,
  scoreBySource,
  mapSeverity,
  calcScore,
  evaluateGate,
  SEVERITY_LEVEL
} from '../src/core/auditScoreEngine.js';

describe('mapSeverity', () => {
  it('critical → BLOCKER', () => {
    expect(mapSeverity('critical')).to.equal(SEVERITY_LEVEL.BLOCKER);
  });
  it('high → MAJOR', () => {
    expect(mapSeverity('high')).to.equal(SEVERITY_LEVEL.MAJOR);
  });
  it('medium → MINOR', () => {
    expect(mapSeverity('medium')).to.equal(SEVERITY_LEVEL.MINOR);
  });
  it('unknown → INFO', () => {
    expect(mapSeverity('bogus')).to.equal(SEVERITY_LEVEL.INFO);
  });
  it('empty string → INFO', () => {
    expect(mapSeverity('')).to.equal(SEVERITY_LEVEL.INFO);
  });
  it('nullish → INFO', () => {
    expect(mapSeverity(null)).to.equal(SEVERITY_LEVEL.INFO);
  });
});

describe('calcScore', () => {
  it('empty counts → 100', () => {
    expect(calcScore({ blocker: 0, major: 0, minor: 0, info: 0 })).to.equal(100);
  });
  it('1 blocker → 75', () => {
    expect(calcScore({ blocker: 1, major: 0, minor: 0, info: 0 })).to.equal(75);
  });
  it('2 blockers → 50', () => {
    expect(calcScore({ blocker: 2, major: 0, minor: 0, info: 0 })).to.equal(50);
  });
  it('1 major → 95', () => {
    expect(calcScore({ blocker: 0, major: 1, minor: 0, info: 0 })).to.equal(95);
  });
  it('mix: 1 blocker + 2 majors → 65', () => {
    // 100 - 25 - 2*5 = 65
    expect(calcScore({ blocker: 1, major: 2, minor: 0, info: 0 })).to.equal(65);
  });
  it('score cannot go below 0', () => {
    expect(calcScore({ blocker: 5, major: 0, minor: 0, info: 0 })).to.equal(0);
  });
});

describe('evaluateGate', () => {
  const defaults = { threshold: 70, maxMajor: 3, maxBlocker: 0 };
  it('passes with 0 blockers, 0 majors', () => {
    const gate = evaluateGate({ blocker: 0, major: 0, minor: 0, info: 0 }, 100, defaults);
    expect(gate.passed).to.be.true;
  });
  it('blocks with 1 blocker (maxBlocker=0)', () => {
    const gate = evaluateGate({ blocker: 1, major: 0, minor: 0, info: 0 }, 75, defaults);
    expect(gate.passed).to.be.false;
    expect(gate.reasons).to.include('blocker:1>0');
  });
  it('blocks when score below threshold', () => {
    const gate = evaluateGate({ blocker: 0, major: 0, minor: 0, info: 0 }, 65, defaults);
    expect(gate.passed).to.be.false;
  });
});

describe('scoreFindings', () => {
  it('empty array → score 100, rating A', () => {
    const result = scoreFindings([]);
    expect(result.score).to.equal(100);
    expect(result.rating).to.equal('A');
    expect(result.gate.passed).to.be.true;
  });
  it('non-array → handles gracefully', () => {
    const result = scoreFindings(null);
    expect(result.score).to.equal(100);
  });
  it('single critical → score 75, rating B', () => {
    const result = scoreFindings([{ severity: 'critical' }]);
    expect(result.score).to.equal(75);
    expect(result.rating).to.equal('B');
    expect(result.counts.blocker).to.equal(1);
  });
  it('3 blockers → score 25, rating D, gate blocked', () => {
    const result = scoreFindings([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' }
    ]);
    expect(result.findingsCount).to.equal(3);
    expect(result.score).to.equal(25);
    expect(result.rating).to.equal('D');
    expect(result.gate.passed).to.be.false;
  });
});

describe('scoreBySource', () => {
  it('separates by source', () => {
    const findings = [
      { severity: 'critical', source: 'heuristic' },
      { severity: 'high', source: 'llm' },
      { severity: 'medium', source: 'react' },
    ];
    const result = scoreBySource(findings);
    expect(result.quickScan.findingsCount).to.equal(1);
    expect(result.llm.findingsCount).to.equal(1);
    expect(result.react.findingsCount).to.equal(1);
    expect(result.overall.findingsCount).to.equal(3);
  });
});
