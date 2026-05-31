import { expect } from 'chai';
import { scoreFindings, scoreBySource } from '../src/core/auditScoreEngine.js';

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

  it('mapSeverity: critical → blocker', () => {
    const result = scoreFindings([{ severity: 'critical' }]);
    expect(result.counts.blocker).to.equal(1);
  });

  it('mapSeverity: high → major', () => {
    const result = scoreFindings([{ severity: 'high' }]);
    expect(result.counts.major).to.equal(1);
  });

  it('mapSeverity: medium → minor', () => {
    const result = scoreFindings([{ severity: 'medium' }]);
    expect(result.counts.minor).to.equal(1);
  });

  it('mapSeverity: unknown → info', () => {
    const result = scoreFindings([{ severity: 'bogus' }]);
    expect(result.counts.info).to.equal(1);
  });

  it('mapSeverity: empty string → info', () => {
    const result = scoreFindings([{ severity: '' }]);
    expect(result.counts.info).to.equal(1);
  });

  it('mapSeverity: null → info', () => {
    const result = scoreFindings([{ severity: null }]);
    expect(result.counts.info).to.equal(1);
  });

  it('calcScore: 1 blocker → score 75', () => {
    const result = scoreFindings([{ severity: 'critical' }]);
    expect(result.score).to.equal(75);
  });

  it('calcScore: 2 blockers → score 50', () => {
    const result = scoreFindings([
      { severity: 'critical' },
      { severity: 'critical' }
    ]);
    expect(result.score).to.equal(50);
  });

  it('calcScore: 1 major → score 95', () => {
    const result = scoreFindings([{ severity: 'high' }]);
    expect(result.score).to.equal(95);
  });

  it('calcScore: 1 blocker + 2 majors → score 65', () => {
    const result = scoreFindings([
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'high' }
    ]);
    expect(result.score).to.equal(65);
  });

  it('calcScore: score cannot go below 0', () => {
    const result = scoreFindings(Array(5).fill({ severity: 'critical' }));
    expect(result.score).to.equal(0);
  });

  it('evaluateGate: passes with 0 blockers', () => {
    const result = scoreFindings([]);
    expect(result.gate.passed).to.be.true;
  });

  it('evaluateGate: blocks with 1 blocker (maxBlocker=0)', () => {
    const result = scoreFindings([{ severity: 'critical' }]);
    expect(result.gate.passed).to.be.false;
  });

  it('evaluateGate: blocks when score below threshold', () => {
    const result = scoreFindings(Array(4).fill({ severity: 'critical' }));
    expect(result.score).to.be.lessThan(70);
    expect(result.gate.passed).to.be.false;
  });

  it('single critical → rating B', () => {
    const result = scoreFindings([{ severity: 'critical' }]);
    expect(result.rating).to.equal('B');
  });

  it('3 blockers → rating D', () => {
    const result = scoreFindings([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' }
    ]);
    expect(result.findingsCount).to.equal(3);
    expect(result.rating).to.equal('D');
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
