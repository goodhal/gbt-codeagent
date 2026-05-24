/**
 * 审计候选预筛选器单元测试
 */
import { expect } from 'chai';
import { AuditCandidateFilter } from '../src/services/auditCandidateFilter.js';

describe('AuditCandidateFilter.scoreCandidate', () => {
  const filter = new AuditCandidateFilter({ enableCodeGraphScoring: false });

  it('scores high finding higher than low', () => {
    const high = filter.scoreCandidate({ severity: 'high', vulnType: 'SQL_INJECTION' });
    const low = filter.scoreCandidate({ severity: 'low', vulnType: 'SQL_INJECTION' });
    expect(high).to.be.greaterThan(low);
  });

  it('scores finding with evidence higher', () => {
    const withEvidence = filter.scoreCandidate({
      severity: 'high',
      evidence: 'db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      language: 'javascript'
    });
    const withoutEvidence = filter.scoreCandidate({
      severity: 'high',
      language: 'javascript'
    });
    expect(withEvidence).to.be.greaterThan(withoutEvidence);
  });

  it('handles null finding gracefully', () => {
    expect(filter.scoreCandidate(null)).to.equal(0);
    expect(filter.scoreCandidate(undefined)).to.equal(0);
  });
});

describe('AuditCandidateFilter.filterCandidatesLenient', () => {
  const filter = new AuditCandidateFilter({
    candidateScoreThreshold: 12,
    minHighRiskScore: 20,
    enableCodeGraphScoring: false
  });

  it('returns stats with total count', () => {
    const findings = [
      { severity: 'critical', evidence: 'Runtime.exec(cmd)', language: 'java' },
      { severity: 'low', language: 'python' },
    ];
    const result = filter.filterCandidatesLenient(findings);
    expect(result.stats.totalCandidates).to.equal(2);
    expect(result.passed.length + result.filtered.length).to.equal(2);
  });

  it('passes high priority findings', () => {
    const findings = [
      {
        severity: 'critical',
        evidence: "Runtime.getRuntime().exec('rm -rf /')",
        language: 'java',
        location: '/api/admin/exec'
      },
    ];
    const result = filter.filterCandidatesLenient(findings);
    expect(result.passed.length).to.equal(1);
    expect(result.passed[0]._auditPriority).to.equal('high');
  });

  it('handles empty array', () => {
    const result = filter.filterCandidatesLenient([]);
    expect(result.stats.totalCandidates).to.equal(0);
    expect(result.passed).to.be.empty;
    expect(result.filtered).to.be.empty;
  });

  it('sorts passed by score descending', () => {
    const findings = [
      {
        severity: 'high',
        evidence: 'db.query(userInput)',
        language: 'javascript',
        location: '/api/data',
      },
      {
        severity: 'high',
        evidence: "Runtime.getRuntime().exec(cmd + userInput)",
        language: 'java',
        location: '/api/admin/exec',
      },
    ];
    const result = filter.filterCandidatesLenient(findings);
    expect(result.passed).to.have.length(2);
    expect(result.passed[0]._auditScore).to.be.greaterThanOrEqual(result.passed[1]._auditScore);
  });
});

describe('AuditCandidateFilter._classifyPriority', () => {
  it('score >= 50 → high', () => {
    const filter = new AuditCandidateFilter();
    expect(filter._classifyPriority(50)).to.equal('high');
    expect(filter._classifyPriority(100)).to.equal('high');
  });
  it('score 20-49 → medium', () => {
    const filter = new AuditCandidateFilter();
    expect(filter._classifyPriority(20)).to.equal('medium');
    expect(filter._classifyPriority(35)).to.equal('medium');
  });
  it('score < 20 → low', () => {
    const filter = new AuditCandidateFilter();
    expect(filter._classifyPriority(0)).to.equal('low');
    expect(filter._classifyPriority(10)).to.equal('low');
  });
});
