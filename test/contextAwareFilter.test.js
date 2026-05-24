/**
 * 上下文感知过滤器单元测试
 */
import { expect } from 'chai';
import { isStringLiteralArg, hasGuardPattern, isTestOrMockFile, evaluateGuardContext } from '../src/services/contextAwareFilter.js';

describe('isStringLiteralArg', () => {
  it('detects string literal', () => {
    expect(isStringLiteralArg('"SELECT * FROM users"')).to.be.true;
  });
  it('detects method call with string literal', () => {
    expect(isStringLiteralArg('  fn("hello")  ')).to.be.true;
  });
  it('rejects variable reference', () => {
    expect(isStringLiteralArg('query(sql)')).to.be.false;
  });
  it('rejects empty string', () => {
    expect(isStringLiteralArg('')).to.be.false;
  });
});

describe('hasGuardPattern', () => {
  it('finds SQL_INJECTION guard: PreparedStatement', () => {
    const window = 'PreparedStatement pstmt = conn.prepareStatement(sql)';
    expect(hasGuardPattern(window, 'SQL_INJECTION')).to.be.true;
  });
  it('finds XSS guard: textContent', () => {
    const window = 'el.textContent = userInput';
    expect(hasGuardPattern(window, 'XSS')).to.be.true;
  });
  it('returns false for unknown vuln type', () => {
    expect(hasGuardPattern('some code', 'UNKNOWN_TYPE')).to.be.false;
  });
  it('returns false when no guard present', () => {
    expect(hasGuardPattern('db.query(sql)', 'SQL_INJECTION')).to.be.false;
  });
});

describe('isTestOrMockFile', () => {
  it('identifies test directory', () => {
    expect(isTestOrMockFile('src/test/java/UserService.java')).to.be.true;
  });
  it('identifies mock directory', () => {
    expect(isTestOrMockFile('src/mock/auth.js')).to.be.true;
  });
  it('identifies .test. file', () => {
    expect(isTestOrMockFile('utils.test.js')).to.be.true;
  });
  it('identifies .spec. file', () => {
    expect(isTestOrMockFile('user.spec.ts')).to.be.true;
  });
  it('passes normal source file', () => {
    expect(isTestOrMockFile('src/controllers/auth.js')).to.be.false;
  });
  it('handles null', () => {
    expect(isTestOrMockFile(null)).to.be.false;
  });
});

describe('evaluateGuardContext', () => {
  it('high confidence for normal code', () => {
    const lines = ['db.query(userInput)'];
    const result = evaluateGuardContext(lines, 0, 'SQL_INJECTION');
    expect(result.confidence).to.equal(1.0);
  });

  it('low confidence for string literal arg', () => {
    const lines = ['  query("SELECT * FROM users")  '];
    const result = evaluateGuardContext(lines, 0, 'SQL_INJECTION');
    expect(result.confidence).to.equal(0.2);
    expect(result.notes).to.include('probably_false_positive_string_arg');
  });

  it('low confidence when guard pattern detected', () => {
    const lines = ['PreparedStatement pstmt = conn.prepareStatement(sql); db.query(pstmt)'];
    const result = evaluateGuardContext(lines, 0, 'SQL_INJECTION');
    expect(result.hasGuardPattern).to.be.true;
  });
});
