/**
 * 规则测试框架
 * 用于验证检测规则的有效性和准确性
 * 支持污点分析测试
 */

import { RulesEngine } from '../analyzers/rulesEngine.js';
import { TaintAnalyzer } from '../analyzers/taintAnalyzer.js';

export class RuleTester {
  constructor() {
    this.engine = new RulesEngine();
    this.taintAnalyzer = new TaintAnalyzer();
    this.testResults = [];
    this.coverageStats = {
      totalRules: 0,
      testedRules: 0,
      passedTests: 0,
      failedTests: 0,
      falsePositives: 0,
      falseNegatives: 0
    };
  }

  async initialize(configPath) {
    await this.engine.initialize(configPath);
    await this.taintAnalyzer.initialize(configPath);
    this.coverageStats.totalRules = this._countAllRules();
  }

  _countAllRules() {
    let count = 0;
    const detectionRules = this.engine.rules?.detectionRules || {};
    for (const ruleId of Object.keys(detectionRules)) {
      const rule = detectionRules[ruleId];
      for (const lang of Object.keys(rule.languages || {})) {
        count++;
      }
    }
    return count;
  }

  async runTest(testCase) {
    const { ruleId, language, code, expectedFindings, description } = testCase;
    
    const result = {
      testId: testCase.testId || `${ruleId}-${language}-${Date.now()}`,
      ruleId,
      language,
      description,
      passed: false,
      actualFindings: [],
      expectedFindings: expectedFindings || [],
      errors: [],
      duration: 0
    };

    const startTime = Date.now();
    
    try {
      const matches = await this.engine.matchVulnerability(code, ruleId, language);
      result.actualFindings = matches;
      
      const passed = this._validateFindings(matches, expectedFindings);
      result.passed = passed;
      
      if (!passed) {
        result.errors = this._generateErrors(matches, expectedFindings);
      }
      
    } catch (error) {
      result.errors = [`Test execution error: ${error.message}`];
    }
    
    result.duration = Date.now() - startTime;
    
    this.testResults.push(result);
    
    return result;
  }

  _validateFindings(actual, expected) {
    if (expected.length === 0 && actual.length === 0) {
      return true;
    }
    
    if (expected.length !== actual.length) {
      return false;
    }
    
    for (let i = 0; i < expected.length; i++) {
      const exp = expected[i];
      const act = actual[i];
      
      if (exp.line !== undefined && act.line !== exp.line) {
        return false;
      }
      
      if (exp.pattern && !act.pattern?.includes(exp.pattern)) {
        return false;
      }
      
      if (exp.severity && act.severity !== exp.severity) {
        return false;
      }
      
      if (exp.match && !act.match?.includes(exp.match)) {
        return false;
      }
    }
    
    return true;
  }

  _generateErrors(actual, expected) {
    const errors = [];
    
    if (actual.length !== expected.length) {
      errors.push(`Expected ${expected.length} findings, got ${actual.length}`);
    }
    
    const minLength = Math.min(actual.length, expected.length);
    
    for (let i = 0; i < minLength; i++) {
      const exp = expected[i];
      const act = actual[i];
      
      if (exp.line !== undefined && act.line !== exp.line) {
        errors.push(`Finding ${i}: Expected line ${exp.line}, got ${act.line}`);
      }
      
      if (exp.severity && act.severity !== exp.severity) {
        errors.push(`Finding ${i}: Expected severity ${exp.severity}, got ${act.severity}`);
      }
    }
    
    if (actual.length > expected.length) {
      for (let i = expected.length; i < actual.length; i++) {
        errors.push(`Unexpected finding at line ${actual[i].line}: ${actual[i].match}`);
      }
    }
    
    return errors;
  }

  async runTestSuite(testSuite) {
    const results = [];
    
    for (const testCase of testSuite) {
      const result = await this.runTest(testCase);
      results.push(result);
      
      if (result.passed) {
        this.coverageStats.passedTests++;
      } else {
        this.coverageStats.failedTests++;
      }
      
      this.coverageStats.testedRules++;
    }
    
    return results;
  }

  async runAllTests(testSuites) {
    const allResults = [];
    
    for (const suite of testSuites) {
      const results = await this.runTestSuite(suite.tests);
      allResults.push({
        suiteName: suite.name,
        suiteDescription: suite.description,
        results
      });
    }
    
    return allResults;
  }

  getReport() {
    const passed = this.testResults.filter(r => r.passed).length;
    const failed = this.testResults.filter(r => !r.passed).length;
    const total = this.testResults.length;
    const passRate = total > 0 ? (passed / total * 100).toFixed(2) : '0.00';
    
    const byRule = {};
    for (const result of this.testResults) {
      if (!byRule[result.ruleId]) {
        byRule[result.ruleId] = { passed: 0, failed: 0, total: 0 };
      }
      byRule[result.ruleId].total++;
      if (result.passed) {
        byRule[result.ruleId].passed++;
      } else {
        byRule[result.ruleId].failed++;
      }
    }
    
    return {
      summary: {
        totalTests: total,
        passed,
        failed,
        passRate: `${passRate}%`,
        totalRules: this.coverageStats.totalRules,
        testedRules: this.coverageStats.testedRules,
        coverageRate: this.coverageStats.totalRules > 0 
          ? `${(this.coverageStats.testedRules / this.coverageStats.totalRules * 100).toFixed(2)}%` 
          : '0.00%'
      },
      byRule,
      detailedResults: this.testResults
    };
  }

  async validateRule(ruleId) {
    const rule = this.engine.getRuleById(ruleId);
    if (!rule) {
      return { valid: false, errors: [`Rule ${ruleId} not found`] };
    }
    
    const errors = [];
    
    if (!rule.description) {
      errors.push('Missing description');
    }
    
    if (!rule.languages || Object.keys(rule.languages).length === 0) {
      errors.push('No languages defined');
    } else {
      for (const [lang, langRule] of Object.entries(rule.languages)) {
        if (!langRule.riskPatterns || langRule.riskPatterns.length === 0) {
          errors.push(`Language ${lang} has no risk patterns`);
        }
        
        for (const patternDef of langRule.riskPatterns || []) {
          const pattern = typeof patternDef === 'string' ? patternDef : patternDef.pattern;
          try {
            new RegExp(pattern);
          } catch {
            errors.push(`Invalid regex pattern: ${pattern}`);
          }
        }
      }
    }
    
    if (!rule.cwe && !rule.gbt) {
      errors.push('Missing CWE or GB/T reference');
    }
    
    return {
      valid: errors.length === 0,
      errors,
      rule
    };
  }

  async validateAllRules() {
    const results = [];
    const detectionRules = this.engine.rules?.detectionRules || {};
    
    for (const ruleId of Object.keys(detectionRules)) {
      const result = await this.validateRule(ruleId);
      results.push({
        ruleId,
        ...result
      });
    }
    
    const valid = results.filter(r => r.valid).length;
    const invalid = results.filter(r => !r.valid).length;
    
    return {
      summary: {
        total: results.length,
        valid,
        invalid
      },
      details: results
    };
  }

  async benchmarkRule(ruleId, code, iterations = 100) {
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await this.engine.matchVulnerability(code, ruleId, 'javascript');
      times.push(Date.now() - start);
    }
    
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);
    
    return {
      ruleId,
      iterations,
      avgTime: `${avg.toFixed(2)}ms`,
      minTime: `${min}ms`,
      maxTime: `${max}ms`,
      times
    };
  }

  async calculateFalsePositiveRate(ruleId, testCases) {
    let falsePositives = 0;
    let totalTests = 0;
    
    for (const testCase of testCases) {
      if (!testCase.expectedFindings || testCase.expectedFindings.length === 0) {
        totalTests++;
        const matches = await this.engine.matchVulnerability(
          testCase.code, 
          ruleId, 
          testCase.language
        );
        if (matches.length > 0) {
          falsePositives++;
        }
      }
    }
    
    return {
      ruleId,
      falsePositives,
      totalTests,
      rate: totalTests > 0 ? `${(falsePositives / totalTests * 100).toFixed(2)}%` : 'N/A'
    };
  }

  clearResults() {
    this.testResults = [];
    this.coverageStats = {
      totalRules: 0,
      testedRules: 0,
      passedTests: 0,
      failedTests: 0,
      falsePositives: 0,
      falseNegatives: 0
    };
  }

  async runTaintTest(testCase) {
    const { language, code, expectedVulnerabilities, description } = testCase;
    
    const result = {
      testId: testCase.testId || `taint-${language}-${Date.now()}`,
      type: 'taint',
      language,
      description,
      passed: false,
      actualVulnerabilities: [],
      expectedVulnerabilities: expectedVulnerabilities || [],
      errors: [],
      duration: 0
    };

    const startTime = Date.now();
    
    try {
      const analysis = await this.taintAnalyzer.analyzeCode(code, language);
      result.actualVulnerabilities = analysis.vulnerabilities;
      result.summary = analysis.summary;
      
      const passed = this._validateTaintFindings(analysis.vulnerabilities, expectedVulnerabilities);
      result.passed = passed;
      
      if (!passed) {
        result.errors = this._generateTaintErrors(analysis.vulnerabilities, expectedVulnerabilities);
      }
      
    } catch (error) {
      result.errors = [`Taint analysis error: ${error.message}`];
    }
    
    result.duration = Date.now() - startTime;
    
    this.testResults.push(result);
    
    return result;
  }

  _validateTaintFindings(actual, expected) {
    if (expected.length === 0 && actual.length === 0) {
      return true;
    }
    
    if (expected.length !== actual.length) {
      return false;
    }
    
    for (let i = 0; i < expected.length; i++) {
      const exp = expected[i];
      const act = actual[i];
      
      if (exp.sourceLine !== undefined && act.source?.line !== exp.sourceLine) {
        return false;
      }
      
      if (exp.sinkLine !== undefined && act.sink?.line !== exp.sinkLine) {
        return false;
      }
      
      if (exp.severity && act.severity !== exp.severity) {
        return false;
      }
      
      if (exp.category && act.category !== exp.category) {
        return false;
      }
    }
    
    return true;
  }

  _generateTaintErrors(actual, expected) {
    const errors = [];
    
    if (actual.length !== expected.length) {
      errors.push(`Expected ${expected.length} vulnerabilities, got ${actual.length}`);
    }
    
    const minLength = Math.min(actual.length, expected.length);
    
    for (let i = 0; i < minLength; i++) {
      const exp = expected[i];
      const act = actual[i];
      
      if (exp.sourceLine !== undefined && act.source?.line !== exp.sourceLine) {
        errors.push(`Vulnerability ${i}: Expected source line ${exp.sourceLine}, got ${act.source?.line}`);
      }
      
      if (exp.sinkLine !== undefined && act.sink?.line !== exp.sinkLine) {
        errors.push(`Vulnerability ${i}: Expected sink line ${exp.sinkLine}, got ${act.sink?.line}`);
      }
      
      if (exp.severity && act.severity !== exp.severity) {
        errors.push(`Vulnerability ${i}: Expected severity ${exp.severity}, got ${act.severity}`);
      }
    }
    
    return errors;
  }

  async runTaintTestSuite(testSuite) {
    const results = [];
    
    for (const testCase of testSuite) {
      const result = await this.runTaintTest(testCase);
      results.push(result);
      
      if (result.passed) {
        this.coverageStats.passedTests++;
      } else {
        this.coverageStats.failedTests++;
      }
    }
    
    return results;
  }

  async benchmarkTaintAnalysis(code, language, iterations = 10) {
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await this.taintAnalyzer.analyzeCode(code, language);
      times.push(Date.now() - start);
    }
    
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);
    
    return {
      language,
      iterations,
      avgTime: `${avg.toFixed(2)}ms`,
      minTime: `${min}ms`,
      maxTime: `${max}ms`,
      times
    };
  }

  getTaintAnalyzer() {
    return this.taintAnalyzer;
  }
}

export async function runDefaultTestSuite(configPath) {
  const tester = new RuleTester();
  await tester.initialize(configPath);
  
  const testSuite = [
    {
      testId: 'cmd-injection-1',
      ruleId: 'command_injection',
      language: 'python',
      code: 'import os\nos.system("ls -l")',
      expectedFindings: [{ line: 2, severity: 'CRITICAL' }],
      description: 'Simple command injection'
    },
    {
      testId: 'cmd-injection-safe',
      ruleId: 'command_injection',
      language: 'python',
      code: 'import subprocess\nresult = subprocess.run(["ls", "-l"], capture_output=True)',
      expectedFindings: [],
      description: 'Safe subprocess usage'
    },
    {
      testId: 'sql-injection-1',
      ruleId: 'sql_injection',
      language: 'python',
      code: 'cursor.execute("SELECT * FROM users WHERE id = " + user_input)',
      expectedFindings: [{ line: 1, severity: 'HIGH' }],
      description: 'SQL injection with string concatenation'
    },
    {
      testId: 'sql-injection-safe',
      ruleId: 'sql_injection',
      language: 'python',
      code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      expectedFindings: [],
      description: 'Safe parameterized query'
    },
    {
      testId: 'xss-1',
      ruleId: 'xss',
      language: 'javascript',
      code: 'document.getElementById("content").innerHTML = userInput;',
      expectedFindings: [{ line: 1, severity: 'HIGH' }],
      description: 'Direct innerHTML assignment'
    },
    {
      testId: 'path-traversal-1',
      ruleId: 'path_traversal',
      language: 'python',
      code: 'file_path = "/home/user/" + user_input\nwith open(file_path) as f:\n    pass',
      expectedFindings: [{ line: 2, severity: 'MEDIUM' }],
      description: 'Path traversal vulnerability'
    },
    {
      testId: 'hardcoded-secret',
      ruleId: 'hardcoded_secrets',
      language: 'python',
      code: "api_key = 'sk-1234567890abcdefghijklmnopqrstuv'",
      expectedFindings: [{ line: 1, severity: 'HIGH' }],
      description: 'Hardcoded API key'
    },
    {
        testId: 'weak-crypto',
        ruleId: 'weak_crypto',
        language: 'java',
        code: 'Cipher cipher = Cipher.getInstance("DES");',
        expectedFindings: [{ line: 1, severity: 'HIGH' }],
        description: 'Weak DES encryption'
    },
    {
      testId: 'cookie-security',
      ruleId: 'cookie_security',
      language: 'javascript',
      code: 'document.cookie = "session=" + sessionId;',
      expectedFindings: [],
      description: 'Cookie missing security attributes'
    },
    {
      testId: 'cookie-security-safe',
      ruleId: 'cookie_security',
      language: 'javascript',
      code: 'document.cookie = "session=" + sessionId + "; Secure; HttpOnly; SameSite=Strict";',
      expectedFindings: [],
      description: 'Secure cookie with all attributes'
    }
  ];
  
  const results = await tester.runTestSuite(testSuite);
  const report = tester.getReport();
  
  return {
    report,
    rawResults: results
  };
}