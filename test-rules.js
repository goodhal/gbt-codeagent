#!/usr/bin/env node
import { runDefaultTestSuite, RuleTester } from './src/testing/ruleTester.js';
import path from 'path';

async function main() {
  console.log('🚀 Starting rule testing...\n');

  try {
    const configPath = path.resolve('./config/detection_rules.yaml');

    console.log('📋 Running default test suite...\n');
    const { report, rawResults } = await runDefaultTestSuite(configPath);

    console.log('\n📊 Test Summary:');
    console.log('================');
    console.log(`- Total tests: ${report.summary?.totalTests || 'N/A'}`);
    console.log(`- Passed: ${report.summary?.passedTests || 'N/A'} ✅`);
    console.log(`- Failed: ${report.summary?.failedTests || 'N/A'} ❌`);
    console.log(`- Pass rate: ${report.summary?.passRate || 'N/A'}`);
    console.log(`- Rules tested: ${report.coverage?.testedRules || 'N/A'} / ${report.coverage?.totalRules || 'N/A'}`);
    console.log(`- Coverage rate: ${report.coverage?.coverageRate || 'N/A'}`);

    if (rawResults) {
      const failedTests = rawResults.filter(t => !t.passed);
      if (failedTests.length > 0) {
        console.log('\n❌ Failed Tests:');
        for (const test of failedTests) {
          console.log(`\n  Test ID: ${test.testId}`);
          console.log(`  Rule ID: ${test.ruleId}`);
          console.log(`  Description: ${test.description}`);
          console.log(`  Status: ${test.message || 'Failed'}`);
          if (test.errors && test.errors.length > 0) {
            console.log('  Errors:');
            test.errors.forEach(e => console.log(`    - ${e}`));
          }
        }
      } else {
        console.log('\n✅ All tests passed!');
      }
    }

    console.log('\n🧪 Running Taint Analysis Tests...\n');
    await runTaintTests(configPath);

    console.log('\n========================');

  } catch (error) {
    console.error('❌ Error during testing:', error);
    process.exit(1);
  }
}

async function runTaintTests(configPath) {
  const tester = new RuleTester();
  await tester.initialize(configPath);

  const taintTestSuite = [
    {
      testId: 'taint-sql-injection',
      language: 'python',
      code: `user_input = request.args.get('id')
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)`,
      expectedVulnerabilities: [
        { sourceLine: 1, sinkLine: 3, severity: 'HIGH' },
        { sourceLine: 1, sinkLine: 3, severity: 'HIGH' }
      ],
      description: 'SQL injection via taint flow'
    },
    {
      testId: 'taint-command-exec',
      language: 'python',
      code: `import os
user_cmd = input("Enter command: ")
os.system(user_cmd)`,
      expectedVulnerabilities: [{ sourceLine: 2, sinkLine: 3, severity: 'CRITICAL' }],
      description: 'Command injection via taint flow'
    },
    {
      testId: 'taint-direct-command',
      language: 'python',
      code: `import os
os.system("ls -l")`,
      expectedVulnerabilities: [],
      description: 'No user input - safe command execution'
    },
    {
      testId: 'taint-xss',
      language: 'javascript',
      code: `const userInput = req.query.input;
document.getElementById('content').innerHTML = userInput;`,
      expectedVulnerabilities: [{ sourceLine: 1, sinkLine: 2, severity: 'HIGH' }],
      description: 'XSS via taint flow'
    },
    {
      testId: 'taint-safe-xss',
      language: 'javascript',
      code: `const userInput = req.query.input;
document.getElementById('content').textContent = userInput;`,
      expectedVulnerabilities: [],
      description: 'Safe textContent usage prevents XSS'
    }
  ];

  const results = await tester.runTaintTestSuite(taintTestSuite);
  const taintReport = tester.getReport();

  console.log('\n🔍 Taint Analysis Test Results:');
  console.log('==============================');
  console.log(`- Total taint tests: ${taintReport.summary?.totalTests || 'N/A'}`);
  console.log(`- Passed: ${taintReport.summary?.passed || 'N/A'} ✅`);
  console.log(`- Failed: ${taintReport.summary?.failed || 'N/A'} ❌`);

  const failedTaintTests = results.filter(t => !t.passed);
  if (failedTaintTests.length > 0) {
    console.log('\n❌ Failed Taint Tests:');
    for (const test of failedTaintTests) {
      console.log(`\n  Test ID: ${test.testId}`);
      console.log(`  Description: ${test.description}`);
      if (test.errors && test.errors.length > 0) {
        console.log('  Errors:');
        test.errors.forEach(e => console.log(`    - ${e}`));
      }
    }
  } else {
    console.log('\n✅ All taint analysis tests passed!');
  }
}

main();
