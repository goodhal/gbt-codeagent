#!/usr/bin/env node
import { LLMOptimizer, createEnhancedPrompt, createIncrementalAuditPrompt } from './src/services/llmOptimizer.js';

console.log('🔬 LLM审计优化效果验证\n');
console.log('='.repeat(60));

async function testOptimizer() {
  const optimizer = new LLMOptimizer();
  await optimizer.initialize();

  console.log('\n📊 1. 结果缓存测试\n');
  console.log('-'.repeat(60));

  const testFiles = [
    { relativePath: 'src/auth/login.py', content: 'def login(username, password):\n    if username == "admin":\n        return True', language: 'python' },
    { relativePath: 'src/api/user.py', content: 'def get_user(user_id):\n    return db.query(user_id)', language: 'python' },
    { relativePath: 'tests/test_auth.py', content: 'def test_login():\n    assert login("admin", "pass") == True', language: 'python' }
  ];

  const projectHash = optimizer.computeProjectHash(testFiles);
  console.log(`项目Hash: ${projectHash}`);

  optimizer.cacheResults(projectHash, testFiles, [
    { title: 'SQL注入', location: 'src/api/user.py:2', confidence: 0.9 },
    { title: '硬编码密码', location: 'src/auth/login.py:1', confidence: 0.85 }
  ]);

  const cached = optimizer.getCachedResults(projectHash, testFiles);
  console.log(`缓存命中: ${cached.isCacheHit ? '是' : '否'}`);
  console.log(`缓存发现数: ${cached.cachedFindings?.length || 0}`);

  const modifiedFiles = [
    { relativePath: 'src/auth/login.py', content: 'def login(username, password):\n    if username == "admin":\n        return True\n    db.execute(username)', language: 'python' },
    { relativePath: 'src/api/user.py', content: 'def get_user(user_id):\n    return db.query(user_id)', language: 'python' }
  ];

  const cached2 = optimizer.getCachedResults(projectHash, modifiedFiles);
  console.log(`\n修改后缓存命中: ${cached2.isCacheHit ? '是' : '否'}`);
  console.log(`变更文件: ${cached2.changedFiles?.join(', ') || '无'}`);

  console.log('\n📊 2. Token预算控制测试\n');
  console.log('-'.repeat(60));

  const largeFiles = Array.from({ length: 20 }, (_, i) => ({
    relativePath: `src/file${i}.py`,
    content: 'x = 1\n' .repeat(1000),
    language: 'python'
  }));

  const budget = optimizer.calculateTokenBudget(largeFiles);
  console.log(`预估Token: ${budget.totalEstimated}`);
  console.log(`剩余预算: ${budget.remainingBudget}`);
  console.log(`需要压缩: ${budget.needsCompression ? '是' : '否'}`);
  console.log(`压缩比: ${(budget.compressionRatio * 100).toFixed(1)}%`);

  console.log('\n📊 3. 文件优先级测试\n');
  console.log('-'.repeat(60));

  const prioritized = optimizer.prioritizeFiles(testFiles, [
    { location: 'src/auth/login.py:1', vulnType: 'auth_bypass' }
  ]);

  console.log('优先级排序:');
  prioritized.forEach((f, i) => console.log(`  ${i + 1}. ${f.relativePath}`));

  console.log('\n📊 4. 防误报机制测试\n');
  console.log('-'.repeat(60));

  const testFindings = [
    { title: '真实漏洞', location: 'src/auth/login.py:5', evidence: '未验证密码直接返回', remediation: '添加密码验证逻辑', confidence: 0.9 },
    { title: '测试文件漏洞', location: 'tests/test_auth.py:3', evidence: 'assert语句', remediation: '删除', confidence: 0.9 },
    { title: '导入语句', location: 'src/import.py:1', evidence: 'import os', remediation: '使用绝对路径', confidence: 0.8 },
    { title: '日志输出', location: 'src/logger.py:2', evidence: 'logger.info', remediation: '正常', confidence: 0.7 }
  ];

  testFindings.forEach(f => {
    const fp = optimizer.isFalsePositive(f, { filePath: f.location, code: f.evidence });
    const v = optimizer.validateFinding(f);
    console.log(`\n  ${f.title}:`);
    console.log(`    误报: ${fp.isFP ? '是 (' + fp.reason + ')' : '否'}`);
    console.log(`    有效: ${v.isValid ? '是' : '否 (缺少: ' + v.issues.join(', ') + ')'}`);
  });

  console.log('\n📊 5. 增强提示词测试\n');
  console.log('-'.repeat(60));

  const enhancedPrompt = createEnhancedPrompt({
    includeContextAnalysis: true,
    includeBusinessLogic: true,
    includeAttackChain: true,
    strictMode: true
  });

  console.log('生成的增强提示词片段:');
  console.log(enhancedPrompt.substring(0, 500) + '...');

  console.log('\n📊 6. 增量审计提示词测试\n');
  console.log('-'.repeat(60));

  const incrementalPrompt = createIncrementalAuditPrompt(['src/auth/login.py', 'src/api/user.py']);
  console.log(incrementalPrompt);

  console.log('\n📊 7. 审计统计\n');
  console.log('-'.repeat(60));

  const stats = optimizer.getAuditStats();
  console.log(`缓存大小: ${stats.cacheSize}`);
  console.log(`历史记录: ${stats.historySize}`);
  console.log(`Token预算: ${stats.tokenBudget.maxTokens}`);
  console.log(`误报率: ${(stats.falsePositiveRate * 100).toFixed(1)}%`);

  console.log('\n' + '='.repeat(60));
  console.log('✅ LLM审计优化功能验证完成');
  console.log('='.repeat(60));
}

testOptimizer().catch(console.error);
