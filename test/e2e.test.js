/**
 * 端到端测试脚本
 * 验证完整的审计工作流程
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function testFrontendPage(name, url) {
  const response = await fetch(url);
  const html = await response.text();
  const hasExpectedContent = html.includes('<!doctype html>') || html.includes('<!DOCTYPE html>');
  return { name, url, success: response.ok && hasExpectedContent, status: response.status };
}

async function runE2ETests() {
  console.log('=== 端到端测试 ===\n');

  const baseUrl = 'http://localhost:3001';
  const results = [];

  // 测试 1: 主页
  results.push(await testFrontendPage('首页', `${baseUrl}/`));

  // 测试 2: 发现页面
  results.push(await testFrontendPage('发现页面', `${baseUrl}/discover.html`));

  // 测试 3: 审计中心
  results.push(await testFrontendPage('审计中心', `${baseUrl}/audit.html`));

  // 测试 4: 指纹页面
  results.push(await testFrontendPage('指纹页面', `${baseUrl}/fingerprints.html`));

  // 测试 5: 设置页面
  results.push(await testFrontendPage('设置页面', `${baseUrl}/settings.html`));

  // 测试 6: API 端点
  const apiTests = [
    { name: 'API - 设置', url: `${baseUrl}/api/settings` },
    { name: 'API - 任务列表', url: `${baseUrl}/api/tasks` },
    { name: 'API - 审计技能', url: `${baseUrl}/api/audit-skills` },
    { name: 'API - 配置文件', url: `${baseUrl}/api/profiles` },
    { name: 'API - 环境信息', url: `${baseUrl}/api/environment` },
  ];

  for (const apiTest of apiTests) {
    try {
      const response = await fetch(apiTest.url);
      const data = await response.json();
      results.push({
        name: apiTest.name,
        url: apiTest.url,
        success: response.ok && data !== null,
        status: response.status
      });
    } catch (error) {
      results.push({
        name: apiTest.name,
        url: apiTest.url,
        success: false,
        status: 'ERROR',
        error: error.message
      });
    }
  }

  // 打印结果
  console.log('测试结果:');
  console.log('-'.repeat(60));

  let passed = 0;
  let failed = 0;

  for (const result of results) {
    const status = result.success ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${result.name} (${result.status})${result.error ? ` - ${result.error}` : ''}`);
    if (result.success) passed++;
    else failed++;
  }

  console.log('-'.repeat(60));
  console.log(`\n总计: ${passed} 通过, ${failed} 失败`);

  return failed === 0;
}

runE2ETests()
  .then(success => {
    console.log(success ? '\n🎉 所有端到端测试通过!' : '\n⚠️ 部分测试失败');
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('测试执行失败:', error);
    process.exit(1);
  });
