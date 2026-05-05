/**
 * 集成测试文件
 * 验证新增功能与现有服务的兼容性
 */

import { CodeAnalysisTool, RulesEngine, StaticAnalyzer, EmbeddingsService, RAGService } from './services/index.js';

async function runIntegrationTests() {
  console.log('=== 开始集成测试 ===\n');

  let allPassed = true;

  // 测试 1: 规则引擎初始化
  try {
    const rulesEngine = new RulesEngine();
    await rulesEngine.initialize('./config/detection_rules.yaml');
    const supportedLangs = rulesEngine.getSupportedLanguages();
    console.log(`✓ 规则引擎初始化成功，支持语言: ${supportedLangs.join(', ')}`);
  } catch (error) {
    console.log(`✗ 规则引擎初始化失败: ${error.message}`);
    allPassed = false;
  }

  // 测试 2: 静态分析器
  try {
    const rulesEngine = new RulesEngine();
    await rulesEngine.initialize('./config/detection_rules.yaml');
    const analyzer = new StaticAnalyzer(rulesEngine);
    
    const testCode = `
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
    `;
    
    const result = await analyzer.analyze(testCode, { language: 'python' });
    console.log(`✓ 静态分析器工作正常，检测到 ${result.vulnerabilities.length} 个漏洞`);
  } catch (error) {
    console.log(`✗ 静态分析器测试失败: ${error.message}`);
    allPassed = false;
  }

  // 测试 3: 代码分析工具（原有功能 + 新功能）
  try {
    const mockLLMService = {
      complete: async (options) => ({
        content: JSON.stringify({
          hasVulnerabilities: false,
          summary: "代码分析完成",
          vulnerabilities: [],
          recommendations: []
        })
      })
    };

    const analyzer = new CodeAnalysisTool(mockLLMService);
    
    // 测试原有 API（不调用 initialize，保持向后兼容）
    const testCode = "print('hello world')";
    const result = await analyzer.analyze(testCode, 'test.py', 'python');
    console.log(`✓ 代码分析工具向后兼容，原有 API 正常工作`);

    // 测试新功能
    await analyzer.initialize({ enableStatic: true });
    const enhancedResult = await analyzer.analyze(testCode, 'test.py', 'python', { useStatic: true });
    console.log(`✓ 代码分析工具新功能正常工作`);
  } catch (error) {
    console.log(`✗ 代码分析工具测试失败: ${error.message}`);
    allPassed = false;
  }

  // 测试 4: RAG 服务（原有功能 + 语义搜索）
  try {
    const ragService = new RAGService();
    await ragService.initialize();
    
    const results = await ragService.query('SQL injection');
    console.log(`✓ RAG 服务工作正常，返回 ${results.length} 个结果`);
  } catch (error) {
    console.log(`✗ RAG 服务测试失败: ${error.message}`);
    allPassed = false;
  }

  // 测试 5: 嵌入服务
  try {
    const embeddingsService = new EmbeddingsService({ providerType: 'local' });
    await embeddingsService.initialize();
    console.log(`✓ 嵌入服务初始化成功，维度: ${embeddingsService.dimension}`);
  } catch (error) {
    console.log(`✗ 嵌入服务测试失败: ${error.message}`);
    allPassed = false;
  }

  console.log('\n=== 测试完成 ===');
  console.log(allPassed ? '✓ 所有测试通过' : '✗ 部分测试失败');

  return allPassed;
}

// 如果直接运行此文件，则执行测试
if (import.meta.url === `file://${process.argv[1]}`) {
  runIntegrationTests().catch(console.error);
}

export { runIntegrationTests };
