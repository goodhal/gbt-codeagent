import { RulesEngine, StaticAnalyzer, TaintAnalyzer, PatternAnalyzer, CompositeAnalyzer } from '../analyzers/index.js';
import { getGlobalVectorStore, createSemanticSearchEngine } from './vectorStore.js';
import { ASTBuilderService } from '../utils/astBuilder.js';

class CodeAnalysisTool {
  constructor(llmService) {
    this.llmService = llmService;
    this._analyzer = null;
    this._rulesEngine = null;
    this._vectorStore = null;
    this._searchEngine = null;
    this._astBuilder = null;
    this._currentProjectId = null;
  }

  async initialize(options = {}) {
    this._rulesEngine = new RulesEngine();
    await this._rulesEngine.initialize('./config/detection_rules.yaml');

    this._analyzer = new CompositeAnalyzer(this._rulesEngine, {
      enableStatic: options.enableStatic !== false,
      enableTaint: options.enableTaint !== false,
      enablePattern: options.enablePattern !== false
    });

    this._vectorStore = await getGlobalVectorStore({
      persistPath: options.vectorPersistPath || './data/vectors.json'
    });

    if (options.embedder) {
      this._searchEngine = createSemanticSearchEngine(this._vectorStore, options.embedder);
    }

    this._astBuilder = new ASTBuilderService({
      cacheEnabled: options.enableAstCache !== false,
      cacheDir: options.astCacheDir || './cache',
      rebuildOnStartup: options.rebuildAstOnStartup || false
    });

    return this;
  }

  async initializeAST(projectId, sourcePath, options = {}) {
    if (!this._astBuilder) {
      this._astBuilder = new ASTBuilderService({
        cacheEnabled: options.enableAstCache !== false,
        cacheDir: options.astCacheDir || './cache'
      });
    }
    
    this._currentProjectId = projectId;
    const astIndex = await this._astBuilder.initialize(projectId, sourcePath, options);
    return astIndex;
  }

  searchClass(className) {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this._astBuilder.searchClass(className);
  }

  searchMethod(className, methodName) {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this._astBuilder.searchMethod(className, methodName);
  }

  searchField(className, fieldName) {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this._astBuilder.searchField(className, fieldName);
  }

  searchCode(options) {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this._astBuilder.search(options);
  }

  getClassHierarchy(className, type = 'super') {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this._astBuilder.getClassHierarchy(className, type);
  }

  getASTStats() {
    if (!this._astBuilder || !this._astBuilder.isInitialized()) {
      return { success: false, error: 'AST Builder not initialized', data: null };
    }
    return this._astBuilder.getStats();
  }

  isASTInitialized() {
    return this._astBuilder && this._astBuilder.isInitialized();
  }

  async analyze(code, filePath = "unknown", language = "python", options = {}) {
    const { focus = null, context = null, useAI = true, useStatic = true, incrementalEnabled = true, cacheEnabled = true } = options;

    const results = {
      success: true,
      filePath,
      language,
      hasVulnerabilities: false,
      summary: "",
      vulnerabilities: [],
      recommendations: [],
      aiAnalysis: null,
      staticAnalysis: null,
      clusters: [],
      filteredCount: 0,
      analysisTime: 0,
      breakdown: {
        standard: 0,
        owasp: 0,
        gbt: 0
      }
    };

    const startTime = Date.now();

    if (useStatic && this._analyzer) {
      try {
        const analyzeOptions = {
          language,
          filePath,
          focus,
          contextWindow: 3,
          minConfidence: 0.5,
          similarityThreshold: 0.8
        };

        let contextResult;
        if (incrementalEnabled && options.diffInfo) {
          contextResult = await this._analyzer.analyzeWithIncremental(code, {
            ...analyzeOptions,
            diffInfo: options.diffInfo
          });
        } else {
          contextResult = await this._analyzer.analyzeWithContext(code, analyzeOptions);
        }

        results.staticAnalysis = contextResult;
        results.vulnerabilities.push(...(contextResult.findings || contextResult.vulnerabilities || []));
        results.clusters = contextResult.clusters || [];
        results.filteredCount = contextResult.filteredCount || 0;
        results.breakdown.standard = (contextResult.findings || contextResult.vulnerabilities || []).length;
      } catch (error) {
        console.error('[CodeAnalysisTool] Static analysis failed:', error);
      }
    }

    if (this._rulesEngine && options.enableOwasp !== false) {
      try {
        const owaspFindings = this._rulesEngine.detectOWASPTop10(code, language);
        if (owaspFindings.length > 0) {
          const filtered = this._rulesEngine.filterFalsePositives(owaspFindings);
          results.vulnerabilities.push(...filtered);
          results.breakdown.owasp = filtered.length;
        }
      } catch (error) {
        console.error('[CodeAnalysisTool] OWASP detection failed:', error);
      }
    }

    if (this._rulesEngine && options.enableGBT !== false) {
      try {
        const gbtFindings = this._rulesEngine.detectGBTStandards(code, language);
        if (gbtFindings.length > 0) {
          const filtered = this._rulesEngine.filterFalsePositives(gbtFindings);
          results.vulnerabilities.push(...filtered);
          results.breakdown.gbt = filtered.length;
        }
      } catch (error) {
        console.error('[CodeAnalysisTool] GB/T detection failed:', error);
      }
    }

    if (useAI && this.llmService) {
      try {
        const prompt = this._buildAnalysisPrompt(code, filePath, language, focus, context);
        const response = await this.llmService.complete({
          prompt,
          temperature: 0.1,
          maxTokens: 4096
        });

        const aiResult = this._parseResponse(response.content, filePath, language);
        results.aiAnalysis = aiResult;
        results.vulnerabilities.push(...(aiResult.vulnerabilities || []));
      } catch (error) {
        console.error('[CodeAnalysisTool] AI analysis failed:', error);
      }
    }

    if (results.vulnerabilities.length > 0 && this._rulesEngine) {
      results.clusters = this._rulesEngine.clusterFindings(results.vulnerabilities, {
        similarityThreshold: options.similarityThreshold || 0.8
      });
    }

    results.hasVulnerabilities = results.vulnerabilities.length > 0;
    results.summary = this._generateSummary(results);
    results.recommendations = this._generateRecommendations(results.vulnerabilities);
    results.analysisTime = Date.now() - startTime;

    return results;
  }

  _buildAnalysisPrompt(code, filePath, language, focus, context) {
    const focusSection = focus ? `\n重点关注漏洞类型: ${focus}` : "";
    const contextSection = context ? `\n额外上下文:\n${context}` : "";

    return `你是代码安全审计专家。请分析以下代码的安全问题。

## 代码信息
- 文件: ${filePath}
- 语言: ${language}
${focusSection}
${contextSection}

## 代码
\`\`\`${language}
${code}
\`\`\`

## 分析要求
请识别以下安全漏洞类型（如适用）：
1. SQL注入
2. 命令注入
3. XSS (跨站脚本)
4. 路径遍历
5. SSRF (服务器端请求伪造)
6. 不安全反序列化
7. 敏感信息泄露
8. 认证绕过
9. 权限提升
10. 业务逻辑漏洞

## 输出格式
请以JSON格式返回分析结果:
{
  "hasVulnerabilities": true/false,
  "summary": "总体评估",
  "vulnerabilities": [
    {
      "type": "漏洞类型",
      "severity": "HIGH/MEDIUM/LOW",
      "location": "代码位置",
      "description": "漏洞描述",
      "evidence": "证据代码",
      "remediation": "修复建议"
    }
  ],
  "recommendations": ["建议1", "建议2"]
}
`;
  }

  _parseResponse(content, filePath, language) {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error("No JSON found in response");
    }

    const result = JSON.parse(jsonMatch[0]);
    return {
      success: true,
      filePath,
      language,
      ...result
    };
  }

  _generateSummary(results) {
    const vulns = results.vulnerabilities;
    if (vulns.length === 0) {
      return "代码未检测到明显安全漏洞。";
    }

    const critical = vulns.filter(v => v.severity === 'CRITICAL' || v.severity === 'critical').length;
    const high = vulns.filter(v => v.severity === 'HIGH' || v.severity === 'high').length;
    const medium = vulns.filter(v => v.severity === 'MEDIUM' || v.severity === 'medium').length;
    const low = vulns.filter(v => v.severity === 'LOW' || v.severity === 'low').length;

    let summary = `检测到 ${vulns.length} 个安全问题。`;
    if (critical > 0) summary += ` 危急: ${critical}`;
    if (high > 0) summary += ` 高危: ${high}`;
    if (medium > 0) summary += ` 中危: ${medium}`;
    if (low > 0) summary += ` 低危: ${low}`;

    return summary;
  }

  _generateRecommendations(vulnerabilities) {
    const recommendations = new Set();

    for (const vuln of vulnerabilities) {
      if (vuln.remediation) {
        recommendations.add(vuln.remediation);
      }
    }

    if (vulnerabilities.length > 0) {
      recommendations.add("对所有用户输入进行严格验证和过滤");
      recommendations.add("使用参数化查询防止SQL注入");
      recommendations.add("遵循最小权限原则");
    }

    return Array.from(recommendations);
  }

  async analyzeMultiple(files, options = {}) {
    const { useAI = true, useStatic = true } = options;
    const results = [];

    for (const file of files) {
      try {
        const result = await this.analyze(
          file.code,
          file.path,
          file.language || this._detectLanguage(file.path),
          { useAI, useStatic, ...options }
        );
        results.push(result);
      } catch (e) {
        results.push({
          success: false,
          filePath: file.path,
          error: e.message
        });
      }
    }

    return this._aggregateResults(results);
  }

  async semanticSearch(query, k = 5) {
    if (!this._searchEngine) {
      throw new Error('Semantic search engine not initialized. Please provide embedder in initialize().');
    }

    return this._searchEngine.search(query, k);
  }

  async addToVectorStore(id, text, metadata = {}) {
    if (!this._searchEngine) {
      throw new Error('Semantic search engine not initialized.');
    }

    await this._searchEngine.index(id, text, metadata);
    await this._vectorStore.persist();
  }

  _detectLanguage(filePath) {
    const ext = filePath.match(/\.[^.]+$/)?.[0] || "";
    const map = {
      ".py": "python",
      ".js": "javascript",
      ".ts": "typescript",
      ".jsx": "javascript",
      ".tsx": "typescript",
      ".java": "java",
      ".php": "php",
      ".go": "go",
      ".rb": "ruby",
      ".rs": "rust",
      ".c": "c",
      ".cpp": "cpp",
      ".cs": "csharp"
    };
    return map[ext] || "unknown";
  }

  _aggregateResults(results) {
    const vulnerabilities = [];
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let criticalCount = 0;

    for (const result of results) {
      if (result.success && result.vulnerabilities) {
        vulnerabilities.push(...result.vulnerabilities);
        for (const vuln of result.vulnerabilities) {
          const severity = vuln.severity?.toUpperCase() || 'MEDIUM';
          if (severity === "CRITICAL") criticalCount++;
          else if (severity === "HIGH") highCount++;
          else if (severity === "MEDIUM") mediumCount++;
          else lowCount++;
        }
      }
    }

    return {
      totalFiles: results.length,
      filesWithVulnerabilities: results.filter(r => r.success && r.hasVulnerabilities).length,
      totalVulnerabilities: vulnerabilities.length,
      bySeverity: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
      vulnerabilities,
      results
    };
  }

  getAnalyzer() {
    return this._analyzer;
  }

  getRulesEngine() {
    return this._rulesEngine;
  }

  getVectorStore() {
    return this._vectorStore;
  }
}

export {
  CodeAnalysisTool
};
