class CodeAnalysisTool {
  constructor(llmService) {
    this.llmService = llmService;
  }

  async analyze(code, filePath = "unknown", language = "python", options = {}) {
    const { focus = null, context = null } = options;

    const prompt = this._buildAnalysisPrompt(code, filePath, language, focus, context);

    const response = await this.llmService.complete({
      prompt,
      temperature: 0.1,
      maxTokens: 4096
    });

    try {
      const result = this._parseResponse(response.content, filePath, language);
      return result;
    } catch (e) {
      return {
        success: false,
        error: "Failed to parse analysis result",
        rawResponse: response.content
      };
    }
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

  async analyzeMultiple(files, options = {}) {
    const results = [];

    for (const file of files) {
      try {
        const result = await this.analyze(
          file.code,
          file.path,
          file.language || this._detectLanguage(file.path),
          options
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

  _detectLanguage(filePath) {
    const ext = filePath.match(/\.[^.]+$/)?.[0] || "";
    const map = {
      ".py": "python",
      ".js": "javascript",
      ".ts": "typescript",
      ".jsx": "jsx",
      ".tsx": "tsx",
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

    for (const result of results) {
      if (result.success && result.vulnerabilities) {
        vulnerabilities.push(...result.vulnerabilities);
        for (const vuln of result.vulnerabilities) {
          if (vuln.severity === "HIGH") highCount++;
          else if (vuln.severity === "MEDIUM") mediumCount++;
          else lowCount++;
        }
      }
    }

    return {
      totalFiles: results.length,
      filesWithVulnerabilities: results.filter(r => r.success && r.hasVulnerabilities).length,
      totalVulnerabilities: vulnerabilities.length,
      bySeverity: { high: highCount, medium: mediumCount, low: lowCount },
      vulnerabilities,
      results
    };
  }
}

export {
  CodeAnalysisTool
};