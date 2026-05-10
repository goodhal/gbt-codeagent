import { withRetry } from './retry.js';
import { EVIDENCE_REQUIRED_MAP } from '../config/llmPrompts.js';

const THOUGHT_PATTERN = /^(?:Thought|思考)[:：]\s*([\s\S]*?)$/im;
const ACTION_PATTERN = /^(?:Action|行动)[:：]\s*(\w+)\s*(?:\(([^)]*)\))?$/im;
const OBSERVATION_PATTERN = /^(?:Observation|观察)[:：]\s*([\s\S]*?)$/im;
const FINAL_ANSWER_PATTERN = /^(?:Final|Final Answer|最终答案)[:：]\s*([\s\S]*)$/i;

class ReActStep {
  constructor({ thought = '', action = '', actionArgs = {}, observation = '', toolResults = [] } = {}) {
    this.thought = thought;
    this.action = action;
    this.actionArgs = actionArgs;
    this.observation = observation;
    this.toolResults = toolResults;
    this.timestamp = Date.now();
  }

  toJSON() {
    return {
      thought: this.thought,
      action: this.action,
      action_args: this.actionArgs,
      observation: this.observation,
      tool_results: this.toolResults,
      timestamp: this.timestamp
    };
  }
}

class ReActResult {
  constructor() {
    this.steps = [];
    this.finalAnswer = '';
    this.issues = [];
    this.recommendations = [];
    this.riskLevel = 'medium';
    this.error = null;
    this.metadata = {};
  }

  addStep(step) {
    this.steps.push(step instanceof ReActStep ? step : new ReActStep(step));
  }

  setFinalAnswer(answer) {
    this.finalAnswer = answer;
  }

  setIssues(issues) {
    this.issues = Array.isArray(issues) ? issues : [];
  }

  setRecommendations(recommendations) {
    this.recommendations = Array.isArray(recommendations) ? recommendations : [];
  }

  setRiskLevel(level) {
    this.riskLevel = level;
  }

  setError(error) {
    this.error = error;
  }

  setMetadata(metadata) {
    this.metadata = { ...this.metadata, ...metadata };
  }

  toJSON() {
    return {
      steps: this.steps.map(s => s.toJSON()),
      final_answer: this.finalAnswer,
      issues: this.issues,
      recommendations: this.recommendations,
      risk_level: this.riskLevel,
      error: this.error,
      metadata: this.metadata
    };
  }
}

class ReActAuditorConfig {
  constructor({
    maxSteps = 10,
    temperature = 0.1,
    maxRetries = 3,
    timeoutMs = 120000,
    verbose = false
  } = {}) {
    this.maxSteps = maxSteps;
    this.temperature = temperature;
    this.maxRetries = maxRetries;
    this.timeoutMs = timeoutMs;
    this.verbose = verbose;
  }
}

class ReActAuditor {
  constructor(llmAdapter, toolExecutor, config = new ReActAuditorConfig()) {
    this.llmAdapter = llmAdapter;
    this.toolExecutor = toolExecutor;
    this.config = config;
    this.messages = [];
    this.result = new ReActResult();
    this.evidencePoints = [];
    this.discoveryHistory = [];
    
    this.registeredTools = {
      read: {
        name: 'read',
        description: '读取指定文件的内容',
        params: { filePath: '文件路径' },
        returns: '文件内容字符串'
      },
      grep: {
        name: 'grep',
        description: '在项目中搜索指定的关键词或模式',
        params: { pattern: '搜索模式', path: '搜索路径（可选）' },
        returns: '匹配结果列表'
      },
      glob: {
        name: 'glob',
        description: '查找匹配指定模式的文件',
        params: { pattern: '文件模式' },
        returns: '匹配的文件路径列表'
      },
      astQuery: {
        name: 'astQuery',
        description: '查询AST节点信息，如类、方法、继承关系',
        params: { query: '查询类型', className: '类名', methodName: '方法名' },
        returns: 'AST节点信息'
      },
      traceDataFlow: {
        name: 'traceDataFlow',
        description: '追踪数据从输入到危险函数的传播路径',
        params: { sourceFile: '源文件', sourceLine: '源行号', sinkType: '目标类型' },
        returns: '数据流追踪结果'
      },
      checkReachability: {
        name: 'checkReachability',
        description: '检查从入口点到敏感操作的可达性',
        params: { entryPoint: '入口方法', sensitiveOperation: '敏感操作' },
        returns: '可达性分析结果'
      },
      getEvidence: {
        name: 'getEvidence',
        description: '获取漏洞证据点信息',
        params: { vulnType: '漏洞类型', location: '位置' },
        returns: '证据点列表'
      }
    };
  }

  _log(level, ...args) {
    if (this.config.verbose || level === 'error') {
      console.log(`[ReAct ${level.toUpperCase()}]`, ...args);
    }
  }

  _getToolDescription() {
    const toolDescriptions = [];
    for (const [name, tool] of Object.entries(this.registeredTools)) {
      const paramsStr = Object.entries(tool.params).map(([key, desc]) => `${key}: ${desc}`).join(', ');
      toolDescriptions.push(`${name}(${paramsStr}) - ${tool.description}`);
    }
    return toolDescriptions.join('\n');
  }

  _buildSystemPrompt(systemPromptContent) {
    const toolDesc = this._getToolDescription();
    return [
      { role: 'system', content: `
${systemPromptContent}

【可用工具】
${toolDesc}

【工具使用格式】
Thought: 思考内容
Action: 工具名(参数)

【输出格式】
- 如果需要更多信息，输出: Thought + Action
- 如果分析完成，输出: Final Answer: {"issues": [...], "recommendations": [...]}

【证据收集要求】
每个漏洞发现必须收集以下证据点：
1. EVID_* 证据点标识
2. 代码片段位置
3. 数据流追踪路径（如适用）
4. 验证结果
      `.trim() }
    ];
  }

  _recordDiscovery(finding) {
    this.discoveryHistory.push({
      timestamp: Date.now(),
      ...finding
    });
  }

  _addEvidencePoint(evidence) {
    if (!this.evidencePoints.includes(evidence)) {
      this.evidencePoints.push(evidence);
    }
  }

  _validateEvidenceCompleteness(vulnType) {
    const requiredEvidence = this._getRequiredEvidence(vulnType);
    const missing = requiredEvidence.filter(e => !this.evidencePoints.includes(e));
    return {
      complete: missing.length === 0,
      missing,
      collected: this.evidencePoints.filter(e => requiredEvidence.includes(e))
    };
  }

  _getRequiredEvidence(vulnType) {
    return EVIDENCE_REQUIRED_MAP[vulnType] || [];
  }

  _buildInitialMessage(userPromptContent) {
    return { role: 'user', content: userPromptContent };
  }

  _parseResponse(content) {
    content = content.trim();

    const finalMatch = content.match(FINAL_ANSWER_PATTERN);
    if (finalMatch) {
      return {
        isFinal: true,
        thought: finalMatch[1].trim(),
        action: '',
        actionArgs: {},
        observation: ''
      };
    }

    const lines = content.split('\n');
    let thought = '';
    let action = '';
    let actionArgsStr = '';
    let observation = '';

    for (const line of lines) {
      const trimmed = line.trim();
      const thoughtMatch = trimmed.match(/^(?:Thought|思考)[:：]\s*(.+)$/i);
      if (thoughtMatch) {
        thought = thoughtMatch[1].trim();
        continue;
      }
      const actionMatch = trimmed.match(/^(?:Action|行动)[:：]\s*(\w+)\s*(?:\(([^)]*)\))?$/i);
      if (actionMatch) {
        action = actionMatch[1].trim();
        actionArgsStr = actionMatch[2] || '';
        continue;
      }
      const obsMatch = trimmed.match(/^(?:Observation|观察)[:：]\s*(.+)$/i);
      if (obsMatch) {
        observation = obsMatch[1].trim();
        break;
      }
    }

    if (thought || action) {
      let actionArgs = {};
      if (actionArgsStr) {
        try {
          actionArgs = JSON.parse(actionArgsStr.replace(/'/g, '"'));
        } catch {
          const argMatch = actionArgsStr.match(/(\w+)=(.+?)(?:,\s*|$)/g);
          if (argMatch) {
            for (const arg of argMatch) {
              const [key, value] = arg.split('=');
              actionArgs[key.trim()] = value.trim().replace(/^["']|["']$/g, '');
            }
          }
        }
      }
      return {
        isFinal: false,
        thought,
        action,
        actionArgs,
        observation
      };
    }

    return {
      isFinal: false,
      thought: content,
      action: '',
      actionArgs: {},
      observation: ''
    };
  }

  _parseFinalAnalysis(content) {
    const jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/) ||
                      content.match(/```\s*([\s\S]*?)\s*```/) ||
                      content.match(/\{[\s\S]*"issues"[\s\S]*\}/);

    if (jsonMatch) {
      try {
        return JSON.parse(jsonMatch[1] || jsonMatch[0]);
      } catch {
        const braceMatch = content.match(/(\{[\s\S]*\})/);
        if (braceMatch) {
          try {
            return JSON.parse(braceMatch[1]);
          } catch {
            return null;
          }
        }
      }
    }
    return null;
  }

  async _callLLM(messages) {
    return withRetry(async () => {
      return await this.llmAdapter.complete(messages, {
        temperature: this.config.temperature,
        maxTokens: 4096
      });
    }, {
      maxAttempts: this.config.maxRetries,
      baseDelay: 1000,
      maxDelay: 30000
    });
  }

  async _executeTool(action, args) {
    if (!this.toolExecutor) {
      return { error: 'Tool executor not configured' };
    }

    const toolName = action.replace(/^local_/, '');
    if (typeof this.toolExecutor.execute === 'function') {
      return await this.toolExecutor.execute(toolName, args);
    }

    const methodName = `execute${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_([a-z])/g, (_, c) => c.toUpperCase())}`;
    if (typeof this.toolExecutor[methodName] === 'function') {
      return await this.toolExecutor[methodName](args);
    }

    if (typeof this.toolExecutor[toolName] === 'function') {
      return await this.toolExecutor[toolName](args);
    }

    return { error: `Unknown tool: ${action}` };
  }

  _extractIssuesFromFinalAnswer(finalAnswer, originalDiff) {
    const issues = [];
    const issuePatterns = [
      /\n\s*[-*]\s*\*\*(.+?)\*\*[:：]\s*(.+?)(?=\n\s*[-*]|\n\n|$)/gi,
      /\n\s*(\d+)\.\s*\*\*(.+?)\*\*[:：]\s*(.+?)(?=\n\s*\d+\.|\n\n|$)/gi
    ];

    for (const pattern of issuePatterns) {
      let match;
      while ((match = pattern.exec(finalAnswer)) !== null) {
        const type = match[1] || match[2] || 'unknown';
        const desc = (match[2] || match[3] || '').trim();

        if (desc && desc.length > 10) {
          issues.push({
            type: type.toLowerCase().replace(/\s+/g, '_'),
            desc: desc.substring(0, 500),
            level: this._inferSeverity(type),
            file: this._extractFileFromContext(finalAnswer, type),
            suggestion: this._generateSuggestion(type, desc)
          });
        }
      }
    }

    return issues;
  }

  _inferSeverity(type) {
    const typeStr = String(type).toLowerCase();
    if (/sql.*inject|xss|command.*inject|path.*traversal|auth.*bypass|credential/i.test(typeStr)) {
      return 'high';
    }
    if (/csrf|open.*redirect|file.*upload|serializ/i.test(typeStr)) {
      return 'medium';
    }
    return 'low';
  }

  _extractFileFromContext(context, issueType) {
    const fileMatch = context.match(/\b([a-zA-Z0-9_./\\-]+\.[a-zA-Z]+)\b/);
    return fileMatch ? fileMatch[1] : 'unknown';
  }

  _generateSuggestion(type, desc) {
    return `建议对 ${type} 相关代码进行安全审查，详情：${desc.substring(0, 100)}...`;
  }

  async audit({ systemPrompt, initialPrompt, projectInfo = {} }) {
    this._log('info', 'Starting ReAct audit');
    this._log('info', 'Max steps:', this.config.maxSteps);
    this._log('info', 'Model:', this.llmAdapter.config?.model || 'unknown');

    this.messages = [
      ...this._buildSystemPrompt(systemPrompt),
      this._buildInitialMessage(initialPrompt)
    ];

    this.result = new ReActResult();
    this.result.setMetadata({
      projectName: projectInfo.name || 'unknown',
      startTime: new Date().toISOString(),
      maxSteps: this.config.maxSteps
    });

    try {
      for (let step = 0; step < this.config.maxSteps; step++) {
        this._log('info', `Step ${step + 1}/${this.config.maxSteps}`);

        const content = await this._callLLM(this.messages);
        this._log('info', `LLM response length: ${content.length}`);

        const parsed = this._parseResponse(content);

        if (parsed.isFinal) {
          this._log('info', 'Reached final answer');
          this.result.setFinalAnswer(parsed.thought);

          const finalAnalysis = this._parseFinalAnalysis(parsed.thought);
          if (finalAnalysis && finalAnalysis.issues) {
            this.result.setIssues(finalAnalysis.issues);
            this.result.setRecommendations(finalAnalysis.recommendations || []);
            this.result.setRiskLevel(finalAnalysis.risk_level || 'medium');
          } else {
            const extractedIssues = this._extractIssuesFromFinalAnswer(parsed.thought, initialPrompt);
            this.result.setIssues(extractedIssues);
            this.result.setRecommendations([
              '建议进行全面的安全代码审查',
              '建议使用静态代码分析工具进行复查',
              '建议定期进行安全培训'
            ]);
          }
          break;
        }

        const reactStep = new ReActStep({
          thought: parsed.thought,
          action: parsed.action,
          actionArgs: parsed.actionArgs,
          observation: ''
        });

        if (parsed.action) {
          this._log('info', `Executing tool: ${parsed.action}`);

          const toolResult = await this._executeTool(parsed.action, parsed.actionArgs);
          const observation = typeof toolResult === 'string' ? toolResult : JSON.stringify(toolResult);

          reactStep.observation = observation;
          reactStep.toolResults = [{
            tool_name: parsed.action,
            tool_args: parsed.actionArgs,
            raw_output: observation,
            output_length: observation.length
          }];

          this._log('info', `Tool result length: ${observation.length}`);

          this.messages.push({ role: 'assistant', content });
          this.messages.push({
            role: 'user',
            content: `Observation: ${observation}\n\n继续分析，如果需要更多信息请继续调用工具，如果分析完成请给出最终答案。`
          });
        } else {
          this.messages.push({ role: 'assistant', content });
        }

        this.result.addStep(reactStep);
      }

      if (this.result.steps.length >= this.config.maxSteps) {
        this._log('warn', 'Reached max steps without final answer');
        this.result.setError('Reached maximum steps without conclusion');
      }
    } catch (error) {
      this._log('error', 'Audit error:', error.message);
      this.result.setError(error.message);
      throw error;
    }

    this.result.metadata.endTime = new Date().toISOString();
    this.result.metadata.totalSteps = this.result.steps.length;

    this._log('info', `Audit complete. Steps: ${this.result.steps.length}, Issues: ${this.result.issues.length}`);

    return this.result;
  }

  getResult() {
    return this.result;
  }

  reset() {
    this.messages = [];
    this.result = new ReActResult();
  }
}

function createReActAuditor(llmAdapter, toolExecutor, config) {
  return new ReActAuditor(llmAdapter, toolExecutor, new ReActAuditorConfig(config));
}

export {
  ReActStep,
  ReActResult,
  ReActAuditorConfig,
  ReActAuditor,
  createReActAuditor
};