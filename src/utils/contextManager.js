import { createRequire } from 'module';
const require = createRequire(import.meta.url);

let tiktoken = null;
try {
  tiktoken = require('tiktoken');
} catch (e) {
  console.warn('[上下文管理器] tiktoken 加载失败，使用启发式估算');
}

const MODEL_MAX_TOKENS = {
  'gpt-4': 8192,
  'gpt-4-32k': 32768,
  'gpt-3.5-turbo': 4096,
  'gpt-3.5-turbo-16k': 16384,
  'qwen': 8192,
  'deepseek': 4096,
  'claude': 100000
};

function getModelMaxTokens(model = 'gpt-3.5-turbo') {
  for (const [key, value] of Object.entries(MODEL_MAX_TOKENS)) {
    if (model.toLowerCase().includes(key.toLowerCase())) {
      return value;
    }
  }
  return 4096;
}

async function countTokensTiktoken(text, model = 'gpt-3.5-turbo') {
  if (!tiktoken) {
    return estimateTokens(text);
  }
  try {
    const encoding = tiktoken.encoding_for_model(model);
    const tokens = encoding.encode(text);
    encoding.free();
    return tokens.length;
  } catch (e) {
    try {
      const encoding = new tiktoken.Encoding('cl100k_base');
      const tokens = encoding.encode(text);
      encoding.free();
      return tokens.length;
    } catch (e2) {
      return estimateTokens(text);
    }
  }
}

function estimateTokens(text) {
  if (!text || typeof text !== 'string') {
    return 0;
  }
  const chineseChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
  const englishChars = text.replace(/[\u4e00-\u9fff]/g, '').length;
  const englishWords = englishChars ? text.replace(/[\u4e00-\u9fff]/g, ' ').split(/\s+/).filter(w => w.length > 0).length : 0;
  const punctuation = (text.match(/[.,;:!?，。；：！？""''（）\(\)\[\]{}]/g) || []).length;
  return Math.ceil(chineseChars * 2.0 + englishWords * 1.3 + punctuation * 0.5);
}

async function estimateTokensAsync(text, model) {
  return countTokensTiktoken(text, model);
}

function estimateMessagesTokens(messages) {
  return messages.reduce((sum, msg) => {
    const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
    return sum + estimateTokens(content) + 4;
  }, 0);
}

async function estimateMessagesTokensAsync(messages, model) {
  let total = 0;
  for (const msg of messages) {
    const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
    total += await countTokensTiktoken(content, model) + 4;
  }
  return total;
}

const ContextConfig = {
  MAX_TOTAL_TOKENS: 100000,
  MAX_PROMPT_TOKENS: 40000,
  MAX_COMPLETION_TOKENS: 4096,
  SAFETY_MARGIN: 0.85,
  MIN_RECENT_MESSAGES: 10,
  COMPRESSION_THRESHOLD: 0.9,
  SEMANTIC_CHUNK_SIZE: 500,
  SEMANTIC_CHUNK_OVERLAP: 50
};

class IncrementalSummary {
  constructor() {
    this.findings = [];
    this.toolsUsed = new Set();
    this.filesAnalyzed = new Set();
    this.errors = [];
    this.decisions = [];
    this.contexts = [];
  }

  addFinding(finding) {
    if (!this.findings.includes(finding)) {
      this.findings.push(finding);
      if (this.findings.length > 20) {
        this.findings = this.findings.slice(-20);
      }
    }
  }

  addTool(tool) {
    this.toolsUsed.add(tool);
  }

  addFile(file) {
    this.filesAnalyzed.add(file);
  }

  addError(error) {
    this.errors.push({ time: Date.now(), error });
    if (this.errors.length > 10) {
      this.errors = this.errors.slice(-10);
    }
  }

  addDecision(decision) {
    this.decisions.push({ time: Date.now(), decision });
    if (this.decisions.length > 10) {
      this.decisions = this.decisions.slice(-10);
    }
  }

  addContext(context) {
    this.contexts.push(context);
    if (this.contexts.length > 5) {
      this.contexts = this.contexts.slice(-5);
    }
  }

  toSummary() {
    const parts = [];

    if (this.findings.length > 0) {
      parts.push(`发现漏洞 (${this.findings.length}): ${this.findings.slice(-5).join(', ')}`);
    }

    if (this.toolsUsed.size > 0) {
      parts.push(`使用工具: ${[...this.toolsUsed].slice(-10).join(', ')}`);
    }

    if (this.filesAnalyzed.size > 0) {
      parts.push(`分析文件: ${[...this.filesAnalyzed].slice(-10).join(', ')}`);
    }

    if (this.decisions.length > 0) {
      parts.push(`关键决策: ${this.decisions.slice(-3).map(d => d.decision).join(' | ')}`);
    }

    if (this.errors.length > 0) {
      parts.push(`错误记录: ${this.errors.slice(-2).map(e => e.error).join(', ')}`);
    }

    if (parts.length === 0) {
      parts.push('[审计进行中，暂无摘要]');
    }

    return {
      role: 'system',
      content: `<audit_summary count="${this.findings.length}" files="${this.filesAnalyzed.size}">${parts.join(' | ')}</audit_summary>`
    };
  }

  toJSON() {
    return {
      findings: this.findings,
      toolsUsed: [...this.toolsUsed],
      filesAnalyzed: [...this.filesAnalyzed],
      errors: this.errors,
      decisions: this.decisions
    };
  }

  static fromJSON(json) {
    const summary = new IncrementalSummary();
    if (json.findings) summary.findings = json.findings;
    if (json.toolsUsed) summary.toolsUsed = new Set(json.toolsUsed);
    if (json.filesAnalyzed) summary.filesAnalyzed = new Set(json.filesAnalyzed);
    if (json.errors) summary.errors = json.errors;
    if (json.decisions) summary.decisions = json.decisions;
    return summary;
  }
}

class SemanticChunker {
  constructor(config = {}) {
    this.chunkSize = config.chunkSize || ContextConfig.SEMANTIC_CHUNK_SIZE;
    this.chunkOverlap = config.chunkOverlap || ContextConfig.SEMANTIC_CHUNK_OVERLAP;
    this.embeddingModel = config.embeddingModel || null;
  }

  chunkByLines(text, maxLines = 100, overlapLines = 10) {
    const lines = text.split('\n');
    const chunks = [];
    let start = 0;

    while (start < lines.length) {
      const end = Math.min(start + maxLines, lines.length);
      const chunk = lines.slice(start, end).join('\n');

      chunks.push({
        content: chunk,
        startLine: start + 1,
        endLine: end,
        index: chunks.length
      });

      start = end - overlapLines;
      if (start <= 0) break;
    }

    return chunks;
  }

  chunkByFunction(text, language = 'auto') {
    const patterns = {
      javascript: /(?:function\s+(\w+)|(?:async\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*\([^)]*\)\s*\{)/g,
      python: /(?:def\s+(\w+)|class\s+(\w+)|async\s+def\s+(\w+))/g,
      java: /(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:\w+)\s+(\w+)\s*\([^)]*\)\s*\{/g,
      csharp: /(?:public|private|protected|internal)?\s*(?:static)?\s*(?:async)?\s*(?:\w+)\s+(\w+)\s*\([^)]*\)\s*\{/g,
      cpp: /(?:void|int|bool|string|auto|const)\s+(\w+)\s*\([^)]*\)\s*\{/g
    };

    const langPatterns = patterns[language] || patterns.javascript;
    const functions = [];
    let match;

    while ((match = langPatterns.exec(text)) !== null) {
      const funcName = match[1] || match[2] || match[3] || 'anonymous';
      functions.push({
        name: funcName,
        position: match.index
      });
    }

    if (functions.length === 0) {
      return this.chunkByLines(text);
    }

    const chunks = [];
    for (let i = 0; i < functions.length; i++) {
      const start = functions[i].position;
      const end = i + 1 < functions.length ? functions[i + 1].position : text.length;
      const content = text.slice(start, end);

      if (content.length > 0) {
        chunks.push({
          content,
          functionName: functions[i].name,
          index: chunks.length
        });
      }
    }

    return chunks;
  }

  chunkBySeverity(text) {
    const severityPattern = /(🔴|🟠|🟡|🟢|Critical|High|Medium|Low|Info|Critical:|High:|Medium:|Low:)/gi;
    const sections = text.split(severityPattern);
    const chunks = [];
    let currentSeverity = 'Info';
    let currentContent = [];

    for (const section of sections) {
      const upperSection = section.toUpperCase();

      if (upperSection.includes('CRITICAL') || section.includes('🔴')) {
        if (currentContent.length > 0) {
          chunks.push({
            content: currentContent.join('\n'),
            severity: currentSeverity
          });
          currentContent = [];
        }
        currentSeverity = 'Critical';
        currentContent.push(section);
      } else if (upperSection.includes('HIGH') || section.includes('🟠')) {
        if (currentContent.length > 0) {
          chunks.push({
            content: currentContent.join('\n'),
            severity: currentSeverity
          });
          currentContent = [];
        }
        currentSeverity = 'High';
        currentContent.push(section);
      } else if (upperSection.includes('MEDIUM') || section.includes('🟡')) {
        if (currentContent.length > 0) {
          chunks.push({
            content: currentContent.join('\n'),
            severity: currentSeverity
          });
          currentContent = [];
        }
        currentSeverity = 'Medium';
        currentContent.push(section);
      } else if (upperSection.includes('LOW') || section.includes('🟢')) {
        if (currentContent.length > 0) {
          chunks.push({
            content: currentContent.join('\n'),
            severity: currentSeverity
          });
          currentContent = [];
        }
        currentSeverity = 'Low';
        currentContent.push(section);
      } else {
        currentContent.push(section);
      }
    }

    if (currentContent.length > 0) {
      chunks.push({
        content: currentContent.join('\n'),
        severity: currentSeverity
      });
    }

    return chunks;
  }
}

class StreamCompressor {
  constructor(options = {}) {
    this.maxTokens = options.maxTokens || 4096;
    this.overflowTokens = options.overflowTokens || 512;
    this.callback = options.callback || null;
  }

  process(chunk) {
    if (typeof chunk !== 'string') {
      chunk = JSON.stringify(chunk);
    }

    const tokens = estimateTokens(chunk);

    if (tokens <= this.maxTokens) {
      return {
        output: chunk,
        truncated: false,
        tokens
      };
    }

    const truncated = this.truncateToTokens(chunk, this.maxTokens - this.overflowTokens);

    if (this.callback) {
      this.callback({
        type: 'truncate',
        originalTokens: tokens,
        truncatedTokens: this.maxTokens,
        savedTokens: tokens - this.maxTokens
      });
    }

    return {
      output: truncated + `\n\n[内容已压缩，原始 ${tokens} tokens，保留最后 ${this.maxTokens} tokens]`,
      truncated: true,
      tokens: this.maxTokens
    };
  }

  truncateToTokens(text, maxTokens) {
    const lines = text.split('\n');
    let result = [];
    let currentTokens = 0;

    for (let i = lines.length - 1; i >= 0; i--) {
      const lineTokens = estimateTokens(lines[i]);
      if (currentTokens + lineTokens <= maxTokens) {
        result.unshift(lines[i]);
        currentTokens += lineTokens;
      } else {
        break;
      }
    }

    return result.join('\n');
  }

  processStream(asyncIterator) {
    const self = this;
    const chunks = [];

    return {
      async *[Symbol.asyncIterator]() {
        for await (const chunk of asyncIterator) {
          const processed = self.process(chunk);
          chunks.push(processed);

          if (self.callback) {
            self.callback({
              type: 'chunk',
              chunk: processed,
              totalChunks: chunks.length
            });
          }

          yield processed.output;
        }
      },

      getStats() {
        return {
          totalChunks: chunks.length,
          totalTokens: chunks.reduce((sum, c) => sum + c.tokens, 0),
          truncatedCount: chunks.filter(c => c.truncated).length
        };
      }
    };
  }
}

class PromptCompressor {
  constructor(config = ContextConfig) {
    this.config = config;
    this.incrementalSummary = new IncrementalSummary();
  }

  shouldCompress(messages) {
    const totalTokens = estimateMessagesTokens(messages);
    return totalTokens > this.config.MAX_TOTAL_TOKENS * this.config.COMPRESSION_THRESHOLD;
  }

  compress(messages) {
    if (!messages || messages.length === 0) {
      return messages;
    }

    const systemMsgs = messages.filter(m => m.role === 'system');
    const regularMsgs = messages.filter(m => m.role !== 'system');

    if (regularMsgs.length <= this.config.MIN_RECENT_MESSAGES) {
      return messages;
    }

    const recentMsgs = regularMsgs.slice(-this.config.MIN_RECENT_MESSAGES);
    const oldMsgs = regularMsgs.slice(0, -this.config.MIN_RECENT_MESSAGES);

    const summary = this._summarizeMessages(oldMsgs);

    return [...systemMsgs, summary, ...recentMsgs];
  }

  compressWithSummary(messages, summary = null) {
    if (!summary) {
      summary = this.incrementalSummary;
    }

    const systemMsgs = messages.filter(m => m.role === 'system');
    const summaryMsg = summary.toSummary();
    const recentMsgs = messages.filter(m => m.role !== 'system').slice(-this.config.MIN_RECENT_MESSAGES);

    return [...systemMsgs, summaryMsg, ...recentMsgs];
  }

  _summarizeMessages(messages) {
    const findings = [];
    const toolsUsed = new Set();

    for (const msg of messages) {
      const content = typeof msg.content === 'string' ? msg.content : '';

      const findingMatches = content.match(/(?:发现|漏洞|vulnerability|finding)[:\s]+([^，,。\n]+)/gi);
      if (findingMatches) {
        findings.push(...findingMatches.slice(0, 5));
      }

      const toolMatches = content.match(/(?:使用工具|tool|call)[:\s]+([^，,。\n]+)/gi);
      if (toolMatches) {
        toolMatches.forEach(m => {
          const tool = m.replace(/(?:使用工具|tool|call)[:\s]+/i, '');
          toolsUsed.add(tool.trim());
        });
      }
    }

    const summaryParts = [];
    if (findings.length > 0) {
      summaryParts.push(`历史发现: ${findings.slice(0, 3).join(', ')}`);
    }
    if (toolsUsed.size > 0) {
      summaryParts.push(`使用工具: ${[...toolsUsed].slice(0, 5).join(', ')}`);
    }
    summaryParts.push(`[已压缩 ${messages.length} 条历史消息]`);

    return {
      role: 'system',
      content: `<memory_summary>${summaryParts.join(' | ')}</memory_summary>`
    };
  }

  truncateToFit(text, maxTokens) {
    const tokens = estimateTokens(text);
    if (tokens <= maxTokens) {
      return text;
    }
    const ratio = maxTokens / tokens;
    const targetLength = Math.floor(text.length * ratio * 0.9);
    return text.slice(0, targetLength) + '...[已截断]';
  }

  buildOptimizedPrompt(systemPrompt, userPrompt, maxTokens) {
    const systemTokens = estimateTokens(systemPrompt);
    const availableForUser = maxTokens - systemTokens - 100;
    const optimizedUser = this.truncateToFit(userPrompt, availableForUser);
    return { systemPrompt, userPrompt: optimizedUser };
  }

  async buildOptimizedPromptAsync(systemPrompt, userPrompt, maxTokens, model) {
    const systemTokens = await countTokensTiktoken(systemPrompt, model);
    const availableForUser = maxTokens - systemTokens - 100;
    const optimizedUser = this.truncateToFit(userPrompt, availableForUser);
    return { systemPrompt, userPrompt: optimizedUser };
  }
}

export {
  estimateTokens,
  estimateTokensAsync,
  estimateMessagesTokens,
  estimateMessagesTokensAsync,
  countTokensTiktoken,
  getModelMaxTokens,
  ContextConfig,
  IncrementalSummary,
  SemanticChunker,
  StreamCompressor,
  PromptCompressor
};