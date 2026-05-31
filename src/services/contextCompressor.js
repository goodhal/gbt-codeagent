/**
 * ContextCompressor — 轮间上下文压缩服务
 * 
 * 借鉴 open-code-review 的 MemoryCompressionTask 设计：
 * 将累积的对话历史压缩为 5 维结构化摘要，释放 token 空间。
 * 
 * 压缩维度：
 *   1. Identified Issues — 已确认的安全问题（文件路径 + 类型 + 严重度）
 *   2. Tool Call Conclusions — 工具调用的关键发现
 *   3. Completed Tasks — 已完成无需跟进
 *   4. Pending Tasks — 进行中仍需关注
 *   5. Current Focus — 当前焦点（一句话）
 * 
 * 用法：
 *   const compressor = new ContextCompressor(llmFactory);
 *   const summary = await compressor.compress(messages, { model: 'deepseek-v4-flash' });
 */

import { estimateMessagesTokens } from '../utils/contextManager.js';

// 压缩 System Prompt（与 open-code-review MEMORY_COMPRESSION_TASK 对齐）
const COMPRESSION_SYSTEM_PROMPT = `## Goal
You are a code review conversation summarizer. Compress the conversation history into a structured summary so the auditor can continue without restarting.

## Output Format
Use these five dimensions with explicit headings:

### Identified Code Issues
List confirmed issues sorted by severity (HIGH / MEDIUM / LOW). Each: file path, issue type, severity, brief description.
- [HIGH] UserService.go:45 — concurrent map write without lock, suggest sync.RWMutex
- [MEDIUM] config.go:12 — incomplete error handling, may swallow critical info

### Tool Call Conclusions
Key findings from each tool call. Example:
- file_read(UserService): confirmed concurrent write-to-map in this function
- code_search("database"): no other related config issues found

### Completed Tasks
Items completed that need no follow-up.

### Pending Tasks
Items started but not yet completed, still need attention.

### Current Focus
One sentence: the core matter currently being investigated.

## Rules
1. No specific code details — only file paths and issue types
2. No repetitive or redundant info
3. Omit any dimension with no relevant content
4. Complete/pending items as full sentences
5. current_focus: no more than one sentence`;

/**
 * 将消息历史文本格式化为压缩请求
 */
function formatMessagesForCompression(messages) {
  const parts = [];
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
    // 截断过长内容（保留首尾）
    const truncated = content.length > 2000
      ? content.substring(0, 1000) + '\n... (truncated) ...\n' + content.substring(content.length - 500)
      : content;
    parts.push(`<message id="${i}" role="${msg.role}">\n${truncated}\n</message>`);
  }
  return parts.join('\n');
}

/**
 * 解析压缩响应为结构化对象
 */
function parseCompressionResult(content) {
  const result = {
    identifiedIssues: [],
    toolConclusions: [],
    completedTasks: [],
    pendingTasks: [],
    currentFocus: '',
  };

  const sections = content.split(/^### /gm);
  for (const section of sections) {
    const lines = section.trim().split('\n');
    const heading = lines[0]?.trim().toLowerCase();
    const body = lines.slice(1).join('\n').trim();

    if (!heading || !body) continue;

    if (heading.includes('identified code issue') || heading.includes('已识别')) {
      result.identifiedIssues = body.split('\n').filter(l => l.trim().startsWith('-')).map(l => l.trim());
    } else if (heading.includes('tool call conclusion') || heading.includes('工具调用')) {
      result.toolConclusions = body.split('\n').filter(l => l.trim().startsWith('-')).map(l => l.trim());
    } else if (heading.includes('completed task') || heading.includes('已完成')) {
      result.completedTasks = body.split('\n').filter(l => l.trim().startsWith('-')).map(l => l.trim());
    } else if (heading.includes('pending task') || heading.includes('待处理')) {
      result.pendingTasks = body.split('\n').filter(l => l.trim().startsWith('-')).map(l => l.trim());
    } else if (heading.includes('current focus') || heading.includes('当前焦点')) {
      result.currentFocus = body.substring(0, 200);
    }
  }

  return result;
}

class ContextCompressor {
  /**
   * @param {Function} complete - LLM 调用函数 `(messages, options) => Promise<string>`
   * @param {Object} [options]
   * @param {string} [options.defaultModel='deepseek-v4-flash'] - 压缩用模型（推荐 flash）
   * @param {number} [options.compressionTriggerMsgCount=6] - 消息数超过此值时触发压缩
   */
  constructor(complete, {
    defaultModel = 'deepseek-v4-flash',
    compressionTriggerMsgCount = 6,
  } = {}) {
    this.complete = complete;
    this.defaultModel = defaultModel;
    this.compressionTriggerMsgCount = compressionTriggerMsgCount;
  }

  /**
   * 判断是否应该触发压缩
   * @param {Array} messages - 当前消息列表
   * @param {number} maxTokens - 模型最大 token
   * @returns {boolean}
   */
  shouldCompress(messages, maxTokens) {
    if (messages.length < this.compressionTriggerMsgCount) return false;
    const estimatedTokens = estimateMessagesTokens(messages);
    const ratio = estimatedTokens / maxTokens;
    return ratio >= 0.55; // 55% 阈值（略低于 TokenTracker 的 60%）
  }

  /**
   * 执行压缩
   * @param {Array} messages - 当前对话消息列表
   * @param {Object} [options]
   * @param {string} [options.model] - 压缩用模型
   * @param {string} [options.additionalContext] - 额外上下文（如项目信息）
   * @returns {Promise<{summary: string, structured: Object, inputTokens: number, outputTokens: number}>}
   */
  async compress(messages, {
    model,
    additionalContext = '',
  } = {}) {
    const modelName = model || this.defaultModel;
    const contextText = formatMessagesForCompression(messages);
    const inputTokens = estimateMessagesTokens(messages);

    const userContent = additionalContext
      ? `${additionalContext}\n\n${contextText}`
      : contextText;

    console.log(`[ContextCompressor] 压缩 ${messages.length} 条消息 → ~${inputTokens} tokens, 模型: ${modelName}`);

    try {
      // 调用 LLM（由外部注入的 complete 函数处理）
      const content = await this.complete(
        [
          { role: 'system', content: COMPRESSION_SYSTEM_PROMPT },
          { role: 'user', content: userContent },
        ],
        { model: modelName, temperature: 0.1, maxTokens: 2048 }
      );
      const outputTokens = content.length / 2;
      const structured = parseCompressionResult(content);

      // 构建紧凑的纯文本摘要（注入回对话）
      const summary = buildCompactSummary(structured);

      console.log(`[ContextCompressor] 压缩完成: ${inputTokens} → ~${outputTokens} tokens (${Math.round(outputTokens/inputTokens*100)}%)`);

      return {
        summary,
        structured,
        inputTokens,
        outputTokens: Math.ceil(outputTokens),
      };
    } catch (err) {
      console.warn('[ContextCompressor] 压缩 LLM 调用失败:', err.message);
      // 降级：返回原始消息的简单截断摘要
      return {
        summary: `[压缩失败: ${err.message}] 无法压缩 ${messages.length} 条历史消息。`,
        structured: { identifiedIssues: [], toolConclusions: [], completedTasks: [], pendingTasks: [], currentFocus: '继续审查' },
        inputTokens,
        outputTokens: 50,
      };
    }
  }

  /**
   * 压缩并替换消息列表
   * 将原始消息替换为：系统提示 + 压缩摘要 + 最近的几条消息
   * 
   * @param {Array} messages - 原始消息列表
   * @param {Object} [options]
   * @param {number} [options.keepRecent=3] - 保留最近的消息数
   * @returns {Promise<Array>} 新的消息列表
   */
  async compressAndReplace(messages, options = {}) {
    const { keepRecent = 3, ...compressOptions } = options;
    
    if (messages.length <= keepRecent + 3) {
      return messages; // 太少，不需要压缩
    }

    const { summary } = await this.compress(messages, compressOptions);
    
    // 保留系统消息 + 压缩摘要 + 最近 N 条消息
    const systemMessages = messages.filter(m => m.role === 'system');
    const recentMessages = messages.slice(-keepRecent);
    
    return [
      ...systemMessages,
      {
        role: 'system',
        content: `[对话历史压缩摘要]\n${summary}\n\n继续审查任务。`,
      },
      ...recentMessages,
    ];
  }
}

/**
 * 从结构化解析结果构建紧凑摘要
 */
function buildCompactSummary(structured) {
  const parts = [];

  if (structured.identifiedIssues.length > 0) {
    parts.push(`已识别 ${structured.identifiedIssues.length} 个问题：\n${structured.identifiedIssues.join('\n')}`);
  }

  if (structured.toolConclusions.length > 0) {
    parts.push(`工具调用结论：\n${structured.toolConclusions.join('\n')}`);
  }

  if (structured.completedTasks.length > 0) {
    parts.push(`已完成：${structured.completedTasks.join('; ')}`);
  }

  if (structured.pendingTasks.length > 0) {
    parts.push(`待处理：${structured.pendingTasks.join('; ')}`);
  }

  if (structured.currentFocus) {
    parts.push(`当前焦点：${structured.currentFocus}`);
  }

  return parts.join('\n\n') || '审查进行中。';
}

export { ContextCompressor, COMPRESSION_SYSTEM_PROMPT };
