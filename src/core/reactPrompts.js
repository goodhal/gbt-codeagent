import { promises as fs } from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { formatToolsForPrompt } from '../tools/mcpTools.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROMPT_DOC_PATH = path.join(__dirname, '../../docs/gbt-audit/workflow/react_audit.md');

let cachedPrompts = null;

async function loadPromptDocument() {
  if (cachedPrompts) {
    return cachedPrompts;
  }

  try {
    const content = await fs.readFile(PROMPT_DOC_PATH, 'utf-8');
    cachedPrompts = parsePromptDocument(content);
    return cachedPrompts;
  } catch (error) {
    console.warn(`[ReAct提示词] 无法读取提示词文档: ${error.message}`);
    return null;
  }
}

function parsePromptDocument(content) {
  const sectionPattern = /^## (.+)$/m;
  const sections = {};
  let lastIndex = 0;
  let match;

  while ((match = sectionPattern.exec(content, lastIndex)) !== null) {
    const title = match[1];
    const start = match.index + match[0].length;
    const nextSection = content.indexOf('\n## ', start);
    const end = nextSection === -1 ? content.length : nextSection;
    sections[title] = content.slice(start, end).trim();
    lastIndex = end;
  }

  return {
    systemPrompt: sections['系统提示词'] || sections['System Prompt'] || '',
    initialPromptTemplate: sections['初始提示词模板'] || sections['Initial Prompt Template'] || '',
    analysisStrategy: sections['分析策略'] || sections['Analysis Strategy'] || '',
    finalAnswerGuidance: sections['最终答案指南'] || sections['Final Answer Guidance'] || ''
  };
}

async function getPrompt(key) {
  const prompts = await loadPromptDocument();
  if (!prompts) {
    throw new Error(`提示词文档不可用，请检查 ${PROMPT_DOC_PATH}`);
  }
  return prompts[key];
}

async function buildReActSystemPrompt() {
  let systemTemplate = await getPrompt('systemPrompt');
  const toolsContent = formatToolsForPrompt();
  return systemTemplate.replace('{TOOLS_CONTENT}', toolsContent);
}

function buildReActInitialPrompt(codeDiff, projectInfo = {}) {
  const template = `请分析以下代码变更，进行深度安全审计：

## 项目信息
- 项目名称：{projectName}
- 项目路径：{projectPath}
- 编程语言：{language}

## 代码变更

\`\`\`diff
{codeDiff}
\`\`\`

## 分析要求
1. 首先使用工具收集变更文件的完整信息
2. 理解代码的业务逻辑和上下文
3. 识别潜在的安全漏洞和风险
4. 提供具体的问题位置和修复建议

请开始使用工具进行分析。`;

  return template
    .replace('{projectName}', projectInfo.name || 'Unknown Project')
    .replace('{projectPath}', projectInfo.path || 'Unknown Path')
    .replace('{language}', projectInfo.language || 'Multiple')
    .replace('{codeDiff}', codeDiff || 'No code diff provided');
}

async function getAnalysisStrategy() {
  return getPrompt('analysisStrategy');
}

async function getFinalAnswerGuidance() {
  return getPrompt('finalAnswerGuidance');
}

async function loadReActPrompts() {
  return loadPromptDocument();
}

export {
  buildReActInitialPrompt,
  buildReActSystemPrompt,
  getAnalysisStrategy,
  getFinalAnswerGuidance,
  loadReActPrompts
};
