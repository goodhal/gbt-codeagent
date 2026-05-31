/**
 * 精简 Prompt 模板加载器
 * 
 * 从 src/config/prompts/ 目录加载 Markdown 模板，组合成 System Prompt。
 * 相比旧 llmPrompts.js 的 JS 常量拼接，此方案：
 *   - 模板与代码分离，易于维护和 A/B 测试
 *   - 每个模板文件独立控制，可按语言/场景选择性加载
 *   - System Prompt 整体长度控制在 ~2500 tokens（旧版 ~6000+）
 * 
 * 用法：
 *   const { buildSystemPrompt } = require('./config/prompts');
 *   const prompt = await buildSystemPrompt({ languages: ['java'], isGbtAudit: false });
 */

import { promises as fs } from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 单文件缓存，避免重复读取
const cache = new Map();

async function loadTemplate(filePath) {
  if (cache.has(filePath)) {
    return cache.get(filePath);
  }
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const trimmed = content.trim();
    cache.set(filePath, trimmed);
    return trimmed;
  } catch (err) {
    console.warn(`[PromptLoader] 无法加载模板 ${filePath}:`, err.message);
    return '';
  }
}

/**
 * 判断是否为支持的语言
 */
const SUPPORTED_LANGUAGES = new Set([
  'java', 'javascript', 'js', 'typescript', 'ts', 'tsx', 'jsx',
  'python', 'py', 'go', 'golang',
  'c', 'cpp', 'c++', 'csharp', 'cs', 'c#',
  'php', 'ruby', 'rust', 'kotlin', 'scala', 'swift',
]);

/**
 * 构建精简版 System Prompt
 * 
 * @param {Object} options
 * @param {string[]} [options.languages=[]] - 项目检测到的语言列表
 * @param {boolean} [options.isGbtAudit=false] - 是否 GB/T 国标审计模式
 * @param {Object} [options.extraSections={}] - 额外注入的 prompt section
 * @returns {Promise<string>} 组合后的 System Prompt
 */
export async function buildSlimSystemPrompt({
  languages = [],
  isGbtAudit = false,
  extraSections = {},
} = {}) {
  const sections = [];

  // 1. 核心系统提示词（~300 词）
  const systemPrompt = await loadTemplate(path.join(__dirname, 'system.md'));
  sections.push(systemPrompt);

  // 2. 通用安全检查清单
  const securityChecklist = await loadTemplate(path.join(__dirname, 'security-checklist.md'));
  sections.push(securityChecklist);

  // 3. 检测模式速查表（始终加载 — Source→Sink→Safety 三段式）
  const detectionPatterns = await loadTemplate(path.join(__dirname, 'detection-patterns.md'));
  if (detectionPatterns) {
    sections.push(detectionPatterns);
  }

  // 4. 语言特定审查清单（检测到支持的语言时加载）
  const hasSupportedLang = languages.some(l => SUPPORTED_LANGUAGES.has(l.toLowerCase()));
  if (hasSupportedLang) {
    const langChecklist = await loadTemplate(path.join(__dirname, 'language-checklist.md'));
    if (langChecklist) {
      sections.push(langChecklist);
    }
  }

  // 5. GB/T 国标审计扩展（按需加载）
  if (isGbtAudit) {
    const gbtSection = await loadTemplate(path.join(__dirname, 'gbt-extension.md'));
    if (gbtSection) {
      sections.push(gbtSection);
    }
  }

  // 6. 额外注入段（如 auditKnowledge、validationFeedback 等）
  for (const [key, value] of Object.entries(extraSections)) {
    if (value && typeof value === 'string' && value.trim()) {
      sections.push(key.startsWith('【') ? value : `【${key}】\n${value}`);
    }
  }

  return sections.join('\n\n');
}

/**
 * 估算 prompt 的 token 数（使用当前 contextManager 的估算逻辑）
 * 延迟加载避免循环依赖
 */
export async function estimatePromptTokens(promptText) {
  try {
    const { estimateTokens } = await import('../utils/contextManager.js');
    return estimateTokens(promptText);
  } catch {
    // 降级估算
    const chineseChars = (promptText.match(/[\u4e00-\u9fff]/g) || []).length;
    const englishWords = promptText.replace(/[\u4e00-\u9fff]/g, ' ').split(/\s+/).filter(w => w.length > 0).length;
    return Math.ceil(chineseChars * 2.0 + englishWords * 1.3);
  }
}

export { SUPPORTED_LANGUAGES };
