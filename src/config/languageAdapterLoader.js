/**
 * 语言安全控制适配器加载器
 * 从 config/language_adapters/*.yaml 读取语言特定的安全控制模式
 * 用于增强 contextAwareFilter 和 securityHintProfile
 */
import { readFileSync, readdirSync } from "node:fs";
import path from "path";
import yaml from "js-yaml";

let _adapters = null;

function loadAllAdapters() {
  const adaptersDir = path.join(process.cwd(), "config", "language_adapters");
  const adapters = {};

  let files;
  try {
    files = readdirSync(adaptersDir);
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.debug('[适配器] language_adapters 目录不存在，跳过加载');
    } else {
      console.warn(`[适配器] 读取目录失败: ${err.message}`);
    }
    return adapters;
  }

  for (const file of files) {
    if (!file.endsWith('.yaml') && !file.endsWith('.yml')) continue;
    const lang = path.basename(file, path.extname(file));
    try {
      const content = readFileSync(path.join(adaptersDir, file), "utf8");
      adapters[lang] = yaml.load(content);
      console.debug(`[适配器] 已加载 ${lang} 语言适配器`);
    } catch (err) {
      console.warn(`[适配器] ${file} 加载失败: ${err.message}`);
    }
  }

  return adapters;
}

export function getLanguageAdapters() {
  if (!_adapters) {
    _adapters = loadAllAdapters();
  }
  return _adapters;
}

/**
 * 获取指定语言的安全控制检测模式
 * 返回 { authentication, authorization, input_validation, parameterized_query, ... }
 */
export function getControlPatterns(language) {
  const adapters = getLanguageAdapters();
  const adapter = adapters[language.toLowerCase()];
  return adapter?.control_patterns || {};
}

/**
 * 获取指定语言的危险模式列表
 * 返回 { command_exec, sql_injection_risk, deserialization, ... }
 */
export function getDangerousPatterns(language) {
  const adapters = getLanguageAdapters();
  const adapter = adapters[language.toLowerCase()];
  return adapter?.dangerous_patterns || {};
}

/**
 * 获取框架特定配置（如 Spring Boot config files 位置）
 */
export function getFrameworkConfig(language) {
  const adapters = getLanguageAdapters();
  const adapter = adapters[language.toLowerCase()];
  return adapter?.framework_configs || {};
}

/**
 * 构建安全控制上下文文本，用于增强 LLM 提示词
 */
export function buildSecurityControlContext(language) {
  const patterns = getControlPatterns(language);
  if (Object.keys(patterns).length === 0) return "";

  const sections = [];
  for (const [category, catPatterns] of Object.entries(patterns)) {
    const names = Array.isArray(catPatterns)
      ? catPatterns.join(", ")
      : Object.values(catPatterns).flat().join(", ");
    if (names) {
      sections.push(`  ${category}: ${names}`);
    }
  }

  return sections.length > 0
    ? `\n【${language} 安全控制模式识别】\n${sections.join("\n")}`
    : "";
}

export function resetLanguageAdapters() {
  _adapters = null;
}
