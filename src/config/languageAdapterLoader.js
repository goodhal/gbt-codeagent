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

function getAdapter(language) {
  const adapters = getLanguageAdapters();
  return adapters[language.toLowerCase()];
}

export function getControlPatterns(language) {
  return getAdapter(language)?.control_patterns || {};
}

export function getDangerousPatterns(language) {
  return getAdapter(language)?.dangerous_patterns || {};
}

export function getFrameworkConfig(language) {
  return getAdapter(language)?.framework_configs || {};
}

export function getUriParsingPatterns(language) {
  return getAdapter(language)?.uri_parsing || {};
}

export function getAuthBypassTechPatterns(language) {
  return getAdapter(language)?.auth_bypass_tech_detection || {};
}

export function getBypassPayloads(language) {
  return getAdapter(language)?.bypass_payloads || {};
}

export function getRouteAnnotations(language) {
  return getAdapter(language)?.route_annotations || {};
}

function flattenPatterns(catPatterns) {
  if (Array.isArray(catPatterns)) return catPatterns;
  return Object.values(catPatterns).flat();
}

export function buildSecurityControlContext(language) {
  const patterns = getControlPatterns(language);
  if (Object.keys(patterns).length === 0) return "";

  const sections = [];
  for (const [category, catPatterns] of Object.entries(patterns)) {
    const names = flattenPatterns(catPatterns).join(", ");
    if (names) {
      sections.push(`  ${category}: ${names}`);
    }
  }

  return sections.length > 0
    ? `\n【${language} 安全控制模式识别】\n${sections.join("\n")}`
    : "";
}

export function buildDangerousPatternsContext(language) {
  const patterns = getDangerousPatterns(language);
  if (Object.keys(patterns).length === 0) return "";

  const sections = [];
  for (const [category, pats] of Object.entries(patterns)) {
    if (Array.isArray(pats) && pats.length > 0) {
      sections.push(`  ${category}:\n    ${pats.join("\n    ")}`);
    }
  }

  return sections.length > 0
    ? `\n【${language} 危险API/模式识别】（重点审查目标）\n${sections.join("\n")}`
    : "";
}

export function buildUriParsingContext(language) {
  const uriParsing = getUriParsingPatterns(language);
  if (Object.keys(uriParsing).length === 0) return "";

  const sections = [];
  if (uriParsing.dangerous_uri_sources?.length) {
    sections.push(`  危险URI获取方式（不处理分号/编码/路径穿越）:\n    ${uriParsing.dangerous_uri_sources.join("\n    ")}`);
  }
  if (uriParsing.safe_uri_sources?.length) {
    sections.push(`  安全URI获取方式（已做归一化处理）:\n    ${uriParsing.safe_uri_sources.join("\n    ")}`);
  }
  if (uriParsing.bypass_indicators?.length) {
    sections.push(`  绕过指示器（存在这些模式说明可能有绕过风险）:\n    ${uriParsing.bypass_indicators.join("\n    ")}`);
  }

  return sections.length > 0
    ? `\n【${language} URI解析与鉴权绕过检测】\n${sections.join("\n")}`
    : "";
}

export function buildAuthBypassTechContext(language) {
  const tech = getAuthBypassTechPatterns(language);
  if (Object.keys(tech).length === 0) return "";

  const sections = [];
  if (tech.shiro_cve?.length) {
    sections.push(`  Shiro已知CVE版本/漏洞:\n    ${tech.shiro_cve.join("\n    ")}`);
  }
  if (tech.spring_security_misconfig?.length) {
    sections.push(`  Spring Security错误配置:\n    ${tech.spring_security_misconfig.join("\n    ")}`);
  }
  if (tech.spring_mvc_suffix?.length) {
    sections.push(`  Spring MVC后缀匹配绕过:\n    ${tech.spring_mvc_suffix.join("\n    ")}`);
  }
  if (tech.path_matching_issues?.length) {
    sections.push(`  路径匹配问题:\n    ${tech.path_matching_issues.join("\n    ")}`);
  }

  return sections.length > 0
    ? `\n【${language} 鉴权绕过技术栈检测】\n${sections.join("\n")}`
    : "";
}

export function buildBypassPayloadsContext(language) {
  const payloads = getBypassPayloads(language);
  if (Object.keys(payloads).length === 0) return "";

  const sections = [];
  if (payloads.semicolon?.length) {
    sections.push(`  分号绕过: ${payloads.semicolon.join(", ")}`);
  }
  if (payloads.path_traversal?.length) {
    sections.push(`  路径穿越: ${payloads.path_traversal.join(", ")}`);
  }
  if (payloads.double_slash?.length) {
    sections.push(`  双斜杠: ${payloads.double_slash.join(", ")}`);
  }
  if (payloads.encoding?.length) {
    sections.push(`  编码绕过: ${payloads.encoding.join(", ")}`);
  }

  return sections.length > 0
    ? `\n【${language} 常见鉴权绕过Payload】\n${sections.join("\n")}`
    : "";
}

export function buildRouteAnnotationsContext(language) {
  const routes = getRouteAnnotations(language);
  if (Object.keys(routes).length === 0) return "";

  const sections = [];
  for (const [framework, annotations] of Object.entries(routes)) {
    if (Array.isArray(annotations) && annotations.length > 0) {
      sections.push(`  ${framework}: ${annotations.join(", ")}`);
    }
  }

  return sections.length > 0
    ? `\n【${language} Web框架路由注解识别】（标记端点后检查是否有鉴权注解）\n${sections.join("\n")}`
    : "";
}

export function buildFrameworkConfigContext(language) {
  const configs = getFrameworkConfig(language);
  if (Object.keys(configs).length === 0) return "";

  const sections = [];
  for (const [framework, cfg] of Object.entries(configs)) {
    const parts = [];
    if (cfg.config_files?.length) {
      parts.push(`配置文件: ${cfg.config_files.join(", ")}`);
    }
    if (cfg.security_location) {
      parts.push(`安全配置位置: ${cfg.security_location}`);
    }
    if (cfg.controller_location) {
      parts.push(`控制器位置: ${cfg.controller_location}`);
    }
    if (cfg.action_location) {
      parts.push(`Action位置: ${cfg.action_location}`);
    }
    if (cfg.mapper_location) {
      parts.push(`Mapper位置: ${cfg.mapper_location}`);
    }
    if (cfg.entity_location) {
      parts.push(`Entity位置: ${cfg.entity_location}`);
    }
    if (cfg.config_class_pattern) {
      parts.push(`配置类模式: ${cfg.config_class_pattern}`);
    }
    if (parts.length > 0) {
      sections.push(`  ${framework}:\n    ${parts.join("\n    ")}`);
    }
  }

  return sections.length > 0
    ? `\n【${language} 框架安全配置定位】\n${sections.join("\n")}`
    : "";
}

export function buildFullLanguageContext(language) {
  const parts = [
    buildSecurityControlContext(language),
    buildDangerousPatternsContext(language),
    buildUriParsingContext(language),
    buildAuthBypassTechContext(language),
    buildBypassPayloadsContext(language),
    buildRouteAnnotationsContext(language),
    buildFrameworkConfigContext(language),
  ];
  return parts.filter(Boolean).join("\n");
}

export function resetLanguageAdapters() {
  _adapters = null;
}
