/**
 * 净化函数模式加载器
 * 从 YAML 配置文件加载净化函数模式，避免与 JS 代码重复
 */

import { promises as fs } from 'node:fs';
import path from 'path';
import yaml from 'yaml';

let sanitizerPatterns = null;

/**
 * 从 YAML 文件加载净化函数模式
 */
export async function loadSanitizerPatterns() {
  if (sanitizerPatterns) {
    return sanitizerPatterns;
  }

  const configPath = path.join(process.cwd(), 'config', 'sanitizer_patterns.yaml');
  
  try {
    const content = await fs.readFile(configPath, 'utf-8');
    const config = yaml.parse(content);
    
    // 将 YAML 格式转换为 JS 正则表达式格式
    sanitizerPatterns = {};
    
    for (const [category, groups] of Object.entries(config.sanitizer_patterns || {})) {
      sanitizerPatterns[category] = [];
      
      for (const group of groups) {
        for (const patternStr of group.patterns || []) {
          // 将字符串转换为正则表达式
          try {
            const regex = new RegExp(patternStr);
            sanitizerPatterns[category].push(regex);
          } catch (e) {
            console.warn(`[SanitizerLoader] Invalid regex pattern: ${patternStr}`);
          }
        }
      }
    }
    
    console.log(`[SanitizerLoader] Loaded ${Object.keys(sanitizerPatterns).length} sanitizer categories`);
    return sanitizerPatterns;
  } catch (error) {
    console.error(`[SanitizerLoader] Failed to load sanitizer patterns:`, error);
    // 返回默认空模式
    return {
      sql: [],
      xss: [],
      cmd: [],
      path: [],
      general: []
    };
  }
}

/**
 * 获取净化函数模式（同步版本，用于初始化）
 */
export function getSanitizerPatterns() {
  return sanitizerPatterns || {
    sql: [],
    xss: [],
    cmd: [],
    path: [],
    general: []
  };
}