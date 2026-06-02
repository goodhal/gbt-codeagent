/**
 * 审计参数配置加载器
 * 从 detection_rules.yaml 的 audit: 区块读取可配置的参数
 * 代替代码中硬编码的常量，实现零代码热配置
 */

import { readFileSync, watchFile } from "node:fs";
import path from "path";
import yaml from "js-yaml";

const DEFAULTS = {
  maxBatches: Infinity,
  maxFilesPerBatch: 3,
  maxCharsPerBatch: 45000,
  maxParallelRequests: 5,
  maxParallelProjects: 4,
  embeddingMaxConcurrency: 5,
  fetchTimeoutMs: 150000,
  codeIndexMinFiles: 30,
  codeIndexMaxFiles: 200,
  checkpointInterval: 2,
};

const BASE_CONTEXT_TOKENS = 128000;

let _auditParams = null;

function loadRawConfig() {
  // 优先读取拆分后的 config/audit-config.yaml；兼容旧 detection_rules.yaml
  const configPath = path.join(process.cwd(), "config", "audit-config.yaml");
  const fallbackPath = path.join(process.cwd(), "config", "detection_rules.yaml");
  try {
    const content = readFileSync(configPath, "utf8");
    const parsed = yaml.load(content);
    return parsed?.audit || {};
  } catch {
    // 兼容旧版单文件
    try {
      const content = readFileSync(fallbackPath, "utf8");
      const parsed = yaml.load(content);
      return parsed?.audit || {};
    } catch (err) {
      console.warn("[审计参数] 配置文件读取失败，使用默认值:", err.message);
      return {};
    }
  }
}

export function loadAuditParams() {
  const raw = loadRawConfig();

  _auditParams = {
    maxBatches: raw.maxBatches ?? DEFAULTS.maxBatches,
    maxFilesPerBatch: raw.maxFilesPerBatch ?? DEFAULTS.maxFilesPerBatch,
    maxCharsPerBatch: raw.maxCharsPerBatch ?? DEFAULTS.maxCharsPerBatch,
    maxParallelRequests: raw.maxParallelRequests ?? DEFAULTS.maxParallelRequests,
    maxParallelProjects: raw.maxParallelProjects ?? DEFAULTS.maxParallelProjects,
    embeddingMaxConcurrency: raw.embeddingMaxConcurrency ?? DEFAULTS.embeddingMaxConcurrency,
    fetchTimeoutMs: raw.fetchTimeoutMs ?? DEFAULTS.fetchTimeoutMs,
    codeIndexMinFiles: raw.codeIndexMinFiles ?? DEFAULTS.codeIndexMinFiles,
    codeIndexMaxFiles: raw.codeIndexMaxFiles ?? DEFAULTS.codeIndexMaxFiles,
    checkpointInterval: raw.checkpointInterval ?? DEFAULTS.checkpointInterval,
  };

  return _auditParams;
}

export function getAuditParams() {
  if (!_auditParams) {
    return loadAuditParams();
  }
  return _auditParams;
}

export function getMaxBatches() {
  return getAuditParams().maxBatches;
}

export function getMaxFilesPerBatch() {
  return getAuditParams().maxFilesPerBatch;
}

export function getMaxCharsPerBatch() {
  return getAuditParams().maxCharsPerBatch;
}

export function getMaxParallelRequests() {
  return getAuditParams().maxParallelRequests;
}

export function getMaxParallelProjects() {
  return getAuditParams().maxParallelProjects;
}

export function getFetchTimeoutMs() {
  return getAuditParams().fetchTimeoutMs;
}

export function getCodeIndexMinFiles() {
  return getAuditParams().codeIndexMinFiles;
}

export function getCheckpointInterval() {
  return getAuditParams().checkpointInterval;
}

export function getEffectiveBatchParams(modelMaxTokens) {
  const base = getAuditParams();
  const scale = (modelMaxTokens || BASE_CONTEXT_TOKENS) / BASE_CONTEXT_TOKENS;
  const scaledFiles = Math.min(20, Math.max(base.maxFilesPerBatch, Math.floor(base.maxFilesPerBatch * scale)));
  const scaledChars = Math.min(300000, Math.max(base.maxCharsPerBatch, Math.floor(base.maxCharsPerBatch * scale)));
  return {
    maxFilesPerBatch: scaledFiles,
    maxCharsPerBatch: scaledChars,
  };
}

export function getCompletionTokens(modelMaxTokens) {
  return Math.min(16384, Math.max(4096, Math.floor((modelMaxTokens || 65536) * 0.08)));
}

// 监听配置文件变更，热更新缓存
const CONFIG_PATH = path.join(process.cwd(), "config", "audit-config.yaml");
const FALLBACK_PATH = path.join(process.cwd(), "config", "detection_rules.yaml");
try {
  watchFile(CONFIG_PATH, (curr, prev) => {
    if (curr.mtimeMs !== prev.mtimeMs) {
      _auditParams = null;
      console.log("[审计参数] 检测到配置文件变更，已热更新缓存");
    }
  });
} catch (err) {
  // 兼容旧版
  try {
    watchFile(FALLBACK_PATH, (curr, prev) => {
      if (curr.mtimeMs !== prev.mtimeMs) {
        _auditParams = null;
        console.log("[审计参数] 检测到配置文件变更，已热更新缓存");
      }
    });
  } catch {
    console.debug("[审计参数] 无法监听配置文件:", err.message);
  }
}

