/**
 * 审计参数配置加载器
 * 从 detection_rules.yaml 的 audit: 区块读取可配置的参数
 * 代替代码中硬编码的常量，实现零代码热配置
 */

import { readFileSync } from "node:fs";
import path from "path";
import yaml from "js-yaml";

const DEFAULTS = {
  maxBatches: 16,
  maxFilesPerBatch: 6,
  maxCharsPerBatch: 35000,
  maxParallelRequests: 5,
  maxParallelProjects: 4,
  embeddingMaxConcurrency: 5,
  fetchTimeoutMs: 150000,
  codeIndexMinFiles: 50,
  codeIndexMaxFiles: 100,
  checkpointInterval: 3,
};

let _auditParams = null;

function loadRawConfig() {
  const configPath = path.join(process.cwd(), "config", "detection_rules.yaml");
  try {
    const content = readFileSync(configPath, "utf8");
    const parsed = yaml.load(content);
    return parsed?.audit || {};
  } catch (err) {
    console.warn("[审计参数] 配置文件读取失败，使用默认值:", err.message);
    return {};
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

export function resetAuditParams() {
  _auditParams = null;
}
