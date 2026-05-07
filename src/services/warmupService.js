/**
 * 缓存预热服务
 * 在服务器启动时预加载常用数据，减少首次请求响应时间
 */

import { promises as fs } from "node:fs";
import path from "path";

let warmupCompleted = false;
const warmupCache = new Map();

export class WarmupService {
  constructor() {
    this._cache = new Map();
  }

  async warmup() {
    if (warmupCompleted) {
      console.log("[预热] 已完成，跳过");
      return;
    }

    console.log("[预热] 开始缓存预热...");
    const startTime = performance.now();

    try {
      await Promise.all([
        this._preloadDetectionRules(),
        this._preloadAuditKnowledge(),
        this._preloadSkillDefinitions()
      ]);

      warmupCompleted = true;
      const duration = (performance.now() - startTime).toFixed(2);
      console.log(`[预热] 缓存预热完成，耗时 ${duration}ms`);
    } catch (error) {
      console.error("[预热] 缓存预热失败:", error.message);
    }
  }

  async _preloadDetectionRules() {
    try {
      const rulesPath = path.join(process.cwd(), "config", "detection_rules.yaml");
      const content = await fs.readFile(rulesPath, "utf8");
      this._cache.set("detection_rules", content);
      console.log("[预热] 已预加载检测规则");
    } catch (error) {
      console.warn("[预热] 无法预加载检测规则:", error.message);
    }
  }

  async _preloadAuditKnowledge() {
    try {
      const docsDir = path.join(process.cwd(), "docs", "gbt-audit");
      
      const knowledgeFiles = [
        "skill.md",
        "workflow/audit_workflow.md",
        "workflow/quality_standards.md",
        "reference/GBT_39412-2020.md"
      ];

      await Promise.all(knowledgeFiles.map(async (filePath) => {
        try {
          const fullPath = path.join(docsDir, filePath);
          const content = await fs.readFile(fullPath, "utf8");
          this._cache.set(`knowledge_${filePath.replace(/\//g, "_")}`, content);
        } catch (error) {
          console.warn(`[预热] 无法预加载 ${filePath}:`, error.message);
        }
      }));

      console.log("[预热] 已预加载审计知识");
    } catch (error) {
      console.warn("[预热] 无法预加载审计知识:", error.message);
    }
  }

  async _preloadSkillDefinitions() {
    try {
      const skillsPath = path.join(process.cwd(), "src", "config", "auditSkills.js");
      const content = await fs.readFile(skillsPath, "utf8");
      this._cache.set("skill_definitions", content);
      console.log("[预热] 已预加载技能定义");
    } catch (error) {
      console.warn("[预热] 无法预加载技能定义:", error.message);
    }
  }

  get(key) {
    return this._cache.get(key);
  }

  has(key) {
    return this._cache.has(key);
  }

  clear() {
    this._cache.clear();
    warmupCompleted = false;
  }

  getStats() {
    return {
      keys: Array.from(this._cache.keys()),
      size: this._cache.size,
      completed: warmupCompleted
    };
  }
}

export const warmupService = new WarmupService();

export async function ensureWarmup() {
  if (!warmupCompleted) {
    await warmupService.warmup();
  }
}
