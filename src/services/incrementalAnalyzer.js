/**
 * 增量分析服务
 * 基于 code-review-graph 的增量更新机制
 * - 检测文件变更
 * - 缓存分析结果
 * - 只重新分析变更部分
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "crypto";
import { CodeGraph } from "./codeGraph.js";

export class IncrementalAnalyzer {
  constructor() {
    this._cacheDir = path.join(process.cwd(), 'cache', 'incremental');
    this._fileHashes = new Map();  // 项目ID -> { 文件路径 -> 哈希 }
    this._analysisCache = new Map();  // 项目ID -> 分析结果
    this._graphCache = new Map();  // 项目ID -> CodeGraph实例
  }

  /**
   * 初始化增量分析器
   */
  async initialize() {
    await fs.mkdir(this._cacheDir, { recursive: true });
    await this._loadCache();
  }

  /**
   * 加载缓存
   */
  async _loadCache() {
    try {
      const cacheFile = path.join(this._cacheDir, 'incremental_cache.json');
      const content = await fs.readFile(cacheFile, 'utf8');
      const cache = JSON.parse(content);
      this._fileHashes = new Map(Object.entries(cache.fileHashes || {}));
      this._analysisCache = new Map(Object.entries(cache.analysisCache || {}));
    } catch {
      // 缓存文件不存在，忽略
    }
  }

  /**
   * 保存缓存
   */
  async _saveCache() {
    const cache = {
      fileHashes: Object.fromEntries(this._fileHashes),
      analysisCache: Object.fromEntries(this._analysisCache)
    };
    await fs.writeFile(
      path.join(this._cacheDir, 'incremental_cache.json'),
      JSON.stringify(cache, null, 2),
      'utf8'
    );
  }

  /**
   * 计算文件哈希
   */
  async _computeFileHash(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }

  /**
   * 获取项目的文件列表和哈希
   */
  async _getFileHashes(projectRoot) {
    const files = await this._collectSourceFiles(projectRoot);
    const hashes = {};
    
    for (const file of files) {
      const hash = await this._computeFileHash(file);
      if (hash) {
        const relativePath = path.relative(projectRoot, file).replaceAll('\\', '/');
        hashes[relativePath] = hash;
      }
    }
    
    return hashes;
  }

  /**
   * 收集源代码文件
   */
  async _collectSourceFiles(projectRoot) {
    const files = [];
    const extensions = ['.js', '.jsx', '.ts', '.tsx', '.java', '.py', '.go', '.php', '.cs', '.cpp', '.rb', '.rs'];
    
    async function collect(dir) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        // 跳过常见忽略目录
        if (['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__'].includes(entry.name)) {
          continue;
        }
        
        if (entry.isDirectory()) {
          await collect(fullPath);
        } else if (extensions.includes(path.extname(entry.name).toLowerCase())) {
          files.push(fullPath);
        }
      }
    }
    
    await collect(projectRoot);
    return files;
  }

  /**
   * 检测变更文件
   */
  async detectChanges(projectId, projectRoot) {
    const currentHashes = await this._getFileHashes(projectRoot);
    const previousHashes = this._fileHashes.get(projectId) || {};
    
    const changes = {
      added: [],
      modified: [],
      deleted: [],
      unchanged: []
    };

    // 检测新增和修改
    for (const [file, hash] of Object.entries(currentHashes)) {
      if (!previousHashes[file]) {
        changes.added.push(file);
      } else if (previousHashes[file] !== hash) {
        changes.modified.push(file);
      } else {
        changes.unchanged.push(file);
      }
    }

    // 检测删除
    for (const file of Object.keys(previousHashes)) {
      if (!currentHashes[file]) {
        changes.deleted.push(file);
      }
    }

    // 更新缓存
    this._fileHashes.set(projectId, currentHashes);
    await this._saveCache();

    return changes;
  }

  /**
   * 分析项目（增量模式）
   */
  async analyze(projectId, projectRoot, options = {}) {
    const { forceFull = false, maxDepth = 3 } = options;

    // 检测变更
    const changes = await this.detectChanges(projectId, projectRoot);
    const hasChanges = changes.added.length > 0 || changes.modified.length > 0 || changes.deleted.length > 0;

    // 如果没有变更且不是强制全量分析，返回缓存结果
    if (!forceFull && !hasChanges) {
      const cached = this._analysisCache.get(projectId);
      if (cached) {
        console.log(`[增量分析] 使用缓存结果，项目: ${projectId}`);
        return cached;
      }
    }

    console.log(`[增量分析] 开始分析项目: ${projectId}`);
    console.log(`[增量分析] 变更统计 - 新增: ${changes.added.length}, 修改: ${changes.modified.length}, 删除: ${changes.deleted.length}`);

    // 构建代码图谱
    const graph = new CodeGraph();
    await graph.build(projectRoot);
    
    // 缓存图谱
    this._graphCache.set(projectId, graph);

    // 分析变更影响
    const analysisResult = await this._analyzeChanges(graph, changes, projectRoot, maxDepth);
    
    // 缓存分析结果
    this._analysisCache.set(projectId, {
      ...analysisResult,
      analyzedAt: new Date().toISOString(),
      changes
    });
    await this._saveCache();

    return {
      ...analysisResult,
      analyzedAt: new Date().toISOString(),
      changes
    };
  }

  /**
   * 分析变更影响
   */
  async _analyzeChanges(graph, changes, projectRoot, maxDepth) {
    const result = {
      impactAnalysis: {},
      criticalPaths: [],
      architectureWarnings: [],
      stats: graph.getStats()
    };

    // 分析新增和修改文件的影响
    const changedFiles = [...changes.added, ...changes.modified];
    if (changedFiles.length > 0) {
      result.impactAnalysis = await this._computeImpactAnalysis(graph, changedFiles, maxDepth);
    }

    // 获取架构概览
    const archOverview = graph.getArchitectureOverview();
    result.architectureWarnings = archOverview.warnings;
    result.communityAnalysis = archOverview.communitiesDetail;

    // 检测关键路径
    const entryPoints = graph.getEntryPoints();
    for (const entry of entryPoints) {
      const flow = graph.traceExecutionFlow(entry.qualifiedName, maxDepth);
      if (flow.criticality > 50) {
        result.criticalPaths.push({
          entryPoint: entry.name,
          ...flow
        });
      }
    }

    // 如果没有明确的入口点，尝试分析所有文件
    if (entryPoints.length === 0 && changedFiles.length > 0) {
      for (const file of changedFiles.slice(0, 5)) {
        const impact = graph.getFileImpactRadius(file, maxDepth);
        if (impact.count > 1) {
          result.criticalPaths.push({
            entryPoint: file,
            ...impact
          });
        }
      }
    }

    return result;
  }

  /**
   * 计算变更影响分析
   */
  async _computeImpactAnalysis(graph, changedFiles, maxDepth) {
    const impactMap = {};

    for (const file of changedFiles) {
      const impact = graph.getFileImpactRadius(file, maxDepth);
      
      impactMap[file] = {
        file,
        affectedNodes: impact.nodes.length,
        affectedEdges: impact.edges.length,
        affectedFiles: [...new Set(impact.nodes.map(n => n.filePath))].length,
        depth: impact.depth,
        nodes: impact.nodes.map(n => ({
          id: n.id,
          name: n.name,
          kind: n.kind,
          filePath: n.filePath
        })),
        criticality: this._estimateCriticality(impact)
      };
    }

    return impactMap;
  }

  /**
   * 估算关键程度
   */
  _estimateCriticality(impact) {
    if (impact.nodes.length === 0) return 0;

    // 检查是否涉及入口点或高连接节点
    const hasEntryPoint = impact.nodes.some(n => n.kind === 'EntryPoint');
    const hasHub = impact.nodes.some(n => {
      const degree = this._getNodeDegree(n.qualifiedName);
      return degree >= 5;
    });

    let score = Math.min(impact.nodes.length / 20, 0.5);
    
    if (hasEntryPoint) score += 0.3;
    if (hasHub) score += 0.2;
    
    return Math.round(score * 100);
  }

  /**
   * 获取节点度数
   */
  _getNodeDegree(nodeQN) {
    // 简化实现：计算边数
    let degree = 0;
    // 实际实现需要访问图的边数据
    return degree;
  }

  /**
   * 获取缓存的图谱
   */
  getGraph(projectId) {
    return this._graphCache.get(projectId);
  }

  /**
   * 清除项目缓存
   */
  clearProjectCache(projectId) {
    this._fileHashes.delete(projectId);
    this._analysisCache.delete(projectId);
    this._graphCache.delete(projectId);
  }

  /**
   * 清除所有缓存
   */
  async clearAllCache() {
    this._fileHashes.clear();
    this._analysisCache.clear();
    this._graphCache.clear();
    await this._saveCache();
    
    // 删除缓存目录
    try {
      await fs.rm(this._cacheDir, { recursive: true });
    } catch {
      // 忽略删除失败
    }
  }

  /**
   * 获取缓存状态
   */
  getCacheStatus() {
    return {
      cachedProjects: this._fileHashes.size,
      cachedAnalyses: this._analysisCache.size,
      cachedGraphs: this._graphCache.size
    };
  }
}

// 创建全局实例
let _globalAnalyzer = null;

export async function getGlobalIncrementalAnalyzer() {
  if (!_globalAnalyzer) {
    _globalAnalyzer = new IncrementalAnalyzer();
    await _globalAnalyzer.initialize();
  }
  return _globalAnalyzer;
}