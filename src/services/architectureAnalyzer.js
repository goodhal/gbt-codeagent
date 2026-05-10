/**
 * 架构分析服务
 * 整合 code-review-graph 的架构分析能力：
 * - 执行流追踪
 * - 社区检测
 * - 架构健康度评估
 * - 代码质量建议
 */

import { CodeGraph } from "./codeGraph.js";
import { getGlobalIncrementalAnalyzer } from "./incrementalAnalyzer.js";

export class ArchitectureAnalyzer {
  constructor() {
    this._graph = null;
    this._projectRoot = null;
  }

  /**
   * 初始化分析器
   */
  async initialize(projectRoot) {
    this._projectRoot = projectRoot;
    
    // 尝试从增量分析器获取缓存的图谱
    const analyzer = await getGlobalIncrementalAnalyzer();
    const projectId = this._getProjectId(projectRoot);
    this._graph = analyzer.getGraph(projectId);
    
    // 如果没有缓存，构建新图谱
    if (!this._graph) {
      this._graph = new CodeGraph();
      await this._graph.build(projectRoot);
    }
  }

  /**
   * 获取项目ID
   */
  _getProjectId(projectRoot) {
    return projectRoot.replace(/[\/\\:]/g, '_');
  }

  /**
   * 执行完整的架构分析
   */
  analyze() {
    if (!this._graph) {
      throw new Error('架构分析器未初始化');
    }

    const result = {
      overview: this._graph.getArchitectureOverview(),
      criticalPaths: this._detectCriticalPaths(),
      hotspots: this._findHotspots(),
      knowledgeGaps: this._graph.findKnowledgeGaps(),
      recommendations: this._generateRecommendations()
    };

    return result;
  }

  /**
   * 检测关键路径
   */
  _detectCriticalPaths() {
    const entryPoints = this._graph.getEntryPoints();
    const criticalPaths = [];

    for (const entry of entryPoints) {
      const flow = this._graph.traceExecutionFlow(entry.qualifiedName, 5);
      
      if (flow.criticality >= 50) {
        criticalPaths.push({
          entryPoint: {
            name: entry.name,
            qualifiedName: entry.qualifiedName,
            filePath: entry.filePath,
            lineStart: entry.lineStart
          },
          criticality: flow.criticality,
          nodeCount: flow.nodeCount,
          edgeCount: flow.edgeCount,
          depth: flow.depth,
          path: flow.path.slice(0, 10).map(p => ({
            source: p.source,
            target: p.target,
            depth: p.depth
          }))
        });
      }
    }

    // 如果没有明确入口点，检测高连接度文件
    if (criticalPaths.length === 0) {
      const hubs = this._graph.findHubNodes(3);
      for (const hub of hubs.slice(0, 5)) {
        const flow = this._graph.traceExecutionFlow(hub.qualifiedName, 3);
        criticalPaths.push({
          entryPoint: {
            name: hub.name,
            qualifiedName: hub.qualifiedName,
            filePath: hub.filePath,
            lineStart: hub.lineStart
          },
          criticality: flow.criticality,
          nodeCount: flow.nodeCount,
          edgeCount: flow.edgeCount,
          depth: flow.depth,
          path: []
        });
      }
    }

    return criticalPaths.sort((a, b) => b.criticality - a.criticality);
  }

  /**
   * 查找热点
   */
  _findHotspots() {
    const hubs = this._graph.findHubNodes(3);
    const bridges = this._graph.findBridgeNodes();
    const communities = this._graph.detectCommunities();

    // 找出社区内的热点节点
    const hotspots = [];
    
    for (const community of communities) {
      // 找到社区内连接度最高的节点
      const communityNodes = community.nodes.filter(n => 
        n.kind === 'Function' || n.kind === 'Method'
      );
      
      for (const node of communityNodes) {
        const degree = this._calculateNodeDegree(node.qualifiedName);
        if (degree >= 3) {
          hotspots.push({
            name: node.name,
            qualifiedName: node.qualifiedName,
            filePath: node.filePath,
            lineStart: node.lineStart,
            kind: node.kind,
            degree,
            community: community.name,
            communityCohesion: community.cohesion,
            isBridge: bridges.some(b => b.qualifiedName === node.qualifiedName)
          });
        }
      }
    }

    return hotspots.sort((a, b) => b.degree - a.degree);
  }

  /**
   * 计算节点度数
   */
  _calculateNodeDegree(nodeQN) {
    let degree = 0;
    for (const edge of this._graph._edges) {
      if (edge.source === nodeQN || edge.target === nodeQN) {
        degree++;
      }
    }
    return degree;
  }

  /**
   * 生成建议
   */
  _generateRecommendations() {
    const overview = this._graph.getArchitectureOverview();
    const criticalPaths = this._detectCriticalPaths();
    const hotspots = this._findHotspots();
    const gaps = this._graph.findKnowledgeGaps();

    const recommendations = [];

    // 架构警告建议
    for (const warning of overview.warnings) {
      recommendations.push({
        type: warning.type,
        severity: warning.severity,
        message: warning.message,
        suggestion: this._getSuggestionForWarning(warning)
      });
    }

    // 关键路径保护建议
    if (criticalPaths.length > 0) {
      recommendations.push({
        type: 'critical_path_protection',
        severity: 'high',
        message: `发现 ${criticalPaths.length} 条关键执行路径`,
        suggestion: '建议对关键路径进行深度安全审计，确保所有入口点都有适当的输入验证和授权检查',
        details: criticalPaths.map(p => p.entryPoint.name)
      });
    }

    // 热点优化建议
    if (hotspots.length > 5) {
      recommendations.push({
        type: 'hotspot_optimization',
        severity: 'medium',
        message: `发现 ${hotspots.length} 个高连接度热点节点`,
        suggestion: '考虑对热点函数进行性能优化和冗余备份，确保高并发场景下的稳定性',
        count: hotspots.length
      });
    }

    // 未测试热点建议
    if (gaps.untestedHotspots.length > 0) {
      recommendations.push({
        type: 'testing_gap',
        severity: 'medium',
        message: `发现 ${gaps.untestedHotspots.length} 个未测试的热点节点`,
        suggestion: '建议为高连接度函数添加单元测试和集成测试，提高代码覆盖率',
        count: gaps.untestedHotspots.length
      });
    }

    // 孤立节点清理建议
    if (gaps.isolatedNodes.length > 0) {
      recommendations.push({
        type: 'dead_code',
        severity: 'low',
        message: `发现 ${gaps.isolatedNodes.length} 个孤立节点`,
        suggestion: '建议检查这些孤立节点是否为死代码，考虑清理或归档',
        count: gaps.isolatedNodes.length
      });
    }

    return recommendations.sort((a, b) => {
      const severityOrder = { high: 0, medium: 1, low: 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }

  /**
   * 根据警告类型生成建议
   */
  _getSuggestionForWarning(warning) {
    switch (warning.type) {
      case 'oversized_community':
        return `建议将 "${warning.community}" 模块拆分为更小的子模块，每个子模块职责单一`;
      case 'low_cohesion':
        return `社区 "${warning.community}" 凝聚力较低，建议检查模块内的职责划分，提高内聚性`;
      case 'untested_hotspots':
        return '建议为高连接度节点添加测试用例，确保核心功能的正确性';
      case 'isolated_nodes':
        return '检查孤立节点是否为死代码，考虑删除或重新整合';
      default:
        return '建议进行人工复核';
    }
  }

  /**
   * 获取风险评估
   */
  getRiskAssessment() {
    const overview = this._graph.getArchitectureOverview();
    const criticalPaths = this._detectCriticalPaths();
    const recommendations = this._generateRecommendations();

    let riskScore = 0;

    // 基于架构警告计算风险
    for (const warning of overview.warnings) {
      const severityWeight = { high: 15, medium: 10, low: 5 };
      riskScore += severityWeight[warning.severity] || 5;
    }

    // 基于关键路径数量
    riskScore += criticalPaths.length * 5;

    // 基于未测试热点数量
    riskScore += overview.untestedHotspotCount * 3;

    // 基于孤立节点数量
    riskScore += overview.isolatedNodeCount * 1;

    // 限制分数范围
    riskScore = Math.min(riskScore, 100);

    // 确定风险等级
    let riskLevel;
    if (riskScore >= 70) riskLevel = 'high';
    else if (riskScore >= 40) riskLevel = 'medium';
    else riskLevel = 'low';

    return {
      score: riskScore,
      level: riskLevel,
      contributingFactors: {
        architectureWarnings: overview.warnings.length,
        criticalPaths: criticalPaths.length,
        untestedHotspots: overview.untestedHotspotCount,
        isolatedNodes: overview.isolatedNodeCount
      },
      recommendations: recommendations.slice(0, 5)
    };
  }

  /**
   * 获取社区详情
   */
  getCommunityDetails() {
    return this._graph.detectCommunities().map(c => ({
      id: c.id,
      name: c.name,
      fileCount: c.files.length,
      nodeCount: c.nodes.length,
      edgeCount: c.edges.length,
      cohesion: Math.round(c.cohesion * 100),
      files: c.files,
      nodes: c.nodes.map(n => ({
        id: n.id,
        name: n.name,
        kind: n.kind,
        lineStart: n.lineStart
      }))
    }));
  }

  /**
   * 获取模块依赖图
   */
  getModuleDependencies() {
    const communities = this._graph.detectCommunities();
    const dependencies = [];

    for (let i = 0; i < communities.length; i++) {
      for (let j = 0; j < communities.length; j++) {
        if (i === j) continue;

        // 检查社区i是否依赖社区j
        const hasDependency = communities[i].edges.some(edge => {
          const targetFile = this._findFileForNode(edge.target);
          return targetFile && communities[j].files.includes(targetFile);
        });

        if (hasDependency) {
          dependencies.push({
            from: communities[i].name,
            to: communities[j].name,
            fromId: communities[i].id,
            toId: communities[j].id
          });
        }
      }
    }

    return dependencies;
  }

  /**
   * 查找节点所属文件
   */
  _findFileForNode(nodeQN) {
    const node = this._graph._nodeIndex.get(nodeQN);
    return node?.filePath || null;
  }

  /**
   * 获取统计信息
   */
  getStats() {
    return this._graph.getStats();
  }
}

// 导出常用函数
export async function analyzeArchitecture(projectRoot) {
  const analyzer = new ArchitectureAnalyzer();
  await analyzer.initialize(projectRoot);
  return analyzer.analyze();
}

export async function getArchitectureRisk(projectRoot) {
  const analyzer = new ArchitectureAnalyzer();
  await analyzer.initialize(projectRoot);
  return analyzer.getRiskAssessment();
}