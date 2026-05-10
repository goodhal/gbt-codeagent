/**
 * 代码知识图谱服务
 * 整合 code-review-graph 的核心功能：
 * - 多语言代码解析（基于现有 AST 工具）
 * - 节点和边的图结构存储
 * - 影响半径查询（BFS）
 * - 社区检测
 * - 执行流追踪
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { ASTBuilderService } from "../utils/astBuilder.js";
import { QueryEngine } from "../utils/queryEngine.js";
import { collectFiles } from "../utils/fileUtils.js";

/**
 * 节点类型
 */
const NODE_KIND = {
  FILE: 'File',
  CLASS: 'Class',
  FUNCTION: 'Function',
  METHOD: 'Method',
  TYPE: 'Type',
  TEST: 'Test',
  ENTRY_POINT: 'EntryPoint'
};

/**
 * 边类型
 */
const EDGE_KIND = {
  CALLS: 'CALLS',
  IMPORTS_FROM: 'IMPORTS_FROM',
  INHERITS: 'INHERITS',
  TESTS: 'TESTS',
  CONTAINS: 'CONTAINS'
};

export class CodeGraph {
  constructor() {
    this._nodes = [];        // { id, kind, name, qualifiedName, filePath, lineStart, lineEnd, language, metadata }
    this._edges = [];        // { id, source, target, kind, filePath, line }
    this._nodeIndex = new Map();  // qualifiedName -> node
    this._fileIndex = new Map();  // filePath -> [nodeIds]
    this._projectRoot = null;
    this._astIndex = null;
  }

  /**
   * 从项目文件构建图谱
   */
  async build(projectRoot) {
    this._projectRoot = projectRoot;
    this._nodes = [];
    this._edges = [];
    this._nodeIndex.clear();
    this._fileIndex.clear();

    // 使用现有 AST 工具构建索引
    const astBuilder = new ASTBuilderService({ cacheEnabled: true });
    const projectId = `graph_${Date.now()}`;
    this._astIndex = await astBuilder.initialize(projectId, projectRoot, {
      includeNodeModules: false,
      includeTests: false
    });

    if (!this._astIndex) {
      console.warn('[CodeGraph] AST索引构建失败，使用简化解析');
      await this._buildFromFiles(projectRoot);
      return;
    }

    await this._buildFromAST();
  }

  /**
   * 从 AST 构建图谱
   */
  async _buildFromAST() {
    const queryEngine = new QueryEngine(this._astIndex);
    
    // 提取文件节点
    for (const fileNode of this._astIndex.files || []) {
      this._addNode({
        kind: NODE_KIND.FILE,
        name: path.basename(fileNode.path),
        qualifiedName: fileNode.path,
        filePath: fileNode.path,
        lineStart: 1,
        lineEnd: fileNode.lineCount || 100,
        language: fileNode.language || 'unknown'
      });
    }

    // 提取类节点
    for (const classInfo of this._astIndex.nodes || []) {
      if (classInfo.type === 'class' || classInfo.type === 'interface') {
        this._addNode({
          kind: NODE_KIND.CLASS,
          name: classInfo.name,
          qualifiedName: classInfo.qualifiedName || classInfo.name,
          filePath: classInfo.filePath,
          lineStart: classInfo.lineStart,
          lineEnd: classInfo.lineEnd,
          language: classInfo.language,
          metadata: {
            modifiers: classInfo.modifiers,
            extends: classInfo.extends,
            implements: classInfo.implements
          }
        });

        // 添加继承边
        if (classInfo.extends) {
          this._addEdge({
            source: classInfo.qualifiedName || classInfo.name,
            target: classInfo.extends,
            kind: EDGE_KIND.INHERITS,
            filePath: classInfo.filePath,
            line: classInfo.lineStart
          });
        }

        // 添加包含边（文件包含类）
        this._addEdge({
          source: classInfo.filePath,
          target: classInfo.qualifiedName || classInfo.name,
          kind: EDGE_KIND.CONTAINS,
          filePath: classInfo.filePath,
          line: classInfo.lineStart
        });
      }
    }

    // 提取方法节点和调用边
    for (const methodInfo of this._astIndex.methods || []) {
      const methodQN = methodInfo.qualifiedName || `${methodInfo.className}.${methodInfo.name}`;
      
      this._addNode({
        kind: NODE_KIND.METHOD,
        name: methodInfo.name,
        qualifiedName: methodQN,
        filePath: methodInfo.filePath,
        lineStart: methodInfo.lineStart,
        lineEnd: methodInfo.lineEnd,
        language: methodInfo.language,
        metadata: {
          className: methodInfo.className,
          returnType: methodInfo.returnType,
          parameters: methodInfo.parameters
        }
      });

      // 添加包含边（类包含方法）
      if (methodInfo.className) {
        const classQN = this._astIndex.nodes?.find(n => n.name === methodInfo.className)?.qualifiedName || methodInfo.className;
        this._addEdge({
          source: classQN,
          target: methodQN,
          kind: EDGE_KIND.CONTAINS,
          filePath: methodInfo.filePath,
          line: methodInfo.lineStart
        });
      }

      // 添加调用边
      for (const call of methodInfo.calls || []) {
        this._addEdge({
          source: methodQN,
          target: call,
          kind: EDGE_KIND.CALLS,
          filePath: methodInfo.filePath,
          line: call.line || methodInfo.lineStart
        });
      }
    }

    // 检测入口点
    await this._detectEntryPoints(queryEngine);
  }

  /**
   * 简化方式从文件构建图谱
   */
  async _buildFromFiles(projectRoot) {
    const files = await collectFiles(projectRoot);
    
    for (const file of files) {
      const relativePath = path.relative(projectRoot, file).replaceAll('\\', '/');
      const ext = path.extname(file).toLowerCase();
      const language = this._inferLanguage(ext);
      
      this._addNode({
        kind: NODE_KIND.FILE,
        name: path.basename(file),
        qualifiedName: relativePath,
        filePath: relativePath,
        lineStart: 1,
        lineEnd: 100,
        language
      });

      // 简单解析文件内容提取函数和导入
      try {
        const content = await fs.readFile(file, 'utf8');
        await this._parseFileContent(file, relativePath, content, language);
      } catch {
        continue;
      }
    }

    // 检测入口点
    await this._detectEntryPointsSimple(files);
  }

  /**
   * 解析文件内容提取函数和导入
   */
  async _parseFileContent(file, relativePath, content, language) {
    const lines = content.split('\n');
    
    // 提取导入语句
    const importPatterns = {
      javascript: /^(import|require)\s*[\s\S]*?['"]([^'"]+)['"]/,
      python: /^from\s+(\S+)\s+import|^import\s+(\S+)/,
      java: /^import\s+([\w.]+)/,
      go: /^import\s+["']([^'"]+)["']/,
      rust: /^use\s+([\w:]+)/
    };

    const pattern = importPatterns[language];
    if (pattern) {
      for (let i = 0; i < Math.min(50, lines.length); i++) {
        const match = lines[i].match(pattern);
        if (match) {
          const imported = match[1] || match[2];
          this._addEdge({
            source: relativePath,
            target: imported,
            kind: EDGE_KIND.IMPORTS_FROM,
            filePath: relativePath,
            line: i + 1
          });
        }
      }
    }

    // 提取函数定义
    const functionPatterns = {
      javascript: /^(async\s+)?function\s+(\w+)\s*\(|^(\w+)\s*=\s*(async\s+)?function\s*\(|^(\w+)\s*=\s*=>\s*\{/,
      python: /^def\s+(\w+)\s*\(/,
      java: /^(public|private|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\(/,
      go: /^func\s+(\w+)\s*\(/,
      rust: /^fn\s+(\w+)\s*\(/
    };

    const funcPattern = functionPatterns[language];
    if (funcPattern) {
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(funcPattern);
        if (match) {
          const funcName = match[2] || match[1] || match[3] || match[5];
          if (funcName) {
            const qn = `${relativePath}::${funcName}`;
            this._addNode({
              kind: NODE_KIND.FUNCTION,
              name: funcName,
              qualifiedName: qn,
              filePath: relativePath,
              lineStart: i + 1,
              lineEnd: i + 1,
              language
            });

            this._addEdge({
              source: relativePath,
              target: qn,
              kind: EDGE_KIND.CONTAINS,
              filePath: relativePath,
              line: i + 1
            });
          }
        }
      }
    }
  }

  /**
   * 检测入口点（简化版本）
   */
  async _detectEntryPointsSimple(files) {
    const entryPatterns = [
      /app\.get\s*\(/, /app\.post\s*\(/, /router\./,
      /main\s*\(/, /handler\s*\(/, /controller/,
      /@RequestMapping/, /@Controller/, /@RestController/
    ];

    for (const file of files) {
      const relativePath = path.relative(this._projectRoot, file).replaceAll('\\', '/');
      try {
        const content = await fs.readFile(file, 'utf8');
        for (const pattern of entryPatterns) {
          if (pattern.test(content)) {
            this._addNode({
              kind: NODE_KIND.ENTRY_POINT,
              name: `Entry:${path.basename(file)}`,
              qualifiedName: `entry://${relativePath}`,
              filePath: relativePath,
              lineStart: 1,
              lineEnd: 100,
              language: this._inferLanguage(path.extname(file))
            });
            break;
          }
        }
      } catch {
        continue;
      }
    }
  }

  /**
   * 使用 QueryEngine 检测入口点
   */
  async _detectEntryPoints(queryEngine) {
    // 查找入口点方法
    const entryPatterns = ['main', 'handler', 'controller', 'router', 'app'];
    
    for (const pattern of entryPatterns) {
      const methods = queryEngine.searchMethods(pattern);
      for (const method of methods) {
        const qn = method.qualifiedName || `${method.className}.${method.name}`;
        const node = this._nodeIndex.get(qn);
        if (node) {
          node.kind = NODE_KIND.ENTRY_POINT;
        }
      }
    }
  }

  /**
   * 添加节点
   */
  _addNode(node) {
    if (this._nodeIndex.has(node.qualifiedName)) {
      return;
    }
    
    const id = this._nodes.length + 1;
    const newNode = { id, ...node };
    this._nodes.push(newNode);
    this._nodeIndex.set(node.qualifiedName, newNode);
    
    if (!this._fileIndex.has(node.filePath)) {
      this._fileIndex.set(node.filePath, []);
    }
    this._fileIndex.get(node.filePath).push(id);
  }

  /**
   * 添加边
   */
  _addEdge(edge) {
    // 跳过自环和无效边
    if (edge.source === edge.target) return;
    if (!this._nodeIndex.has(edge.source) && !edge.source.startsWith('entry://')) return;
    
    const id = this._edges.length + 1;
    this._edges.push({ id, ...edge });
  }

  /**
   * 计算影响半径（BFS）
   */
  getImpactRadius(startNodeQN, maxDepth = 3) {
    const startNode = this._nodeIndex.get(startNodeQN);
    if (!startNode) {
      return { nodes: [], edges: [], depth: 0 };
    }

    const visited = new Set([startNodeQN]);
    const resultNodes = [startNode];
    const resultEdges = [];
    const queue = [{ qn: startNodeQN, depth: 0 }];

    while (queue.length > 0) {
      const { qn, depth } = queue.shift();
      
      if (depth >= maxDepth) continue;

      // 找到所有从该节点出发的边
      const outgoingEdges = this._edges.filter(e => e.source === qn);
      
      for (const edge of outgoingEdges) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          resultEdges.push(edge);
          
          const targetNode = this._nodeIndex.get(edge.target);
          if (targetNode) {
            resultNodes.push(targetNode);
            queue.push({ qn: edge.target, depth: depth + 1 });
          }
        }
      }
    }

    return {
      nodes: resultNodes,
      edges: resultEdges,
      depth: maxDepth,
      count: resultNodes.length
    };
  }

  /**
   * 计算文件影响范围
   */
  getFileImpactRadius(filePath, maxDepth = 3) {
    const fileQN = this._fileIndex.has(filePath) ? filePath : 
                   this._nodes.find(n => n.filePath === filePath)?.qualifiedName;
    
    if (!fileQN) {
      return { nodes: [], edges: [], depth: 0 };
    }

    return this.getImpactRadius(fileQN, maxDepth);
  }

  /**
   * 查找枢纽节点（高连接度节点）
   */
  findHubNodes(minDegree = 5) {
    const degreeMap = new Map();
    
    for (const edge of this._edges) {
      degreeMap.set(edge.source, (degreeMap.get(edge.source) || 0) + 1);
      degreeMap.set(edge.target, (degreeMap.get(edge.target) || 0) + 1);
    }

    const hubs = [];
    for (const [qn, degree] of degreeMap) {
      if (degree >= minDegree) {
        const node = this._nodeIndex.get(qn);
        if (node) {
          hubs.push({ ...node, degree });
        }
      }
    }

    return hubs.sort((a, b) => b.degree - a.degree);
  }

  /**
   * 查找桥节点（高介数中心性）
   */
  findBridgeNodes() {
    // 简化的桥节点检测：连接不同文件的节点
    const bridges = [];
    const fileNodes = this._nodes.filter(n => n.kind === NODE_KIND.FILE);
    
    for (const edge of this._edges) {
      if (edge.kind === EDGE_KIND.CALLS) {
        const sourceNode = this._nodeIndex.get(edge.source);
        const targetNode = this._nodeIndex.get(edge.target);
        
        if (sourceNode && targetNode && sourceNode.filePath !== targetNode.filePath) {
          if (!bridges.find(b => b.qualifiedName === edge.source)) {
            bridges.push({ ...sourceNode, isBridge: true });
          }
        }
      }
    }

    return bridges;
  }

  /**
   * 查找知识缺口（孤立节点、未测试的热点）
   */
  findKnowledgeGaps() {
    const gaps = {
      isolatedNodes: [],
      untestedHotspots: [],
      orphanFiles: []
    };

    // 查找孤立节点（无入边也无出边）
    const hasInEdge = new Set(this._edges.map(e => e.target));
    const hasOutEdge = new Set(this._edges.map(e => e.source));
    
    for (const node of this._nodes) {
      const hasIn = hasInEdge.has(node.qualifiedName);
      const hasOut = hasOutEdge.has(node.qualifiedName);
      
      if (!hasIn && !hasOut) {
        gaps.isolatedNodes.push(node);
      }
    }

    // 查找未测试的热点（高连接但无测试）
    const testFiles = new Set(this._nodes
      .filter(n => n.kind === NODE_KIND.FILE && /test|spec/i.test(n.name))
      .map(n => n.filePath));
    
    const hubs = this.findHubNodes(3);
    for (const hub of hubs) {
      if (!testFiles.has(hub.filePath)) {
        gaps.untestedHotspots.push(hub);
      }
    }

    // 查找孤立文件
    for (const fileNode of this._nodes.filter(n => n.kind === NODE_KIND.FILE)) {
      const fileEdges = this._edges.filter(e => e.filePath === fileNode.filePath);
      if (fileEdges.length === 0) {
        gaps.orphanFiles.push(fileNode);
      }
    }

    return gaps;
  }

  /**
   * 社区检测（基于文件分组）
   */
  detectCommunities() {
    const communities = [];
    const visited = new Set();
    
    for (const fileNode of this._nodes.filter(n => n.kind === NODE_KIND.FILE)) {
      if (visited.has(fileNode.filePath)) continue;
      
      const community = {
        id: `community_${communities.length + 1}`,
        name: this._inferCommunityName(fileNode),
        files: [],
        nodes: [],
        edges: [],
        cohesion: 0
      };

      // BFS 查找相关文件
      const queue = [fileNode.filePath];
      visited.add(fileNode.filePath);

      while (queue.length > 0) {
        const currentFile = queue.shift();
        
        // 添加文件节点
        const fileNodeInCommunity = this._nodes.find(n => n.filePath === currentFile);
        if (fileNodeInCommunity) {
          community.files.push(currentFile);
        }

        // 添加该文件中的所有节点
        const fileNodes = this._nodes.filter(n => n.filePath === currentFile);
        community.nodes.push(...fileNodes);

        // 添加相关边
        const fileEdges = this._edges.filter(e => 
          e.filePath === currentFile || 
          (e.source === currentFile) || 
          (e.target === currentFile)
        );
        community.edges.push(...fileEdges);

        // 查找引用该文件或被该文件引用的其他文件
        for (const edge of fileEdges) {
          if (edge.kind === EDGE_KIND.IMPORTS_FROM || edge.kind === EDGE_KIND.CALLS) {
            const targetFile = this._findNodeFile(edge.target);
            if (targetFile && !visited.has(targetFile)) {
              visited.add(targetFile);
              queue.push(targetFile);
            }
          }
        }
      }

      // 计算凝聚力
      if (community.edges.length > 0) {
        const internalEdges = community.edges.filter(e => 
          community.files.includes(e.filePath)
        );
        community.cohesion = internalEdges.length / community.edges.length;
      }

      communities.push(community);
    }

    return communities.sort((a, b) => b.nodes.length - a.nodes.length);
  }

  /**
   * 推断社区名称
   */
  _inferCommunityName(fileNode) {
    const name = fileNode.name;
    if (/controller/i.test(name)) return 'Controller层';
    if (/service/i.test(name)) return 'Service层';
    if (/repository/i.test(name)) return '数据访问层';
    if (/model/i.test(name)) return '模型层';
    if (/utils/i.test(name)) return '工具模块';
    if (/config/i.test(name)) return '配置模块';
    return `模块 ${name.split('.')[0]}`;
  }

  /**
   * 查找节点所属文件
   */
  _findNodeFile(nodeQN) {
    const node = this._nodeIndex.get(nodeQN);
    return node?.filePath || null;
  }

  /**
   * 获取架构概览
   */
  getArchitectureOverview() {
    const communities = this.detectCommunities();
    const hubs = this.findHubNodes(5);
    const bridges = this.findBridgeNodes();
    const gaps = this.findKnowledgeGaps();

    return {
      totalNodes: this._nodes.length,
      totalEdges: this._edges.length,
      totalFiles: this._nodes.filter(n => n.kind === NODE_KIND.FILE).length,
      communities: communities.length,
      communitiesDetail: communities.slice(0, 10).map(c => ({
        id: c.id,
        name: c.name,
        fileCount: c.files.length,
        nodeCount: c.nodes.length,
        cohesion: Math.round(c.cohesion * 100)
      })),
      hubCount: hubs.length,
      bridgeCount: bridges.length,
      isolatedNodeCount: gaps.isolatedNodes.length,
      untestedHotspotCount: gaps.untestedHotspots.length,
      orphanFileCount: gaps.orphanFiles.length,
      warnings: this._generateArchitectureWarnings(communities, gaps)
    };
  }

  /**
   * 生成架构警告
   */
  _generateArchitectureWarnings(communities, gaps) {
    const warnings = [];

    // 检测超大社区
    for (const community of communities) {
      if (community.nodes.length > 50) {
        warnings.push({
          type: 'oversized_community',
          severity: 'high',
          message: `社区 "${community.name}" 过大（${community.nodes.length} 个节点），建议拆分`,
          community: community.name
        });
      }
    }

    // 检测低凝聚力社区
    for (const community of communities) {
      if (community.nodes.length > 10 && community.cohesion < 0.5) {
        warnings.push({
          type: 'low_cohesion',
          severity: 'medium',
          message: `社区 "${community.name}" 凝聚力较低（${Math.round(community.cohesion * 100)}%）`,
          community: community.name
        });
      }
    }

    // 检测未测试热点
    if (gaps.untestedHotspots.length > 0) {
      warnings.push({
        type: 'untested_hotspots',
        severity: 'medium',
        message: `发现 ${gaps.untestedHotspots.length} 个高连接但未测试的热点节点`,
        count: gaps.untestedHotspots.length
      });
    }

    // 检测孤立节点
    if (gaps.isolatedNodes.length > 0) {
      warnings.push({
        type: 'isolated_nodes',
        severity: 'low',
        message: `发现 ${gaps.isolatedNodes.length} 个孤立节点，可能是死代码`,
        count: gaps.isolatedNodes.length
      });
    }

    return warnings;
  }

  /**
   * 追踪执行流
   */
  traceExecutionFlow(entryPointQN, maxDepth = 5) {
    const entryNode = this._nodeIndex.get(entryPointQN);
    if (!entryNode) {
      // 尝试查找入口点节点
      const entryNodes = this._nodes.filter(n => n.kind === NODE_KIND.ENTRY_POINT);
      if (entryNodes.length === 0) {
        return { path: [], depth: 0, criticality: 0 };
      }
      entryPointQN = entryNodes[0].qualifiedName;
    }

    const path = [];
    const visited = new Set([entryPointQN]);
    const queue = [{ qn: entryPointQN, depth: 0, path: [entryPointQN] }];

    while (queue.length > 0) {
      const { qn, depth, path: currentPath } = queue.shift();
      
      if (depth >= maxDepth) continue;

      const outgoingEdges = this._edges.filter(e => e.source === qn && e.kind === EDGE_KIND.CALLS);
      
      for (const edge of outgoingEdges) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          const newPath = [...currentPath, edge.target];
          path.push({
            source: qn,
            target: edge.target,
            edge: edge,
            depth: depth + 1,
            fullPath: newPath
          });
          
          queue.push({ qn: edge.target, depth: depth + 1, path: newPath });
        }
      }
    }

    // 计算关键程度
    const criticality = this._calculateCriticality(path);

    return {
      path,
      depth: maxDepth,
      criticality,
      nodeCount: visited.size,
      edgeCount: path.length
    };
  }

  /**
   * 计算关键程度评分
   */
  _calculateCriticality(path) {
    if (path.length === 0) return 0;

    // 文件扩散度
    const files = new Set();
    for (const step of path) {
      const sourceNode = this._nodeIndex.get(step.source);
      const targetNode = this._nodeIndex.get(step.target);
      if (sourceNode) files.add(sourceNode.filePath);
      if (targetNode) files.add(targetNode.filePath);
    }
    const fileSpreadScore = Math.min(files.size / 10, 1);

    // 安全敏感性（检测危险函数调用）
    const dangerousPatterns = ['exec', 'eval', 'system', 'query', 'execute', 'write'];
    let securityScore = 0;
    for (const step of path) {
      if (dangerousPatterns.some(p => step.target.toLowerCase().includes(p))) {
        securityScore += 0.2;
      }
    }
    securityScore = Math.min(securityScore, 1);

    // 深度评分
    const maxDepth = Math.max(...path.map(p => p.depth));
    const depthScore = Math.min(maxDepth / 5, 1);

    // 综合评分
    return Math.round((fileSpreadScore * 0.3 + securityScore * 0.4 + depthScore * 0.3) * 100);
  }

  /**
   * 获取入口点列表
   */
  getEntryPoints() {
    return this._nodes.filter(n => n.kind === NODE_KIND.ENTRY_POINT);
  }

  /**
   * 推断语言
   */
  _inferLanguage(ext) {
    const langMap = {
      '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
      '.java': 'java', '.py': 'python', '.php': 'php', '.c': 'c', '.cpp': 'cpp',
      '.cs': 'csharp', '.go': 'go', '.rb': 'ruby', '.swift': 'swift',
      '.kt': 'kotlin', '.scala': 'scala', '.rs': 'rust', '.go': 'go'
    };
    return langMap[ext] || 'unknown';
  }

  /**
   * 获取统计信息
   */
  getStats() {
    const byKind = {};
    for (const node of this._nodes) {
      byKind[node.kind] = (byKind[node.kind] || 0) + 1;
    }

    const byLanguage = {};
    for (const node of this._nodes) {
      byLanguage[node.language] = (byLanguage[node.language] || 0) + 1;
    }

    const byEdgeKind = {};
    for (const edge of this._edges) {
      byEdgeKind[edge.kind] = (byEdgeKind[edge.kind] || 0) + 1;
    }

    return {
      totalNodes: this._nodes.length,
      totalEdges: this._edges.length,
      byKind,
      byLanguage,
      byEdgeKind
    };
  }
}

// 导出常量
export { NODE_KIND, EDGE_KIND };