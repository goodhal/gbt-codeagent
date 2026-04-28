class AgentRegistry {
  constructor() {
    this._lock = false;

    this._agentGraph = {
      nodes: {},
      edges: []
    };

    this._agentInstances = new Map();
    this._agentStates = new Map();
    this._agentMessages = new Map();

    this._rootAgentId = null;
    this._runningAgents = new Map();
  }

  _acquireLock() {
    this._lock = true;
  }

  _releaseLock() {
    this._lock = false;
  }

  _withLock(callback) {
    this._acquireLock();
    try {
      return callback();
    } finally {
      this._releaseLock();
    }
  }

  registerAgent({
    agentId,
    agentName,
    agentType,
    task,
    parentId = null,
    agentInstance = null,
    state = null,
    knowledgeModules = []
  }) {
    return this._withLock(() => {
      const now = new Date().toISOString();

      const node = {
        id: agentId,
        name: agentName,
        type: agentType,
        task: task,
        status: "running",
        parentId: parentId,
        createdAt: now,
        finishedAt: null,
        result: null,
        knowledgeModules: knowledgeModules || [],
        children: []
      };

      this._agentGraph.nodes[agentId] = node;

      if (agentInstance) {
        this._agentInstances.set(agentId, agentInstance);
      }

      if (state) {
        this._agentStates.set(agentId, state);
      }

      if (!this._agentMessages.has(agentId)) {
        this._agentMessages.set(agentId, []);
      }

      if (parentId) {
        this._agentGraph.edges.push({
          from: parentId,
          to: agentId,
          type: "delegation",
          createdAt: now
        });

        if (parentId in this._agentGraph.nodes) {
          if (!this._agentGraph.nodes[parentId].children) {
            this._agentGraph.nodes[parentId].children = [];
          }
          this._agentGraph.nodes[parentId].children.push(agentId);
        }
      }

      if (parentId === null && this._rootAgentId === null) {
        this._rootAgentId = agentId;
      }

      return node;
    });
  }

  unregisterAgent(agentId) {
    this._withLock(() => {
      if (agentId in this._agentGraph.nodes) {
        delete this._agentGraph.nodes[agentId];
      }

      this._agentInstances.delete(agentId);
      this._agentStates.delete(agentId);
      this._agentMessages.delete(agentId);
      this._runningAgents.delete(agentId);

      this._agentGraph.edges = this._agentGraph.edges.filter(
        e => e.from !== agentId && e.to !== agentId
      );
    });
  }

  updateAgentStatus(agentId, status, result = null) {
    this._withLock(() => {
      if (agentId in this._agentGraph.nodes) {
        const node = this._agentGraph.nodes[agentId];
        node.status = status;

        if (["completed", "failed", "stopped"].includes(status)) {
          node.finishedAt = new Date().toISOString();
        }

        if (result) {
          node.result = result;
        }
      }
    });
  }

  getAgentStatus(agentId) {
    return this._withLock(() => {
      if (agentId in this._agentGraph.nodes) {
        return this._agentGraph.nodes[agentId].status;
      }
      return null;
    });
  }

  getAgent(agentId) {
    return this._agentInstances.get(agentId);
  }

  getAgentState(agentId) {
    return this._agentStates.get(agentId);
  }

  getAgentNode(agentId) {
    return this._agentGraph.nodes[agentId] || null;
  }

  getRootAgentId() {
    return this._rootAgentId;
  }

  getChildren(agentId) {
    return this._withLock(() => {
      const node = this._agentGraph.nodes[agentId];
      return node ? (node.children || []) : [];
    });
  }

  getParent(agentId) {
    return this._withLock(() => {
      const node = this._agentGraph.nodes[agentId];
      return node ? node.parentId : null;
    });
  }

  getAgentTree() {
    return this._withLock(() => ({
      nodes: { ...this._agentGraph.nodes },
      edges: [...this._agentGraph.edges],
      rootAgentId: this._rootAgentId
    }));
  }

  getAgentTreeView(agentId = null) {
    return this._withLock(() => {
      const lines = ["=== AGENT TREE ==="];

      const rootId = agentId || this._rootAgentId;
      if (!rootId || !(rootId in this._agentGraph.nodes)) {
        return "No agents in the tree";
      }

      const statusEmoji = {
        running: "🔄",
        waiting: "⏳",
        completed: "✅",
        failed: "❌",
        stopped: "🛑",
        created: "🆕"
      };

      const buildTree = (aid, depth = 0) => {
        const node = this._agentGraph.nodes[aid];
        if (!node) return;

        const indent = "  ".repeat(depth);
        const emoji = statusEmoji[node.status] || "❓";

        lines.push(`${indent}${emoji} ${node.name} (${aid})`);
        lines.push(`${indent}   Task: ${(node.task || "").slice(0, 50)}${(node.task || "").length > 50 ? "..." : ""}`);
        lines.push(`${indent}   Status: ${node.status}`);

        if (node.knowledgeModules && node.knowledgeModules.length > 0) {
          lines.push(`${indent}   Modules: ${node.knowledgeModules.join(", ")}`);
        }

        if (node.children) {
          for (const childId of node.children) {
            buildTree(childId, depth + 1);
          }
        }
      };

      buildTree(rootId);
      return lines.join("\n");
    });
  }

  getStatistics() {
    return this._withLock(() => {
      const stats = {
        total: Object.keys(this._agentGraph.nodes).length,
        running: 0,
        waiting: 0,
        completed: 0,
        failed: 0,
        stopped: 0,
        created: 0
      };

      for (const node of Object.values(this._agentGraph.nodes)) {
        const status = node.status || "unknown";
        if (status in stats) {
          stats[status]++;
        }
      }

      return stats;
    });
  }

  sendMessage(agentId, message) {
    this._withLock(() => {
      if (!this._agentMessages.has(agentId)) {
        this._agentMessages.set(agentId, []);
      }
      this._agentMessages.get(agentId).push({
        ...message,
        timestamp: new Date().toISOString()
      });
    });
  }

  getMessages(agentId, limit = 100) {
    return this._withLock(() => {
      const messages = this._agentMessages.get(agentId) || [];
      return messages.slice(-limit);
    });
  }

  clearMessages(agentId) {
    this._withLock(() => {
      this._agentMessages.set(agentId, []);
    });
  }

  setRunningAgent(agentId, thread) {
    this._runningAgents.set(agentId, thread);
  }

  getRunningAgent(agentId) {
    return this._runningAgents.get(agentId) || null;
  }

  stopRunningAgent(agentId) {
    const thread = this._runningAgents.get(agentId);
    if (thread && typeof thread.cancel === "function") {
      thread.cancel();
    }
  }

  clear() {
    this._withLock(() => {
      this._agentGraph = { nodes: {}, edges: [] };
      this._agentInstances.clear();
      this._agentStates.clear();
      this._agentMessages.clear();
      this._runningAgents.clear();
      this._rootAgentId = null;
    });
  }
}

const agentRegistry = new AgentRegistry();

export { AgentRegistry, agentRegistry };