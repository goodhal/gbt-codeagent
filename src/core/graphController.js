import { agentRegistry } from "./agentRegistry.js";

const MessageType = {
  INFORMATION: "information",
  INSTRUCTION: "instruction",
  QUERY: "query",
  RESPONSE: "response",
  ERROR: "error",
  EVENT: "event"
};

const MessagePriority = {
  LOW: 0,
  NORMAL: 1,
  HIGH: 2,
  CRITICAL: 3
};

class MessageBus {
  constructor() {
    this._messages = [];
    this._maxMessages = 10000;
    this._subscribers = new Map();
    this._idCounter = 0;
  }

  _generateId() {
    return `msg_${Date.now().toString(36)}_${(++this._idCounter).toString(36)}`;
  }

  sendMessage({
    fromAgent,
    toAgent,
    content,
    messageType = MessageType.INFORMATION,
    priority = MessagePriority.NORMAL
  }) {
    const message = {
      id: this._generateId(),
      fromAgent,
      toAgent,
      content,
      messageType,
      priority,
      timestamp: new Date().toISOString(),
      read: false
    };

    this._messages.push(message);

    if (this._messages.length > this._maxMessages) {
      this._messages.shift();
    }

    this._notifySubscribers(message);

    return message;
  }

  getMessages(agentId = null, options = {}) {
    let messages = agentId
      ? this._messages.filter(m => m.toAgent === agentId || m.fromAgent === agentId)
      : [...this._messages];

    if (options.unreadOnly) {
      messages = messages.filter(m => !m.read);
    }

    if (options.since) {
      const since = new Date(options.since);
      messages = messages.filter(m => new Date(m.timestamp) >= since);
    }

    if (options.limit) {
      messages = messages.slice(-options.limit);
    }

    return messages;
  }

  markAsRead(messageId) {
    const message = this._messages.find(m => m.id === messageId);
    if (message) {
      message.read = true;
    }
  }

  markAllAsRead(agentId) {
    for (const message of this._messages) {
      if (message.toAgent === agentId) {
        message.read = true;
      }
    }
  }

  subscribe(agentId, callback) {
    if (!this._subscribers.has(agentId)) {
      this._subscribers.set(agentId, new Set());
    }
    this._subscribers.get(agentId).add(callback);

    return () => {
      const subs = this._subscribers.get(agentId);
      if (subs) {
        subs.delete(callback);
      }
    };
  }

  _notifySubscribers(message) {
    const agentSubs = this._subscribers.get(message.toAgent);
    if (agentSubs) {
      for (const callback of agentSubs) {
        try {
          callback(message);
        } catch (e) {
          console.error("Message subscriber error:", e);
        }
      }
    }

    const allSubs = this._subscribers.get("*");
    if (allSubs) {
      for (const callback of allSubs) {
        try {
          callback(message);
        } catch (e) {
          console.error("Wildcard subscriber error:", e);
        }
      }
    }
  }

  clear(agentId = null) {
    if (agentId) {
      this._messages = this._messages.filter(
        m => m.toAgent !== agentId && m.fromAgent !== agentId
      );
    } else {
      this._messages = [];
    }
  }

  getStats() {
    return {
      totalMessages: this._messages.length,
      unreadCount: this._messages.filter(m => !m.read).length,
      subscriberCount: this._subscribers.size
    };
  }
}

const messageBus = new MessageBus();

class AgentGraphController {
  constructor() {
    this._lock = false;
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

  stopAgent(agentId) {
    return this._withLock(() => {
      const node = agentRegistry.getAgentNode(agentId);
      if (!node) {
        return {
          success: false,
          error: `Agent '${agentId}' not found`
        };
      }

      const status = node.status || "";
      if (["completed", "failed", "stopped"].includes(status)) {
        return {
          success: true,
          message: `Agent '${node.name}' is already ${status}`,
          previousStatus: status
        };
      }

      const agentState = agentRegistry.getAgentState(agentId);
      if (agentState && typeof agentState.requestStop === "function") {
        agentState.requestStop();
      }

      const agentInstance = agentRegistry.getAgent(agentId);
      if (agentInstance) {
        if (typeof agentInstance.cancel === "function") {
          agentInstance.cancel();
        }
        if (agentInstance._cancelled !== undefined) {
          agentInstance._cancelled = true;
        }
      }

      agentRegistry.updateAgentStatus(agentId, "stopping");

      return {
        success: true,
        message: `Stop request sent to Agent '${node.name}'`,
        agentId: agentId,
        agentName: node.name,
        note: "Agent will stop after current iteration"
      };
    });
  }

  stopAllAgents(excludeRoot = true) {
    return this._withLock(() => {
      const tree = agentRegistry.getAgentTree();
      const rootId = tree.rootAgentId;

      const stopped = [];
      const failed = [];

      for (const [agentId, node] of Object.entries(tree.nodes)) {
        if (excludeRoot && agentId === rootId) {
          continue;
        }

        if (["completed", "failed", "stopped"].includes(node.status)) {
          continue;
        }

        const result = this.stopAgent(agentId);
        if (result.success) {
          stopped.push(agentId);
        } else {
          failed.push({ id: agentId, error: result.error });
        }
      }

      return {
        success: failed.length === 0,
        stoppedCount: stopped.length,
        failedCount: failed.length,
        stopped,
        failed
      };
    });
  }

  sendMessageToAgent({
    fromAgent,
    targetAgentId,
    message,
    messageType = MessageType.INFORMATION,
    priority = MessagePriority.NORMAL
  }) {
    const node = agentRegistry.getAgentNode(targetAgentId);
    if (!node) {
      return {
        success: false,
        error: `Target agent '${targetAgentId}' not found`
      };
    }

    const sentMessage = messageBus.sendMessage({
      fromAgent,
      toAgent: targetAgentId,
      content: message,
      messageType,
      priority
    });

    return {
      success: true,
      messageId: sentMessage.id,
      message: `Message sent to '${node.name}'`,
      targetAgent: {
        id: targetAgentId,
        name: node.name,
        status: node.status
      }
    };
  }

  sendUserMessage(targetAgentId, message) {
    return this.sendMessageToAgent({
      fromAgent: "user",
      targetAgentId,
      message,
      messageType: MessageType.INSTRUCTION,
      priority: MessagePriority.HIGH
    });
  }

  getAgentGraph(currentAgentId = null) {
    const tree = agentRegistry.getAgentTree();
    const stats = agentRegistry.getStatistics();
    const treeView = this._buildTreeView(tree, currentAgentId);

    return {
      graphStructure: treeView,
      summary: stats,
      nodes: tree.nodes,
      edges: tree.edges,
      rootAgentId: tree.rootAgentId
    };
  }

  _buildTreeView(tree, currentAgentId = null) {
    const lines = ["=== AGENT GRAPH STRUCTURE ==="];

    const rootId = tree.rootAgentId;
    if (!rootId || !(rootId in tree.nodes)) {
      return "No agents in the graph";
    }

    const statusEmoji = {
      running: "🔄",
      waiting: "⏳",
      completed: "✅",
      failed: "❌",
      stopped: "🛑",
      stopping: "⏸️",
      created: "🆕"
    };

    const buildNode = (agentId, depth = 0) => {
      const node = tree.nodes[agentId];
      if (!node) return;

      const indent = "  ".repeat(depth);
      const emoji = statusEmoji[node.status] || "❓";
      const currentMarker = agentId === currentAgentId ? " 👉" : "";

      lines.push(`${indent}${emoji} ${node.name}${currentMarker}`);
      lines.push(`${indent}   Type: ${node.type}, Status: ${node.status}`);
      lines.push(`${indent}   Task: ${(node.task || "").slice(0, 40)}${(node.task || "").length > 40 ? "..." : ""}`);

      if (node.children && node.children.length > 0) {
        lines.push(`${indent}   Children: ${node.children.length}`);
        for (const childId of node.children) {
          buildNode(childId, depth + 1);
        }
      }
    };

    buildNode(rootId);
    return lines.join("\n");
  }

  createSubAgent({
    parentAgentId,
    agentName,
    agentType,
    task,
    knowledgeModules = [],
    agentInstance = null,
    state = null
  }) {
    const parentNode = agentRegistry.getAgentNode(parentAgentId);
    if (!parentNode) {
      return {
        success: false,
        error: `Parent agent '${parentAgentId}' not found`
      };
    }

    const agentId = `agent_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;

    const node = agentRegistry.registerAgent({
      agentId,
      agentName,
      agentType,
      task,
      parentId: parentAgentId,
      agentInstance,
      state,
      knowledgeModules
    });

    return {
      success: true,
      agentId,
      agentName,
      parentId: parentAgentId,
      message: `Sub-agent '${agentName}' created under '${parentNode.name}'`
    };
  }

  getAgentInfo(agentId) {
    const node = agentRegistry.getAgentNode(agentId);
    if (!node) {
      return null;
    }

    const state = agentRegistry.getAgentState(agentId);
    const messages = messageBus.getMessages(agentId, { limit: 10 });

    return {
      ...node,
      recentMessages: messages,
      state: state ? state.toJSON ? state.toJSON() : state : null
    };
  }

  waitForAgent(agentId, timeoutMs = 60000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      const checkInterval = 100;

      const interval = setInterval(() => {
        const status = agentRegistry.getAgentStatus(agentId);

        if (["completed", "failed", "stopped", "stopping"].includes(status)) {
          clearInterval(interval);
          resolve({
            agentId,
            status,
            finished: true
          });
          return;
        }

        if (Date.now() - startTime > timeoutMs) {
          clearInterval(interval);
          reject(new Error(`Timeout waiting for agent ${agentId}`));
        }
      }, checkInterval);
    });
  }
}

const globalMessageBus = messageBus;
const globalGraphController = new AgentGraphController();

export {
  MessageType,
  MessagePriority,
  MessageBus,
  messageBus,
  AgentGraphController,
  globalGraphController
};