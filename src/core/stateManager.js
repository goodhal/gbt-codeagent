import { promises as fs } from "node:fs";
import path from "path";

const AgentStatus = {
  CREATED: "created",
  RUNNING: "running",
  WAITING: "waiting",
  PAUSED: "paused",
  COMPLETED: "completed",
  FAILED: "failed",
  STOPPED: "stopped",
  STOPPING: "stopping",
  TIMEOUT: "timeout"
};

class AuditState {
  constructor() {
    this.agentId = this._generateAgentId();
    this.agentName = "GB/T Code Agent";
    this.agentType = "code-audit";
    this.parentId = null;

    this.task = "";
    this.taskContext = {};
    this.inheritedContext = {};

    this.knowledgeModules = [];

    this.status = AgentStatus.CREATED;
    this.iteration = 0;
    this.maxIterations = 50;

    this.messages = [];
    this.systemPrompt = "";

    this.actionsTaken = [];
    this.observations = [];
    this.errors = [];

    this.findings = [];

    this.createdAt = new Date().toISOString();
    this.startedAt = null;
    this.lastUpdated = new Date().toISOString();
    this.finishedAt = null;

    this.waitingForInput = false;
    this.waitingStartTime = null;
    this.waitingReason = "";
    this.waitingTimeoutSeconds = 600;

    this.finalResult = null;

    this.totalTokens = 0;
    this.toolCalls = 0;

    this.stopRequested = false;
    this.maxIterationsWarningSent = false;

    this.heartbeatInterval = 30000;
    this.lastHeartbeat = null;
    this.heartbeatCount = 0;
    this.healthStatus = "healthy";

    this.progress = {
      currentStep: 0,
      totalSteps: 0,
      stepName: "",
      estimatedTimeRemaining: null
    };

    this.performance = {
      iterationTimes: [],
      avgIterationTime: 0,
      maxIterationTime: 0,
      totalProcessingTime: 0
    };

    this.resourceUsage = {
      memoryUsage: [],
      cpuUsage: [],
      peakMemory: 0
    };
  }

  _generateAgentId() {
    return `agent_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  }

  start() {
    this.status = AgentStatus.RUNNING;
    this.startedAt = new Date().toISOString();
    this._updateTimestamp();
    this.recordHeartbeat();
  }

  incrementIteration(startTime = null) {
    this.iteration++;
    
    if (startTime) {
      const iterationTime = Date.now() - startTime;
      this.performance.iterationTimes.push(iterationTime);
      this.performance.maxIterationTime = Math.max(this.performance.maxIterationTime, iterationTime);
      this.performance.totalProcessingTime += iterationTime;
      this.performance.avgIterationTime = 
        this.performance.totalProcessingTime / this.performance.iterationTimes.length;
    }
    
    this._updateTimestamp();

    if (this.iteration >= this.maxIterations && !this.maxIterationsWarningSent) {
      this.maxIterationsWarningSent = true;
    }
  }

  recordHeartbeat() {
    this.lastHeartbeat = new Date().toISOString();
    this.heartbeatCount++;
    this._updateTimestamp();
  }

  setHealthStatus(status, message = "") {
    this.healthStatus = status;
    if (message) {
      this.addObservation(`Health status changed to ${status}: ${message}`, "health");
    }
    this._updateTimestamp();
  }

  updateProgress(currentStep, totalSteps, stepName = "") {
    this.progress = {
      currentStep,
      totalSteps,
      stepName,
      estimatedTimeRemaining: this._calculateEstimatedTime(currentStep, totalSteps)
    };
    this._updateTimestamp();
  }

  _calculateEstimatedTime(currentStep, totalSteps) {
    if (currentStep === 0 || this.performance.avgIterationTime === 0) {
      return null;
    }
    const remainingSteps = totalSteps - currentStep;
    return Math.round(remainingSteps * this.performance.avgIterationTime / 1000);
  }

  recordResourceUsage() {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      const memoryMB = (memUsage.heapUsed / 1024 / 1024).toFixed(2);
      this.resourceUsage.memoryUsage.push({
        timestamp: new Date().toISOString(),
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external
      });
      this.resourceUsage.peakMemory = Math.max(
        this.resourceUsage.peakMemory,
        memUsage.heapUsed
      );
    }
    this._updateTimestamp();
  }

  isHeartbeatExpired(timeoutSeconds = 120) {
    if (!this.lastHeartbeat) return false;
    const now = new Date();
    const lastHeartbeat = new Date(this.lastHeartbeat);
    const diffSeconds = (now - lastHeartbeat) / 1000;
    return diffSeconds > timeoutSeconds;
  }

  getDuration() {
    if (!this.startedAt) return 0;
    const endTime = this.finishedAt ? new Date(this.finishedAt) : new Date();
    return Math.round((endTime - new Date(this.startedAt)) / 1000);
  }

  getStatusSummary() {
    return {
      agentId: this.agentId,
      status: this.status,
      iteration: this.iteration,
      maxIterations: this.maxIterations,
      findingsCount: this.findings.length,
      errorsCount: this.errors.length,
      duration: this.getDuration(),
      healthStatus: this.healthStatus,
      lastHeartbeat: this.lastHeartbeat,
      progress: this.progress,
      performance: {
        avgIterationTime: this.performance.avgIterationTime,
        totalProcessingTime: this.performance.totalProcessingTime
      }
    };
  }

  setCompleted(finalResult = null) {
    this.status = AgentStatus.COMPLETED;
    this.finalResult = finalResult;
    this.finishedAt = new Date().toISOString();
    this._updateTimestamp();
  }

  setFailed(error) {
    this.status = AgentStatus.FAILED;
    this.errors.push({
      message: error?.message || String(error),
      timestamp: new Date().toISOString()
    });
    this.finishedAt = new Date().toISOString();
    this._updateTimestamp();
  }

  pause() {
    this.status = AgentStatus.PAUSED;
    this._updateTimestamp();
  }

  resume() {
    this.status = AgentStatus.RUNNING;
    this._updateTimestamp();
  }

  requestStop() {
    this.stopRequested = true;
    this.status = AgentStatus.STOPPING;
    this._updateTimestamp();
  }

  addMessage(role, content, metadata = {}) {
    this.messages.push({
      role,
      content,
      timestamp: new Date().toISOString(),
      ...metadata
    });
    this._updateTimestamp();
  }

  addAction(action, result = null) {
    this.actionsTaken.push({
      action,
      result,
      timestamp: new Date().toISOString()
    });
    this._updateTimestamp();
  }

  addObservation(observation, source = "system") {
    this.observations.push({
      observation,
      source,
      timestamp: new Date().toISOString()
    });
    this._updateTimestamp();
  }

  addFinding(finding) {
    this.findings.push({
      ...finding,
      discoveredAt: new Date().toISOString(),
      iteration: this.iteration
    });
    this._updateTimestamp();
  }

  updateTokens(tokens) {
    this.totalTokens += tokens;
  }

  incrementToolCalls() {
    this.toolCalls++;
  }

  _updateTimestamp() {
    this.lastUpdated = new Date().toISOString();
  }

  toJSON() {
    return {
      agentId: this.agentId,
      agentName: this.agentName,
      agentType: this.agentType,
      parentId: this.parentId,
      task: this.task,
      taskContext: this.taskContext,
      inheritedContext: this.inheritedContext,
      knowledgeModules: this.knowledgeModules,
      status: this.status,
      iteration: this.iteration,
      maxIterations: this.maxIterations,
      messages: this.messages,
      systemPrompt: this.systemPrompt,
      actionsTaken: this.actionsTaken,
      observations: this.observations,
      errors: this.errors,
      findings: this.findings,
      createdAt: this.createdAt,
      startedAt: this.startedAt,
      lastUpdated: this.lastUpdated,
      finishedAt: this.finishedAt,
      waitingForInput: this.waitingForInput,
      waitingReason: this.waitingReason,
      waitingTimeoutSeconds: this.waitingTimeoutSeconds,
      finalResult: this.finalResult,
      totalTokens: this.totalTokens,
      toolCalls: this.toolCalls,
      stopRequested: this.stopRequested,
      maxIterationsWarningSent: this.maxIterationsWarningSent,
      heartbeatInterval: this.heartbeatInterval,
      lastHeartbeat: this.lastHeartbeat,
      heartbeatCount: this.heartbeatCount,
      healthStatus: this.healthStatus,
      progress: this.progress,
      performance: this.performance,
      resourceUsage: this.resourceUsage
    };
  }

  static fromJSON(json) {
    const state = new AuditState();
    Object.assign(state, json);
    return state;
  }
}

class StatePersistence {
  constructor(persistDir = "./audit_checkpoints") {
    this.persistDir = persistDir;
    this._ensureDir();
  }

  async _ensureDir() {
    try {
      await fs.mkdir(this.persistDir, { recursive: true });
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    }
  }

  _getCheckpointPath(agentId, checkpointName = null) {
    const filename = checkpointName
      ? `${agentId}_${checkpointName}.json`
      : `${agentId}_${Date.now().toString(36)}.json`;
    return path.join(this.persistDir, filename);
  }

  async saveState(state, checkpointName = null) {
    await this._ensureDir();
    const filepath = this._getCheckpointPath(state.agentId, checkpointName);

    const stateJson = state instanceof AuditState ? state.toJSON() : state;

    await fs.writeFile(filepath, JSON.stringify(stateJson, null, 2), "utf-8");

    return filepath;
  }

  async loadState(filepath) {
    try {
      const content = await fs.readFile(filepath, "utf-8");
      const stateJson = JSON.parse(content);
      return AuditState.fromJSON(stateJson);
    } catch (e) {
      console.error(`Failed to load state from ${filepath}:`, e);
      return null;
    }
  }

  async listCheckpoints(agentId = null) {
    await this._ensureDir();
    const files = await fs.readdir(this.persistDir);

    const checkpoints = [];
    for (const file of files) {
      if (!file.endsWith(".json")) continue;

      const [id, ...rest] = file.replace(".json", "").split("_");
      if (agentId && id !== agentId) continue;

      const filepath = path.join(this.persistDir, file);
      const stat = await fs.stat(filepath);

      checkpoints.push({
        agentId: id,
        checkpointName: rest.join("_") || null,
        filepath,
        createdAt: stat.mtime.toISOString(),
        size: stat.size
      });
    }

    return checkpoints.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  async deleteCheckpoint(filepath) {
    try {
      await fs.unlink(filepath);
      return true;
    } catch (e) {
      console.error(`Failed to delete checkpoint ${filepath}:`, e);
      return false;
    }
  }

  async deleteAgentCheckpoints(agentId) {
    const checkpoints = await this.listCheckpoints(agentId);
    let deleted = 0;
    for (const cp of checkpoints) {
      if (await this.deleteCheckpoint(cp.filepath)) deleted++;
    }
    return deleted;
  }

  async cleanupOldCheckpoints(maxAgeMs = 7 * 24 * 60 * 60 * 1000) {
    const now = Date.now();
    const files = await fs.readdir(this.persistDir);
    let deleted = 0;

    for (const file of files) {
      if (!file.endsWith(".json")) continue;

      const filepath = path.join(this.persistDir, file);
      const stat = await fs.stat(filepath);

      if (now - stat.mtime.getTime() > maxAgeMs) {
        if (await this.deleteCheckpoint(filepath)) deleted++;
      }
    }

    return deleted;
  }
}

class CheckpointManager {
  constructor(persistence) {
    this.persistence = persistence;
    this.activeCheckpoints = new Map();
  }

  async createCheckpoint(state, name = "auto") {
    const checkpointName = name === "auto"
      ? `cp_${state.iteration}_${Date.now().toString(36)}`
      : name;

    const filepath = await this.persistence.saveState(state, checkpointName);

    if (!this.activeCheckpoints.has(state.agentId)) {
      this.activeCheckpoints.set(state.agentId, []);
    }
    this.activeCheckpoints.get(state.agentId).push({
      name: checkpointName,
      filepath,
      iteration: state.iteration,
      createdAt: new Date().toISOString()
    });

    return filepath;
  }

  async getLatestCheckpoint(agentId) {
    const checkpoints = await this.persistence.listCheckpoints(agentId);
    if (checkpoints.length === 0) return null;
    return this.persistence.loadState(checkpoints[0].filepath);
  }

  async restoreFromCheckpoint(filepath) {
    return this.persistence.loadState(filepath);
  }

  async getCheckpointHistory(agentId) {
    return this.persistence.listCheckpoints(agentId);
  }
}

const globalStatePersistence = new StatePersistence();
const globalCheckpointManager = new CheckpointManager(globalStatePersistence);

export {
  AgentStatus,
  AuditState,
  StatePersistence,
  CheckpointManager,
  globalStatePersistence,
  globalCheckpointManager
};