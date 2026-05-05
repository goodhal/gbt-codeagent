const AgentType = {
  ORCHESTRATOR: "orchestrator",
  RECON: "recon",
  ANALYSIS: "analysis",
  VERIFICATION: "verification"
};

const AgentPattern = {
  REACT: "react",
  PLAN_AND_EXECUTE: "plan_execute"
};

const AgentStatus = {
  IDLE: "idle",
  RUNNING: "running",
  WAITING: "waiting",
  COMPLETED: "completed",
  FAILED: "failed",
  STOPPED: "stopped"
};

class TaskHandoff {
  constructor({
    fromAgent,
    toAgent,
    task,
    context = {},
    findings = [],
    recommendations = []
  }) {
    this.fromAgent = fromAgent;
    this.toAgent = toAgent;
    this.task = task;
    this.context = context;
    this.findings = findings;
    this.recommendations = recommendations;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      fromAgent: this.fromAgent,
      toAgent: this.toAgent,
      task: this.task,
      context: this.context,
      findings: this.findings,
      recommendations: this.recommendations,
      timestamp: this.timestamp
    };
  }
}

class AgentResult {
  constructor({
    success,
    data = null,
    error = null,
    iterations = 0,
    toolCalls = 0,
    tokensUsed = 0,
    durationMs = 0,
    intermediateSteps = [],
    metadata = {},
    handoff = null
  }) {
    this.success = success;
    this.data = data;
    this.error = error;
    this.iterations = iterations;
    this.toolCalls = toolCalls;
    this.tokensUsed = tokensUsed;
    this.durationMs = durationMs;
    this.intermediateSteps = intermediateSteps;
    this.metadata = metadata;
    this.handoff = handoff;
  }

  toJSON() {
    return {
      success: this.success,
      data: this.data,
      error: this.error,
      iterations: this.iterations,
      toolCalls: this.toolCalls,
      tokensUsed: this.tokensUsed,
      durationMs: this.durationMs,
      intermediateSteps: this.intermediateSteps,
      metadata: this.metadata,
      handoff: this.handoff?.toJSON() || null
    };
  }
}

class BaseAgent {
  constructor(config) {
    if (new.target === BaseAgent) {
      throw new Error("BaseAgent is abstract and cannot be instantiated directly");
    }

    this.config = config;
    this.id = `agent_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    this.status = AgentStatus.IDLE;
    this.iterations = 0;
    this.toolCalls = 0;
    this.startTime = null;
    this.endTime = null;
    this.intermediateSteps = [];
    this.currentTask = null;
    this._cancelled = false;
    this._llmService = null;
  }

  get name() {
    return this.config.name;
  }

  get agentType() {
    return this.config.agentType;
  }

  async initialize(llmService) {
    this._llmService = llmService;
  }

  async execute(task, context = {}) {
    throw new Error("execute() must be implemented by subclass");
  }

  async cancel() {
    this._cancelled = true;
    this.status = AgentStatus.STOPPED;
  }

  requestStop() {
    this._cancelled = true;
  }

  async _createIterationLog(thought, action, observation) {
    return {
      agentId: this.id,
      agentName: this.name,
      iteration: this.iterations,
      thought,
      action,
      observation,
      timestamp: new Date().toISOString()
    };
  }

  _checkCancellation() {
    if (this._cancelled) {
      throw new Error(`Agent ${this.name} was cancelled`);
    }
  }

  async runReactLoop(task, context = {}, actionHandlers = {}) {
    this.status = AgentStatus.RUNNING;
    this.startTime = Date.now();
    this.currentTask = task;
    this._cancelled = false;

    let observation = null;

    while (this.iterations < this.config.maxIterations && !this._cancelled) {
      this._checkCancellation();
      this.iterations++;

      const thought = await this._think(task, context, observation);

      const action = await this._decideAction(thought, task, context, observation);

      observation = await this._executeAction(action, actionHandlers);

      this.intermediateSteps.push({
        iteration: this.iterations,
        thought,
        action,
        observation,
        timestamp: new Date().toISOString()
      });

      if (action.type === "finish" || action.type === "stop") {
        break;
      }
    }

    this.endTime = Date.now();
    this.status = this._cancelled ? AgentStatus.STOPPED : AgentStatus.COMPLETED;

    return observation;
  }

  async _think(task, context, previousObservation) {
    const prompt = `
Task: ${task}

Context:
${JSON.stringify(context, null, 2)}

Previous Observation:
${previousObservation ? JSON.stringify(previousObservation, null, 2) : "None"}

Think about what to do next. Consider:
1. What information has been gathered?
2. What still needs to be analyzed?
3. What are the next steps?

Provide your thought process.
`;

    const response = await this._llmService.complete({
      prompt,
      temperature: this.config.temperature,
      maxTokens: this.config.maxTokens
    });

    return response.content;
  }

  async _decideAction(thought, task, context, observation) {
    const prompt = `
Based on your thought process, decide the next action.

Thought:
${thought}

Available Actions:
- dispatch_agent: Send task to a sub-agent
- tool_call: Execute a tool
- summarize: Summarize findings
- finish: Complete the current task

Current Task: ${task}

Respond with JSON:
{"type": "action_type", "params": {...}}
`;

    const response = await this._llmService.complete({
      prompt,
      temperature: 0.0,
      maxTokens: 500
    });

    try {
      const jsonMatch = response.content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      console.warn("Failed to parse action JSON:", e);
    }

    return { type: "finish", params: {} };
  }

  async _executeAction(action, handlers = {}) {
    const handler = handlers[action.type];
    if (handler) {
      return await handler(action.params || {});
    }

    return { type: action.type, result: "No handler found" };
  }
}

class OrchestratorAgent extends BaseAgent {
  constructor(config, subAgents = {}) {
    super(config);
    this.subAgents = subAgents;
    this.findings = [];
    this.context = {};
  }

  async execute(task, context = {}) {
    this.context = context;

    const actionHandlers = {
      dispatch_agent: async (params) => this._dispatchAgent(params),
      summarize: async (params) => this._summarize(params),
      finish: async (params) => this._finish(params)
    };

    const finalObservation = await this.runReactLoop(task, context, actionHandlers);

    return new AgentResult({
      success: true,
      data: {
        findings: this.findings,
        context: this.context,
        observation: finalObservation
      },
      iterations: this.iterations,
      toolCalls: this.toolCalls,
      intermediateSteps: this.intermediateSteps,
      handoff: new TaskHandoff({
        fromAgent: this.name,
        toAgent: null,
        task,
        context: this.context,
        findings: this.findings
      })
    });
  }

  async _dispatchAgent({ agent, task, agentContext = {} }) {
    const subAgent = this.subAgents[agent];
    if (!subAgent) {
      return { error: `Sub-agent '${agent}' not found` };
    }

    const mergedContext = { ...this.context, ...agentContext };
    const result = await subAgent.execute(task, mergedContext);

    if (result.handoff) {
      this.findings = [...this.findings, ...(result.handoff.findings || [])];
    }

    return {
      type: "agent_result",
      agent,
      result: result.toJSON()
    };
  }

  async _summarize({ findings, analysis }) {
    this.findings = [...this.findings, ...findings];
    return {
      type: "summary",
      analysis,
      findingsCount: this.findings.length
    };
  }

  async _finish({ conclusion, recommendations = [] }) {
    return {
      type: "finish",
      conclusion,
      findings: this.findings,
      recommendations
    };
  }
}

class ReconAgent extends BaseAgent {
  async execute(task, context = {}) {
    const actionHandlers = {
      scan_file: async (params) => this._scanFile(params),
      analyze_structure: async (params) => this._analyzeStructure(params),
      identify_tech_stack: async (params) => this._identifyTechStack(params),
      finish: async (params) => this._finish(params)
    };

    const result = await this.runReactLoop(task, context, actionHandlers);

    return new AgentResult({
      success: true,
      data: result,
      iterations: this.iterations,
      toolCalls: this.toolCalls,
      intermediateSteps: this.intermediateSteps,
      handoff: new TaskHandoff({
        fromAgent: this.name,
        toAgent: "analysis",
        task,
        context: this.context,
        findings: this.findings || []
      })
    });
  }

  async _scanFile({ path }) {
    return { scanned: path };
  }

  async _analyzeStructure({ root }) {
    return { structure: "analyzed" };
  }

  async _identifyTechStack({ files }) {
    return { techStack: [] };
  }

  async _finish(params) {
    return params;
  }
}

class AnalysisAgent extends BaseAgent {
  constructor(config) {
    super(config);
    this.findings = [];
  }

  async execute(task, context = {}) {
    this.context = context;

    const actionHandlers = {
      analyze_code: async (params) => this._analyzeCode(params),
      detect_vulnerability: async (params) => this._detectVulnerability(params),
      finish: async (params) => this._finish(params)
    };

    const result = await this.runReactLoop(task, context, actionHandlers);

    return new AgentResult({
      success: true,
      data: result,
      iterations: this.iterations,
      toolCalls: this.toolCalls,
      intermediateSteps: this.intermediateSteps,
      handoff: new TaskHandoff({
        fromAgent: this.name,
        toAgent: "verification",
        task,
        context: this.context,
        findings: this.findings
      })
    });
  }

  async _analyzeCode({ file, code }) {
    return { analyzed: file };
  }

  async _detectVulnerability({ type, location, evidence }) {
    this.findings.push({ type, location, evidence });
    return { detected: true };
  }

  async _finish(params) {
    return params;
  }
}

export {
  AgentType,
  AgentPattern,
  AgentStatus,
  TaskHandoff,
  AgentResult,
  BaseAgent,
  OrchestratorAgent,
  ReconAgent,
  AnalysisAgent
};