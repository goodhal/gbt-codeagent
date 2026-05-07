import { promises as fs } from "node:fs";
import path from "path";

const SpanStatus = {
  OK: "ok",
  ERROR: "error",
  UNKNOWN: "unknown"
};

const SpanKind = {
  INTERNAL: "internal",
  SERVER: "server",
  CLIENT: "client",
  PRODUCER: "producer",
  CONSUMER: "consumer"
};

class Span {
  constructor(options = {}) {
    this.spanId = this._generateId();
    this.traceId = options.traceId || this._generateId();
    this.parentSpanId = options.parentSpanId || null;

    this.name = options.name || "unknown";
    this.kind = options.kind || SpanKind.INTERNAL;
    this.service = options.service || "gbt-codeagent";

    this.startTime = new Date();
    this.endTime = null;
    this.duration = null;

    this.status = SpanStatus.UNKNOWN;
    this.statusMessage = "";

    this.attributes = new Map(options.attributes || []);
    this.events = [];
    this.links = [];

    this._ended = false;
  }

  _generateId() {
    return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  }

  setAttribute(key, value) {
    this.attributes.set(key, value);
    return this;
  }

  setAttributes(attributes) {
    for (const [key, value] of Object.entries(attributes)) {
      this.attributes.set(key, value);
    }
    return this;
  }

  addEvent(name, attributes = {}) {
    this.events.push({
      name,
      timestamp: new Date().toISOString(),
      attributes
    });
    return this;
  }

  setStatus(status, message = "") {
    this.status = status;
    this.statusMessage = message;
    return this;
  }

  end() {
    if (this._ended) return this;

    this.endTime = new Date();
    this.duration = this.endTime.getTime() - this.startTime.getTime();
    this._ended = true;
    return this;
  }

  isEnded() {
    return this._ended;
  }

  toJSON() {
    return {
      spanId: this.spanId,
      traceId: this.traceId,
      parentSpanId: this.parentSpanId,
      name: this.name,
      kind: this.kind,
      service: this.service,
      startTime: this.startTime.toISOString(),
      endTime: this.endTime ? this.endTime.toISOString() : null,
      duration: this.duration,
      status: this.status,
      statusMessage: this.statusMessage,
      attributes: Object.fromEntries(this.attributes),
      events: this.events,
      links: this.links
    };
  }
}

class Tracer {
  constructor(options = {}) {
    this.serviceName = options.serviceName || "gbt-codeagent";
    this.runName = options.runName || null;
    this.runId = options.runId || this._generateRunId();

    this.startTime = new Date();
    this.endTime = null;

    this.spans = new Map();
    this._spanStack = [];

    this.agents = new Map();
    this.toolExecutions = new Map();
    this.chatMessages = [];

    this.vulnerabilityReports = [];
    this.finalScanResult = null;

    this.scanConfig = null;
    this.scanResults = null;

    this.runMetadata = {
      runId: this.runId,
      runName: this.runName,
      startTime: this.startTime.toISOString(),
      endTime: null,
      status: "running"
    };

    this.outputDir = options.outputDir || null;
    this.runDir = null;

    this._nextExecutionId = 1;
    this._nextMessageId = 1;
    this._savedVulnIds = new Set();

    this.vulnerabilityFoundCallback = null;
    this.agentStatusCallback = null;

    this._enabled = true;

    this.logLevel = options.logLevel || LogLevel.INFO;
    this.auditEvents = [];
    this.performanceMetrics = new PerformanceMetrics();
    this.errorAggregator = new ErrorAggregator();
    this._eventListeners = new Map();
  }

  setLogLevel(level) {
    this.logLevel = level;
  }

  getLogLevel() {
    return this.logLevel;
  }

  log(level, message, context = {}) {
    if (level < this.logLevel) {
      return;
    }
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: LogLevelNames[level],
      message,
      context,
      runId: this.runId
    };
    if (typeof console !== 'undefined') {
      const prefix = `[${logEntry.level}]`;
      if (level >= LogLevel.ERROR) {
        console.error(prefix, message, context);
      } else if (level >= LogLevel.WARN) {
        console.warn(prefix, message, context);
      } else {
        console.log(prefix, message, context);
      }
    }
    return logEntry;
  }

  debug(message, context = {}) {
    return this.log(LogLevel.DEBUG, message, context);
  }

  info(message, context = {}) {
    return this.log(LogLevel.INFO, message, context);
  }

  warn(message, context = {}) {
    return this.log(LogLevel.WARN, message, context);
  }

  error(message, error = null, context = {}) {
    if (error) {
      this.errorAggregator.recordError(error, context);
    }
    return this.log(LogLevel.ERROR, message, { ...context, error: error?.message });
  }

  critical(message, error = null, context = {}) {
    if (error) {
      this.errorAggregator.recordError(error, context);
    }
    return this.log(LogLevel.CRITICAL, message, { ...context, error: error?.message });
  }

  recordAuditEvent(eventType, data = {}) {
    const event = {
      type: eventType,
      timestamp: new Date().toISOString(),
      runId: this.runId,
      data
    };
    this.auditEvents.push(event);

    const listeners = this._eventListeners.get(eventType) || [];
    for (const listener of listeners) {
      try {
        listener(event);
      } catch (e) {
        this.error('Audit event listener error', e, { eventType });
      }
    }

    if (eventType === AuditEventType.VULNERABILITY_FOUND) {
      this.performanceMetrics.incrementCounter('vulnerabilities_found', 1, { severity: data.severity });
    } else if (eventType === AuditEventType.FILE_SCANNED) {
      this.performanceMetrics.incrementCounter('files_scanned', 1, { language: data.language });
    } else if (eventType === AuditEventType.SUPPRESSION_APPLIED) {
      this.performanceMetrics.incrementCounter('suppressions_applied', 1);
    }

    return event;
  }

  onAuditEvent(eventType, listener) {
    if (!this._eventListeners.has(eventType)) {
      this._eventListeners.set(eventType, []);
    }
    this._eventListeners.get(eventType).push(listener);
  }

  removeAuditEventListener(eventType, listener) {
    const listeners = this._eventListeners.get(eventType) || [];
    const index = listeners.indexOf(listener);
    if (index > -1) {
      listeners.splice(index, 1);
    }
  }

  recordMetric(name, value, type = 'counter', labels = {}) {
    switch (type) {
      case 'counter':
        this.performanceMetrics.incrementCounter(name, value, labels);
        break;
      case 'histogram':
        this.performanceMetrics.recordHistogram(name, value, labels);
        break;
      case 'gauge':
        this.performanceMetrics.setGauge(name, value, labels);
        break;
    }
  }

  startOperationTimer(name, labels = {}) {
    this.performanceMetrics.startTimer(name, labels);
  }

  endOperationTimer(name, labels = {}) {
    return this.performanceMetrics.endTimer(name, labels);
  }

  getPerformanceReport() {
    const report = {
      timestamp: new Date().toISOString(),
      runId: this.runId,
      counters: {},
      histograms: {},
      gauges: {}
    };

    for (const [name] of this.performanceMetrics.counters) {
      report.counters[name] = this.performanceMetrics.counters.get(name);
    }

    for (const [name] of this.performanceMetrics.histograms) {
      report.histograms[name] = this.performanceMetrics.getHistogramStats(name);
    }

    for (const [name] of this.performanceMetrics.gauges) {
      report.gauges[name] = this.performanceMetrics.gauges.get(name);
    }

    return report;
  }

  getAuditEvents(eventType = null) {
    if (eventType) {
      return this.auditEvents.filter(e => e.type === eventType);
    }
    return this.auditEvents;
  }

  getErrorReport() {
    return {
      totalErrors: this.errorAggregator.errors.size,
      topErrors: this.errorAggregator.getTopErrors(10),
      allErrors: this.errorAggregator.getErrorGroups()
    };
  }

  _generateRunId() {
    return `run_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  }

  enable() {
    this._enabled = true;
  }

  disable() {
    this._enabled = false;
  }

  isEnabled() {
    return this._enabled;
  }

  setRunName(runName) {
    this.runName = runName;
    this.runId = runName;
    this.runMetadata.runName = runName;
    this.runMetadata.runId = runName;
  }

  async getRunDir() {
    if (this.runDir) return this.runDir;

    const baseDir = this.outputDir
      ? path.resolve(this.outputDir)
      : path.join(process.cwd(), "audit_runs");

    try {
      await fs.mkdir(baseDir, { recursive: true });
    } catch (e) {}

    const runDirName = this.runName || this.runId;
    const cleanName = runDirName.replace(/[^a-zA-Z0-9\-_]/g, "_");
    this.runDir = path.join(baseDir, cleanName);

    try {
      await fs.mkdir(this.runDir, { recursive: true });
    } catch (e) {}

    return this.runDir;
  }

  startSpan(name, options = {}) {
    if (!this._enabled) {
      return new Span({ name, ...options });
    }

    const parentSpan = this._spanStack.length > 0
      ? this._spanStack[this._spanStack.length - 1]
      : null;

    const span = new Span({
      name,
      parentSpanId: parentSpan?.spanId || null,
      traceId: parentSpan?.traceId || this._generateTraceId(),
      ...options
    });

    this.spans.set(span.spanId, span);
    this._spanStack.push(span);

    return span;
  }

  endSpan(span) {
    if (!this._enabled) return;

    span.end();

    const index = this._spanStack.indexOf(span);
    if (index > -1) {
      this._spanStack.splice(index, 1);
    }
  }

  _generateTraceId() {
    return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 18)}${Math.random().toString(36).slice(2, 10)}`;
  }

  recordAgent(agentData) {
    const agentId = agentData.agentId || this._generateAgentId();
    this.agents.set(agentId, {
      ...agentData,
      agentId,
      recordedAt: new Date().toISOString()
    });
    return agentId;
  }

  _generateAgentId() {
    return `agent_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  }

  recordToolExecution(executionData) {
    const executionId = this._nextExecutionId++;
    const record = {
      executionId,
      ...executionData,
      timestamp: new Date().toISOString()
    };
    this.toolExecutions.set(executionId, record);
    return executionId;
  }

  recordChatMessage(message) {
    const messageId = this._nextMessageId++;
    const record = {
      messageId,
      ...message,
      timestamp: new Date().toISOString()
    };
    this.chatMessages.push(record);
    return messageId;
  }

  recordVulnerability(vuln) {
    if (this._savedVulnIds.has(vuln.id)) {
      return null;
    }

    this._savedVulnIds.add(vuln.id);

    const record = {
      ...vuln,
      recordedAt: new Date().toISOString()
    };
    this.vulnerabilityReports.push(record);

    if (this.vulnerabilityFoundCallback) {
      try {
        this.vulnerabilityFoundCallback(vuln.id, vuln.title, vuln.severity, vuln.location);
      } catch (e) {
        console.error("Vulnerability callback error:", e);
      }
    }

    return vuln.id;
  }

  setFinalScanResult(result) {
    this.finalScanResult = result;
  }

  setScanConfig(config) {
    this.scanConfig = config;
  }

  setScanResults(results) {
    this.scanResults = results;
  }

  getSummary() {
    return {
      runId: this.runId,
      runName: this.runName,
      serviceName: this.serviceName,
      status: this.runMetadata.status,
      startTime: this.runMetadata.startTime,
      endTime: this.runMetadata.endTime,
      duration: this.endTime
        ? new Date(this.endTime).getTime() - new Date(this.startTime).getTime()
        : null,
      agents: {
        total: this.agents.size,
        byType: this._countByType(this.agents)
      },
      toolExecutions: {
        total: this.toolExecutions.size,
        byTool: this._countByField(this.toolExecutions, "tool")
      },
      vulnerabilities: {
        total: this.vulnerabilityReports.length,
        bySeverity: this._countByField(this.vulnerabilityReports, "severity"),
        byType: this._countByField(this.vulnerabilityReports, "vulnType")
      },
      chatMessages: this.chatMessages.length,
      spans: {
        total: this.spans.size,
        ended: [...this.spans.values()].filter(s => s.isEnded()).length
      }
    };
  }

  _countByType(map) {
    const counts = {};
    for (const item of map.values()) {
      const type = item.agentType || "unknown";
      counts[type] = (counts[type] || 0) + 1;
    }
    return counts;
  }

  _countByField(map, field) {
    const counts = {};
    for (const item of map.values()) {
      const value = item[field] || "unknown";
      counts[value] = (counts[value] || 0) + 1;
    }
    return counts;
  }

  async save() {
    if (!this._enabled) return;

    const runDir = await this.getRunDir();

    const data = {
      runMetadata: this.runMetadata,
      summary: this.getSummary(),
      agents: Array.from(this.agents.values()),
      toolExecutions: Array.from(this.toolExecutions.values()),
      chatMessages: this.chatMessages,
      vulnerabilityReports: this.vulnerabilityReports,
      spans: Array.from(this.spans.values()).map(s => s.toJSON()),
      scanConfig: this.scanConfig,
      scanResults: this.scanResults,
      finalScanResult: this.finalScanResult,
      auditEvents: this.auditEvents,
      performanceMetrics: this.performanceMetrics.getAllMetrics(),
      errorReport: this.getErrorReport(),
      logLevel: this.logLevel
    };

    const jsonPath = path.join(runDir, "trace.json");
    await fs.writeFile(jsonPath, JSON.stringify(data, null, 2), "utf-8");

    await this._saveCSV(runDir);

    return runDir;
  }

  async _saveCSV(runDir) {
    if (this.vulnerabilityReports.length === 0) return;

    const csvPath = path.join(runDir, "vulnerabilities.csv");
    const headers = ["id", "title", "severity", "vulnType", "location", "confidence", "recordedAt"];

    const rows = this.vulnerabilityReports.map(v => [
      v.id || "",
      (v.title || "").replace(/"/g, '""'),
      v.severity || "",
      v.vulnType || "",
      (v.location || "").replace(/"/g, '""'),
      v.confidence || "",
      v.recordedAt || ""
    ]);

    const csvContent = [headers.join(","), ...rows.map(r => r.map(c => `"${c}"`).join(","))].join("\n");
    await fs.writeFile(csvPath, csvContent, "utf-8");
  }

  finish(status = "completed") {
    this.endTime = new Date();
    this.runMetadata.endTime = this.endTime.toISOString();
    this.runMetadata.status = status;

    for (const span of this._spanStack) {
      span.end();
    }
    this._spanStack = [];
  }

  reset() {
    this.spans.clear();
    this.agents.clear();
    this.toolExecutions.clear();
    this.chatMessages = [];
    this.vulnerabilityReports = [];
    this.finalScanResult = null;
    this.scanConfig = null;
    this.scanResults = null;
    this._savedVulnIds.clear();
    this._spanStack = [];
    this.startTime = new Date();
    this.endTime = null;
    this.runMetadata = {
      runId: this.runId,
      runName: this.runName,
      startTime: this.startTime.toISOString(),
      endTime: null,
      status: "running"
    };
  }
}

let globalTracer = null;

const LogLevel = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  CRITICAL: 4,
  NONE: 5
};

const LogLevelNames = {
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.WARN]: 'WARN',
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.CRITICAL]: 'CRITICAL',
  [LogLevel.NONE]: 'NONE'
};

const AuditEventType = {
  RULE_LOADED: 'rule_loaded',
  RULE_MATCHED: 'rule_matched',
  VULNERABILITY_FOUND: 'vulnerability_found',
  VULNERABILITY_CONFIRMED: 'vulnerability_confirmed',
  VULNERABILITY_FALSE_POSITIVE: 'vulnerability_false_positive',
  SCAN_STARTED: 'scan_started',
  SCAN_COMPLETED: 'scan_completed',
  SCAN_FAILED: 'scan_failed',
  FILE_SCANNED: 'file_scanned',
  SUPPRESSION_APPLIED: 'suppression_applied',
  GUIDELINE_VIOLATION: 'guideline_violation',
  COMPLIANCE_CHECK: 'compliance_check'
};

class PerformanceMetrics {
  constructor() {
    this.counters = new Map();
    this.histograms = new Map();
    this.gauges = new Map();
    this.timers = new Map();
  }

  incrementCounter(name, value = 1, labels = {}) {
    const key = this._makeKey(name, labels);
    const current = this.counters.get(key) || 0;
    this.counters.set(key, current + value);
  }

  recordHistogram(name, value, labels = {}) {
    const key = this._makeKey(name, labels);
    if (!this.histograms.has(key)) {
      this.histograms.set(key, []);
    }
    this.histograms.get(key).push(value);
  }

  setGauge(name, value, labels = {}) {
    const key = this._makeKey(name, labels);
    this.gauges.set(key, { value, timestamp: new Date().toISOString() });
  }

  startTimer(name, labels = {}) {
    const key = this._makeKey(name, labels);
    this.timers.set(key, Date.now());
  }

  endTimer(name, labels = {}) {
    const key = this._makeKey(name, labels);
    const startTime = this.timers.get(key);
    if (startTime) {
      const duration = Date.now() - startTime;
      this.timers.delete(key);
      this.recordHistogram(name, duration, labels);
      return duration;
    }
    return null;
  }

  getHistogramStats(name, labels = {}) {
    const key = this._makeKey(name, labels);
    const values = this.histograms.get(key) || [];
    if (values.length === 0) {
      return null;
    }
    const sorted = [...values].sort((a, b) => a - b);
    const sum = values.reduce((a, b) => a + b, 0);
    return {
      count: values.length,
      sum,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean: sum / values.length,
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p90: sorted[Math.floor(sorted.length * 0.9)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }

  _makeKey(name, labels) {
    if (Object.keys(labels).length === 0) {
      return name;
    }
    const labelStr = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
    return `${name}{${labelStr}}`;
  }

  getAllMetrics() {
    return {
      counters: Object.fromEntries(this.counters),
      histograms: Object.fromEntries(this.histograms),
      gauges: Object.fromEntries(this.gauges)
    };
  }
}

class ErrorAggregator {
  constructor() {
    this.errors = new Map();
    this.errorGroups = new Map();
  }

  recordError(error, context = {}) {
    const signature = this._computeSignature(error);
    const existing = this.errors.get(signature);

    if (existing) {
      existing.count++;
      existing.lastSeen = new Date().toISOString();
      existing.contexts.push(context);
    } else {
      this.errors.set(signature, {
        signature,
        message: error.message || String(error),
        stack: error.stack,
        count: 1,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        contexts: [context]
      });
    }
  }

  getErrorGroups() {
    return Array.from(this.errors.values());
  }

  getTopErrors(limit = 10) {
    return Array.from(this.errors.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  _computeSignature(error) {
    const msg = error.message || String(error);
    const stack = error.stack || '';
    const match = stack.match(/\/([^:/]+):(\d+):(\d+)/);
    if (match) {
      return `${msg}@${match[1]}:${match[2]}`;
    }
    return `${msg}@${stack.split('\n')[1] || 'unknown'}`;
  }
}

function getGlobalTracer() {
  if (!globalTracer) {
    globalTracer = new Tracer();
  }
  return globalTracer;
}

function setGlobalTracer(tracer) {
  globalTracer = tracer;
}

function createTracer(options = {}) {
  return new Tracer(options);
}

export {
  SpanStatus,
  SpanKind,
  Span,
  Tracer,
  LogLevel,
  LogLevelNames,
  AuditEventType,
  PerformanceMetrics,
  ErrorAggregator,
  getGlobalTracer,
  setGlobalTracer,
  createTracer
};