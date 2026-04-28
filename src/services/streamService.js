const EventType = {
  LLM_START: 'llm_start',
  LLM_THINKING: 'llm_thinking',
  LLM_DECISION: 'llm_decision',
  LLM_COMPLETE: 'llm_complete',
  TOOL_CALL_START: 'tool_call_start',
  TOOL_CALL_END: 'tool_call_end',
  TOOL_CALL_ERROR: 'tool_call_error',
  FINDING_NEW: 'finding_new',
  FINDING_VERIFIED: 'finding_verified',
  PROGRESS: 'progress',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'error',
  HEARTBEAT: 'heartbeat'
};

class StreamEvent {
  constructor(eventType, data = {}) {
    this.eventType = eventType;
    this.data = data;
    this.timestamp = new Date().toISOString();
    this.sequence = 0;
  }

  toSSE() {
    return `event: ${this.eventType}\ndata: ${JSON.stringify(this.data)}\n\n`;
  }

  toJSON() {
    return {
      eventType: this.eventType,
      data: this.data,
      timestamp: this.timestamp,
      sequence: this.sequence
    };
  }
}

class StreamService {
  constructor() {
    this.listeners = new Map();
    this.sequence = 0;
    this.enabled = true;
  }

  addListener(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType).add(callback);
    return () => this.removeListener(eventType, callback);
  }

  removeListener(eventType, callback) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).delete(callback);
    }
  }

  emit(eventType, data = {}) {
    if (!this.enabled) return;

    const event = new StreamEvent(eventType, data);
    event.sequence = this.sequence++;

    const callbacks = this.listeners.get(eventType);
    if (callbacks) {
      callbacks.forEach(cb => {
        try {
          cb(event);
        } catch (e) {
          console.error(`[流式服务] 事件处理错误: ${e.message}`);
        }
      });
    }

    const wildcardCallbacks = this.listeners.get('*');
    if (wildcardCallbacks) {
      wildcardCallbacks.forEach(cb => {
        try {
          cb(event);
        } catch (e) {
          console.error(`[流式服务] 全局事件处理错误: ${e.message}`);
        }
      });
    }

    return event;
  }

  emitLLMStart(model, task) {
    return this.emit(EventType.LLM_START, { model, task });
  }

  emitLLMThinking(content) {
    return this.emit(EventType.LLM_THINKING, { content });
  }

  emitLLMDecision(decision, reasoning) {
    return this.emit(EventType.LLM_DECISION, { decision, reasoning });
  }

  emitLLMComplete(usage) {
    return this.emit(EventType.LLM_COMPLETE, { usage });
  }

  emitToolCallStart(toolName, params) {
    return this.emit(EventType.TOOL_CALL_START, { toolName, params });
  }

  emitToolCallEnd(toolName, result) {
    return this.emit(EventType.TOOL_CALL_END, { toolName, result });
  }

  emitToolCallError(toolName, error) {
    return this.emit(EventType.TOOL_CALL_ERROR, { toolName, error });
  }

  emitFindingNew(finding) {
    return this.emit(EventType.FINDING_NEW, { finding });
  }

  emitFindingVerified(finding, verified) {
    return this.emit(EventType.FINDING_VERIFIED, { finding, verified });
  }

  emitProgress(current, total, label) {
    return this.emit(EventType.PROGRESS, { current, total, label });
  }

  emitInfo(message) {
    return this.emit(EventType.INFO, { message });
  }

  emitWarning(message) {
    return this.emit(EventType.WARNING, { message });
  }

  emitError(message, error) {
    return this.emit(EventType.ERROR, { message, error });
  }

  emitHeartbeat() {
    return this.emit(EventType.HEARTBEAT, { timestamp: Date.now() });
  }

  disable() {
    this.enabled = false;
  }

  enable() {
    this.enabled = true;
  }

  clear() {
    this.listeners.clear();
    this.sequence = 0;
  }
}

const streamService = new StreamService();

export { StreamService, StreamEvent, EventType, streamService };