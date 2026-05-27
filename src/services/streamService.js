const EventType = {
  LLM_START: 'llm_start',
  LLM_THINKING: 'llm_thinking',
  LLM_STREAM_TOKEN: 'llm_stream_token',
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
    this._taskId = null;
  }

  setTaskId(taskId) {
    this._taskId = taskId;
  }

  clearTaskId() {
    this._taskId = null;
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

  emitLLMStart(model, task, taskId) {
    const tid = taskId || this._taskId;
    console.log(`[SSE] 发射事件 llm_start → taskId=${tid || '(none)'}`);
    // 扁平化数据以匹配前端期望：batchIndex / totalBatches 直接放在顶层
    return this.emit(EventType.LLM_START, { 
      model, 
      batchIndex: task?.batchIndex || 0, 
      totalBatches: task?.totalBatches || 0,
      _taskId: tid 
    });
  }

  emitLLMThinking(content, taskId) {
    const tid = taskId || this._taskId;
    console.log(`[SSE] 发射事件 llm_thinking → taskId=${tid || '(none)'}`);
    return this.emit(EventType.LLM_THINKING, { content, _taskId: tid });
  }

  emitLLMStreamToken(token, batchIndex, totalBatches, taskId) {
    const tid = taskId || this._taskId;
    if (this._tokenCount === undefined) this._tokenCount = 0;
    this._tokenCount++;
    if (this._tokenCount <= 3 || this._tokenCount % 100 === 0) {
      console.log(`[SSE] 发射事件 llm_stream_token #${this._tokenCount} → taskId=${tid || '(none)'}`);
    }
    return this.emit(EventType.LLM_STREAM_TOKEN, { token, batchIndex, totalBatches, _taskId: tid });
  }

  emitLLMDecision(decision, reasoning, taskId) {
    return this.emit(EventType.LLM_DECISION, { decision, reasoning, _taskId: taskId || this._taskId });
  }

  emitLLMComplete(usage, taskId) {
    return this.emit(EventType.LLM_COMPLETE, { usage, _taskId: taskId || this._taskId });
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

  emitInfo(message, taskId) {
    return this.emit(EventType.INFO, { message, _taskId: taskId || this._taskId });
  }

  emitWarning(message, taskId) {
    return this.emit(EventType.WARNING, { message, _taskId: taskId || this._taskId });
  }

  emitError(message, error, taskId) {
    return this.emit(EventType.ERROR, { message, error, _taskId: taskId || this._taskId });
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