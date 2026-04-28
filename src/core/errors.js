const ErrorSeverity = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
};

const RecoveryStrategy = {
  RETRY: "retry",
  RETRY_WITH_BACKOFF: "retry_backoff",
  SKIP: "skip",
  FALLBACK: "fallback",
  ABORT: "abort",
  MANUAL: "manual"
};

const ErrorCode = {
  AGENT_ERROR: "AGENT_ERROR",
  LLM_ERROR: "LLM_ERROR",
  LLM_TIMEOUT: "LLM_TIMEOUT",
  LLM_RATE_LIMIT: "LLM_RATE_LIMIT",
  LLM_CONTEXT_LENGTH: "LLM_CONTEXT_LENGTH",
  LLM_AUTH_ERROR: "LLM_AUTH_ERROR",
  TOOL_ERROR: "TOOL_ERROR",
  TOOL_NOT_FOUND: "TOOL_NOT_FOUND",
  TOOL_TIMEOUT: "TOOL_TIMEOUT",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  EXTERNAL_TOOL_ERROR: "EXTERNAL_TOOL_ERROR",
  FILE_ERROR: "FILE_ERROR",
  NETWORK_ERROR: "NETWORK_ERROR",
  CIRCUIT_OPEN: "CIRCUIT_OPEN",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  MAX_RETRIES_EXCEEDED: "MAX_RETRIES_EXCEEDED",
  VALIDATION_FAILED: "VALIDATION_FAILED",
  PARSE_ERROR: "PARSE_ERROR",
  STATE_ERROR: "STATE_ERROR",
  PERSISTENCE_ERROR: "PERSISTENCE_ERROR"
};

class ErrorContext {
  constructor(data = {}) {
    this.correlationId = data.correlationId || null;
    this.agentId = data.agentId || null;
    this.agentName = data.agentName || null;
    this.taskId = data.taskId || null;
    this.iteration = data.iteration || null;
    this.toolName = data.toolName || null;
    this.timestamp = data.timestamp || new Date().toISOString();
    this.additionalData = data.additionalData || {};
  }

  toDict() {
    return {
      correlationId: this.correlationId,
      agentId: this.agentId,
      agentName: this.agentName,
      taskId: this.taskId,
      iteration: this.iteration,
      toolName: this.toolName,
      timestamp: this.timestamp,
      ...this.additionalData
    };
  }

  set(key, value) {
    this.additionalData[key] = value;
    return this;
  }
}

class AgentError extends Error {
  static errorCode = ErrorCode.AGENT_ERROR;
  static recoverable = false;
  static recoveryStrategy = RecoveryStrategy.ABORT;
  static severity = ErrorSeverity.HIGH;

  constructor(message, options = {}) {
    super(message);
    this.name = this.constructor.name;
    this.message = message;

    this.errorCode = options.errorCode || this.constructor.errorCode;
    this.recoverable = options.recoverable !== undefined ? options.recoverable : this.constructor.recoverable;
    this.recoveryStrategy = options.recoveryStrategy || this.constructor.recoveryStrategy;
    this.retryAfter = options.retryAfter !== undefined ? options.retryAfter : this.constructor.retryAfter;
    this.severity = options.severity || this.constructor.severity;
    this.context = options.context || new ErrorContext();
    this.cause = options.cause || null;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toDict() {
    return {
      name: this.name,
      message: this.message,
      errorCode: this.errorCode,
      recoverable: this.recoverable,
      recoveryStrategy: this.recoveryStrategy,
      retryAfter: this.retryAfter,
      severity: this.severity,
      context: this.context?.toDict(),
      timestamp: this.context?.timestamp,
      stack: this.stack
    };
  }
}

class LLMError extends AgentError {
  static errorCode = ErrorCode.LLM_ERROR;
  static recoverable = true;
  static recoveryStrategy = RecoveryStrategy.RETRY_WITH_BACKOFF;
  static severity = ErrorSeverity.HIGH;
}

class LLMTimeoutError extends LLMError {
  static errorCode = ErrorCode.LLM_TIMEOUT;
  static retryAfter = 30;
  static severity = ErrorSeverity.MEDIUM;
}

class LLMRateLimitError extends LLMError {
  static errorCode = ErrorCode.LLM_RATE_LIMIT;
  static retryAfter = 60;
  static severity = ErrorSeverity.MEDIUM;
}

class LLMContextLengthError extends LLMError {
  static errorCode = ErrorCode.LLM_CONTEXT_LENGTH;
  static recoverable = true;
  static recoveryStrategy = RecoveryStrategy.FALLBACK;
  static severity = ErrorSeverity.HIGH;
}

class LLMAuthError extends LLMError {
  static errorCode = ErrorCode.LLM_AUTH_ERROR;
  static recoverable = false;
  static recoveryStrategy = RecoveryStrategy.ABORT;
  static severity = ErrorSeverity.CRITICAL;
}

class ToolError extends AgentError {
  static errorCode = ErrorCode.TOOL_ERROR;
  static recoverable = true;
  static recoveryStrategy = RecoveryStrategy.RETRY;
}

class ToolNotFoundError extends ToolError {
  static errorCode = ErrorCode.TOOL_NOT_FOUND;
  static recoverable = false;
  static severity = ErrorSeverity.HIGH;
}

class ToolTimeoutError extends ToolError {
  static errorCode = ErrorCode.TOOL_TIMEOUT;
  static retryAfter = 10;
  static severity = ErrorSeverity.MEDIUM;
}

class ValidationError extends AgentError {
  static errorCode = ErrorCode.VALIDATION_ERROR;
  static recoverable = false;
  static severity = ErrorSeverity.LOW;
}

class ExternalToolError extends AgentError {
  static errorCode = ErrorCode.EXTERNAL_TOOL_ERROR;
  static recoverable = true;
  static severity = ErrorSeverity.MEDIUM;
}

class MaxRetriesExceededError extends AgentError {
  static errorCode = ErrorCode.MAX_RETRIES_EXCEEDED;
  static recoverable = false;
  static severity = ErrorSeverity.HIGH;
}

class ParseError extends AgentError {
  static errorCode = ErrorCode.PARSE_ERROR;
  static recoverable = true;
  static severity = ErrorSeverity.MEDIUM;
}

class StatePersistenceError extends AgentError {
  static errorCode = ErrorCode.PERSISTENCE_ERROR;
  static recoverable = false;
  static severity = ErrorSeverity.HIGH;
}

class ErrorHandler {
  constructor(options = {}) {
    this.logger = options.logger || console;
    this.errorListeners = new Map();
    this.errorLog = [];
    this.maxLogSize = options.maxLogSize || 1000;
  }

  on(errorType, callback) {
    if (!this.errorListeners.has(errorType)) {
      this.errorListeners.set(errorType, []);
    }
    this.errorListeners.get(errorType).push(callback);
    return () => this.off(errorType, callback);
  }

  off(errorType, callback) {
    if (!this.errorListeners.has(errorType)) return;
    const callbacks = this.errorListeners.get(errorType);
    const index = callbacks.indexOf(callback);
    if (index > -1) callbacks.splice(index, 1);
  }

  handle(error, context = null) {
    const errorData = {
      error: error instanceof Error ? error.toDict ? error.toDict() : {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : { message: String(error) },
      context: context?.toDict ? context.toDict() : context,
      handledAt: new Date().toISOString()
    };

    this._logError(errorData);

    const errorType = error?.constructor?.errorCode || ErrorCode.AGENT_ERROR;
    if (this.errorListeners.has(errorType)) {
      for (const callback of this.errorListeners.get(errorType)) {
        try {
          callback(errorData);
        } catch (e) {
          this.logger.error("Error in error handler:", e);
        }
      }
    }

    if (this.errorListeners.has("*")) {
      for (const callback of this.errorListeners.get("*")) {
        try {
          callback(errorData);
        } catch (e) {
          this.logger.error("Error in wildcard error handler:", e);
        }
      }
    }

    return this._determineRecoveryAction(error);
  }

  _logError(errorData) {
    this.errorLog.push(errorData);
    if (this.errorLog.length > this.maxLogSize) {
      this.errorLog.shift();
    }
  }

  _determineRecoveryAction(error) {
    const agentError = error instanceof AgentError ? error : new AgentError(error?.message || String(error));

    return {
      shouldRetry: agentError.recoverable,
      strategy: agentError.recoveryStrategy,
      retryAfter: agentError.retryAfter,
      shouldAbort: agentError.recoveryStrategy === RecoveryStrategy.ABORT,
      shouldFallback: agentError.recoveryStrategy === RecoveryStrategy.FALLBACK,
      shouldSkip: agentError.recoveryStrategy === RecoveryStrategy.SKIP
    };
  }

  getErrorLog(limit = 100, severity = null) {
    let logs = this.errorLog;
    if (severity) {
      logs = logs.filter(e => e.error?.severity === severity);
    }
    return logs.slice(-limit);
  }

  clearErrorLog() {
    this.errorLog = [];
  }

  getErrorStats() {
    const stats = {
      total: this.errorLog.length,
      bySeverity: {},
      byType: {},
      recoverable: 0,
      nonRecoverable: 0
    };

    for (const entry of this.errorLog) {
      const severity = entry.error?.severity || "unknown";
      const type = entry.error?.errorCode || "unknown";

      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.byType[type] = (stats.byType[type] || 0) + 1;

      if (entry.error?.recoverable) {
        stats.recoverable++;
      } else {
        stats.nonRecoverable++;
      }
    }

    return stats;
  }
}

const globalErrorHandler = new ErrorHandler();

export {
  ErrorSeverity,
  RecoveryStrategy,
  ErrorCode,
  ErrorContext,
  AgentError,
  LLMError,
  LLMTimeoutError,
  LLMRateLimitError,
  LLMContextLengthError,
  LLMAuthError,
  ToolError,
  ToolNotFoundError,
  ToolTimeoutError,
  ValidationError,
  ExternalToolError,
  MaxRetriesExceededError,
  ParseError,
  StatePersistenceError,
  ErrorHandler,
  globalErrorHandler
};