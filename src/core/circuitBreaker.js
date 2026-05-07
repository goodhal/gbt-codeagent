const CircuitState = {
  CLOSED: 'closed',
  OPEN: 'open',
  HALF_OPEN: 'half_open'
};

const CircuitBreakerConfig = {
  failureThreshold: 5,
  successThreshold: 3,
  recoveryTimeout: 30000,
  halfOpenMaxCalls: 3,
  rollingWindowSize: 100,
  minSamples: 10,
  onStateChange: null,
  onRejection: null,
  failureRateThreshold: 0.5
};

class CircuitStats {
  constructor() {
    this.totalCalls = 0;
    this.successfulCalls = 0;
    this.failedCalls = 0;
    this.rejectedCalls = 0;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.lastFailureTime = null;
    this.lastSuccessTime = null;
    this.totalLatency = 0;
    this.minLatency = Infinity;
    this.maxLatency = 0;
    this.callTimestamps = [];
    this.rollingFailures = [];
    this.rollingSuccesses = [];
    this.stateTransitions = [];
    this.errorTypes = new Map();
  }

  get failureRate() {
    return this.totalCalls > 0 ? this.failedCalls / this.totalCalls : 0;
  }

  get rollingFailureRate() {
    const total = this.rollingFailures.length + this.rollingSuccesses.length;
    return total > 0 ? this.rollingFailures.length / total : 0;
  }

  get avgLatency() {
    return this.totalCalls > 0 ? this.totalLatency / this.totalCalls : 0;
  }

  recordSuccess(latency = 0) {
    this.totalCalls++;
    this.successfulCalls++;
    this.consecutiveSuccesses++;
    this.consecutiveFailures = 0;
    this.lastSuccessTime = Date.now();
    this._updateLatency(latency);
    this._updateRollingWindow('success');
  }

  recordFailure(latency = 0, errorType = 'unknown') {
    this.totalCalls++;
    this.failedCalls++;
    this.consecutiveFailures++;
    this.consecutiveSuccesses = 0;
    this.lastFailureTime = Date.now();
    this._updateLatency(latency);
    this._updateRollingWindow('failure');
    this.errorTypes.set(errorType, (this.errorTypes.get(errorType) || 0) + 1);
  }

  recordRejection() {
    this.rejectedCalls++;
  }

  recordStateTransition(fromState, toState) {
    this.stateTransitions.push({
      from: fromState,
      to: toState,
      timestamp: Date.now()
    });
  }

  _updateLatency(latency) {
    this.totalLatency += latency;
    this.minLatency = Math.min(this.minLatency, latency);
    this.maxLatency = Math.max(this.maxLatency, latency);
  }

  _updateRollingWindow(resultType, windowSize = 100) {
    const timestamp = Date.now();
    if (resultType === 'failure') {
      this.rollingFailures.push(timestamp);
    } else {
      this.rollingSuccesses.push(timestamp);
    }

    const cutoff = timestamp - 60000;
    this.rollingFailures = this.rollingFailures.filter(t => t > cutoff);
    this.rollingSuccesses = this.rollingSuccesses.filter(t => t > cutoff);
  }

  reset() {
    this.totalCalls = 0;
    this.successfulCalls = 0;
    this.failedCalls = 0;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.totalLatency = 0;
    this.minLatency = Infinity;
    this.maxLatency = 0;
    this.rollingFailures = [];
    this.rollingSuccesses = [];
    this.errorTypes.clear();
  }

  getRecentHistory(minutes = 5) {
    const cutoff = Date.now() - minutes * 60 * 1000;
    const recentFailures = this.rollingFailures.filter(t => t > cutoff);
    const recentSuccesses = this.rollingSuccesses.filter(t => t > cutoff);
    return {
      recentFailures: recentFailures.length,
      recentSuccesses: recentSuccesses.length,
      recentFailureRate: recentFailures.length + recentSuccesses.length > 0
        ? recentFailures.length / (recentFailures.length + recentSuccesses.length)
        : 0
    };
  }
}

class CircuitBreaker {
  constructor(name, config = CircuitBreakerConfig) {
    this.name = name;
    this.config = { ...CircuitBreakerConfig, ...config };
    this.state = CircuitState.CLOSED;
    this.stats = new CircuitStats();
    this._halfOpenCalls = 0;
    this._lastStateChange = Date.now();
    this._lock = false;
    this._pendingRequests = 0;
  }

  get currentState() {
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this._lastStateChange;
      if (elapsed >= this.config.recoveryTimeout) {
        this._transitionToState(CircuitState.HALF_OPEN);
        this._halfOpenCalls = 0;
      }
    }
    return this.state;
  }

  get pendingRequests() {
    return this._pendingRequests;
  }

  async call(fn, options = {}) {
    const state = this.currentState;
    const startTime = Date.now();

    if (state === CircuitState.OPEN) {
      this.stats.recordRejection();
      if (this.config.onRejection) {
        this.config.onRejection(this.name, state);
      }
      throw new CircuitOpenError(`[熔断器] ${this.name} 处于 OPEN 状态，拒绝调用`);
    }

    if (state === CircuitState.HALF_OPEN) {
      if (this._halfOpenCalls >= this.config.halfOpenMaxCalls) {
        this.stats.recordRejection();
        if (this.config.onRejection) {
          this.config.onRejection(this.name, state);
        }
        throw new CircuitOpenError(`[熔断器] ${this.name} HALF_OPEN 状态已达到最大调用次数`);
      }
      this._halfOpenCalls++;
    }

    this._pendingRequests++;

    try {
      const result = await fn();
      const latency = Date.now() - startTime;
      this._onSuccess(latency);
      return result;
    } catch (error) {
      const latency = Date.now() - startTime;
      const errorType = this._extractErrorType(error);
      this._onFailure(latency, errorType);
      throw error;
    } finally {
      this._pendingRequests--;
    }
  }

  async callWithFallback(fn, fallbackFn, options = {}) {
    try {
      return await this.call(fn, options);
    } catch (error) {
      if (error instanceof CircuitOpenError && typeof fallbackFn === 'function') {
        console.log(`[熔断器] ${this.name} 熔断触发，执行降级方案`);
        return await fallbackFn(error);
      }
      throw error;
    }
  }

  _transitionToState(newState) {
    const oldState = this.state;
    if (oldState === newState) return;

    this.state = newState;
    this._lastStateChange = Date.now();
    this.stats.recordStateTransition(oldState, newState);

    console.log(`[熔断器] ${this.name} 从 ${oldState} 转为 ${newState}`);

    if (this.config.onStateChange) {
      this.config.onStateChange(this.name, oldState, newState);
    }
  }

  _onSuccess(latency) {
    this.stats.recordSuccess(latency);

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.stats.consecutiveSuccesses >= this.config.successThreshold) {
        this._transitionToState(CircuitState.CLOSED);
        this.stats.reset();
      }
    }
    this._lastStateChange = Date.now();
  }

  _onFailure(latency, errorType) {
    this.stats.recordFailure(latency, errorType);

    const shouldOpen = this._shouldOpenCircuit();

    if (this.state === CircuitState.HALF_OPEN) {
      this._transitionToState(CircuitState.OPEN);
    } else if (shouldOpen) {
      this._transitionToState(CircuitState.OPEN);
    }
  }

  _shouldOpenCircuit() {
    if (this.stats.consecutiveFailures >= this.config.failureThreshold) {
      return true;
    }

    if (this.stats.totalCalls >= this.config.minSamples) {
      if (this.stats.rollingFailureRate >= this.config.failureRateThreshold) {
        return true;
      }
    }

    return false;
  }

  _extractErrorType(error) {
    if (error && typeof error === 'object') {
      if (error.code) return error.code;
      if (error.statusCode) return `HTTP_${error.statusCode}`;
      if (error.response?.status) return `HTTP_${error.response.status}`;
      if (error.name) return error.name;
    }
    return 'unknown';
  }

  forceOpen() {
    if (this.state !== CircuitState.OPEN) {
      this._transitionToState(CircuitState.OPEN);
    }
  }

  forceClose() {
    if (this.state !== CircuitState.CLOSED) {
      this._transitionToState(CircuitState.CLOSED);
      this.stats.reset();
      this._halfOpenCalls = 0;
    }
  }

  getStatus() {
    const recentHistory = this.stats.getRecentHistory(5);
    return {
      name: this.name,
      state: this.currentState,
      lastStateChange: this._lastStateChange,
      pendingRequests: this._pendingRequests,
      stats: {
        totalCalls: this.stats.totalCalls,
        successfulCalls: this.stats.successfulCalls,
        failedCalls: this.stats.failedCalls,
        rejectedCalls: this.stats.rejectedCalls,
        failureRate: this.stats.failureRate.toFixed(2),
        rollingFailureRate: this.stats.rollingFailureRate.toFixed(2),
        consecutiveFailures: this.stats.consecutiveFailures,
        consecutiveSuccesses: this.stats.consecutiveSuccesses,
        avgLatency: this.stats.avgLatency.toFixed(2),
        minLatency: this.stats.minLatency,
        maxLatency: this.stats.maxLatency,
        lastFailureTime: this.stats.lastFailureTime,
        lastSuccessTime: this.stats.lastSuccessTime,
        errorTypes: Object.fromEntries(this.stats.errorTypes),
        ...recentHistory
      },
      config: this.config,
      stateTransitions: this.stats.stateTransitions.slice(-10)
    };
  }

  reset() {
    this._transitionToState(CircuitState.CLOSED);
    this.stats.reset();
    this._halfOpenCalls = 0;
    console.log(`[熔断器] ${this.name} 已重置`);
  }

  getHealthScore() {
    const status = this.getStatus();
    const { state, stats } = status;

    let score = 100;

    if (state === CircuitState.OPEN) {
      score -= 50;
    } else if (state === CircuitState.HALF_OPEN) {
      score -= 25;
    }

    score -= stats.failureRate * 30;
    score -= stats.rollingFailureRate * 20;

    return Math.max(0, Math.min(100, score));
  }
}

class CircuitOpenError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CircuitOpenError';
    this.recoverable = true;
  }
}

export { CircuitBreaker, CircuitOpenError, CircuitState, CircuitStats, CircuitBreakerConfig };