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
    this.rollingFailures = [];
    this.rollingSuccesses = [];
  }

  get failureRate() {
    return this.totalCalls > 0 ? this.failedCalls / this.totalCalls : 0;
  }

  get rollingFailureRate() {
    const total = this.rollingFailures.length + this.rollingSuccesses.length;
    return total > 0 ? this.rollingFailures.length / total : 0;
  }

  recordSuccess() {
    this.totalCalls++;
    this.successfulCalls++;
    this.consecutiveSuccesses++;
    this.consecutiveFailures = 0;
    this.lastSuccessTime = Date.now();
    this._updateRollingWindow('success');
  }

  recordFailure(errorType = 'unknown') {
    this.totalCalls++;
    this.failedCalls++;
    this.consecutiveFailures++;
    this.consecutiveSuccesses = 0;
    this.lastFailureTime = Date.now();
    this._updateRollingWindow('failure');
  }

  recordRejection() {
    this.rejectedCalls++;
  }

  _updateRollingWindow(resultType) {
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
    this.rollingFailures = [];
    this.rollingSuccesses = [];
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
      this._onSuccess();
      return result;
    } catch (error) {
      const errorType = this._extractErrorType(error);
      this._onFailure(errorType);
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

    console.log(`[熔断器] ${this.name} 从 ${oldState} 转为 ${newState}`);

    if (this.config.onStateChange) {
      this.config.onStateChange(this.name, oldState, newState);
    }
  }

  _onSuccess() {
    this.stats.recordSuccess();

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.stats.consecutiveSuccesses >= this.config.successThreshold) {
        this._transitionToState(CircuitState.CLOSED);
        this.stats.reset();
      }
    }
    this._lastStateChange = Date.now();
  }

  _onFailure(errorType) {
    this.stats.recordFailure(errorType);

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

  forceClose() {
    if (this.state !== CircuitState.CLOSED) {
      this._transitionToState(CircuitState.CLOSED);
      this.stats.reset();
      this._halfOpenCalls = 0;
    }
  }

  reset() {
    this._transitionToState(CircuitState.CLOSED);
    this.stats.reset();
    this._halfOpenCalls = 0;
    console.log(`[熔断器] ${this.name} 已重置`);
  }
}

class CircuitOpenError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CircuitOpenError';
    this.recoverable = true;
  }
}

export { CircuitBreaker, CircuitOpenError, CircuitState, CircuitBreakerConfig };
