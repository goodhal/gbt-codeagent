const CircuitState = {
  CLOSED: 'closed',
  OPEN: 'open',
  HALF_OPEN: 'half_open'
};

const CircuitBreakerConfig = {
  failureThreshold: 5,
  successThreshold: 3,
  recoveryTimeout: 30000,
  halfOpenMaxCalls: 3
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
  }

  get failureRate() {
    return this.totalCalls > 0 ? this.failedCalls / this.totalCalls : 0;
  }

  recordSuccess() {
    this.totalCalls++;
    this.successfulCalls++;
    this.consecutiveSuccesses++;
    this.consecutiveFailures = 0;
  }

  recordFailure() {
    this.totalCalls++;
    this.failedCalls++;
    this.consecutiveFailures++;
    this.consecutiveSuccesses = 0;
    this.lastFailureTime = Date.now();
  }

  recordRejection() {
    this.rejectedCalls++;
  }

  reset() {
    this.totalCalls = 0;
    this.successfulCalls = 0;
    this.failedCalls = 0;
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
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
  }

  get currentState() {
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this._lastStateChange;
      if (elapsed >= this.config.recoveryTimeout) {
        this.state = CircuitState.HALF_OPEN;
        this._halfOpenCalls = 0;
        console.log(`[熔断器] ${this.name} 从 OPEN 转为 HALF_OPEN`);
      }
    }
    return this.state;
  }

  async call(fn) {
    const state = this.currentState;

    if (state === CircuitState.OPEN) {
      this.stats.recordRejection();
      throw new CircuitOpenError(`[熔断器] ${this.name} 处于 OPEN 状态，拒绝调用`);
    }

    if (state === CircuitState.HALF_OPEN) {
      if (this._halfOpenCalls >= this.config.halfOpenMaxCalls) {
        this.stats.recordRejection();
        throw new CircuitOpenError(`[熔断器] ${this.name} HALF_OPEN 状态已达到最大调用次数`);
      }
      this._halfOpenCalls++;
    }

    try {
      const result = await fn();
      this._onSuccess();
      return result;
    } catch (error) {
      this._onFailure(error);
      throw error;
    }
  }

  _onSuccess() {
    if (this.state === CircuitState.HALF_OPEN) {
      if (this.stats.consecutiveSuccesses >= this.config.successThreshold) {
        this.state = CircuitState.CLOSED;
        this.stats.reset();
        console.log(`[熔断器] ${this.name} 从 HALF_OPEN 恢复为 CLOSED`);
      }
    } else {
      this.stats.recordSuccess();
    }
    this._lastStateChange = Date.now();
  }

  _onFailure(error) {
    this.stats.recordFailure();

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      this._lastStateChange = Date.now();
      console.log(`[熔断器] ${this.name} 从 HALF_OPEN 转为 OPEN（HALF_OPEN 状态下失败）`);
    } else if (this.stats.consecutiveFailures >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      this._lastStateChange = Date.now();
      console.log(`[熔断器] ${this.name} 从 CLOSED 转为 OPEN（连续失败 ${this.stats.consecutiveFailures} 次）`);
    }
  }

  getStatus() {
    return {
      name: this.name,
      state: this.currentState,
      stats: {
        totalCalls: this.stats.totalCalls,
        successfulCalls: this.stats.successfulCalls,
        failedCalls: this.stats.failedCalls,
        rejectedCalls: this.stats.rejectedCalls,
        failureRate: this.stats.failureRate.toFixed(2),
        consecutiveFailures: this.stats.consecutiveFailures,
        consecutiveSuccesses: this.stats.consecutiveSuccesses
      },
      config: this.config
    };
  }

  reset() {
    this.state = CircuitState.CLOSED;
    this.stats.reset();
    this._halfOpenCalls = 0;
    this._lastStateChange = Date.now();
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

export { CircuitBreaker, CircuitOpenError, CircuitState, CircuitStats, CircuitBreakerConfig };