class RateLimiterConfig {
  constructor(rate = 10, burst = 20, name = "default") {
    this.rate = rate;
    this.burst = burst;
    this.name = name;
  }
}

class TokenBucketRateLimiter {
  constructor(config = new RateLimiterConfig()) {
    this.rate = config.rate;
    this.burst = config.burst;
    this.name = config.name;
    this.tokens = config.burst;
    this.lastUpdate = Date.now();
    this._lock = false;
  }

  _replenish() {
    const now = Date.now();
    const elapsed = (now - this.lastUpdate) / 1000;
    const tokensToAdd = elapsed * this.rate;
    this.tokens = Math.min(this.burst, this.tokens + tokensToAdd);
    this.lastUpdate = now;
  }

  async acquire(tokens = 1, timeoutMs = 30000) {
    const startTime = Date.now();

    while (true) {
      while (this._lock) {
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      this._lock = true;

      try {
        this._replenish();

        if (this.tokens >= tokens) {
          this.tokens -= tokens;
          return true;
        }

        const tokensNeeded = tokens - this.tokens;
        const waitTimeMs = (tokensNeeded / this.rate) * 1000;

        this._lock = false;

        if (Date.now() - startTime + waitTimeMs > timeoutMs) {
          return false;
        }

        await new Promise(resolve => setTimeout(resolve, Math.min(waitTimeMs, 100)));
      } finally {
        this._lock = false;
      }
    }
  }

  tryAcquire(tokens = 1) {
    this._replenish();

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  getAvailableTokens() {
    this._replenish();
    return Math.floor(this.tokens);
  }

  getStatus() {
    this._replenish();
    return {
      name: this.name,
      availableTokens: this.getAvailableTokens(),
      rate: this.rate,
      burst: this.burst,
      usagePercent: ((this.tokens / this.burst) * 100).toFixed(1)
    };
  }

  reset() {
    this.tokens = this.burst;
    this.lastUpdate = Date.now();
  }
}

class RateLimiterRegistry {
  constructor() {
    this.limiters = new Map();
  }

  get(name) {
    if (!this.limiters.has(name)) {
      this.limiters.set(name, new TokenBucketRateLimiter({ name }));
    }
    return this.limiters.get(name);
  }

  create(name, config) {
    const limiter = new TokenBucketRateLimiter({ ...config, name });
    this.limiters.set(name, limiter);
    return limiter;
  }

  remove(name) {
    return this.limiters.delete(name);
  }

  clear() {
    this.limiters.clear();
  }

  getAllStatus() {
    const status = {};
    for (const [name, limiter] of this.limiters) {
      status[name] = limiter.getStatus();
    }
    return status;
  }
}

const globalRateLimiterRegistry = new RateLimiterRegistry();

export { RateLimiterConfig, TokenBucketRateLimiter, RateLimiterRegistry, globalRateLimiterRegistry };