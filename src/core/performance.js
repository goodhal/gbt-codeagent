import { performance } from "node:perf_hooks";

// 性能监控
const metrics = {
  requests: {
    total: 0,
    success: 0,
    failed: 0,
    durations: []
  },
  api: {},
  cache: {
    hits: 0,
    misses: 0
  }
};

export function recordRequest(path, duration, success) {
  metrics.requests.total++;
  if (success) {
    metrics.requests.success++;
  } else {
    metrics.requests.failed++;
  }
  metrics.requests.durations.push(duration);
  if (metrics.requests.durations.length > 1000) {
    metrics.requests.durations.shift();
  }
  if (!metrics.api[path]) {
    metrics.api[path] = { count: 0, durations: [] };
  }
  metrics.api[path].count++;
  metrics.api[path].durations.push(duration);
  if (metrics.api[path].durations.length > 100) {
    metrics.api[path].durations.shift();
  }
}

export function getPerformanceMetrics() {
  const durations = metrics.requests.durations;
  const avgDuration = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;
  const sorted = [...durations].sort((a, b) => a - b);
  const p95 = sorted.length >= 95 ? sorted[Math.floor(sorted.length * 0.95)] : 0;
  const p99 = sorted.length >= 99 ? sorted[Math.floor(sorted.length * 0.99)] : 0;
  return {
    requests: {
      ...metrics.requests,
      avgDuration,
      p95,
      p99
    },
    api: Object.fromEntries(
      Object.entries(metrics.api).map(([path, data]) => {
        const avg = data.durations.length ? data.durations.reduce((a, b) => a + b, 0) / data.durations.length : 0;
        return [path, { count: data.count, avgDuration: avg }];
      })
    ),
    cache: metrics.cache,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };
}

// 内存缓存
const cache = new Map();
const cacheTimers = new Map();

const DEFAULT_TTL = 5 * 60 * 1000; // 5分钟

export function setCache(key, value, ttl = DEFAULT_TTL) {
  cache.set(key, { value, expires: Date.now() + ttl });
  if (cacheTimers.has(key)) {
    clearTimeout(cacheTimers.get(key));
  }
  if (ttl > 0) {
    const timer = setTimeout(() => {
      cache.delete(key);
      cacheTimers.delete(key);
    }, ttl);
    cacheTimers.set(key, timer);
  }
}

export function getCache(key) {
  const entry = cache.get(key);
  if (!entry) {
    metrics.cache.misses++;
    return undefined;
  }
  if (entry.expires < Date.now()) {
    cache.delete(key);
    metrics.cache.misses++;
    return undefined;
  }
  metrics.cache.hits++;
  return entry.value;
}

export function deleteCache(key) {
  cache.delete(key);
  if (cacheTimers.has(key)) {
    clearTimeout(cacheTimers.get(key));
    cacheTimers.delete(key);
  }
}

export function clearCache() {
  cache.clear();
  for (const timer of cacheTimers.values()) {
    clearTimeout(timer);
  }
  cacheTimers.clear();
}

// 性能装饰器
export function measurePerformance(fn, name) {
  return async (...args) => {
    const start = performance.now();
    try {
      const result = await fn(...args);
      const duration = performance.now() - start;
      recordRequest(name, duration, true);
      return result;
    } catch (error) {
      const duration = performance.now() - start;
      recordRequest(name, duration, false);
      throw error;
    }
  };
}

export function withCache(fn, keyFn, ttl = DEFAULT_TTL) {
  return async (...args) => {
    const key = keyFn ? keyFn(...args) : JSON.stringify(args);
    const cached = getCache(key);
    if (cached !== undefined) {
      return cached;
    }
    const result = await fn(...args);
    setCache(key, result, ttl);
    return result;
  };
}

// 连接池 (简化版用于演示)
const connectionPool = {
  size: 10,
  available: [],
  inUse: new Set(),
  createConnection: null,
  destroyConnection: null,
  
  init({ size = 10, createConnection, destroyConnection }) {
    this.size = size;
    this.createConnection = createConnection;
    this.destroyConnection = destroyConnection;
    for (let i = 0; i < size; i++) {
      this.available.push(createConnection());
    }
  },
  
  async acquire() {
    if (this.available.length > 0) {
      const conn = this.available.pop();
      this.inUse.add(conn);
      return conn;
    }
    if (this.createConnection) {
      const conn = this.createConnection();
      this.inUse.add(conn);
      return conn;
    }
    await new Promise(resolve => {
      const check = setInterval(() => {
        if (this.available.length > 0) {
          clearInterval(check);
          resolve();
        }
      }, 100);
    });
    return this.acquire();
  },
  
  release(conn) {
    this.inUse.delete(conn);
    if (this.available.length < this.size) {
      this.available.push(conn);
    } else if (this.destroyConnection) {
      this.destroyConnection(conn);
    }
  }
};

export { connectionPool };
