import { performance } from "node:perf_hooks";

const MAX_DURATIONS = 1000;
const MAX_API_DURATIONS = 100;
const MAX_CACHE_SIZE = 2000;

const metrics = {
  requests: {
    total: 0,
    success: 0,
    failed: 0,
    durations: new Array(MAX_DURATIONS),
    _writeIdx: 0,
    _count: 0
  },
  api: {},
  cache: {
    hits: 0,
    misses: 0
  }
};

function _addToBuffer(buf, maxSize, value) {
  buf[buf._writeIdx] = value;
  buf._writeIdx = (buf._writeIdx + 1) % maxSize;
  if (buf._count < maxSize) buf._count++;
}

function _getBufferValues(buf) {
  const { _writeIdx, _count } = buf;
  if (_count < buf.length) return buf.slice(0, _count);
  const result = new Array(_count);
  let idx = _writeIdx;
  for (let i = 0; i < _count; i++) {
    result[i] = buf[idx % buf.length];
    idx++;
  }
  return result;
}

export function recordRequest(path, duration, success) {
  metrics.requests.total++;
  if (success) {
    metrics.requests.success++;
  } else {
    metrics.requests.failed++;
  }
  _addToBuffer(metrics.requests.durations, MAX_DURATIONS, duration);

  if (!metrics.api[path]) {
    metrics.api[path] = {
      count: 0,
      durations: new Array(MAX_API_DURATIONS),
      _writeIdx: 0,
      _count: 0
    };
  }
  metrics.api[path].count++;
  _addToBuffer(metrics.api[path].durations, MAX_API_DURATIONS, duration);
}

export function getPerformanceMetrics() {
  const durations = _getBufferValues(metrics.requests.durations);
  const avgDuration = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;
  const sorted = [...durations].sort((a, b) => a - b);
  const p95 = sorted.length >= 95 ? sorted[Math.floor(sorted.length * 0.95)] : 0;
  const p99 = sorted.length >= 99 ? sorted[Math.floor(sorted.length * 0.99)] : 0;
  return {
    requests: {
      total: metrics.requests.total,
      success: metrics.requests.success,
      failed: metrics.requests.failed,
      durations: _getBufferValues(metrics.requests.durations),
      avgDuration,
      p95,
      p99
    },
    api: Object.fromEntries(
      Object.entries(metrics.api).map(([path, data]) => {
        const raw = _getBufferValues(data.durations);
        const avg = raw.length ? raw.reduce((a, b) => a + b, 0) / raw.length : 0;
        return [path, { count: data.count, avgDuration: avg }];
      })
    ),
    cache: metrics.cache,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };
}

const cache = new Map();
const cacheTimers = new Map();

const DEFAULT_TTL = 5 * 60 * 1000;

export function setCache(key, value, ttl = DEFAULT_TTL) {
  if (cache.size >= MAX_CACHE_SIZE && !cache.has(key)) {
    const iter = cache.keys().next();
    if (!iter.done) {
      const oldestKey = iter.value;
      if (cacheTimers.has(oldestKey)) {
        clearTimeout(cacheTimers.get(oldestKey));
        cacheTimers.delete(oldestKey);
      }
      cache.delete(oldestKey);
    }
  }
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
