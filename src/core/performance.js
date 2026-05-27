/**
 * 性能监控模块（精简版）
 * 用于请求记录和性能指标收集
 */
import { performance } from "node:perf_hooks";

const requestStats = {
  total: 0,
  successful: 0,
  failed: 0,
  byPath: {},
  startTime: Date.now(),
};

export function recordRequest(path, duration, success) {
  requestStats.total++;
  if (success) requestStats.successful++;
  else requestStats.failed++;

  if (!requestStats.byPath[path]) {
    requestStats.byPath[path] = { count: 0, totalDuration: 0 };
  }
  requestStats.byPath[path].count++;
  requestStats.byPath[path].totalDuration += duration;
}

export function getPerformanceMetrics() {
  const now = Date.now();
  return {
    uptime: now - requestStats.startTime,
    totalRequests: requestStats.total,
    successfulRequests: requestStats.successful,
    failedRequests: requestStats.failed,
    byPath: requestStats.byPath,
    memoryUsage: process.memoryUsage(),
  };
}

// 保留未使用的导出以避免 import 断裂
export function getCache() { return null; }
export function setCache() {}
export function withCache(fn) { return fn(); }
export function measurePerformance(fn) { return fn(); }
