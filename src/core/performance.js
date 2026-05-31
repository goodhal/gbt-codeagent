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
