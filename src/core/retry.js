const random = Math.random;

const Sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const RetryConfig = {
  maxAttempts: 3,
  baseDelay: 1000,
  maxDelay: 60000,
  exponentialBase: 2,
  jitter: true,
  jitterFactor: 0.5
};

const RetryableErrors = [
  'ECONNRESET',
  'ETIMEDOUT',
  'ECONNREFUSED',
  'socket hang up',
  'network error',
  'rate limit',
  '429',
  '503',
  '504'
];

function isRetryable(error) {
  if (!error) return false;
  const errorStr = String(error).toLowerCase();
  return RetryableErrors.some(e => errorStr.includes(e.toLowerCase()));
}

function calculateDelay(attempt, config = RetryConfig) {
  const delay = Math.min(
    config.baseDelay * Math.pow(config.exponentialBase, attempt),
    config.maxDelay
  );

  if (config.jitter) {
    const jitterRange = delay * config.jitterFactor;
    return delay + (random() * 2 - 1) * jitterRange;
  }
  return delay;
}

async function withRetry(fn, config = RetryConfig) {
  let lastError;

  for (let attempt = 0; attempt < config.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt === config.maxAttempts - 1) {
        break;
      }

      if (!isRetryable(error)) {
        throw error;
      }

      const delay = calculateDelay(attempt, config);
      console.log(`[重试] 第 ${attempt + 1} 次失败，${delay.toFixed(0)}ms 后重试...`);
      await Sleep(delay);
    }
  }

  throw lastError;
}

export { withRetry, isRetryable, calculateDelay, RetryConfig };