const random = Math.random;

const Sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const RetryConfig = {
  maxAttempts: 3,
  baseDelay: 1000,
  maxDelay: 60000,
  exponentialBase: 2,
  jitter: true,
  jitterFactor: 0.5,
  retryableErrors: [
    'ECONNRESET',
    'ETIMEDOUT',
    'ECONNREFUSED',
    'socket hang up',
    'network error',
    'rate limit',
    '429',
    '503',
    '504'
  ],
  retryableStatusCodes: [429, 500, 502, 503, 504],
  backoffStrategy: 'exponential',
  onRetry: null,
  onFail: null,
  maxTotalDelay: null
};

function isRetryable(error, config = RetryConfig) {
  if (!error) return false;
  
  const errorStr = String(error).toLowerCase();
  
  for (const err of config.retryableErrors) {
    if (errorStr.includes(err.toLowerCase())) {
      return true;
    }
  }

  if (error.statusCode && config.retryableStatusCodes.includes(error.statusCode)) {
    return true;
  }

  if (error.response?.status && config.retryableStatusCodes.includes(error.response.status)) {
    return true;
  }

  return false;
}

function calculateDelay(attempt, config = RetryConfig) {
  let delay;

  switch (config.backoffStrategy) {
    case 'linear':
      delay = config.baseDelay * (attempt + 1);
      break;
    case 'exponential':
    default:
      delay = config.baseDelay * Math.pow(config.exponentialBase, attempt);
      break;
    case 'fibonacci':
      delay = config.baseDelay * fibonacci(attempt + 1);
      break;
    case 'constant':
      delay = config.baseDelay;
      break;
  }

  delay = Math.min(delay, config.maxDelay);

  if (config.jitter) {
    const jitterRange = delay * config.jitterFactor;
    delay = delay + (random() * 2 - 1) * jitterRange;
  }

  return Math.max(0, delay);
}

function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

async function withRetry(fn, config = RetryConfig) {
  const mergedConfig = { ...RetryConfig, ...config };
  let lastError;
  let totalDelay = 0;

  for (let attempt = 0; attempt < mergedConfig.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt === mergedConfig.maxAttempts - 1) {
        if (mergedConfig.onFail) {
          mergedConfig.onFail(error, attempt + 1, mergedConfig.maxAttempts);
        }
        break;
      }

      if (!isRetryable(error, mergedConfig)) {
        throw error;
      }

      const delay = calculateDelay(attempt, mergedConfig);

      if (mergedConfig.maxTotalDelay && totalDelay + delay > mergedConfig.maxTotalDelay) {
        if (mergedConfig.onFail) {
          mergedConfig.onFail(error, attempt + 1, mergedConfig.maxAttempts);
        }
        throw lastError;
      }

      totalDelay += delay;

      if (mergedConfig.onRetry) {
        mergedConfig.onRetry(error, attempt + 1, mergedConfig.maxAttempts, delay);
      } else {
        console.log(`[重试] 第 ${attempt + 1} 次失败，${delay.toFixed(0)}ms 后重试...`);
      }

      await Sleep(delay);
    }
  }

  throw lastError;
}

async function withRetryWithFallback(fn, fallbackFn, config = RetryConfig) {
  try {
    return await withRetry(fn, config);
  } catch (error) {
    if (typeof fallbackFn === 'function') {
      console.log(`[重试] 所有重试失败，执行降级方案...`);
      return await fallbackFn(error);
    }
    throw error;
  }
}

function createRetryDecorator(config = RetryConfig) {
  return function(target, propertyKey, descriptor) {
    const originalMethod = descriptor.value;
    descriptor.value = async function(...args) {
      return await withRetry(() => originalMethod.apply(this, args), config);
    };
    return descriptor;
  };
}

export { 
  withRetry, 
  withRetryWithFallback,
  createRetryDecorator,
  isRetryable, 
  calculateDelay, 
  RetryConfig 
};