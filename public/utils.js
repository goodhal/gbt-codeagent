function debounce(fn, delay = 300) {
  let timer = null;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

function throttle(fn, delay = 300) {
  let last = 0;
  return function(...args) {
    const now = Date.now();
    if (now - last >= delay) {
      last = now;
      fn.apply(this, args);
    }
  };
}

const Hotkeys = {
  handlers: {},

  init() {
    document.addEventListener('keydown', (e) => {
      let key = '';
      if (e.ctrlKey) key += 'ctrl+';
      if (e.shiftKey) key += 'shift+';
      if (e.altKey) key += 'alt+';
      key += e.key.toLowerCase();
      
      if (this.handlers[key]) {
        e.preventDefault();
        this.handlers[key]();
      }
    });
  },

  register(key, handler) {
    this.handlers[key] = handler;
  },

  unregister(key) {
    delete this.handlers[key];
  }
};

function renderSkeleton(type) {
  switch(type) {
    case 'card':
      return `
        <div class="skeleton skeleton-card">
          <div class="skeleton-line" style="width: 60%; height: 20px; margin-bottom: 12px;"></div>
          <div class="skeleton-line" style="width: 100%; height: 14px; margin-bottom: 8px;"></div>
          <div class="skeleton-line" style="width: 80%; height: 14px;"></div>
        </div>
      `;
    case 'list':
      return Array.from({ length: 5 }, () => `
        <div class="skeleton skeleton-row">
          <div class="skeleton-line" style="width: 30%; height: 16px;"></div>
          <div class="skeleton-line" style="width: 70%; height: 14px;"></div>
        </div>
      `).join('');
    case 'grid':
      return Array.from({ length: 4 }, () => `
        <div class="skeleton skeleton-card">
          <div class="skeleton-line" style="width: 40%; height: 18px; margin-bottom: 10px;"></div>
          <div class="skeleton-line" style="width: 100%; height: 12px; margin-bottom: 6px;"></div>
          <div class="skeleton-line" style="width: 90%; height: 12px;"></div>
        </div>
      `).join('');
    default:
      return '';
  }
}

const PerformanceMonitor = {
  metrics: {
    requests: 0,
    errors: 0,
    timings: {}
  },

  start(key) {
    this.metrics.timings[key] = performance.now();
  },

  end(key) {
    if (this.metrics.timings[key]) {
      const duration = performance.now() - this.metrics.timings[key];
      this.metrics.timings[key] = duration;
      console.log(`[Performance] ${key}: ${duration.toFixed(2)}ms`);
      return duration;
    }
  },

  recordRequest(url, success) {
    this.metrics.requests++;
    if (!success) this.metrics.errors++;
  },

  getMetrics() {
    return this.metrics;
  }
};

export {
  debounce,
  throttle,
  Hotkeys,
  renderSkeleton,
  PerformanceMonitor
};
