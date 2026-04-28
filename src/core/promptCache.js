const CacheStrategy = {
  NONE: "none",
  SYSTEM_ONLY: "system_only",
  SYSTEM_AND_EARLY: "system_early",
  MULTI_POINT: "multi_point"
};

const CacheConfig = {
  enabled: true,
  strategy: CacheStrategy.SYSTEM_AND_EARLY,
  minSystemPromptTokens: 1000,
  earlyMessagesCount: 5,
  multiPointInterval: 10,
  maxCachePoints: 4
};

const CacheStats = {
  cacheHits: 0,
  cacheMisses: 0,
  cachedTokens: 0,
  totalTokens: 0,

  get hitRate() {
    const total = this.cacheHits + this.cacheMisses;
    return total > 0 ? (this.cacheHits / total * 100).toFixed(1) + "%" : "0%";
  },

  get tokenSavings() {
    return this.totalTokens > 0 ? (this.cachedTokens / this.totalTokens * 100).toFixed(1) + "%" : "0%";
  },

  reset() {
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.cachedTokens = 0;
    this.totalTokens = 0;
  }
};

const CACHEABLE_MODELS = {
  "claude-3-5-sonnet": true,
  "claude-3-5-sonnet-20241022": true,
  "claude-3-opus": true,
  "claude-3-opus-20240229": true,
  "claude-3-haiku": true,
  "claude-3-haiku-20240307": true,
  "claude-3-sonnet": true,
  "claude-3-sonnet-20240229": true
};

class PromptCacheManager {
  constructor(config = CacheConfig) {
    this.config = { ...CacheConfig, ...config };
    this.stats = { ...CacheStats };
    this._cacheEnabledForSession = true;
    this._anthropicCacheControl = { type: "ephemeral" };
  }

  supportsCaching(model, provider) {
    if (!this.config.enabled) {
      return false;
    }

    const providerLower = provider?.toLowerCase() || "";

    if (providerLower === "anthropic" || providerLower === "claude") {
      const modelKey = Object.keys(CACHEABLE_MODELS).find(k =>
        model?.toLowerCase().includes(k.toLowerCase())
      );
      return !!modelKey;
    }

    return false;
  }

  selectStrategy(messageCount, systemPromptTokens) {
    if (!this.config.enabled) {
      return CacheStrategy.NONE;
    }

    if (systemPromptTokens < this.config.minSystemPromptTokens) {
      return CacheStrategy.NONE;
    }

    if (messageCount < 10) {
      return CacheStrategy.SYSTEM_ONLY;
    } else if (messageCount < 30) {
      return CacheStrategy.SYSTEM_AND_EARLY;
    } else {
      return CacheStrategy.MULTI_POINT;
    }
  }

  prepareMessagesWithCache(messages, model, provider) {
    if (!this.supportsCaching(model, provider)) {
      return { messages, cacheStats: null };
    }

    const strategy = this.selectStrategy(messages.length, this._estimateTokens(messages[0]?.content || ""));

    const resultMessages = [];
    let cachedMessageCount = 0;

    switch (strategy) {
      case CacheStrategy.SYSTEM_ONLY:
        resultMessages.push(this._wrapWithCacheControl(messages[0]));
        cachedMessageCount = 1;
        resultMessages.push(...messages.slice(1));
        break;

      case CacheStrategy.SYSTEM_AND_EARLY:
        resultMessages.push(this._wrapWithCacheControl(messages[0]));

        const earlyEnd = Math.min(this.config.earlyMessagesCount + 1, messages.length);
        for (let i = 1; i < earlyEnd; i++) {
          resultMessages.push(this._wrapWithCacheControl(messages[i]));
          cachedMessageCount++;
        }
        resultMessages.push(...messages.slice(earlyEnd));
        break;

      case CacheStrategy.MULTI_POINT:
        resultMessages.push(this._wrapWithCacheControl(messages[0]));
        cachedMessageCount = 1;

        const interval = this.config.multiPointInterval;
        const maxCachePoints = this.config.maxCachePoints;

        for (let i = 1; i < messages.length && cachedMessageCount < maxCachePoints * interval; i++) {
          if (i % interval === 0) {
            resultMessages.push(this._wrapWithCacheControl(messages[i]));
            cachedMessageCount++;
          } else {
            resultMessages.push(messages[i]);
          }
        }
        break;

      default:
        return { messages, cacheStats: null };
    }

    const cachedTokens = this._estimateTokens(
      resultMessages.slice(0, cachedMessageCount + 1).map(m => m.content).join("")
    );

    this.stats.cacheHits++;
    this.stats.cachedTokens += cachedTokens;

    return {
      messages: resultMessages,
      cacheStats: {
        strategy,
        cachedMessages: cachedMessageCount,
        cachedTokens,
        hitRate: this.stats.hitRate
      }
    };
  }

  _wrapWithCacheControl(message) {
    if (!message) return message;

    const wrapped = { ...message };

    if (message.role === "system") {
      wrapped.content = [
        { type: "text", text: message.content },
        { type: "cache_control", ...this._anthropicCacheControl }
      ];
    } else if (message.content && typeof message.content === "string") {
      wrapped.content = [
        { type: "text", text: message.content },
        { type: "cache_control", ...this._anthropicCacheControl }
      ];
    }

    return wrapped;
  }

  _estimateTokens(text) {
    if (!text) return 0;
    const chineseChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
    const englishWords = text.replace(/[\u4e00-\u9fff]/g, ' ').split(/\s+/).filter(w => w.length > 0).length;
    return Math.ceil(chineseChars * 2.0 + englishWords * 1.3);
  }

  getStats() {
    return {
      ...this.stats,
      cacheEnabled: this._cacheEnabledForSession
    };
  }

  disable() {
    this._cacheEnabledForSession = false;
  }

  enable() {
    this._cacheEnabledForSession = true;
  }
}

export { CacheStrategy, CacheConfig, CacheStats, CACHEABLE_MODELS, PromptCacheManager };