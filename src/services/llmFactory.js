const LLMProvider = {
  OPENAI: "openai",
  ANTHROPIC: "anthropic",
  GEMINI: "gemini",
  QWEN: "qwen",
  DEEPSEEK: "deepseek",
  BAIDU: "baidu",
  MINIMAX: "minimax",
  DOUBAO: "doubao",
  CUSTOM: "custom"
};

const DEFAULT_MODELS = {
  [LLMProvider.OPENAI]: "gpt-4o-mini",
  [LLMProvider.ANTHROPIC]: "claude-3-5-sonnet-20241022",
  [LLMProvider.GEMINI]: "gemini-2.0-flash",
  [LLMProvider.QWEN]: "qwen-plus",
  [LLMProvider.DEEPSEEK]: "deepseek-chat",
  [LLMProvider.BAIDU]: "ernie-4.0-8k",
  [LLMProvider.MINIMAX]: "abab6.5s-chat",
  [LLMProvider.DOUBAO]: "doubao-pro-32k",
  [LLMProvider.CUSTOM]: "custom"
};

const COMPATIBILITY_MODE = {
  OPENAI: "openai",
  ANTHROPIC: "anthropic",
  GEMINI: "gemini"
};

class LLMConfig {
  constructor({
    provider = LLMProvider.OPENAI,
    model = null,
    apiKey = null,
    baseUrl = null,
    compatibility = null,
    maxTokens = 4096,
    temperature = 0.1,
    timeoutMs = 120000
  } = {}) {
    this.provider = provider;
    this.model = model || DEFAULT_MODELS[provider] || "gpt-4o-mini";
    this.apiKey = apiKey;
    this.baseUrl = baseUrl || this._getDefaultBaseUrl(provider);
    this.compatibility = compatibility || this._getDefaultCompatibility(provider);
    this.maxTokens = maxTokens;
    this.temperature = temperature;
    this.timeoutMs = timeoutMs;
  }

  _getDefaultBaseUrl(provider) {
    const baseUrls = {
      [LLMProvider.OPENAI]: "https://api.openai.com/v1",
      [LLMProvider.ANTHROPIC]: "https://api.anthropic.com",
      [LLMProvider.GEMINI]: "https://generativelanguage.googleapis.com",
      [LLMProvider.QWEN]: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      [LLMProvider.DEEPSEEK]: "https://api.deepseek.com/v1",
      [LLMProvider.BAIDU]: "https://aip.baidubce.com/rpc/2.0/ai_custom/v1",
      [LLMProvider.MINIMAX]: "https://api.minimax.chat/v1",
      [LLMProvider.DOUBAO]: "https://ark.cn-beijing.volces.com/api/v3"
    };
    return baseUrls[provider] || "https://api.openai.com/v1";
  }

  _getDefaultCompatibility(provider) {
    const compatMap = {
      [LLMProvider.OPENAI]: COMPATIBILITY_MODE.OPENAI,
      [LLMProvider.ANTHROPIC]: COMPATIBILITY_MODE.ANTHROPIC,
      [LLMProvider.GEMINI]: COMPATIBILITY_MODE.GEMINI,
      [LLMProvider.QWEN]: COMPATIBILITY_MODE.OPENAI,
      [LLMProvider.DEEPSEEK]: COMPATIBILITY_MODE.OPENAI
    };
    return compatMap[provider] || COMPATIBILITY_MODE.OPENAI;
  }

  clone() {
    return new LLMConfig({
      provider: this.provider,
      model: this.model,
      apiKey: this.apiKey,
      baseUrl: this.baseUrl,
      compatibility: this.compatibility,
      maxTokens: this.maxTokens,
      temperature: this.temperature,
      timeoutMs: this.timeoutMs
    });
  }
}

class BaseLLMAdapter {
  constructor(config) {
    this.config = config;
  }

  static supportsProvider(provider) {
    return false;
  }

  async complete(messages, options = {}) {
    throw new Error("Not implemented");
  }

  async *streamComplete(messages, options = {}) {
    throw new Error("Not implemented");
  }

  getConfig() {
    return this.config;
  }
}

class OpenAIAdapter extends BaseLLMAdapter {
  static supportsProvider(provider) {
    return [LLMProvider.OPENAI, LLMProvider.QWEN, LLMProvider.DEEPSEEK].includes(provider);
  }

  async complete(messages, options = {}) {
    const { maxTokens = this.config.maxTokens, temperature = this.config.temperature } = options;

    const response = await fetchWithTimeout(
      `${this.config.baseUrl}/chat/completions`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify({
          model: this.config.model,
          messages,
          max_tokens: maxTokens,
          temperature
        })
      },
      this.config.timeoutMs
    );

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data = await response.json();
    return data.choices?.[0]?.message?.content || "";
  }

  async *streamComplete(messages, options = {}) {
    const { maxTokens = this.config.maxTokens, temperature = this.config.temperature } = options;

    const response = await fetchWithTimeout(
      `${this.config.baseUrl}/chat/completions`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify({
          model: this.config.model,
          messages,
          max_tokens: maxTokens,
          temperature,
          stream: true
        })
      },
      this.config.timeoutMs
    );

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split("\n");

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          try {
            const parsed = JSON.parse(data);
            const token = parsed.choices?.[0]?.delta?.content;
            if (token) yield token;
          } catch (e) {}
        }
      }
    }
  }
}

class AnthropicAdapter extends BaseLLMAdapter {
  static supportsProvider(provider) {
    return provider === LLMProvider.ANTHROPIC;
  }

  async complete(messages, options = {}) {
    const { maxTokens = this.config.maxTokens, temperature = this.config.temperature } = options;

    const systemPrompt = messages.find(m => m.role === "system")?.content || "";
    const conversationMessages = messages.filter(m => m.role !== "system");

    const response = await fetchWithTimeout(
      `${this.config.baseUrl}/v1/messages`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.config.apiKey,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify({
          model: this.config.model,
          max_tokens: maxTokens,
          temperature,
          system: systemPrompt,
          messages: conversationMessages.map(m => ({
            role: m.role,
            content: typeof m.content === "string" ? m.content : m.content[0]?.text || ""
          }))
        })
      },
      this.config.timeoutMs
    );

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = await response.json();
    return (data.content || []).map(item => item.text || "").join("\n");
  }
}

class GeminiAdapter extends BaseLLMAdapter {
  static supportsProvider(provider) {
    return provider === LLMProvider.GEMINI;
  }

  async complete(messages, options = {}) {
    const { maxTokens = this.config.maxTokens, temperature = this.config.temperature } = options;

    const systemPrompt = messages.find(m => m.role === "system")?.content || "";
    const conversationMessages = messages.filter(m => m.role !== "system");

    const response = await fetchWithTimeout(
      `${this.config.baseUrl}/v1beta/models/${this.config.model}:generateContent?key=${this.config.apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: conversationMessages.map(m => ({
            role: m.role === "assistant" ? "model" : "user",
            parts: [{ text: typeof m.content === "string" ? m.content : m.content[0]?.text || "" }]
          })),
          generationConfig: { temperature, maxOutputTokens: maxTokens }
        })
      },
      this.config.timeoutMs
    );

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("\n") || "";
  }
}

class LLMFactory {
  constructor() {
    this._adapters = new Map();
  }

  _getCacheKey(config) {
    const keyPrefix = config.apiKey ? config.apiKey.slice(0, 8) : "no-key";
    return `${config.provider}:${config.model}:${keyPrefix}`;
  }

  createAdapter(config) {
    const llmConfig = config instanceof LLMConfig ? config : new LLMConfig(config);
    const cacheKey = this._getCacheKey(llmConfig);

    if (this._adapters.has(cacheKey)) {
      return this._adapters.get(cacheKey);
    }

    let adapter;

    if (AnthropicAdapter.supportsProvider(llmConfig.provider)) {
      adapter = new AnthropicAdapter(llmConfig);
    } else if (GeminiAdapter.supportsProvider(llmConfig.provider)) {
      adapter = new GeminiAdapter(llmConfig);
    } else if (OpenAIAdapter.supportsProvider(llmConfig.provider)) {
      adapter = new OpenAIAdapter(llmConfig);
    } else {
      adapter = new OpenAIAdapter(llmConfig);
    }

    this._adapters.set(cacheKey, adapter);
    return adapter;
  }

  clearCache() {
    this._adapters.clear();
  }

  getSupportedProviders() {
    return Object.values(LLMProvider);
  }

  getDefaultModel(provider) {
    return DEFAULT_MODELS[provider] || "gpt-4o-mini";
  }
}

function fetchWithTimeout(url, options, timeoutMs = 120000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timeout));
}

const globalLLMFactory = new LLMFactory();

export {
  LLMProvider,
  DEFAULT_MODELS,
  COMPATIBILITY_MODE,
  LLMConfig,
  BaseLLMAdapter,
  OpenAIAdapter,
  AnthropicAdapter,
  GeminiAdapter,
  LLMFactory,
  globalLLMFactory,
  fetchWithTimeout
};