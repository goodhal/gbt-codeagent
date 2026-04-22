const PROVIDER_PRESETS = {
  openai: {
    label: "OpenAI / Compatible",
    env: {
      baseUrl: ["OPENAI_BASE_URL", "LLM_BASE_URL"],
      apiKey: ["OPENAI_API_KEY", "LLM_API_KEY"],
      model: ["OPENAI_MODEL", "LLM_MODEL"]
    },
    defaultBaseUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4.1-mini",
    compatibility: "openai"
  },
  compatible: {
    label: "OpenAI-Compatible Gateway",
    env: {
      baseUrl: ["LLM_BASE_URL", "OPENAI_BASE_URL"],
      apiKey: ["LLM_API_KEY", "OPENAI_API_KEY"],
      model: ["LLM_MODEL", "OPENAI_MODEL"]
    },
    defaultBaseUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4.1-mini",
    compatibility: "openai"
  },
  anthropic: {
    label: "Anthropic",
    env: {
      baseUrl: ["ANTHROPIC_BASE_URL"],
      apiKey: ["ANTHROPIC_API_KEY"],
      model: ["ANTHROPIC_MODEL"]
    },
    defaultBaseUrl: "https://api.anthropic.com",
    defaultModel: "claude-3-7-sonnet-latest",
    compatibility: "anthropic"
  },
  gemini: {
    label: "Google Gemini",
    env: {
      baseUrl: ["GEMINI_BASE_URL"],
      apiKey: ["GEMINI_API_KEY"],
      model: ["GEMINI_MODEL"]
    },
    defaultBaseUrl: "https://generativelanguage.googleapis.com",
    defaultModel: "gemini-2.5-pro",
    compatibility: "gemini"
  },
  deepseek: {
    label: "DeepSeek",
    env: {
      baseUrl: ["DEEPSEEK_BASE_URL"],
      apiKey: ["DEEPSEEK_API_KEY"],
      model: ["DEEPSEEK_MODEL"]
    },
    defaultBaseUrl: "https://api.deepseek.com",
    defaultModel: "deepseek-chat",
    compatibility: "openai"
  },
  qwen: {
    label: "Qwen / DashScope Compatible",
    env: {
      baseUrl: ["QWEN_BASE_URL"],
      apiKey: ["QWEN_API_KEY"],
      model: ["QWEN_MODEL"]
    },
    defaultBaseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    defaultModel: "qwen-max",
    compatibility: "openai"
  }
};

export function getProviderCatalog() {
  return Object.entries(PROVIDER_PRESETS).map(([id, preset]) => ({
    id,
    label: preset.label,
    compatibility: preset.compatibility,
    defaultBaseUrl: preset.defaultBaseUrl,
    defaultModel: preset.defaultModel
  }));
}

export function getProviderPreset(providerId) {
  return PROVIDER_PRESETS[providerId] || PROVIDER_PRESETS.openai;
}

export function resolveLlmConfig(env = process.env, overrides = {}) {
  const providerId = (overrides.providerId || env.LLM_PROVIDER || "openai").toLowerCase();
  const preset = getProviderPreset(providerId);

  return {
    providerId,
    label: preset.label,
    compatibility: preset.compatibility,
    baseUrl: overrides.baseUrl || pickFirstEnv(env, preset.env.baseUrl) || preset.defaultBaseUrl,
    apiKey: overrides.apiKey || pickFirstEnv(env, preset.env.apiKey) || "",
    model: overrides.model || pickFirstEnv(env, preset.env.model) || preset.defaultModel
  };
}

export function maskSecret(secret) {
  if (!secret) {
    return "";
  }
  if (secret.length <= 8) {
    return "*".repeat(secret.length);
  }
  return `${secret.slice(0, 4)}***${secret.slice(-4)}`;
}

function pickFirstEnv(env, names) {
  for (const name of names) {
    if (env[name]) {
      return env[name];
    }
  }
  return "";
}
