export async function buildEnvironmentReport(options = {}) {
  const { rootDir = ".", downloadsDir = "./workspace/downloads", settings = {} } = options;

  const llmConfig = settings.llm || {};
  const activeProvider = llmConfig.provider || "";
  const activeModel = llmConfig.model || "";
  const providerLabel = {
    openai: "OpenAI",
    anthropic: "Anthropic",
    gemini: "Gemini",
    deepseek: "DeepSeek",
    qwen: "Qwen",
    baidu: "Baidu",
    minimax: "MiniMax",
    doubao: "Doubao"
  }[activeProvider] || activeProvider;

  const githubConfig = settings.github || {};
  const crawlMode = githubConfig.crawlMode || "org";

  return {
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch
    },
    workspace: {
      rootDir,
      downloadsDir
    },
    llm: {
      active: {
        label: providerLabel,
        model: activeModel
      }
    },
    github: {
      tokenConfigured: !!(githubConfig.token),
      crawlMode
    },
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    reportTime: new Date().toISOString()
  };
}
