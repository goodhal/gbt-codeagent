import os from "node:os";
import { promises as fs } from "node:fs";
import path from "node:path";
import { getProviderCatalog, maskSecret, resolveLlmConfig } from "../config/llmProviders.js";

export async function buildEnvironmentReport({ rootDir, downloadsDir, settings }) {
  const llm = resolveLlmConfig(process.env, settings?.llm || {});
  const [downloadsExists, packageJsonExists] = await Promise.all([
    pathExists(downloadsDir),
    pathExists(path.join(rootDir, "package.json"))
  ]);

  return {
    generatedAt: new Date().toISOString(),
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cwd: process.cwd(),
      hostname: os.hostname()
    },
    workspace: {
      rootDir,
      downloadsDir,
      packageJsonExists,
      downloadsExists
    },
    llm: {
      active: {
        providerId: llm.providerId,
        label: llm.label,
        compatibility: llm.compatibility,
        baseUrl: llm.baseUrl,
        model: llm.model,
        apiKeyConfigured: Boolean(llm.apiKey),
        apiKeyMasked: maskSecret(llm.apiKey)
      },
      supportedProviders: getProviderCatalog()
    },
    github: {
      tokenConfigured: Boolean(settings?.github?.token),
      tokenMasked: maskSecret(settings?.github?.token || ""),
      ownerFilter: settings?.github?.ownerFilter || "",
      crawlMode: "GitHub Search API -> Trees API -> raw.githubusercontent.com audit mirror fetch"
    },
    checks: [
      checkItem("Node.js 18+", satisfiesNodeVersion(process.version)),
      checkItem("Workspace writable folders ready", downloadsExists && packageJsonExists),
      checkItem("LLM provider selected", Boolean(llm.providerId)),
      checkItem("LLM API key configured", Boolean(llm.apiKey), "Optional for current demo, required for future AI-assisted summaries"),
      checkItem("GitHub token configured", Boolean(settings?.github?.token), "Optional, but strongly recommended to reduce rate-limit and improve stability")
    ]
  };
}

function satisfiesNodeVersion(version) {
  const major = Number(String(version).replace(/^v/, "").split(".")[0]);
  return Number.isFinite(major) && major >= 18;
}

function checkItem(name, ok, note = "") {
  return {
    name,
    status: ok ? "pass" : "warn",
    note
  };
}

async function pathExists(target) {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}
