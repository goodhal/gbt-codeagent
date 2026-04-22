import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_SETTINGS = {
  llm: {
    providerId: "openai",
    baseUrl: "",
    apiKey: "",
    model: ""
  },
  github: {
    token: "",
    ownerFilter: "",
    notes: ""
  },
  updatedAt: null
};

export function createSettingsStore({ filePath }) {
  return {
    async read() {
      try {
        const raw = await fs.readFile(filePath, "utf8");
        return normalize(JSON.parse(raw));
      } catch {
        return structuredClone(DEFAULT_SETTINGS);
      }
    },

    async write(patch) {
      const current = await this.read();
      const next = normalize({
        ...current,
        ...patch,
        llm: { ...current.llm, ...(patch.llm || {}) },
        github: { ...current.github, ...(patch.github || {}) },
        updatedAt: new Date().toISOString()
      });
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, JSON.stringify(next, null, 2), "utf8");
      return next;
    },

    async clearSecrets(targets = []) {
      const current = await this.read();
      const next = normalize({
        ...current,
        llm: {
          ...current.llm,
          apiKey: targets.includes("llm") ? "" : current.llm.apiKey
        },
        github: {
          ...current.github,
          token: targets.includes("github") ? "" : current.github.token
        },
        updatedAt: new Date().toISOString()
      });
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, JSON.stringify(next, null, 2), "utf8");
      return next;
    }
  };
}

function normalize(value) {
  return {
    llm: {
      providerId: value?.llm?.providerId || DEFAULT_SETTINGS.llm.providerId,
      baseUrl: value?.llm?.baseUrl || "",
      apiKey: value?.llm?.apiKey || "",
      model: value?.llm?.model || ""
    },
    github: {
      token: value?.github?.token || "",
      ownerFilter: value?.github?.ownerFilter || "",
      notes: value?.github?.notes || ""
    },
    updatedAt: value?.updatedAt || null
  };
}
