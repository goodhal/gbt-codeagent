import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_MEMORY = {
  preferences: {
    preferredQuery: 'topic:cms OR "headless cms" OR "content management system"',
    preferredMinAdoption: 100,
    autoUseMemory: true
  },
  rules: [
    "Stay defensive-only and never output exploit payloads.",
    "Prefer high-adoption CMS projects and explain findings with remediation first.",
    "Use local samples and evidence-backed heuristics before broadening scope."
  ],
  recentSummaries: [],
  learnedPatterns: [],
  updatedAt: null
};

export function createMemoryStore({ filePath }) {
  return {
    async read() {
      try {
        const raw = await fs.readFile(filePath, "utf8");
        const parsed = JSON.parse(raw);
        return normalizeMemory(parsed);
      } catch {
        return structuredClone(DEFAULT_MEMORY);
      }
    },

    async write(patch) {
      const current = await this.read();
      const next = normalizeMemory({
        ...current,
        ...patch,
        preferences: {
          ...current.preferences,
          ...(patch.preferences || {})
        },
        updatedAt: new Date().toISOString()
      });

      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, JSON.stringify(next, null, 2), "utf8");
      return next;
    },

    async appendRunSummary(summary) {
      const current = await this.read();
      const recentSummaries = [summary, ...current.recentSummaries].slice(0, 8);
      const learnedPatterns = dedupePatterns([
        ...(summary.learnedPatterns || []),
        ...current.learnedPatterns
      ]).slice(0, 12);

      return this.write({ recentSummaries, learnedPatterns });
    }
  };
}

function normalizeMemory(memory) {
  return {
    preferences: {
      preferredQuery: memory?.preferences?.preferredQuery || DEFAULT_MEMORY.preferences.preferredQuery,
      preferredMinAdoption: Number(memory?.preferences?.preferredMinAdoption || DEFAULT_MEMORY.preferences.preferredMinAdoption),
      autoUseMemory: memory?.preferences?.autoUseMemory !== false
    },
    rules: Array.isArray(memory?.rules) && memory.rules.length ? memory.rules : [...DEFAULT_MEMORY.rules],
    recentSummaries: Array.isArray(memory?.recentSummaries) ? memory.recentSummaries : [],
    learnedPatterns: Array.isArray(memory?.learnedPatterns) ? memory.learnedPatterns : [],
    updatedAt: memory?.updatedAt || null
  };
}

function dedupePatterns(patterns) {
  return [...new Set(patterns.filter(Boolean))];
}
