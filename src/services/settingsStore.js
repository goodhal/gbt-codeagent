/**
 * 设置存储模块（精简版）
 * 提供应用设置的读写功能
 */
import { promises as fs } from "node:fs";
import path from "node:path";

export function createSettingsStore({ filePath } = {}) {
  const storePath = filePath || "./workspace/settings/app-settings.json";

  return {
    async read() {
      try {
        const data = await fs.readFile(storePath, "utf8");
        return JSON.parse(data);
      } catch {
        return { llm: {}, github: {}, general: {} };
      }
    },

    async write(settings) {
      await fs.mkdir(path.dirname(storePath), { recursive: true });
      await fs.writeFile(storePath, JSON.stringify(settings, null, 2), "utf8");
    },

    async clearSecrets(targets) {
      const settings = await this.read();
      for (const target of targets) {
        const keys = target.split(".");
        let obj = settings;
        for (let i = 0; i < keys.length - 1; i++) {
          if (obj[keys[i]] === undefined) break;
          obj = obj[keys[i]];
        }
        if (obj && keys.length > 0) {
          delete obj[keys[keys.length - 1]];
        }
      }
      return this.write(settings).then(() => settings);
    },
  };
}
