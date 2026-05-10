import { promises as fs } from "node:fs";
import path from "node:path";

export const CODE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".php",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".cs",
  ".rs",
  ".cpp",
  ".cc",
  ".c",
  ".h",
  ".hpp"
]);

export function extensionToLanguage(ext) {
  return {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".php": "PHP",
    ".py": "Python",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".cs": "C#",
    ".rs": "Rust",
    ".cpp": "C++",
    ".cc": "C++",
    ".c": "C",
    ".h": "C",
    ".hpp": "C++",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML"
  }[ext] || "Unknown";
}

export function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

export function inferFenceLanguage(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  if (basename === ".env" || basename.startsWith(".env.")) {
    return "dotenv";
  }

  return {
    ".ts": "ts",
    ".tsx": "tsx",
    ".js": "js",
    ".jsx": "jsx",
    ".mjs": "js",
    ".cjs": "js",
    ".php": "php",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".cs": "csharp",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".xml": "xml",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp"
  }[path.extname(filePath).toLowerCase()] || "";
}

/**
 * 递归收集目录下所有文件
 * @param {string} root - 根目录路径
 * @returns {Promise<string[]>} 文件路径数组
 */
export async function collectFiles(root) {
  try {
    const entries = await fs.readdir(root, { withFileTypes: true });
    const output = [];
    for (const entry of entries) {
      const target = path.join(root, entry.name);
      if (entry.isDirectory()) {
        output.push(...(await collectFiles(target)));
      } else {
        output.push(target);
      }
    }
    return output;
  } catch {
    return [];
  }
}
