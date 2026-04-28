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
