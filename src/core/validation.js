const DANGEROUS_PATH_PATTERNS = [
  /\.\./,
  /\.\.\//,
  /\.\.\\/,
  /^\//,
  /^[A-Za-z]:/,
  /~/,
  /\$/,
  /%/
];

const BLOCKED_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib",
  ".bin", ".dat",
  ".key", ".pem", ".p12", ".pfx",
  ".env"
]);

const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;
const DEFAULT_MAX_PATH_LENGTH = 500;
const DEFAULT_MAX_CONTENT_LENGTH = 100000;

class ValidationError extends Error {
  constructor(message, code = "VALIDATION_ERROR") {
    super(message);
    this.name = "ValidationException";
    this.code = code;
  }
}

class PathTraversalException extends ValidationError {
  constructor(path) {
    super(`Path traversal detected: ${path}`, "PATH_TRAVERSAL");
    this.name = "PathTraversalException";
  }
}

class FileSizeExceededException extends ValidationError {
  constructor(size, maxSize) {
    super(`File size ${size} exceeds maximum ${maxSize}`, "FILE_SIZE_EXCEEDED");
    this.name = "FileSizeExceededException";
    this.size = size;
    this.maxSize = maxSize;
  }
}

class InputValidationException extends ValidationError {
  constructor(field, message) {
    super(`${field}: ${message}`, "INPUT_VALIDATION");
    this.name = "InputValidationException";
    this.field = field;
  }
}

function validatePath(path, projectRoot, options = {}) {
  const { allowAbsolute = false } = options;

  if (!path || !path.trim()) {
    throw new InputValidationException("path", "cannot be empty");
  }

  path = path.trim();

  if (path.length > DEFAULT_MAX_PATH_LENGTH) {
    throw new InputValidationException("path", `exceeds maximum length of ${DEFAULT_MAX_PATH_LENGTH}`);
  }

  for (const pattern of DANGEROUS_PATH_PATTERNS) {
    if (pattern.test(path)) {
      throw new PathTraversalException(path);
    }
  }

  if (!allowAbsolute) {
    if (path.startsWith("/") || /^[A-Za-z]:/.test(path)) {
      throw new InputValidationException("path", "absolute paths are not allowed");
    }
  }

  const normalized = path.replace(/\\/g, "/");

  if (normalized.includes("..")) {
    throw new PathTraversalException(path);
  }

  return normalized;
}

function validateFilePath(filePath, projectRoot, options = {}) {
  const { maxSize = DEFAULT_MAX_FILE_SIZE, allowBlockedExtensions = false } = options;

  const validated = validatePath(filePath, projectRoot, options);

  const ext = getExtension(filePath);

  if (!allowBlockedExtensions && BLOCKED_EXTENSIONS.has(ext)) {
    throw new InputValidationException("file", `blocked file extension: ${ext}`);
  }

  return validated;
}

function validateFileSize(size, maxSize = DEFAULT_MAX_FILE_SIZE) {
  if (size > maxSize) {
    throw new FileSizeExceededException(size, maxSize);
  }
  return true;
}

function validateContentLength(content, maxLength = DEFAULT_MAX_CONTENT_LENGTH) {
  if (content.length > maxLength) {
    throw new InputValidationException("content", `exceeds maximum length of ${maxLength}`);
  }
  return true;
}

function validateProjectRoot(rootPath) {
  if (!rootPath || !rootPath.trim()) {
    throw new InputValidationException("projectRoot", "cannot be empty");
  }

  const pattern = /[\.\/\\]\.\./;
  if (pattern.test(rootPath)) {
    throw new PathTraversalException(rootPath);
  }

  return rootPath;
}

function validateLanguage(language) {
  const supported = [
    "python", "javascript", "typescript", "jsx", "tsx",
    "java", "php", "ruby", "go", "rust", "c", "cpp",
    "csharp", "swift", "kotlin", "scala"
  ];

  if (!supported.includes(language.toLowerCase())) {
    throw new InputValidationException("language", `not supported: ${language}`);
  }

  return language.toLowerCase();
}

function validateSeverity(severity) {
  const valid = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  if (!valid.includes(severity.toUpperCase())) {
    throw new InputValidationException("severity", `invalid: ${severity}`);
  }

  return severity.toUpperCase();
}

function validateVulnType(vulnType) {
  const valid = [
    "sql_injection", "command_injection", "xss", "path_traversal",
    "ssrf", "xxe", "csrf", "idor", "insecure_deserialization",
    "sensitive_data_exposure", "auth_bypass", "crypto_weakness"
  ];

  if (!valid.includes(vulnType)) {
    throw new InputValidationException("vulnType", `invalid: ${vulnType}`);
  }

  return vulnType;
}

function validateAgentConfig(config) {
  if (!config || typeof config !== "object") {
    throw new InputValidationException("config", "must be an object");
  }

  if (!config.name || typeof config.name !== "string") {
    throw new InputValidationException("config.name", "must be a non-empty string");
  }

  if (!config.agentType || typeof config.agentType !== "string") {
    throw new InputValidationException("config.agentType", "must be a non-empty string");
  }

  if (config.maxTokens !== undefined) {
    if (typeof config.maxTokens !== "number" || config.maxTokens < 100) {
      throw new InputValidationException("config.maxTokens", "must be a number >= 100");
    }
  }

  if (config.temperature !== undefined) {
    if (typeof config.temperature !== "number" || config.temperature < 0 || config.temperature > 2) {
      throw new InputValidationException("config.temperature", "must be a number between 0 and 2");
    }
  }

  return true;
}

function validateScanOptions(options) {
  if (!options || typeof options !== "object") {
    throw new InputValidationException("options", "must be an object");
  }

  if (options.maxFiles !== undefined) {
    if (typeof options.maxFiles !== "number" || options.maxFiles < 1) {
      throw new InputValidationException("options.maxFiles", "must be a positive number");
    }
  }

  if (options.scanTypes !== undefined) {
    if (!Array.isArray(options.scanTypes)) {
      throw new InputValidationException("options.scanTypes", "must be an array");
    }
    const validTypes = ["pattern", "secret", "dependency"];
    for (const type of options.scanTypes) {
      if (!validTypes.includes(type)) {
        throw new InputValidationException("options.scanTypes", `invalid type: ${type}`);
      }
    }
  }

  return true;
}

function getExtension(filePath) {
  const match = filePath.match(/\.[^.]+$/);
  return match ? match[0].toLowerCase() : "";
}

function isBlockedExtension(filePath) {
  return BLOCKED_EXTENSIONS.has(getExtension(filePath));
}

export {
  PathTraversalException,
  FileSizeExceededException,
  InputValidationException,
  DANGEROUS_PATH_PATTERNS,
  BLOCKED_EXTENSIONS,
  DEFAULT_MAX_FILE_SIZE,
  DEFAULT_MAX_PATH_LENGTH,
  DEFAULT_MAX_CONTENT_LENGTH,
  validatePath,
  validateFilePath,
  validateFileSize,
  validateContentLength,
  validateProjectRoot,
  validateLanguage,
  validateSeverity,
  validateVulnType,
  validateAgentConfig,
  validateScanOptions,
  getExtension,
  isBlockedExtension
};