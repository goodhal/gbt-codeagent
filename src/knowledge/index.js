import { KnowledgeCategory } from './frameworks.js';

const CWE_CATEGORIES = {
  "CWE-89": {
    name: "SQL Injection",
    description: "The software constructs all or part of an SQL command using externally-influenced input",
    mitigations: ["Use parameterized queries", "Use ORM", "Input validation"]
  },
  "CWE-78": {
    name: "OS Command Injection",
    description: "The software constructs all or part of an OS command using externally-influenced input",
    mitigations: ["Avoid shell commands", "Use APIs instead of exec", "Input validation"]
  },
  "CWE-79": {
    name: "Cross-Site Scripting",
    description: "The software does not neutralize or incorrectly neutralizes user-controllable input",
    mitigations: ["Output encoding", "Content Security Policy", "HTTPOnly cookies"]
  },
  "CWE-22": {
    name: "Path Traversal",
    description: "The software accepts input that contains path traversal characters",
    mitigations: ["Use path.resolve()", "Validate paths against whitelist"]
  },
  "CWE-918": {
    name: "Server-Side Request Forgery",
    description: "The software fetches a remote resource without validating the URL",
    mitigations: ["URL validation", "Allowlist domains", "Disable redirects"]
  },
  "CWE-502": {
    name: "Deserialization of Untrusted Data",
    description: "The software deserializes untrusted data without sufficient validation",
    mitigations: ["Use secure serialization formats", "Implement strict type checking"]
  },
  "CWE-611": {
    name: "XML External Entity",
    description: "The software processes XML documents without properly disabling external entity resolution",
    mitigations: ["Disable external entities", "Enable secure processing"]
  },
  "CWE-798": {
    name: "Hardcoded Credentials",
    description: "The software contains hardcoded credentials",
    mitigations: ["Use environment variables", "Use secure key management"]
  },
  "CWE-327": {
    name: "Use of Broken or Risky Cryptographic Algorithm",
    description: "The software uses a broken or risky cryptographic algorithm",
    mitigations: ["Use modern cryptographic algorithms", "Avoid MD5/SHA1"]
  },
  "CWE-639": {
    name: "Insecure Direct Object Reference",
    description: "The software exposes a reference to an internal object without proper authorization",
    mitigations: ["Implement proper authorization checks", "Use indirect references"]
  }
};

const VulnerabilityPatterns = {
  SQL_INJECTION: {
    id: "sql_injection",
    title: "SQL Injection",
    severity: "HIGH",
    cwe: "CWE-89",
    patterns: [
      /\bSELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+.*\$\{.*\}/i,
      /["'`].*SELECT.*FROM.*WHERE.*["'`]/
    ],
    remediation: "Use parameterized queries or ORM"
  },
  COMMAND_INJECTION: {
    id: "command_injection",
    title: "Command Injection",
    severity: "HIGH",
    cwe: "CWE-78",
    patterns: [
      /exec\s*\(\s*[`'"].*\$/,
      /system\s*\(\s*[`'"].*\$/,
      /shell_exec\s*\(\s*.*\$/
    ],
    remediation: "Validate and sanitize all user inputs"
  },
  PATH_TRAVERSAL: {
    id: "path_traversal",
    title: "Path Traversal",
    severity: "MEDIUM",
    cwe: "CWE-22",
    patterns: [
      /\.\.\/|\.\.\\ /,
      /readFile\s*\(\s*.*\+\s*.*\)/,
      /open\s*\(\s*.*\+\s*.*\)/
    ],
    remediation: "Use path.resolve and validate paths"
  },
  XSS: {
    id: "xss",
    title: "Cross-Site Scripting",
    severity: "MEDIUM",
    cwe: "CWE-79",
    patterns: [
      /innerHTML\s*=\s*.*\+/,
      /document\.write\s*\(/,
      /dangerouslySetInnerHTML/
    ],
    remediation: "Escape user input, use safe APIs"
  },
  XXE: {
    id: "xxe",
    title: "XML External Entity",
    severity: "HIGH",
    cwe: "CWE-611",
    patterns: [
      /SIMPLEXML_LOAD_STRING/i,
      /libxml_set_streams_context/,
      /<\?xml.*<!ENTITY/
    ],
    remediation: "Disable external entities in XML parser"
  },
  SSRF: {
    id: "ssrf",
    title: "Server-Side Request Forgery",
    severity: "HIGH",
    cwe: "CWE-918",
    patterns: [
      /file_get_contents\s*\(\s*\$_(GET|POST)/,
      /curl_setopt\s*\(\s*\$ch,\s*CURLOPT_URL/
    ],
    remediation: "Validate and whitelist URLs"
  },
  INSECURE_DESERIALIZATION: {
    id: "insecure_deserialization",
    title: "Insecure Deserialization",
    severity: "HIGH",
    cwe: "CWE-502",
    patterns: [
      /unserialize\s*\(/,
      /pickle\.loads\s*\(/,
      /JSON\.parse\s*\(.*\$/
    ],
    remediation: "Use secure serialization formats"
  },
  IDOR: {
    id: "idor",
    title: "Insecure Direct Object Reference",
    severity: "MEDIUM",
    cwe: "CWE-639",
    patterns: [
      /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+_id\s*=/i
    ],
    remediation: "Implement proper authorization checks"
  }
};

const ALL_VULNERABILITY_DOCS = Object.values(VulnerabilityPatterns).map(v => ({
  id: v.id,
  title: v.title,
  severity: v.severity,
  cwe: v.cwe,
  content: `${v.title}: ${v.remediation}`,
  tags: [v.id, v.cwe, v.severity.toLowerCase()],
  cweIds: [v.cwe],
  category: KnowledgeCategory.VULNERABILITY,
  remediation: v.remediation,
  patterns: v.patterns
}));

export { Severity, KnowledgeCategory } from './frameworks.js';

export {
  CWE_CATEGORIES,
  VulnerabilityPatterns,
  ALL_VULNERABILITY_DOCS
};
