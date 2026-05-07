import { promises as fs } from "node:fs";
import path from "path";
import { fileURLToPath } from "node:url";
import { getRulesEngine } from '../analyzers/rulesEngine.js';
import { KnowledgeCategory } from './frameworks.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const KNOWLEDGE_BASE_DIR = path.join(__dirname, "knowledge");

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

class KnowledgeIndex {
  constructor() {
    this._rulesEngine = null;
    this._cache = new Map();
    this._useYamlRules = false;
  }

  async initialize() {
    if (this._rulesEngine) {
      return;
    }

    try {
      this._rulesEngine = await getRulesEngine('./config/detection_rules.yaml');
      this._useYamlRules = true;
      console.log('[KnowledgeIndex] Loaded rules from YAML configuration');
    } catch (error) {
      console.warn('[KnowledgeIndex] Failed to load YAML rules, falling back to built-in patterns');
      this._useYamlRules = false;
    }
  }

  getPattern(id) {
    if (this._useYamlRules && this._rulesEngine) {
      return this._rulesEngine._ruleIndex.get(id) || null;
    }
    return this._getBuiltinPattern(id);
  }

  getAllPatterns() {
    if (this._useYamlRules && this._rulesEngine) {
      return Array.from(this._rulesEngine._ruleIndex.values());
    }
    return Object.values(this._getBuiltinPatterns());
  }

  searchBySeverity(severity) {
    if (this._useYamlRules && this._rulesEngine) {
      return Array.from(this._rulesEngine._ruleIndex.values()).filter(
        rule => rule.severity && rule.severity.toLowerCase() === severity.toLowerCase()
      );
    }
    return Object.values(this._getBuiltinPatterns()).filter(p => p.severity === severity);
  }

  searchByCWE(cweId) {
    if (this._useYamlRules && this._rulesEngine) {
      return Array.from(this._rulesEngine._ruleIndex.values()).find(
        rule => rule.cwe === cweId
      ) || CWE_CATEGORIES[cweId] || null;
    }
    return CWE_CATEGORIES[cweId] || null;
  }

  matchPatterns(code, language = 'python') {
    const matches = [];

    if (this._useYamlRules && this._rulesEngine) {
      const rules = this._rulesEngine.getRulesForLanguage(language);
      for (const rule of rules) {
        const ruleMatches = this._rulesEngine.matchVulnerability(code, rule.id, language);
        for (const match of ruleMatches) {
          matches.push({
            patternId: match.ruleId,
            title: match.description,
            severity: match.severity,
            cwe: match.cwe,
            match: match.match,
            remediation: match.remediation
          });
        }
      }
    } else {
      for (const [id, pattern] of Object.entries(this._getBuiltinPatterns())) {
        for (const regex of pattern.patterns) {
          const matches_found = code.match(regex);
          if (matches_found) {
            matches.push({
              patternId: id,
              title: pattern.title,
              severity: pattern.severity,
              cwe: pattern.cwe,
              match: matches_found[0],
              remediation: pattern.remediation
            });
            break;
          }
        }
      }
    }

    return matches;
  }

  getRemediation(patternId) {
    const pattern = this.getPattern(patternId);
    return pattern?.remediation || "No specific remediation available";
  }

  getCWEInfo(cweId) {
    return CWE_CATEGORIES[cweId] || null;
  }

  async saveToFile(filepath) {
    const data = {
      patterns: this._useYamlRules ? {} : this._getBuiltinPatterns(),
      cweCategories: CWE_CATEGORIES
    };
    await fs.writeFile(filepath, JSON.stringify(data, null, 2), "utf-8");
  }

  static async loadFromFile(filepath) {
    const content = await fs.readFile(filepath, "utf-8");
    const data = JSON.parse(content);
    const index = new KnowledgeIndex();
    return index;
  }

  _getBuiltinPattern(id) {
    return this._getBuiltinPatterns()[id] || null;
  }

  _getBuiltinPatterns() {
    return {
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
  }

  get rulesEngine() {
    return this._rulesEngine;
  }

  checkGuidelinesCompliance(vulnerabilities) {
    const compliance = {
      total: vulnerabilities.length,
      byGuideline: {},
      uncovered: [],
      summary: {}
    };

    const guidelineTypes = ['cwe', 'owasp', 'gbt'];

    for (const vuln of vulnerabilities) {
      let foundGuideline = false;

      for (const glType of guidelineTypes) {
        const glKey = glType === 'cwe' ? vuln.cwe : glType === 'owasp' ? vuln.owasp : vuln.gbt;
        if (glKey) {
          const guidelines = Array.isArray(glKey) ? glKey : [glKey];
          for (const gl of guidelines) {
            const glKeyLower = gl.toLowerCase();
            if (!compliance.byGuideline[glKeyLower]) {
              compliance.byGuideline[glKeyLower] = {
                type: glType,
                count: 0,
                vulnerabilities: []
              };
            }
            compliance.byGuideline[glKeyLower].count++;
            compliance.byGuideline[glKeyLower].vulnerabilities.push({
              id: vuln.patternId || vuln.id,
              title: vuln.title,
              severity: vuln.severity
            });
            foundGuideline = true;
          }
        }
      }

      if (!foundGuideline) {
        compliance.uncovered.push({
          id: vuln.patternId || vuln.id,
          title: vuln.title,
          severity: vuln.severity
        });
      }
    }

    for (const [glKey, glData] of Object.entries(compliance.byGuideline)) {
      compliance.summary[glKey] = {
        type: glData.type,
        count: glData.count,
        coverage: ((glData.count / compliance.total) * 100).toFixed(2) + '%'
      };
    }

    return compliance;
  }

  getGuidelineSummary() {
    if (this._useYamlRules && this._rulesEngine) {
      const summary = {};
      for (const [ruleId, rule] of this._rulesEngine._labelIndex) {
        for (const [glType, glValues] of Object.entries(rule.guidelines || {})) {
          for (const glValue of glValues) {
            const key = `${glType.toLowerCase()}:${glValue.toLowerCase()}`;
            if (!summary[key]) {
              summary[key] = {
                type: glType,
                value: glValue,
                count: 0,
                rules: []
              };
            }
            summary[key].count++;
            summary[key].rules.push(ruleId);
          }
        }
      }
      return summary;
    }
    return {};
  }

  getRulesByProfile(profile) {
    if (this._useYamlRules && this._rulesEngine) {
      return this._rulesEngine.getRulesByProfile(profile);
    }
    return [];
  }

  getComplianceReport(vulnerabilities, targetGuidelines = null) {
    const compliance = this.checkGuidelinesCompliance(vulnerabilities);
    const report = {
      timestamp: new Date().toISOString(),
      totalVulnerabilities: compliance.total,
      guidelineCoverage: {},
      recommendations: []
    };

    const targetSet = targetGuidelines
      ? new Set(targetGuidelines.map(g => g.toLowerCase()))
      : null;

    for (const [glKey, glData] of Object.entries(compliance.summary)) {
      if (!targetSet || targetSet.has(glKey)) {
        report.guidelineCoverage[glKey] = {
          type: glData.type,
          vulnerabilitiesFound: glData.count,
          coveragePercentage: glData.coverage
        };
      }
    }

    for (const vuln of compliance.uncovered) {
      report.recommendations.push({
        type: 'missing_guideline',
        vulnerability: vuln,
        message: `Vulnerability '${vuln.title}' is not mapped to any guideline. Consider adding appropriate guideline mappings.`
      });
    }

    const coveragePercentages = Object.values(report.guidelineCoverage)
      .map(g => parseFloat(g.coveragePercentage));
    if (coveragePercentages.length > 0) {
      report.averageCoverage = (coveragePercentages.reduce((a, b) => a + b, 0) / coveragePercentages.length).toFixed(2) + '%';
    }

    return report;
  }
}

const globalKnowledgeIndex = new KnowledgeIndex();

export { Severity, KnowledgeCategory } from './frameworks.js';

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

export {
  KNOWLEDGE_BASE_DIR,
  VulnerabilityPatterns,
  CWE_CATEGORIES,
  KnowledgeIndex,
  globalKnowledgeIndex,
  ALL_VULNERABILITY_DOCS
};
