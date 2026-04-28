const VulnType = {
  SQL_INJECTION: "sql_injection",
  COMMAND_INJECTION: "command_injection",
  CODE_INJECTION: "code_injection",
  XSS: "xss",
  PATH_TRAVERSAL: "path_traversal",
  SSRF: "ssrf",
  XXE: "xxe",
  DESERIALIZATION: "deserialization",
  SSTI: "ssti",
  LDAP_INJECTION: "ldap_injection",
  NOSQL_INJECTION: "nosql_injection",
  XPATH_INJECTION: "xpath_injection"
};

const SandboxConfig = {
  memoryLimit: "512m",
  cpuLimit: 1.0,
  timeout: 60000,
  networkMode: "none",
  readOnly: true,
  user: "1000:1000",
  capDrop: ["ALL"],
  noNewPrivileges: true
};

class ToolResult {
  constructor({ success, result = null, error = null, metadata = {} } = {}) {
    this.success = success;
    this.result = result;
    this.error = error;
    this.metadata = metadata;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      success: this.success,
      result: this.result,
      error: this.error,
      metadata: this.metadata,
      timestamp: this.timestamp
    };
  }
}

class SandboxManager {
  constructor(config = {}) {
    this.config = { ...SandboxConfig, ...config };
    this._initialized = false;
    this._initError = null;
    this._dockerAvailable = false;
    this._dockerClient = null;
  }

  async initialize() {
    if (this._initialized) return;

    try {
      const docker = await import("dockerode");
      this._dockerClient = new docker.default();
      await this._dockerClient.ping();
      this._dockerAvailable = true;
      this._initError = null;
    } catch (e) {
      this._dockerClient = null;
      this._dockerAvailable = false;
      this._initError = e.message || String(e);
    }

    this._initialized = true;
  }

  get isAvailable() {
    return this._dockerAvailable;
  }

  getDiagnosis() {
    return this._dockerAvailable
      ? "Docker Service Available"
      : `Docker Service Unavailable. Error: ${this._initError || "Not initialized"}`;
  }

  async executeCommand(command, options = {}) {
    if (!this._dockerAvailable) {
      return new ToolResult({
        success: false,
        error: "Docker not available"
      });
    }

    const {
      workingDir = "/workspace",
      env = {},
      timeout = this.config.timeout
    } = options;

    try {
      const container = await this._dockerClient.container.create({
        Image: "ubuntu:22.04",
        Cmd: ["/bin/sh", "-c", command],
        WorkingDir: workingDir,
        Env: Object.entries(env).map(([k, v]) => `${k}=${v}`),
        HostConfig: {
          Memory: this._parseMemory(this.config.memoryLimit),
          NanoCpus: Math.floor(this.config.cpuLimit * 1e9),
          NetworkMode: this.config.networkMode,
          ReadonlyRootfs: this.config.readOnly,
          CapDrop: this.config.capDrop,
          SecurityOpt: ["no-new-privileges:true"]
        },
        User: this.config.user,
        AttachStdout: true,
        AttachStderr: true
      });

      await container.start();

      const result = await this._waitForContainer(container, timeout);

      await container.remove({ force: true });

      return result;
    } catch (e) {
      return new ToolResult({
        success: false,
        error: e.message
      });
    }
  }

  async _waitForContainer(container, timeout) {
    return new Promise((resolve) => {
      let output = "";
      let errorOutput = "";

      container.attach({ stream: true, stdout: true, stderr: true }, (err, stream) => {
        if (err) {
          resolve(new ToolResult({ success: false, error: err.message }));
          return;
        }

        stream.on("data", (chunk) => {
          output += chunk.toString();
        });

        stream.on("end", () => {
          resolve(new ToolResult({ success: true, result: output }));
        });
      });

      setTimeout(() => {
        container.kill().catch(() => {});
        resolve(new ToolResult({
          success: false,
          error: `Timeout after ${timeout}ms`,
          result: output
        }));
      }, timeout);
    });
  }

  _parseMemory(memoryStr) {
    const match = memoryStr.match(/^(\d+)([kmg]?)$/i);
    if (!match) return 512 * 1024 * 1024;

    const value = parseInt(match[1], 10);
    const unit = (match[2] || "").toLowerCase();

    const multipliers = { "": 1, k: 1024, m: 1024 * 1024, g: 1024 * 1024 * 1024 };
    return value * (multipliers[unit] || 1);
  }

  async cleanup() {
    if (!this._dockerAvailable) return;

    try {
      const containers = await this._dockerClient.container.list({ all: true });
      for (const containerInfo of containers) {
        if (containerInfo.Image.startsWith("audit-sandbox-")) {
          const container = this._dockerClient.container.get(containerInfo.Id);
          await container.remove({ force: true });
        }
      }
    } catch (e) {
      console.error("Cleanup error:", e);
    }
  }
}

class CommandInjectionTester {
  constructor(sandboxManager = null) {
    this.sandboxManager = sandboxManager || new SandboxManager();
    this.projectRoot = ".";
  }

  detectLanguage(filePath, code = "") {
    const ext = filePath.split(".").pop()?.toLowerCase() || "";

    const extMap = {
      php: "php",
      py: "python",
      js: "javascript",
      ts: "javascript",
      java: "java",
      go: "go",
      rb: "ruby",
      sh: "shell",
      bash: "shell"
    };

    if (extMap[ext]) return extMap[ext];

    if (code.includes("<?php") || code.includes("<?")) return "php";
    if (code.includes("import ") && (code.includes("os.") || code.includes("subprocess"))) return "python";
    if (code.includes("require(") || code.includes("import ")) return "javascript";
    if (code.includes("package main")) return "go";
    if (code.includes("class ") && code.includes("public ")) return "java";
    if (code.includes("#!/bin/bash") || code.includes("#!/bin/sh")) return "shell";

    return "shell";
  }

  buildTestPayload(code, paramName, testCommand, language) {
    const payloads = {
      php: `<?php
        $${paramName} = '${testCommand}';
        // Simulated vulnerable code
        echo "Output: ";
        passthru($${paramName});
      ?>`,

      python: `
import subprocess
${paramName} = '${testCommand}'
# Simulated vulnerable code
result = subprocess.check_output(${paramName}, shell=True)
print(f"Output: {result.decode()}")
      `,

      javascript: `
const { execSync } = require('child_process');
const ${paramName} = '${testCommand}';
// Simulated vulnerable code
try {
  const result = execSync(${paramName}).toString();
  console.log('Output:', result);
} catch (e) {
  console.log('Error:', e.message);
}
      `,

      shell: `${testCommand}`,

      java: `
public class Test {
  public static void main(String[] args) {
    String ${paramName} = "${testCommand}";
    Runtime rt = Runtime.getRuntime();
    try {
      Process p = rt.exec(${paramName});
      java.io.BufferedReader br = new java.io.BufferedReader(
        new java.io.InputStreamReader(p.getInputStream())
      );
      String line;
      while ((line = br.readLine()) != null) {
        System.out.println(line);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
      `
    };

    return payloads[language] || payloads.shell;
  }

  async testCommandInjection(targetFile, options = {}) {
    const {
      paramName = "cmd",
      testCommand = "id",
      language = "auto",
      code = ""
    } = options;

    const detectedLang = language === "auto"
      ? this.detectLanguage(targetFile, code)
      : language;

    const testCode = this.buildTestPayload(code || targetFile, paramName, testCommand, detectedLang);

    const result = await this.sandboxManager.executeCommand(
      `echo '${testCode.replace(/'/g, "'\\''")}' > /tmp/test.js && node /tmp/test.js`
    );

    const vulnIndicators = [
      "uid=", "root", "www-data", "user=", "groups=",
      testCommand.includes("echo") ? testCommand.split(" ").pop() : null
    ].filter(Boolean);

    const isVulnerable = result.success && vulnIndicators.some(indicator =>
      result.result?.includes(indicator)
    );

    return new ToolResult({
      success: true,
      result: {
        vulnerable: isVulnerable,
        evidence: result.result,
        language: detectedLang,
        testCommand,
        indicators: vulnIndicators
      },
      metadata: {
        vulnType: VulnType.COMMAND_INJECTION,
        targetFile,
        paramName
      }
    });
  }
}

class PathTraversalTester {
  constructor(sandboxManager = null) {
    this.sandboxManager = sandboxManager || new SandboxManager();
  }

  async testPathTraversal(targetFile, options = {}) {
    const {
      paramName = "file",
      testPaths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
      ]
    } = options;

    const results = [];

    for (const testPath of testPaths) {
      const cmd = `echo "Test path: ${testPath}" && cat "${testPath}" 2>&1 | head -5`;
      const result = await this.sandboxManager.executeCommand(cmd);

      const isVulnerable = result.success && (
        result.result?.includes("root:") ||
        result.result?.includes("[boot loader]") ||
        result.result?.includes("Permission denied") === false
      );

      results.push({
        path: testPath,
        vulnerable: isVulnerable,
        evidence: result.result?.slice(0, 500)
      });
    }

    const isVulnerable = results.some(r => r.vulnerable);

    return new ToolResult({
      success: true,
      result: {
        vulnerable: isVulnerable,
        tests: results
      },
      metadata: {
        vulnType: VulnType.PATH_TRAVERSAL,
        targetFile
      }
    });
  }
}

class SqlInjectionTester {
  constructor(sandboxManager = null) {
    this.sandboxManager = sandboxManager || new SandboxManager();
  }

  buildSqlTest(code, paramName, sqlPayload) {
    return `
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run("CREATE TABLE users (id INT, name TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin')");

  const stmt = db.prepare("SELECT * FROM users WHERE id = ${paramName}".replace('${paramName}', '${' + paramName + '}'));
  const ${paramName} = '${sqlPayload}';
  stmt.all(${paramName}, (err, rows) => {
    if (err) console.error('Error:', err.message);
    console.log('Results:', JSON.stringify(rows));
  });
});

db.close();
    `.replace('${paramName}', paramName);
  }

  async testSqlInjection(targetFile, options = {}) {
    const {
      paramName = "id",
      sqlPayloads = [
        "1 OR 1=1",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1; DROP TABLE users--"
      ]
    } = options;

    const results = [];

    for (const payload of sqlPayloads) {
      const testCode = this.buildSqlTest(targetFile, paramName, payload);
      const result = await this.sandboxManager.executeCommand(
        `cd /tmp && echo '${testCode.replace(/'/g, "'\\''")}' > test.sql.js && node test.sql.js`
      );

      const isVulnerable = result.success && (
        result.result?.includes('"id":1') ||
        result.result?.includes("admin") ||
        !result.result?.includes("Error")
      );

      results.push({
        payload,
        vulnerable: isVulnerable,
        evidence: result.result?.slice(0, 300)
      });
    }

    const isVulnerable = results.some(r => r.vulnerable);

    return new ToolResult({
      success: true,
      result: {
        vulnerable: isVulnerable,
        tests: results
      },
      metadata: {
        vulnType: VulnType.SQL_INJECTION,
        targetFile,
        paramName
      }
    });
  }
}

class VulnerabilityValidator {
  constructor(sandboxManager = null) {
    this.sandboxManager = sandboxManager || new SandboxManager();
    this.commandTester = new CommandInjectionTester(this.sandboxManager);
    this.pathTester = new PathTraversalTester(this.sandboxManager);
    this.sqlTester = new SqlInjectionTester(this.sandboxManager);
  }

  async validate(finding, codeContext = "") {
    const { vulnType, location, evidence } = finding;

    switch (vulnType) {
      case VulnType.COMMAND_INJECTION:
        return this.commandTester.testCommandInjection(location, {
          code: codeContext
        });

      case VulnType.PATH_TRAVERSAL:
        return this.pathTester.testPathTraversal(location);

      case VulnType.SQL_INJECTION:
        return this.sqlTester.testSqlInjection(location);

      default:
        return new ToolResult({
          success: false,
          error: `Validation for ${vulnType} not implemented`
        });
    }
  }

  async initialize() {
    await this.sandboxManager.initialize();
  }

  get isAvailable() {
    return this.sandboxManager.isAvailable;
  }
}

const globalSandboxManager = new SandboxManager();
const globalVulnValidator = new VulnerabilityValidator(globalSandboxManager);

export {
  VulnType,
  SandboxConfig,
  ToolResult,
  SandboxManager,
  CommandInjectionTester,
  PathTraversalTester,
  SqlInjectionTester,
  VulnerabilityValidator,
  globalSandboxManager,
  globalVulnValidator
};