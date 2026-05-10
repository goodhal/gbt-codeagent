import { exec } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

const execAsync = async (command, options = {}) => {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`命令执行超时: ${command}`));
    }, options.timeout || 30000); // 默认30秒超时

    exec(command, options, (error, stdout, stderr) => {
      clearTimeout(timeout);
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
};

/**
 * 外部工具集成服务
 * 支持集成：
 * - Gitleaks: 密钥和敏感信息检测
 * - Bandit: Python 代码安全分析
 * - Semgrep: 多语言静态分析
 * - ilspycmd: .NET 反编译工具
 * - de4dot: .NET 去混淆工具
 */
export class ExternalToolService {
  constructor() {
    this.tools = {
      gitleaks: {
        name: "Gitleaks",
        description: "密钥和敏感信息检测工具",
        installCommand: this.getInstallCommand("gitleaks"),
        checkCommand: "gitleaks --version",
        scanCommand: this.scanWithGitleaks.bind(this)
      },
      bandit: {
        name: "Bandit",
        description: "Python 代码安全分析工具",
        installCommand: this.getInstallCommand("bandit"),
        checkCommand: "bandit --version",
        scanCommand: this.scanWithBandit.bind(this)
      },
      semgrep: {
        name: "Semgrep",
        description: "多语言静态分析工具",
        installCommand: this.getInstallCommand("semgrep"),
        checkCommand: "semgrep --version",
        scanCommand: this.scanWithSemgrep.bind(this)
      },
      ilspycmd: {
        name: "ILSpy Command Line",
        description: ".NET 反编译工具",
        installCommand: this.getInstallCommand("ilspycmd"),
        checkCommand: "ilspycmd --version",
        scanCommand: null
      },
      de4dot: {
        name: "de4dot",
        description: ".NET 去混淆工具",
        installCommand: this.getInstallCommand("de4dot"),
        checkCommand: "de4dot --help",
        scanCommand: null
      }
    };
  }

  /**
   * 获取安装命令
   */
  getInstallCommand(tool) {
    const platform = os.platform();
    const installCommands = {
      gitleaks: {
        win32: "choco install gitleaks",
        darwin: "brew install gitleaks",
        linux: "sudo apt-get install gitleaks || sudo yum install gitleaks"
      },
      bandit: {
        win32: "pip install bandit",
        darwin: "pip install bandit",
        linux: "pip install bandit"
      },
      semgrep: {
        win32: "pip install semgrep",
        darwin: "brew install semgrep",
        linux: "pip install semgrep"
      },
      ilspycmd: {
        win32: "dotnet tool install -g ilspycmd",
        darwin: "dotnet tool install -g ilspycmd",
        linux: "dotnet tool install -g ilspycmd"
      },
      de4dot: {
        win32: "powershell -Command \"Invoke-WebRequest -Uri 'https://github.com/kant2002/de4dot/releases/download/v3.2.0/de4dot-net48.zip' -OutFile de4dot.zip; Expand-Archive de4dot.zip -DestinationPath C:\\tools\\de4dot; Add-Content -Path $env:PATH -Value ';C:\\tools\\de4dot'\"",
        darwin: "brew install mono && curl -L -o /tmp/de4dot-net48.zip https://github.com/kant2002/de4dot/releases/download/v3.2.0/de4dot-net48.zip && mkdir -p ~/tools/de4dot && unzip /tmp/de4dot-net48.zip -d ~/tools/de4dot && echo 'alias de4dot=\"mono ~/tools/de4dot/de4dot.exe\"' >> ~/.zshrc",
        linux: "sudo apt-get install -y mono-complete && curl -L -o /tmp/de4dot-net48.zip https://github.com/kant2002/de4dot/releases/download/v3.2.0/de4dot-net48.zip && mkdir -p ~/tools/de4dot && unzip /tmp/de4dot-net48.zip -d ~/tools/de4dot && echo 'alias de4dot=\"mono ~/tools/de4dot/de4dot.exe\"' >> ~/.bashrc"
      }
    };
    return installCommands[tool]?.[platform] || installCommands[tool]?.linux;
  }

  /**
   * 检查工具是否已安装
   */
  async checkToolInstalled(toolName) {
    const tool = this.tools[toolName];
    if (!tool) {
      throw new Error(`未知工具：${toolName}`);
    }

    try {
      await execAsync(tool.checkCommand, { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * 检查所有工具安装状态
   */
  async checkAllTools() {
    const status = {};
    for (const toolName of Object.keys(this.tools)) {
      status[toolName] = await this.checkToolInstalled(toolName);
    }
    return status;
  }

  /**
   * 使用 Gitleaks 扫描密钥
   */
  async scanWithGitleaks(projectRoot) {
    const findings = [];
    
    try {
      // 检查是否已安装
      if (!await this.checkToolInstalled("gitleaks")) {
        console.warn("Gitleaks 未安装，跳过扫描");
        return findings;
      }

      // 创建临时目录存放结果
      const tempDir = path.join(os.tmpdir(), `gitleaks-${Date.now()}`);
      await fs.mkdir(tempDir, { recursive: true });
      const reportPath = path.join(tempDir, "report.json");

      // 执行扫描（注意：Gitleaks 找到密钥时返回 exit code 1，这是正常行为）
      const command = `gitleaks detect --source "${projectRoot}" --report-path "${reportPath}" --report-format json --no-git`;
      
      try {
        await execAsync(command);
      } catch (error) {
        // Gitleaks 找到密钥时会返回 exit code 1，这是正常行为，不是错误
        // 只有当找不到报告文件时才是真正的错误
        if (!error.stderr?.includes("leaks found")) {
          console.warn("Gitleaks 扫描异常:", error.message);
        }
      }

      // 读取结果（即使 exit code 为 1，报告文件仍然存在）
      try {
        const reportContent = await fs.readFile(reportPath, "utf8");
        const report = JSON.parse(reportContent);

        // 转换为统一格式
        for (const item of report) {
          findings.push({
            source: "external_tool",
            toolName: "Gitleaks",
            skillId: "gbt-code-audit",
            vulnId: "SECRET_DETECTION",
            title: `发现敏感信息：${item.RuleID}`,
          severity: "high",
          severityLabel: "高危",
          confidence: 0.9,
          location: `${item.File}:${item.StartLine}`,
          file: path.relative(projectRoot, item.File).replaceAll("\\", "/"),
          line: item.StartLine,
          vulnType: "HARD_CODED_SECRET",
          cwe: "CWE-798",
          language: "unknown",
          gbtMapping: "GB/T39412-6.1.1.10 硬编码敏感信息",
          cvssScore: 8.5,
          evidence: `在 ${item.File}:${item.StartLine} 发现 ${item.RuleID} 类型的敏感信息`,
          impact: "可能导致未授权访问、数据泄露或系统被入侵",
          remediation: "立即删除硬编码的敏感信息，使用环境变量或密钥管理服务",
          safeValidation: "建议立即删除并使用安全的密钥管理方案",
          codeSnippet: item.Secret || item.Match,
          status: "误报", // 默认状态，等待验证
          externalToolData: {
            ruleId: item.RuleID,
            commit: item.Commit,
            author: item.Author,
            email: item.Email,
            date: item.Date,
            message: item.Message
          }
        });
      }
      } catch (readError) {
        // 报告文件不存在或无法读取，说明没有发现密钥
        console.log("Gitleaks 未发现密钥或报告文件不存在");
      }

      // 清理临时文件
      try {
        await fs.unlink(reportPath);
        await fs.rmdir(tempDir);
      } catch (cleanupError) {
        // 清理失败不影响结果
      }

    } catch (error) {
      console.error("Gitleaks 扫描失败:", error);
    }

    return findings;
  }

  /**
   * 使用 Bandit 扫描 Python 代码
   */
  async scanWithBandit(projectRoot) {
    const findings = [];
    
    try {
      // 检查是否已安装
      if (!await this.checkToolInstalled("bandit")) {
        console.warn("Bandit 未安装，跳过扫描");
        return findings;
      }

      // 创建临时目录存放结果
      const tempDir = path.join(os.tmpdir(), `bandit-${Date.now()}`);
      await fs.mkdir(tempDir, { recursive: true });
      const reportPath = path.join(tempDir, "report.json");

      // 执行扫描
      const command = `bandit -r "${projectRoot}" -f json -o "${reportPath}"`;
      await execAsync(command);

      // 读取结果
      const reportContent = await fs.readFile(reportPath, "utf8");
      const report = JSON.parse(reportContent);

      // 转换为统一格式
      for (const item of report.results || []) {
        const severity = this.mapBanditSeverity(item.issue_severity);
        findings.push({
          source: "external_tool",
          toolName: "Bandit",
          skillId: "gbt-code-audit",
          vulnId: item.test_id,
          title: item.issue_text,
          severity,
          severityLabel: this.severityLabel(severity),
          confidence: 0.85,
          location: `${item.filename}:${item.line_number}`,
          file: path.relative(projectRoot, item.filename).replaceAll("\\", "/"),
          line: item.line_number,
          vulnType: this.mapBanditToVulnType(item.test_id),
          cwe: item.issue_cwe?.id || "CWE-unknown",
          language: "python",
          gbtMapping: this.getBanditGbtMapping(item.test_id),
          cvssScore: this.calculateBanditCVSS(severity),
          evidence: `在 ${item.filename}:${item.line_number} 发现 ${item.issue_text}`,
          impact: item.issue_text,
          remediation: `参考 Bandit 建议：${item.more_info || "请查阅相关安全编码规范"}`,
          safeValidation: "建议人工复核代码上下文，确认是否存在实际安全风险",
          codeSnippet: item.code?.raw || "",
          status: "误报", // 默认状态，等待验证
          externalToolData: {
            testId: item.test_id,
            testName: item.test_name,
            severity: item.issue_severity,
            confidence: item.issue_confidence,
            moreInfo: item.more_info
          }
        });
      }

      // 清理临时文件
      await fs.unlink(reportPath);
      await fs.rmdir(tempDir);

    } catch (error) {
      console.error("Bandit 扫描失败:", error);
      if (error.message.includes("No issues identified")) {
        return findings;
      }
    }

    return findings;
  }

  /**
   * 使用 Semgrep 扫描多语言代码
   */
  async scanWithSemgrep(projectRoot) {
    const findings = [];
    
    try {
      // 检查是否已安装
      if (!await this.checkToolInstalled("semgrep")) {
        console.warn("Semgrep 未安装，跳过扫描");
        return findings;
      }

      // 创建临时目录存放结果
      const tempDir = path.join(os.tmpdir(), `semgrep-${Date.now()}`);
      await fs.mkdir(tempDir, { recursive: true });
      const reportPath = path.join(tempDir, "report.json");

      // 执行扫描（使用默认规则集）
      const command = `semgrep --json --output "${reportPath}" "${projectRoot}"`;
      await execAsync(command);

      // 读取结果
      const reportContent = await fs.readFile(reportPath, "utf8");
      const report = JSON.parse(reportContent);

      // 转换为统一格式
      for (const item of report.results || []) {
        const severity = this.mapSemgrepSeverity(item.severity);
        findings.push({
          source: "external_tool",
          toolName: "Semgrep",
          skillId: "gbt-code-audit",
          vulnId: item.check_id,
          title: item.message,
          severity,
          severityLabel: this.severityLabel(severity),
          confidence: 0.85,
          location: `${item.path}:${item.start.line}`,
          file: path.relative(projectRoot, item.path).replaceAll("\\", "/"),
          line: item.start.line,
          vulnType: this.mapSemgrepToVulnType(item.check_id),
          cwe: this.extractCWE(item.message) || "CWE-unknown",
          language: this.detectLanguage(item.path),
          gbtMapping: this.getSemgrepGbtMapping(item.check_id),
          cvssScore: this.calculateSemgrepCVSS(severity),
          evidence: `在 ${item.path}:${item.start.line} 发现 ${item.message}`,
          impact: item.message,
          remediation: item.fix || "请查阅相关安全编码规范",
          safeValidation: "建议人工复核代码上下文，确认是否存在实际安全风险",
          codeSnippet: item.extra?.lines || "",
          status: "误报", // 默认状态，等待验证
          externalToolData: {
            checkId: item.check_id,
            message: item.message,
            severity: item.severity,
            fix: item.fix,
            metadata: item.extra?.metadata
          }
        });
      }

      // 清理临时文件
      await fs.unlink(reportPath);
      await fs.rmdir(tempDir);

    } catch (error) {
      console.error("Semgrep 扫描失败:", error);
      if (error.message.includes("No findings")) {
        return findings;
      }
    }

    return findings;
  }

  /**
   * 执行所有已安装工具的扫描
   */
  async scanAll(projectRoot) {
    const allFindings = [];
    const toolStatus = await this.checkAllTools();

    // 并行执行所有可用工具的扫描
    const scanPromises = [];

    // Gitleaks - 密钥检测
    if (toolStatus.gitleaks) {
      scanPromises.push(this.scanWithGitleaks(projectRoot));
    }

    // Bandit - Python 代码
    if (toolStatus.bandit) {
      scanPromises.push(this.scanWithBandit(projectRoot));
    }

    // Semgrep - 多语言
    if (toolStatus.semgrep) {
      scanPromises.push(this.scanWithSemgrep(projectRoot));
    }

    // 等待所有扫描完成
    if (scanPromises.length > 0) {
      const results = await Promise.all(scanPromises);
      results.forEach(findings => {
        allFindings.push(...findings);
      });
    }

    return allFindings;
  }

  // 辅助方法
  mapBanditSeverity(severity) {
    const mapping = {
      "HIGH": "high",
      "MEDIUM": "medium",
      "LOW": "low"
    };
    return mapping[severity] || "medium";
  }

  mapSemgrepSeverity(severity) {
    const mapping = {
      "ERROR": "high",
      "WARNING": "medium",
      "INFO": "low"
    };
    return mapping[severity] || "medium";
  }

  severityLabel(severity) {
    const mapping = {
      "high": "高危",
      "medium": "中危",
      "low": "低危"
    };
    return mapping[severity] || "中危";
  }

  mapBanditToVulnType(testId) {
    const mapping = {
      "B101": "ASSERT_STATEMENT",
      "B102": "EXEC_STATEMENT",
      "B103": "INSECURE_FILE_PERMISSIONS",
      "B104": "HARDCODED_BIND_ADDRESS",
      "B105": "HARD_CODED_PASSWORD",
      "B106": "HARD_CODED_PASSWORD",
      "B107": "HARD_CODED_PASSWORD",
      "B108": "INSECURE_TEMP_FILE",
      "B109": "HARD_CODED_PASSWORD",
      "B110": "EXCEPT_PASS",
      "B111": "EXCEPT_PASS",
      "B112": "EXCEPT_PASS",
      "B113": "REQUEST_WITHOUT_TIMEOUT",
      "B201": "FLASK_DEBUG_TRUE",
      "B301": "INSECURE_UNPICKLE",
      "B302": "INSECURE_MARSHAL",
      "B303": "WEAK_CRYPTO_MD5",
      "B304": "WEAK_CRYPTO_CIPHER",
      "B305": "WEAK_CRYPTO_CIPHER",
      "B306": "INSECURE_HASH_SHA1",
      "B307": "DANGEROUS_EVAL",
      "B308": "INSECURE_YAML_LOAD",
      "B310": "INSECURE_URL_OPEN",
      "B311": "WEAK_RANDOM",
      "B312": "TELNET_USAGE",
      "B313": "WEAK_CRYPTO_XML",
      "B314": "WEAK_CRYPTO_XML",
      "B315": "WEAK_CRYPTO_XML",
      "B316": "WEAK_CRYPTO_XML",
      "B317": "WEAK_CRYPTO_XML",
      "B318": "WEAK_CRYPTO_XML",
      "B319": "WEAK_CRYPTO_XML",
      "B320": "WEAK_CRYPTO_XML",
      "B321": "FTP_USAGE",
      "B322": "BUILTIN_OPEN",
      "B323": "UNSAFE_XSLT",
      "B324": "WEAK_HASH",
      "B401": "INSECURE_IMPORT",
      "B402": "INSECURE_IMPORT",
      "B403": "INSECURE_IMPORT",
      "B404": "INSECURE_IMPORT",
      "B405": "INSECURE_IMPORT",
      "B406": "INSECURE_IMPORT",
      "B407": "INSECURE_IMPORT",
      "B408": "INSECURE_IMPORT",
      "B409": "INSECURE_IMPORT",
      "B410": "INSECURE_IMPORT",
      "B411": "INSECURE_IMPORT",
      "B412": "INSECURE_IMPORT",
      "B413": "INSECURE_IMPORT",
      "B414": "INSECURE_IMPORT",
      "B501": "REQUEST_WITHOUT_TIMEOUT",
      "B502": "SSL_INSECURE",
      "B503": "SSL_WEAK",
      "B504": "SSL_WEAK",
      "B505": "WEAK_CRYPTO_DSA",
      "B506": "INSECURE_YAML_LOAD",
      "B507": "SSH_NO_HOST_VERIFY",
      "B508": "SSH_NO_HOST_VERIFY",
      "B509": "WEAK_CRYPTO",
      "B601": "PARAMETERIZED_COMMAND",
      "B602": "SUBPROCESS_SHELL_TRUE",
      "B603": "SUBPROCESS_WITHOUT_SHELL",
      "B604": "ANY_INSECURE_FUNCTION",
      "B605": "OS_STARTFILE_WITH_SHELL",
      "B606": "START_PROCESS_WITH_SHELL",
      "B607": "START_PROCESS_WITH_PARTIAL_PATH",
      "B608": "HARDCODED_SQL",
      "B609": "LINUX_COMMAND_WILDCARD_INJECTION",
      "B610": "DJANGO_EXTRA",
      "B611": "DJANGO_RAW_SQL",
      "B701": "JINJA2_AUTOESCAPE_DISABLED",
      "B702": "TARFILE_UNSAFE_EXTRACTION",
      "B703": "MARKUPSAFE_UNSAFE"
    };
    return mapping[testId] || "UNKNOWN";
  }

  mapSemgrepToVulnType(checkId) {
    // 简化处理，根据 check_id 推断
    const lowerId = checkId.toLowerCase();
    if (lowerId.includes("sql")) return "SQL_INJECTION";
    if (lowerId.includes("xss")) return "XSS";
    if (lowerId.includes("command") || lowerId.includes("exec")) return "COMMAND_INJECTION";
    if (lowerId.includes("path")) return "PATH_TRAVERSAL";
    if (lowerId.includes("secret") || lowerId.includes("credential")) return "HARD_CODED_SECRET";
    if (lowerId.includes("crypto") || lowerId.includes("encryption")) return "WEAK_CRYPTO";
    if (lowerId.includes("deserial")) return "DESERIALIZATION";
    if (lowerId.includes("ssrf")) return "SSRF";
    if (lowerId.includes("xxe")) return "XXE";
    return "UNKNOWN";
  }

  extractCWE(message) {
    const cweMatch = message.match(/CWE-(\d+)/);
    return cweMatch ? `CWE-${cweMatch[1]}` : null;
  }

  detectLanguage(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const mapping = {
      ".py": "python",
      ".java": "java",
      ".js": "javascript",
      ".ts": "typescript",
      ".go": "go",
      ".c": "c",
      ".cpp": "cpp",
      ".h": "cpp",
      ".cs": "csharp",
      ".php": "php",
      ".rb": "ruby",
      ".rs": "rust"
    };
    return mapping[ext] || "unknown";
  }

  calculateBanditCVSS(severity) {
    const mapping = {
      "high": 8.5,
      "medium": 5.5,
      "low": 3.0
    };
    return mapping[severity] || 5.0;
  }

  calculateSemgrepCVSS(severity) {
    const mapping = {
      "high": 8.5,
      "medium": 5.5,
      "low": 3.0
    };
    return mapping[severity] || 5.0;
  }

  getBanditGbtMapping(testId) {
    // 简化处理，返回通用映射
    return "GB/T39412-6.1.1.1 输入验证不足";
  }

  getSemgrepGbtMapping(checkId) {
    // 简化处理，返回通用映射
    return "GB/T39412-6.1.1.1 输入验证不足";
  }

  /**
   * 查找项目中的 .NET 程序集文件
   */
  async findDotnetAssemblies(projectRoot) {
    const assemblies = [];
    const dllPatterns = ["**/*.dll", "**/*.exe"];
    
    for (const pattern of dllPatterns) {
      const glob = await import('glob');
      const files = await glob.glob(pattern, { cwd: projectRoot, absolute: true });
      assemblies.push(...files);
    }
    
    return assemblies;
  }

  /**
   * 使用 ilspycmd 反编译 .NET 程序集
   */
  async decompileDotnetAssembly(assemblyPath, outputDir) {
    try {
      if (!await this.checkToolInstalled("ilspycmd")) {
        console.warn("ilspycmd 未安装，跳过反编译");
        return null;
      }

      await fs.mkdir(outputDir, { recursive: true });

      const command = `ilspycmd "${assemblyPath}" -o "${outputDir}" --use-short-names`;
      await execAsync(command, { timeout: 120000 });

      const decompiledFiles = await this._getDecompiledFiles(outputDir);
      
      return {
        success: true,
        assemblyPath,
        outputDir,
        files: decompiledFiles
      };
    } catch (error) {
      console.error("ilspycmd 反编译失败:", error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * 使用 de4dot 检测混淆并去混淆
   */
  async detectAndDeobfuscate(assemblyPath, outputDir) {
    try {
      if (!await this.checkToolInstalled("de4dot")) {
        console.warn("de4dot 未安装，跳过去混淆");
        return { success: false, skipped: true, reason: "de4dot 未安装" };
      }

      await fs.mkdir(outputDir, { recursive: true });

      const command = `de4dot "${assemblyPath}" -o "${path.join(outputDir, path.basename(assemblyPath))}"`;
      const { stdout, stderr } = await execAsync(command, { timeout: 60000 });

      const obfuscator = this._detectObfuscator(stdout, stderr);
      
      return {
        success: true,
        assemblyPath,
        outputDir,
        obfuscator,
        deobfuscatedPath: path.join(outputDir, path.basename(assemblyPath))
      };
    } catch (error) {
      console.error("de4dot 去混淆失败:", error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * 批量反编译 .NET 程序集
   */
  async decompileDotnetProject(projectRoot, outputDir) {
    const assemblies = await this.findDotnetAssemblies(projectRoot);
    
    if (assemblies.length === 0) {
      console.log("未找到 .NET 程序集文件");
      return { success: true, files: [], assemblies: [] };
    }

    const results = [];
    const decompileDir = path.join(outputDir, "decompiled");

    for (const assemblyPath of assemblies) {
      const assemblyName = path.basename(assemblyPath, path.extname(assemblyPath));
      const assemblyOutputDir = path.join(decompileDir, assemblyName);

      // 先尝试去混淆
      const deobfuscateResult = await this.detectAndDeobfuscate(assemblyPath, path.join(outputDir, "deobfuscated"));
      
      const targetAssembly = deobfuscateResult.success 
        ? deobfuscateResult.deobfuscatedPath 
        : assemblyPath;

      // 反编译
      const decompileResult = await this.decompileDotnetAssembly(targetAssembly, assemblyOutputDir);
      
      if (decompileResult.success) {
        results.push({
          assembly: path.relative(projectRoot, assemblyPath),
          obfuscated: deobfuscateResult.success,
          obfuscator: deobfuscateResult.obfuscator,
          decompiledFiles: decompileResult.files,
          outputDir: assemblyOutputDir
        });
      }
    }

    return {
      success: true,
      assemblies: results,
      totalDecompiled: results.length,
      outputDir: decompileDir
    };
  }

  /**
   * 获取反编译后的文件列表
   */
  async _getDecompiledFiles(outputDir) {
    const files = [];
    const glob = await import('glob');
    const csFiles = await glob.glob("**/*.cs", { cwd: outputDir, absolute: true });
    
    for (const file of csFiles) {
      const content = await fs.readFile(file, "utf8");
      files.push({
        path: file,
        relativePath: path.relative(outputDir, file),
        size: content.length,
        lines: content.split('\n').length
      });
    }
    
    return files;
  }

  /**
   * 从 de4dot 输出中检测混淆器类型
   */
  _detectObfuscator(stdout, stderr) {
    const output = (stdout || "") + (stderr || "");
    
    if (output.includes("ConfuserEx")) return "ConfuserEx";
    if (output.includes("Eazfuscator")) return "Eazfuscator";
    if (output.includes("SmartAssembly")) return "SmartAssembly";
    if (output.includes("Dotfuscator")) return "Dotfuscator";
    if (output.includes("CryptoObfuscator")) return "CryptoObfuscator";
    if (output.includes("CodeVeil")) return "CodeVeil";
    if (output.includes("Xenocode")) return "Xenocode";
    
    return "Unknown";
  }
}
