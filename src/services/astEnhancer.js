import path from 'path';
import { promises as fs } from 'node:fs';
import { ASTBuilderService } from '../utils/astBuilder.js';
import { QueryEngine } from '../utils/queryEngine.js';
import { SearchHandler } from '../utils/searchHandler.js';

const DANGEROUS_SINKS = {
  'eval': { severity: 'critical', desc: '动态代码执行', vulnType: 'CODE_INJECTION' },
  'exec': { severity: 'critical', desc: '命令执行', vulnType: 'COMMAND_INJECTION' },
  'system': { severity: 'critical', desc: '系统命令调用', vulnType: 'COMMAND_INJECTION' },
  'spawn': { severity: 'high', desc: '进程创建', vulnType: 'COMMAND_INJECTION' },
  'execSync': { severity: 'critical', desc: '同步命令执行', vulnType: 'COMMAND_INJECTION' },
  'execFile': { severity: 'high', desc: '进程文件执行', vulnType: 'COMMAND_INJECTION' },
  'sql.query': { severity: 'high', desc: '原始SQL查询', vulnType: 'SQL_INJECTION' },
  'sql.execute': { severity: 'high', desc: 'SQL执行', vulnType: 'SQL_INJECTION' },
  'raw': { severity: 'medium', desc: '动态查询构造', vulnType: 'SQL_INJECTION' },
  'innerHTML': { severity: 'high', desc: '动态HTML插入', vulnType: 'XSS' },
  'dangerouslySetInnerHTML': { severity: 'high', desc: 'React动态HTML', vulnType: 'XSS' },
  'document.write': { severity: 'high', desc: '文档写入', vulnType: 'XSS' },
  'v-html': { severity: 'high', desc: 'Vue动态HTML', vulnType: 'XSS' },
  'innerText': { severity: 'medium', desc: '文本插入', vulnType: 'XSS' },
  'textContent': { severity: 'medium', desc: '文本内容设置', vulnType: 'XSS' },
  'execute': { severity: 'high', desc: '动态执行', vulnType: 'CODE_INJECTION' },
  'run': { severity: 'high', desc: '动态运行', vulnType: 'CODE_INJECTION' },
  'loadStrings': { severity: 'medium', desc: '字符串加载执行', vulnType: 'CODE_INJECTION' },
  'fetch': { severity: 'medium', desc: 'HTTP请求', vulnType: 'SSRF' },
  'axios': { severity: 'medium', desc: 'HTTP客户端', vulnType: 'SSRF' },
  'http.request': { severity: 'medium', desc: 'HTTP请求', vulnType: 'SSRF' },
  'url.open': { severity: 'medium', desc: 'URL打开', vulnType: 'SSRF' },
  'request': { severity: 'medium', desc: '网络请求', vulnType: 'SSRF' },
  'urllib': { severity: 'medium', desc: 'URL库', vulnType: 'SSRF' },
  'httpx': { severity: 'medium', desc: 'HTTPX客户端', vulnType: 'SSRF' },
  'readFile': { severity: 'medium', desc: '文件读取', vulnType: 'PATH_TRAVERSAL' },
  'readFileSync': { severity: 'medium', desc: '同步文件读取', vulnType: 'PATH_TRAVERSAL' },
  'readdir': { severity: 'medium', desc: '目录读取', vulnType: 'PATH_TRAVERSAL' },
  'createReadStream': { severity: 'medium', desc: '流式文件读取', vulnType: 'PATH_TRAVERSAL' },
  'XMLParser': { severity: 'high', desc: 'XML解析器', vulnType: 'XXE' },
  'DocumentBuilder': { severity: 'high', desc: '文档构建器', vulnType: 'XXE' },
  'SAXParser': { severity: 'high', desc: 'SAX解析器', vulnType: 'XXE' },
  'SAXReader': { severity: 'high', desc: 'SAX读取器', vulnType: 'XXE' },
  'XMLReader': { severity: 'high', desc: 'XML读取器', vulnType: 'XXE' },
  'TransformerFactory': { severity: 'high', desc: 'XSLT工厂', vulnType: 'XSLT_INJECTION' },
  'XSLTProcessor': { severity: 'high', desc: 'XSLT处理器', vulnType: 'XSLT_INJECTION' },
  'pickle.loads': { severity: 'critical', desc: 'Pickle反序列化', vulnType: 'INSECURE_DESERIALIZATION' },
  'pickle.load': { severity: 'critical', desc: 'Pickle加载', vulnType: 'INSECURE_DESERIALIZATION' },
  'yaml.load': { severity: 'critical', desc: 'YAML加载', vulnType: 'INSECURE_DESERIALIZATION' },
  'unserialize': { severity: 'critical', desc: '反序列化', vulnType: 'INSECURE_DESERIALIZATION' },
  'readObject': { severity: 'critical', desc: '对象读取', vulnType: 'INSECURE_DESERIALIZATION' },
  'ObjectInputStream': { severity: 'critical', desc: '对象输入流', vulnType: 'INSECURE_DESERIALIZATION' },
  'md5': { severity: 'medium', desc: 'MD5哈希', vulnType: 'WEAK_CRYPTO' },
  'sha1': { severity: 'medium', desc: 'SHA1哈希', vulnType: 'WEAK_CRYPTO' },
  'des': { severity: 'medium', desc: 'DES加密', vulnType: 'WEAK_CRYPTO' },
  'rc4': { severity: 'medium', desc: 'RC4加密', vulnType: 'WEAK_CRYPTO' },
  'random': { severity: 'medium', desc: '随机数', vulnType: 'INSECURE_RANDOM' },
  'Math.random': { severity: 'medium', desc: 'JS随机数', vulnType: 'INSECURE_RANDOM' }
};

const AUTH_PATTERNS = {
  required: ['authenticate', 'verify', 'checkPermission', 'authorize', 'isAuthenticated', 'hasRole', 'hasPermission', 'requireAuth', 'login', 'checkSession'],
  optional: ['optional', 'public', 'anonymous', 'guest', 'permitAll', 'anonymousOk']
};

const ACCESS_CONTROL_PATTERNS = {
  inherit: ['extends', 'implements', 'BaseController', 'BaseService', 'Parent'],
  check: ['checkOwner', 'checkTenant', 'validateOwnership', 'canAccess', 'canModify', 'isOwner', 'hasAccess']
};

class ASTEnhancerService {
  constructor() {
    this.builder = null;
    this.queryEngine = null;
    this.searchHandler = null;
    this.initialized = false;
  }

  async initialize(projectPath, options = {}) {
    if (this.initialized) {
      return this;
    }

    const projectId = path.basename(projectPath);
    this.builder = new ASTBuilderService({
      cacheEnabled: options.cacheEnabled !== false,
      cacheDir: options.cacheDir || './cache/ast'
    });

    try {
      await this.builder.initialize(projectId, projectPath, {
        forceRebuild: options.forceRebuild || false,
        includeNodeModules: false,
        includeTests: false
      });

      this.queryEngine = this.builder.queryEngine;
      this.searchHandler = new SearchHandler(this.queryEngine);
      this.initialized = true;

      console.log(`[AST增强] 已初始化，项目: ${projectId}, AST节点数: ${this.builder.astIndex?.nodes?.size || 0}`);
    } catch (error) {
      console.warn(`[AST增强] 初始化失败: ${error.message}`);
    }

    return this;
  }

  async enhanceFindings(findings, sourceRoot) {
    if (!this.initialized) {
      return findings;
    }

    const enhancedFindings = [];

    for (const finding of findings) {
      const enhanced = { ...finding };
      let context = null;

      if (finding.vulnType === 'COMMAND_INJECTION' || finding.vulnType === 'CODE_INJECTION') {
        context = await this.analyzeInjectionRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'SQL_INJECTION') {
        context = await this.analyzeSQLRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'XSS') {
        context = await this.analyzeXSSRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'SSRF') {
        context = await this.analyzeSSRFRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'PATH_TRAVERSAL') {
        context = await this.analyzePathTraversalRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'XXE' || finding.vulnType === 'XSLT_INJECTION') {
        context = await this.analyzeXMLRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.1, 1.0);
        }
      } else if (finding.vulnType === 'INSECURE_DESERIALIZATION') {
        context = await this.analyzeDeserializationRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.15, 1.0);
        }
      } else if (finding.vulnType === 'WEAK_CRYPTO' || finding.vulnType === 'INSECURE_RANDOM') {
        context = await this.analyzeCryptoRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.05, 1.0);
        }
      } else if (finding.skillId === 'access-control') {
        context = await this.analyzeAccessControl(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.05, 1.0);
        }
      } else {
        context = await this.analyzeGenericRisk(finding, sourceRoot);
        if (context) {
          enhanced.confidence = Math.min(enhanced.confidence + 0.02, 1.0);
        }
      }

      if (context) {
        enhanced.astContext = context;
      }

      enhancedFindings.push(enhanced);
    }

    return enhancedFindings;
  }

  async analyzeInjectionRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;

      const dangerousMethods = Object.keys(DANGEROUS_SINKS).filter(sink =>
        evidence.toLowerCase().includes(sink.toLowerCase())
      );

      if (dangerousMethods.length === 0) {
        return null;
      }

      const sink = dangerousMethods[0];
      const sinkInfo = DANGEROUS_SINKS[sink];

      const filePath = path.join(sourceRoot, location.split(':')[0]);
      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 10);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const contextAnalysis = {
        sink,
        sinkSeverity: sinkInfo.severity,
        sinkDesc: sinkInfo.desc,
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasValidation: this.checkValidation(contextLines),
        hasEncoding: this.checkEncoding(contextLines),
        recommendation: this.generateInjectionRecommendation(sink, contextLines)
      };

      return contextAnalysis;
    } catch (error) {
      console.warn(`[AST增强] 分析注入风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeSQLRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 8);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      return {
        queryType: this.detectQueryType(contextLines),
        hasParameterization: this.checkParameterization(contextLines),
        hasORM: this.checkORMUsage(contextLines),
        hasInputValidation: this.checkValidation(contextLines),
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        recommendation: this.generateSQLRecommendation(contextLines)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析SQL风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeAccessControl(finding, sourceRoot) {
    try {
      const { location } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 15);
      const contextEnd = Math.min(lines.length, lineNum + 15);
      const contextLines = lines.slice(contextStart, contextEnd);

      const className = this.extractClassName(contextLines);
      let inheritance = null;
      let hasAuthCheck = false;
      let hasOwnerCheck = false;

      if (className && this.queryEngine) {
        const classResult = this.searchHandler.searchClassOnly(className);
        if (classResult.success && classResult.data.length > 0) {
          const classData = classResult.data[0];
          inheritance = {
            extends: classData.extends || [],
            implements: classData.interfaces || []
          };

          hasAuthCheck = classData.methods?.some(m =>
            AUTH_PATTERNS.required.some(pattern => m.name.toLowerCase().includes(pattern.toLowerCase()))
          );

          hasOwnerCheck = classData.methods?.some(m =>
            ACCESS_CONTROL_PATTERNS.check.some(pattern => m.name.toLowerCase().includes(pattern.toLowerCase()))
          );
        }
      }

      return {
        className,
        inheritance,
        hasAuthCheck,
        hasOwnerCheck,
        hasAuthAnnotation: this.checkAuthAnnotation(contextLines),
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        recommendation: this.generateAccessControlRecommendation(className, hasAuthCheck, hasOwnerCheck)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析访问控制失败: ${error.message}`);
      return null;
    }
  }

  checkUserInput(lines) {
    const userInputPatterns = [
      /\b(req|request|params|query|body|headers|cookies)\b/,
      /\b(input|userInput|formData)\b/,
      /\b(getPost|getQuery|getParam)\b/,
      /\$_(GET|POST|REQUEST|COOKIES)/
    ];

    return lines.some(line => userInputPatterns.some(pattern => pattern.test(line)));
  }

  checkValidation(lines) {
    const validationPatterns = [
      /\b(validate|sanitize|escape|encode|decode|clean)\b/i,
      /\b(check|verify|assert)\b/i,
      /\b(regex|pattern|match)\b/i,
      /\b(whitelist|blacklist|allowlist|blocklist)\b/i
    ];

    return lines.some(line => validationPatterns.some(pattern => pattern.test(line)));
  }

  checkEncoding(lines) {
    const encodingPatterns = [
      /\b(encodeURI|encodeURIComponent|escape|htmlEncode|entityEncode)\b/,
      /\b(btoa|Buffer\.from.*base64)\b/
    ];

    return lines.some(line => encodingPatterns.some(pattern => pattern.test(line)));
  }

  checkParameterization(lines) {
    const paramPatterns = [
      /\?|\$\d|\:\w/,
      /\b(query|execute|run)\s*\(/,
      /\b(bind|param|prepare)\s*\(/
    ];

    return lines.some(line => paramPatterns.some(pattern => pattern.test(line)));
  }

  checkORMUsage(lines) {
    const ormPatterns = [
      /\b(sequelize|typeorm|prisma|bookshelf|mongoose|ActiveRecord)\b/i,
      /\b\.find|\.create|\.update|\.delete\b/i,
      /\bwhere\(\)|\.where\(/i
    ];

    return lines.some(line => ormPatterns.some(pattern => pattern.test(line)));
  }

  checkAuthAnnotation(lines) {
    const annotationPatterns = [
      /@(PreAuthorize|Secured|RequiresPermissions|RolesAllowed)/,
      /@(Auth|Authenticated|Anonymous)/,
      /#(auth|permission|role)/,
      /--\s*(auth|permission|role)/
    ];

    return lines.some(line => annotationPatterns.some(pattern => pattern.test(line)));
  }

  detectQueryType(lines) {
    const queryPatterns = {
      'raw_sql': /\b(raw|query|execute)\s*\(\s*`|\.query\s*\(/i,
      'orm': /\b(find|create|update|delete|where)\s*\(/i,
      'parameterized': /\b(prepare|bind|param)\s*\(/i
    };

    for (const [type, pattern] of Object.entries(queryPatterns)) {
      if (lines.some(line => pattern.test(line))) {
        return type;
      }
    }

    return 'unknown';
  }

  extractClassName(lines) {
    const classPattern = /class\s+(\w+)/;
    for (const line of lines) {
      const match = line.match(classPattern);
      if (match) {
        return match[1];
      }
    }
    return null;
  }

  async analyzeXSSRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 8);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const xssSinks = ['innerHTML', 'dangerouslySetInnerHTML', 'document.write', 'v-html', 'innerText', 'textContent'];
      const matchedSink = xssSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: 'high',
        sinkDesc: 'XSS风险sink',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasSanitization: this.checkXSSSanitization(contextLines),
        hasEncoding: this.checkEncoding(contextLines),
        recommendation: this.generateXSSRecommendation(contextLines, matchedSink)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析XSS风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeSSRFRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 8);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const ssrfSinks = ['fetch', 'axios', 'http.request', 'url.open', 'request', 'urllib', 'httpx'];
      const matchedSink = ssrfSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: 'medium',
        sinkDesc: 'SSRF风险sink',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasURLValidation: this.checkURLValidation(contextLines),
        hasAllowlist: this.checkAllowlist(contextLines),
        recommendation: this.generateSSRFRecommendation(contextLines)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析SSRF风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzePathTraversalRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 10);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const pathSinks = ['readFile', 'readFileSync', 'readdir', 'createReadStream'];
      const matchedSink = pathSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: 'medium',
        sinkDesc: '路径遍历风险sink',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasPathValidation: this.checkPathValidation(contextLines),
        hasNormalization: this.checkPathNormalization(contextLines),
        recommendation: this.generatePathTraversalRecommendation(contextLines)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析路径遍历风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeXMLRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 8);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const xmlSinks = ['XMLParser', 'DocumentBuilder', 'SAXParser', 'SAXReader', 'XMLReader', 'TransformerFactory', 'XSLTProcessor'];
      const matchedSink = xmlSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: 'high',
        sinkDesc: finding.vulnType === 'XXE' ? 'XXE风险sink' : 'XSLT注入风险sink',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasXXEProtection: this.checkXXEProtection(contextLines),
        hasSecureParsing: this.checkSecureXMLParsing(contextLines),
        recommendation: this.generateXMLRecommendation(contextLines, finding.vulnType)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析XML风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeDeserializationRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 8);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const deserializationSinks = ['pickle.loads', 'pickle.load', 'yaml.load', 'unserialize', 'readObject', 'ObjectInputStream'];
      const matchedSink = deserializationSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: 'critical',
        sinkDesc: '反序列化风险sink',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasSignatureValidation: this.checkSignatureValidation(contextLines),
        hasTypeChecking: this.checkTypeChecking(contextLines),
        recommendation: this.generateDeserializationRecommendation(contextLines)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析反序列化风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeCryptoRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 5);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const weakCryptoSinks = ['md5', 'sha1', 'des', 'rc4', 'random', 'Math.random'];
      const matchedSink = weakCryptoSinks.find(sink => evidence.toLowerCase().includes(sink.toLowerCase()));

      return {
        sink: matchedSink || 'unknown',
        sinkSeverity: finding.vulnType === 'WEAK_CRYPTO' ? 'medium' : 'low',
        sinkDesc: finding.vulnType === 'WEAK_CRYPTO' ? '弱加密算法' : '不安全随机数',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasSalt: this.checkSaltUsage(contextLines),
        hasSecureAlternative: this.checkSecureCrypto(contextLines),
        recommendation: this.generateCryptoRecommendation(contextLines, finding.vulnType)
      };
    } catch (error) {
      console.warn(`[AST增强] 分析加密风险失败: ${error.message}`);
      return null;
    }
  }

  async analyzeGenericRisk(finding, sourceRoot) {
    try {
      const { location, evidence } = finding;
      const filePath = path.join(sourceRoot, location.split(':')[0]);

      let fileContent;
      try {
        fileContent = await fs.readFile(filePath, 'utf8');
      } catch {
        return null;
      }

      const lines = fileContent.split('\n');
      const lineNum = parseInt(location.split(':')[1]) || 1;
      const contextStart = Math.max(0, lineNum - 10);
      const contextEnd = Math.min(lines.length, lineNum + 5);
      const contextLines = lines.slice(contextStart, contextEnd);

      const matchedSink = this.detectSink(evidence);

      return {
        sink: matchedSink || 'generic',
        sinkSeverity: 'unknown',
        sinkDesc: '通用风险分析',
        contextLines: contextLines.map((line, idx) => ({
          lineNum: contextStart + idx + 1,
          content: line.trim()
        })),
        hasUserInput: this.checkUserInput(contextLines),
        hasValidation: this.checkValidation(contextLines),
        recommendation: '建议对用户输入进行严格验证和转义处理'
      };
    } catch (error) {
      console.warn(`[AST增强] 通用风险分析失败: ${error.message}`);
      return null;
    }
  }

  detectSink(evidence) {
    for (const [sink, info] of Object.entries(DANGEROUS_SINKS)) {
      if (evidence.toLowerCase().includes(sink.toLowerCase())) {
        return sink;
      }
    }
    return null;
  }

  checkXSSSanitization(lines) {
    const patterns = [
      /\b(sanitize|DOMPurify|escapeHtml|htmlEscape)\b/i,
      /\b(textContent|innerText)\b/,
      /\b(stripTags|removeHtml|stripHtml)\b/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkURLValidation(lines) {
    const patterns = [
      /\b(isValidUrl|validateUrl|checkUrl|verifyUrl)\b/i,
      /\b(hostname|port|protocol)\b/,
      /\b(allowlist|blocklist)\b/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkAllowlist(lines) {
    const patterns = [
      /\b(allowlist|whitelist|approvedUrls)\b/i,
      /\b(validHosts|trustedDomains)\b/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkPathValidation(lines) {
    const patterns = [
      /\b(realpath|normalize|resolve)\b/,
      /\b(isInside|checkPath|validatePath)\b/i,
      /\b(basename|dirname)\b/
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkPathNormalization(lines) {
    const patterns = [
      /\b(normalize|resolve|join)\b.*\b\.\./,
      /\breadFileSync\s*\(\s*path\.join/,
      /\bpath\.normalize\b/
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkXXEProtection(lines) {
    const patterns = [
      /disallow-doctype-decl/i,
      /external-general-entities/i,
      /external-parameter-entities/i,
      /\bXMLConstants\b/,
      /\b_FEATURE_SECURE_PROCESSING\b/
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkSecureXMLParsing(lines) {
    const patterns = [
      /setFeature.*secure/i,
      /setProperty.*secure/i,
      /SAXParserFactory.*newInstance/i,
      /DocumentBuilderFactory.*newInstance/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkSignatureValidation(lines) {
    const patterns = [
      /\b(verify|validateSignature|checkSignature)\b/i,
      /\b(crypto\.createVerify)\b/,
      /\b(hmac|mac)\b/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkTypeChecking(lines) {
    const patterns = [
      /\b(instanceof|typeof|type)\b/,
      /\b(allowedClasses|whitelist)\b/i
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkSaltUsage(lines) {
    const patterns = [
      /\b(salt|SALT)\b/,
      /\bcrypto\.randomBytes\b/
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  checkSecureCrypto(lines) {
    const patterns = [
      /\b(sha256|sha384|sha512|bcrypt|argon2|scrypt)\b/i,
      /\bcrypto\.randomUUID\b/
    ];
    return lines.some(line => patterns.some(p => p.test(line)));
  }

  generateXSSRecommendation(contextLines, sink) {
    if (this.checkXSSSanitization(contextLines)) {
      return '已检测到净化处理，需确认净化库版本和配置正确';
    }
    const bases = {
      'innerHTML': '避免使用 innerHTML，改用 textContent 或对输入进行 HTML 转义',
      'dangerouslySetInnerHTML': '使用 DOMPurify 库净化 HTML 输入',
      'document.write': '避免使用 document.write，改用 textContent',
      'v-html': '使用 v-text 或对内容进行净化处理',
      'innerText': 'innerText 相对安全，但建议确认无 HTML 解析风险'
    };
    return bases[sink] || '对用户输入进行 HTML 转义或使用安全净化库';
  }

  generateSSRFRecommendation(contextLines) {
    if (this.checkURLValidation(contextLines) || this.checkAllowlist(contextLines)) {
      return '已检测到URL验证，需确认验证逻辑完整性';
    }
    return '建议添加URL验证（协议、主机白名单、端口限制），防止SSRF攻击';
  }

  generatePathTraversalRecommendation(contextLines) {
    if (this.checkPathValidation(contextLines) || this.checkPathNormalization(contextLines)) {
      return '已检测到路径验证，需确认验证逻辑覆盖所有入口点';
    }
    return '建议使用 path.normalize() 和 realpath() 进行路径验证和规范化';
  }

  generateXMLRecommendation(contextLines, vulnType) {
    if (this.checkXXEProtection(contextLines) || this.checkSecureXMLParsing(contextLines)) {
      return '已检测到XXE保护配置，需确认配置正确生效';
    }
    if (vulnType === 'XSLT_INJECTION') {
      return 'XSLT处理可能执行恶意代码，建议使用安全的模板引擎';
    }
    return '建议禁用外部实体引用，使用安全的XML解析配置';
  }

  generateDeserializationRecommendation(contextLines) {
    if (this.checkSignatureValidation(contextLines) || this.checkTypeChecking(contextLines)) {
      return '已检测到签名或类型检查，需确认检查充分性';
    }
    return '反序列化风险极高，建议使用JSON替代，或实现签名验证和类型白名单';
  }

  generateCryptoRecommendation(contextLines, vulnType) {
    if (this.checkSecureCrypto(contextLines)) {
      return '检测到使用更安全的加密算法，建议移除不安全的实现';
    }
    if (vulnType === 'WEAK_CRYPTO') {
      return '建议使用 SHA-256/384/512 或 Argon2/bcrypt/scrypt 等安全算法';
    }
    return '用于安全目的的随机数建议使用 crypto.randomBytes() 或 crypto.randomUUID()';
  }

  generateInjectionRecommendation(sink, contextLines) {
    const recommendations = {
      eval: '避免使用 eval()，使用 JSON.parse() 解析 JSON，或使用沙箱环境执行动态代码',
      exec: '使用参数化的系统调用API，避免 shell 命令拼接',
      system: '避免使用 system()，使用 child_process.spawn() 并参数化命令参数',
      spawn: '确保命令参数完全参数化，避免 shell=true',
      execSync: '避免使用 execSync()，使用 spawnSync() 并参数化',
      'sql.query': '使用参数化查询替代字符串拼接',
      'innerHTML': '使用 textContent 或对输入进行 HTML 转义',
      'dangerouslySetInnerHTML': '对输入进行 HTML 转义或使用 DOMPurify 库净化'
    };

    const base = recommendations[sink] || '对用户输入进行严格验证和转义处理';

    if (this.checkValidation(contextLines)) {
      return base + '（已检测到验证逻辑，需确认验证充分性）';
    }

    return base + '（建议添加输入验证和输出编码）';
  }

  generateSQLRecommendation(contextLines) {
    if (this.checkParameterization(contextLines)) {
      return '已使用参数化查询，需确认所有用户输入都通过参数绑定';
    }

    if (this.checkORMUsage(contextLines)) {
      return '使用 ORM 查询，需确保动态条件也通过 ORM API 构建，避免字符串拼接';
    }

    return '建议将原始 SQL 查询改为参数化查询，或使用 ORM 框架';
  }

  generateAccessControlRecommendation(className, hasAuthCheck, hasOwnerCheck) {
    const parts = [];

    if (!hasAuthCheck) {
      parts.push('建议在类/方法上添加权限注解或检查逻辑');
    }

    if (!hasOwnerCheck && className) {
      parts.push('建议添加对象所有权验证，防止水平越权');
    }

    if (hasAuthCheck && hasOwnerCheck) {
      return '访问控制逻辑完整，建议确认检查覆盖所有入口点';
    }

    return parts.join('；') || '建议添加访问控制检查';
  }

  async searchClassHierarchy(className) {
    if (!this.searchHandler) {
      return null;
    }

    try {
      const result = this.searchHandler.searchClassOnly(className);
      if (result.success && result.data.length > 0) {
        return {
          className,
          extends: result.data[0].extends,
          implements: result.data[0].interfaces,
          methods: result.data[0].methods,
          fields: result.data[0].fields
        };
      }
    } catch (error) {
      console.warn(`[AST增强] 查询类继承失败: ${error.message}`);
    }

    return null;
  }

  async findMethodCalls(methodName) {
    if (!this.searchHandler) {
      return [];
    }

    try {
      const result = this.searchHandler.searchMethodByName(methodName);
      return result.success ? result.data : [];
    } catch (error) {
      console.warn(`[AST增强] 查询方法调用失败: ${error.message}`);
      return [];
    }
  }

  cleanup() {
    if (this.builder?.persistenceManager) {
      this.builder.persistenceManager.invalidateAll?.();
    }
    this.initialized = false;
    this.builder = null;
    this.queryEngine = null;
    this.searchHandler = null;
  }
}

let globalEnhancer = null;

export async function getGlobalASTEnhancer() {
  if (!globalEnhancer) {
    globalEnhancer = new ASTEnhancerService();
  }
  return globalEnhancer;
}

export { ASTEnhancerService };
