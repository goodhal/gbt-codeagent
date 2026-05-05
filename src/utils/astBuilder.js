import fs from 'fs';
import path from 'path';
import { UniversalASTNode, ClassRef, FieldInfo, MethodInfo, ASTIndex } from './astCommon.js';
import { QueryEngine } from './queryEngine.js';
import { SearchHandler } from './searchHandler.js';
import { ASTPersistenceManager } from './astPersistence.js';

class ASTBuilderService {
  constructor(options = {}) {
    this.persistenceManager = new ASTPersistenceManager({
      enabled: options.cacheEnabled !== undefined ? options.cacheEnabled : true,
      cacheDir: options.cacheDir || './cache',
      rebuildOnStartup: options.rebuildOnStartup || false
    });
    this.queryEngine = new QueryEngine();
    this.searchHandler = new SearchHandler(this.queryEngine);
    this.projectId = null;
    this.isReady = false;
    this.supportedLanguages = ['java', 'javascript', 'typescript', 'python'];
  }

  async initialize(projectId, sourcePath, options = {}) {
    this.projectId = projectId;
    this.isReady = false;

    let astIndex = null;

    if (this.persistenceManager.enabled && !options.forceRebuild) {
      astIndex = this.persistenceManager.loadASTIndex(projectId);
    }

    if (astIndex) {
      console.info(`Loaded AST index from cache for project ${projectId}`);
    } else {
      console.info(`Building AST index for project ${projectId}`);
      astIndex = await this.buildASTIndex(sourcePath, options);
      
      if (this.persistenceManager.enabled && astIndex) {
        this.persistenceManager.saveASTIndex(astIndex, projectId);
      }
    }

    if (astIndex) {
      this.queryEngine.setASTIndex(astIndex);
      this.isReady = true;
      console.info(`AST Builder initialized successfully for project ${projectId}`);
    }

    return astIndex;
  }

  async buildASTIndex(sourcePath, options = {}) {
    const astIndex = new ASTIndex();
    astIndex.projectId = this.projectId;

    const files = await this.scanSourceFiles(sourcePath, options);
    
    for (const file of files) {
      try {
        const nodes = await this.parseFile(file);
        for (const node of nodes) {
          astIndex.addNode(node);
        }
      } catch (error) {
        console.warn(`Failed to parse file ${file}: ${error.message}`);
      }
    }

    await this.buildClassHierarchy(astIndex);

    return astIndex;
  }

  async scanSourceFiles(sourcePath, options = {}) {
    const files = [];
    const extensions = options.extensions || ['.java', '.js', '.ts', '.jsx', '.tsx', '.py'];
    
    const scanDir = async (dir) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          if (!options.includeNodeModules && entry.name === 'node_modules') continue;
          if (!options.includeTests && (entry.name === 'test' || entry.name === 'tests')) continue;
          await scanDir(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (extensions.includes(ext)) {
            files.push(fullPath);
          }
        }
      }
    };

    await scanDir(sourcePath);
    return files;
  }

  async parseFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const content = fs.readFileSync(filePath, 'utf8');
    
    switch (ext) {
      case '.java':
        return this.parseJavaFile(filePath, content);
      case '.js':
      case '.jsx':
        return this.parseJavaScriptFile(filePath, content);
      case '.ts':
      case '.tsx':
        return this.parseTypeScriptFile(filePath, content);
      case '.py':
        return this.parsePythonFile(filePath, content);
      default:
        return [];
    }
  }

  parseJavaFile(filePath, content) {
    const nodes = [];
    const lines = content.split('\n');
    
    let currentNode = null;
    let packageName = '';
    let inComment = false;
    
    const packageMatch = content.match(/^\s*package\s+([a-zA-Z0-9.]+)\s*;/m);
    if (packageMatch) {
      packageName = packageMatch[1];
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('/*')) {
        inComment = true;
      }
      if (inComment) {
        if (trimmedLine.endsWith('*/')) {
          inComment = false;
        }
        continue;
      }
      if (trimmedLine.startsWith('//')) {
        continue;
      }

      const classMatch = trimmedLine.match(/^(?:(public|private|protected)\s+)?(?:abstract\s+)?(?:final\s+)?(class|interface|enum)\s+(\w+)/);
      if (classMatch) {
        const modifiers = [];
        if (classMatch[1]) modifiers.push(classMatch[1]);
        if (trimmedLine.includes('abstract')) modifiers.push('abstract');
        if (trimmedLine.includes('final')) modifiers.push('final');
        
        currentNode = new UniversalASTNode();
        currentNode.id = `${packageName}.${classMatch[3]}`;
        currentNode.name = classMatch[3];
        currentNode.type = classMatch[2];
        currentNode.language = 'java';
        currentNode.package = packageName;
        currentNode.filePath = filePath;
        currentNode.startLine = i + 1;
        currentNode.modifiers = modifiers;

        const extendsMatch = trimmedLine.match(/extends\s+([a-zA-Z0-9.]+)/);
        if (extendsMatch) {
          const superClassName = extendsMatch[1];
          const superPkg = superClassName.includes('.') ? 
            superClassName.substring(0, superClassName.lastIndexOf('.')) : '';
          const superName = superClassName.includes('.') ? 
            superClassName.substring(superClassName.lastIndexOf('.') + 1) : superClassName;
          currentNode.addSuperClass(new ClassRef(superName, superPkg));
        }

        const implementsMatch = trimmedLine.match(/implements\s+([a-zA-Z0-9.,\s]+)/);
        if (implementsMatch) {
          const interfaces = implementsMatch[1].split(',').map(s => s.trim());
          for (const iface of interfaces) {
            const ifacePkg = iface.includes('.') ? 
              iface.substring(0, iface.lastIndexOf('.')) : '';
            const ifaceName = iface.includes('.') ? 
              iface.substring(iface.lastIndexOf('.') + 1) : iface;
            currentNode.addSuperClass(new ClassRef(ifaceName, ifacePkg, true));
          }
        }

        nodes.push(currentNode);
      }

      if (currentNode) {
        const fieldMatch = trimmedLine.match(/^(?:(public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?([a-zA-Z<>[\]0-9.]+)\s+(\w+)\s*(?:=\s*[^;]*)?;/);
        if (fieldMatch) {
          const modifiers = [];
          if (fieldMatch[1]) modifiers.push(fieldMatch[1]);
          if (trimmedLine.includes('static')) modifiers.push('static');
          if (trimmedLine.includes('final')) modifiers.push('final');
          currentNode.addField(new FieldInfo(fieldMatch[3], fieldMatch[2], modifiers));
        }

        const methodMatch = trimmedLine.match(/^(?:(public|private|protected)\s+)?(?:static\s+)?(?:abstract\s+)?(?:final\s+)?([a-zA-Z<>[\]0-9.]+)\s+(\w+)\s*\(/);
        if (methodMatch) {
          const modifiers = [];
          if (methodMatch[1]) modifiers.push(methodMatch[1]);
          if (trimmedLine.includes('static')) modifiers.push('static');
          if (trimmedLine.includes('abstract')) modifiers.push('abstract');
          if (trimmedLine.includes('final')) modifiers.push('final');
          
          const params = this.extractMethodParams(line, lines.slice(i));
          currentNode.addMethod(new MethodInfo(methodMatch[3], methodMatch[2], params, modifiers, currentNode.name));
        }
      }

      if (trimmedLine === '}' && currentNode && !currentNode.endLine) {
        currentNode.endLine = i + 1;
      }
    }

    return nodes;
  }

  parseJavaScriptFile(filePath, content) {
    return this.parseJSOrTSFile(filePath, content, 'javascript');
  }

  parseTypeScriptFile(filePath, content) {
    return this.parseJSOrTSFile(filePath, content, 'typescript');
  }

  parseJSOrTSFile(filePath, content, language) {
    const nodes = [];
    const lines = content.split('\n');
    
    let currentNode = null;
    let inComment = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('/*')) {
        inComment = true;
      }
      if (inComment) {
        if (trimmedLine.endsWith('*/')) {
          inComment = false;
        }
        continue;
      }
      if (trimmedLine.startsWith('//')) {
        continue;
      }

      const classMatch = trimmedLine.match(/^(?:(export\s+)?(default\s+)?class)\s+(\w+)/);
      if (classMatch) {
        currentNode = new UniversalASTNode();
        currentNode.id = classMatch[3];
        currentNode.name = classMatch[3];
        currentNode.type = 'class';
        currentNode.language = language;
        currentNode.filePath = filePath;
        currentNode.startLine = i + 1;
        currentNode.modifiers = [];
        if (classMatch[1]) currentNode.modifiers.push('export');

        const extendsMatch = trimmedLine.match(/extends\s+(\w+)/);
        if (extendsMatch) {
          currentNode.addSuperClass(new ClassRef(extendsMatch[1]));
        }

        nodes.push(currentNode);
      }

      if (currentNode) {
        const methodMatch = trimmedLine.match(/^(?:static\s+)?(\w+)\s*\(/);
        if (methodMatch && !trimmedLine.includes('=') && !trimmedLine.includes('function')) {
          const modifiers = [];
          if (trimmedLine.includes('static')) modifiers.push('static');
          const params = this.extractMethodParams(line, lines.slice(i));
          currentNode.addMethod(new MethodInfo(methodMatch[1], 'any', params, modifiers, currentNode.name));
        }

        const fieldMatch = trimmedLine.match(/^(?:static\s+)?(\w+)\s*[?:]\s*.+/);
        if (fieldMatch && !trimmedLine.includes('(') && !trimmedLine.includes('function')) {
          const modifiers = [];
          if (trimmedLine.includes('static')) modifiers.push('static');
          currentNode.addField(new FieldInfo(fieldMatch[1], 'any', modifiers));
        }
      }

      if (trimmedLine === '}' && currentNode && !currentNode.endLine) {
        currentNode.endLine = i + 1;
      }
    }

    return nodes;
  }

  parsePythonFile(filePath, content) {
    const nodes = [];
    const lines = content.split('\n');
    
    let currentNode = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmedLine = line.trim();

      if (trimmedLine.startsWith('#')) {
        continue;
      }

      const classMatch = trimmedLine.match(/^class\s+(\w+)(?:\s*\(([^)]+)\))?/);
      if (classMatch) {
        currentNode = new UniversalASTNode();
        currentNode.id = classMatch[1];
        currentNode.name = classMatch[1];
        currentNode.type = 'class';
        currentNode.language = 'python';
        currentNode.filePath = filePath;
        currentNode.startLine = i + 1;

        if (classMatch[2]) {
          const superClasses = classMatch[2].split(',').map(s => s.trim());
          for (const superClass of superClasses) {
            if (superClass) {
              currentNode.addSuperClass(new ClassRef(superClass));
            }
          }
        }

        nodes.push(currentNode);
      }

      if (currentNode) {
        const methodMatch = trimmedLine.match(/^(?:@\w+\s*\n)?\s*def\s+(\w+)\s*\(/);
        if (methodMatch) {
          const params = this.extractPythonMethodParams(methodMatch[0], lines.slice(i));
          currentNode.addMethod(new MethodInfo(methodMatch[1], 'any', params, [], currentNode.name));
        }

        if (!trimmedLine.startsWith('def ') && !trimmedLine.startsWith('@') && trimmedLine.includes('=')) {
          const parts = trimmedLine.split('=');
          if (parts.length >= 2) {
            const fieldName = parts[0].trim();
            if (fieldName && !fieldName.includes(' ')) {
              currentNode.addField(new FieldInfo(fieldName, 'any', []));
            }
          }
        }
      }

      if (currentNode && !currentNode.endLine) {
        const nextLine = lines[i + 1];
        if (nextLine && nextLine.trim() && !nextLine.startsWith(' ') && !nextLine.startsWith('\t')) {
          currentNode.endLine = i + 1;
        }
      }
    }

    return nodes;
  }

  extractMethodParams(line, remainingLines) {
    const params = [];
    const fullLine = line + remainingLines.join('\n');
    const startIdx = fullLine.indexOf('(');
    const endIdx = fullLine.indexOf(')');

    if (startIdx === -1 || endIdx === -1) {
      return params;
    }

    const paramContent = fullLine.substring(startIdx + 1, endIdx);
    const paramParts = paramContent.split(',');
    
    for (const part of paramParts) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      
      const typeMatch = trimmed.match(/^(\w+)\s+(\w+)$/);
      if (typeMatch) {
        params.push({ type: typeMatch[1], name: typeMatch[2] });
      } else {
        const name = trimmed.split('=')[0].trim();
        if (name) {
          params.push({ type: 'any', name: name });
        }
      }
    }

    return params;
  }

  extractPythonMethodParams(methodLine, remainingLines) {
    const params = [];
    const fullLine = methodLine + remainingLines.join('\n');
    const startIdx = fullLine.indexOf('(');
    const endIdx = fullLine.indexOf(')');

    if (startIdx === -1 || endIdx === -1) {
      return params;
    }

    const paramContent = fullLine.substring(startIdx + 1, endIdx);
    const paramParts = paramContent.split(',').map(p => p.trim()).filter(p => p);
    
    for (const part of paramParts) {
      if (part === 'self' || part === 'cls') continue;
      
      const match = part.match(/^(\w+)(?:\s*:\s*(\w+))?/);
      if (match) {
        params.push({ type: match[2] || 'any', name: match[1] });
      }
    }

    return params;
  }

  async buildClassHierarchy(astIndex) {
    for (const node of astIndex.nodes) {
      for (const superClass of node.superClasses) {
        const superNode = astIndex.getClassByName(superClass.fullName);
        if (superNode) {
          superNode.addSubClass(new ClassRef(node.name, node.package));
        }
      }
    }
  }

  search(options) {
    if (!this.isReady) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this.searchHandler.unifiedSearch(options);
  }

  searchClass(className) {
    if (!this.isReady) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this.searchHandler.searchClassOnly(className);
  }

  searchMethod(className, methodName) {
    if (!this.isReady) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this.searchHandler.searchClassMethod(className, methodName);
  }

  searchField(className, fieldName) {
    if (!this.isReady) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this.searchHandler.searchClassField(className, fieldName);
  }

  getClassHierarchy(className, type = 'super') {
    if (!this.isReady) {
      return { success: false, error: 'AST Builder not initialized', data: [] };
    }
    return this.searchHandler.getClassHierarchy(className, type);
  }

  getStats() {
    return this.searchHandler.getStats();
  }

  invalidateCache() {
    if (this.projectId) {
      return this.persistenceManager.invalidate(this.projectId);
    }
    return false;
  }

  isInitialized() {
    return this.isReady;
  }
}

export { ASTBuilderService };