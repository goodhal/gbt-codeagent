import { promises as fs } from "node:fs";
import path from "node:path";
import { exec } from "node:child_process";
import { CODE_EXTENSIONS } from "../utils/fileUtils.js";

const execAsync = (command, options = {}) => {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`命令执行超时: ${command}`));
    }, options.timeout || 30000);

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

class LocalToolExecutor {
  constructor({ rootPath }) {
    this.rootPath = rootPath || process.cwd();
  }

  _resolvePath(filePath) {
    if (path.isAbsolute(filePath)) {
      return filePath;
    }
    return path.join(this.rootPath, filePath);
  }

  _validatePath(filePath) {
    const resolved = this._resolvePath(filePath);
    const normalized = path.normalize(resolved);
    if (!normalized.startsWith(path.normalize(this.rootPath))) {
      throw new Error(`路径越界: ${filePath}`);
    }
    return resolved;
  }

  async execute(toolName, args) {
    const methodName = `execute${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_([a-z])/g, (_, c) => c.toUpperCase())}`;
    if (typeof this[methodName] === 'function') {
      return await this[methodName](args);
    }

    const simpleMethodName = `execute${toolName.replace(/^local_/, '').split('_').map((p, i) => i === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1)).join('')}`;
    if (typeof this[simpleMethodName] === 'function') {
      return await this[simpleMethodName](args);
    }

    return { error: `Unknown tool: ${toolName}` };
  }

  async executeFileContent({ file_path, ref }) {
    try {
      const fullPath = this._validatePath(file_path);
      const content = await fs.readFile(fullPath, 'utf8');
      const stats = await fs.stat(fullPath);

      return {
        file_path,
        content: content.length > 50000 ? content.substring(0, 50000) + '\n... (truncated)' : content,
        lines: content.split('\n').length,
        size: stats.size,
        truncated: content.length > 50000
      };
    } catch (error) {
      return { error: `无法读取文件: ${error.message}`, file_path };
    }
  }

  async executeFileInfo({ file_path }) {
    try {
      const fullPath = this._validatePath(file_path);
      const stats = await fs.stat(fullPath);
      const content = await fs.readFile(fullPath, 'utf8');
      const ext = path.extname(file_path).toLowerCase();

      return {
        file_path,
        exists: true,
        size: stats.size,
        lines: content.split('\n').length,
        extension: ext,
        language: this._extToLanguage(ext),
        is_code: CODE_EXTENSIONS.has(ext)
      };
    } catch (error) {
      return { file_path, exists: false, error: error.message };
    }
  }

  async executeProjectStructure({ include_content = false, file_type_filter }) {
    try {
      const files = await this._walkDirectory(this.rootPath, file_type_filter);

      if (!include_content) {
        return { files: files.map(f => f.replace(this.rootPath, '').replace(/^[/\\]/, '')) };
      }

      const filesWithContent = await Promise.all(
        files.slice(0, 100).map(async (file) => {
          try {
            const content = await fs.readFile(file, 'utf8');
            const relativePath = file.replace(this.rootPath, '').replace(/^[/\\]/, '');
            return {
              path: relativePath,
              preview: content.substring(0, 500),
              lines: content.split('\n').length
            };
          } catch {
            return null;
          }
        })
      );

      return {
        files: files.filter(f => !f.includes('node_modules')).map(f => f.replace(this.rootPath, '').replace(/^[/\\]/, '')),
        preview_count: filesWithContent.filter(Boolean).length,
        previews: filesWithContent.filter(Boolean)
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeSearchCode({ query, file_type, case_sensitive = false }) {
    try {
      const ext = file_type ? `.${file_type.replace(/^\./, '')}` : '';
      const flags = case_sensitive ? '' : 'i';
      const pattern = new RegExp(this._escapeRegex(query), flags);

      const results = [];
      const files = await this._walkDirectory(this.rootPath, file_type);

      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf8');
          const lines = content.split('\n');

          for (let i = 0; i < lines.length; i++) {
            if (pattern.test(lines[i])) {
              results.push({
                file: file.replace(this.rootPath, '').replace(/^[/\\]/, ''),
                line: i + 1,
                content: lines[i].trim()
              });

              if (results.length >= 100) break;
            }
          }
        } catch {
        }

        if (results.length >= 100) break;
      }

      return {
        query,
        file_type,
        case_sensitive,
        count: results.length,
        results: results.slice(0, 50)
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeGlobalSearch({ search_patterns, file_patterns, exclude_patterns, case_sensitive = false, include_context = true, context_lines = 3 }) {
    try {
      const patterns = Array.isArray(search_patterns) ? search_patterns : [search_patterns];
      const results = [];

      let grepQuery = patterns.map(p => `"${p}"`).join(' ');
      if (file_patterns && file_patterns.length) {
        grepQuery += ' ' + file_patterns.map(p => `--include="${p}"`).join(' ');
      }
      if (exclude_patterns && exclude_patterns.length) {
        grepQuery += ' ' + exclude_patterns.map(p => `--exclude="${p}"`).join(' ');
      }
      if (!case_sensitive) {
        grepQuery += ' -i';
      }

      try {
        const { stdout } = await execAsync(`grep -rn ${grepQuery} "${this.rootPath}"`, { timeout: 30000 });
        const lines = stdout.split('\n').filter(Boolean);

        for (const line of lines) {
          const match = line.match(/^([^:]+):(\d+):(.*)$/);
          if (match) {
            const [, file, lineNum, content] = match;
            const relativePath = file.replace(this.rootPath, '').replace(/^[/\\]/, '');

            if (include_context) {
              results.push({
                file: relativePath,
                line: parseInt(lineNum),
                content: content.trim()
              });
            } else {
              results.push({ file: relativePath, line: parseInt(lineNum) });
            }

            if (results.length >= 100) break;
          }
        }
      } catch (grepError) {
        if (grepError.stdout) {
          const lines = grepError.stdout.split('\n').filter(Boolean);
          for (const line of lines) {
            const match = line.match(/^([^:]+):(\d+):(.*)$/);
            if (match) {
              const [, file, lineNum, content] = match;
              results.push({
                file: file.replace(this.rootPath, '').replace(/^[/\\]/, ''),
                line: parseInt(lineNum),
                content: content.trim()
              });
            }
          }
        }
      }

      return {
        patterns,
        file_patterns,
        count: results.length,
        results: results.slice(0, 50)
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeContextAnalysis({ file_path, line_number, context_lines = 5 }) {
    try {
      const fullPath = this._validatePath(file_path);
      const content = await fs.readFile(fullPath, 'utf8');
      const lines = content.split('\n');

      const startLine = Math.max(0, line_number - context_lines - 1);
      const endLine = Math.min(lines.length, line_number + context_lines);

      const context = lines.slice(startLine, endLine).map((line, idx) => ({
        line: startLine + idx + 1,
        content: line,
        marker: startLine + idx + 1 === line_number ? '>>>' : '   '
      }));

      return {
        file_path,
        target_line: line_number,
        context_start: startLine + 1,
        context_end: endLine,
        context
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeFunctionAnalysis({ file_path, function_name, include_calls = true }) {
    try {
      const fullPath = this._validatePath(file_path);
      const content = await fs.readFile(fullPath, 'utf8');
      const lines = content.split('\n');

      const functionPattern = this._getFunctionPattern(file_path);
      const results = [];

      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(functionPattern);
        if (match && match[1] === function_name) {
          const funcInfo = {
            name: match[1],
            line: i + 1,
            definition: lines[i].trim()
          };

          if (include_calls) {
            const funcBody = lines.slice(i, Math.min(lines.length, i + 100)).join('\n');
            const calls = this._extractFunctionCalls(funcBody, function_name);
            funcInfo.calls = calls;
          }

          results.push(funcInfo);
        }
      }

      return {
        file_path,
        function_name,
        found: results.length,
        functions: results
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeRecursiveFunctionAnalysis({ file_path, function_name, max_depth = 3, analyze_cross_file_calls = true }) {
    try {
      const visited = new Set();
      const callChain = [];

      const analyzeFunc = async (fp, funcName, depth) => {
        if (depth > max_depth) return;

        const key = `${fp}:${funcName}`;
        if (visited.has(key)) return;
        visited.add(key);

        const result = await this.executeFunctionAnalysis({ file_path: fp, function_name: funcName, include_calls: true });

        for (const func of result.functions || []) {
          callChain.push({
            depth,
            file: fp,
            function: funcName,
            line: func.line
          });

          for (const call of func.calls || []) {
            if (analyze_cross_file_calls) {
              const callFile = call.file || fp;
              await analyzeFunc(callFile, call.name, depth + 1);
            }
          }
        }
      };

      await analyzeFunc(file_path, function_name, 1);

      return {
        file_path,
        function_name,
        max_depth,
        total_calls: callChain.length,
        call_chain: callChain
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async executeDependencyAnalysis({ file_path }) {
    try {
      const fullPath = this._validatePath(file_path);

      if (!fullPath.includes('package.json') && !fullPath.includes('go.mod') &&
          !fullPath.includes('requirements.txt') && !fullPath.includes('pom.xml') &&
          !fullPath.includes('build.gradle')) {
        return { error: 'Not a recognized dependency file', file_path };
      }

      const content = await fs.readFile(fullPath, 'utf8');
      const ext = path.extname(file_path).toLowerCase();

      let dependencies = [];
      if (ext === '.json' && fullPath.includes('package.json')) {
        try {
          const pkg = JSON.parse(content);
          dependencies = Object.entries({
            ...pkg.dependencies || {},
            ...pkg.devDependencies || {}
          }).map(([name, version]) => ({ name, version: String(version) }));
        } catch {
          return { error: 'Invalid JSON', file_path };
        }
      } else if (ext === '.mod') {
        const lines = content.split('\n');
        let currentRequire = null;
        for (const line of lines) {
          const requireMatch = line.match(/^require\s+\(([^)]+)\)/);
          if (requireMatch) currentRequire = requireMatch[1];
          const depMatch = line.match(/^\s+(\S+)\s+v(\S+)/);
          if (depMatch && currentRequire) {
            dependencies.push({ name: depMatch[1], version: `v${depMatch[2]}`, require: currentRequire });
          }
        }
      } else if (ext === '.txt' && fullPath.includes('requirements')) {
        dependencies = content.split('\n')
          .filter(l => l.trim() && !l.startsWith('#'))
          .map(l => {
            const [name, version] = l.split(/[=<>!]/);
            return { name: name.trim(), version: version ? version.trim() : 'any' };
          });
      }

      return {
        file_path,
        type: ext,
        count: dependencies.length,
        dependencies: dependencies.slice(0, 50)
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  _walkDirectory(dir, fileTypeFilter) {
    return new Promise(async (resolve, reject) => {
      const results = [];
      const ext = fileTypeFilter ? `.${fileTypeFilter.replace(/^\./, '')}` : null;

      const walk = async (d) => {
        try {
          const entries = await fs.readdir(d, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(d, entry.name);
            if (entry.isDirectory()) {
              if (!entry.name.startsWith('.') && entry.name !== 'node_modules' &&
                  entry.name !== 'vendor' && entry.name !== 'dist' && entry.name !== 'build') {
                await walk(fullPath);
              }
            } else if (entry.isFile()) {
              if (!ext || entry.name.endsWith(ext)) {
                results.push(fullPath);
              }
            }
          }
        } catch {
        }
      };

      await walk(dir);
      resolve(results);
    });
  }

  _escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  _extToLanguage(ext) {
    const map = {
      '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'JavaScript', '.tsx': 'TypeScript',
      '.py': 'Python', '.go': 'Go', '.java': 'Java', '.rb': 'Ruby', '.rs': 'Rust',
      '.cs': 'C#', '.cpp': 'C++', '.c': 'C', '.php': 'PHP'
    };
    return map[ext] || 'Unknown';
  }

  _getFunctionPattern(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const patterns = {
      '.js': /^(?:export\s+)?(?:async\s+)?function\s+(\w+)|^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])*\s*=>|class\s+\w+/,
      '.ts': /^(?:export\s+)?(?:async\s+)?function\s+(\w+)|^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])*\s*=>|class\s+\w+/,
      '.py': /^def\s+(\w+)\s*\(/,
      '.go': /^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/,
      '.java': /^(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*\w+\s+(\w+)\s*\(/,
      '.rb': /^def\s+(\w+)/,
      '.rs': /^fn\s+(\w+)/,
      '.cs': /^(?:public|private|protected|internal)?\s*static?\s*(?:async)?\s*\w+\s+(\w+)\s*\(/,
      '.cpp': /^(?:virtual\s+)?(?:void|int|string|\w+)\s+(?:\w+::)?(\w+)\s*\(/,
      '.c': /^(?:void|int|char|\w+)\s+(\w+)\s*\(/,
      '.php': /^(?:public|private|protected)?\s*function\s+(\w+)\s*\(/
    };
    return patterns[ext] || /(\w+)\s*\(/;
  }

  _extractFunctionCalls(code, excludeName) {
    const calls = [];
    const callPattern = /(\w+)\s*\(/g;
    let match;

    while ((match = callPattern.exec(code)) !== null) {
      const name = match[1];
      if (name !== excludeName && !name.match(/^(?:if|else|while|for|return|throw|new|console)$/)) {
        const lineNum = code.substring(0, match.index).split('\n').length;
        calls.push({ name, line: lineNum });
      }
    }

    return calls.slice(0, 20);
  }
}

function createLocalToolExecutor(rootPath) {
  return new LocalToolExecutor({ rootPath });
}

export {
  LocalToolExecutor,
  createLocalToolExecutor
};