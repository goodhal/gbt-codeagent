const ChunkType = {
  FUNCTION: "function",
  CLASS: "class",
  MODULE: "module",
  FILE: "file",
  BLOCK: "block",
  COMMENT: "comment"
};

class CodeChunk {
  constructor({
    id,
    content,
    filePath,
    language,
    chunkType,
    lineStart,
    lineEnd,
    name = null,
    parentName = null,
    signature = null,
    securityIndicators = [],
    metadata = {}
  }) {
    this.id = id;
    this.content = content;
    this.filePath = filePath;
    this.language = language;
    this.chunkType = chunkType;
    this.lineStart = lineStart;
    this.lineEnd = lineEnd;
    this.name = name;
    this.parentName = parentName;
    this.signature = signature;
    this.securityIndicators = securityIndicators;
    this.metadata = metadata;
  }

  toJSON() {
    return {
      id: this.id,
      content: this.content,
      filePath: this.filePath,
      language: this.language,
      chunkType: this.chunkType,
      lineStart: this.lineStart,
      lineEnd: this.lineEnd,
      name: this.name,
      parentName: this.parentName,
      signature: this.signature,
      securityIndicators: this.securityIndicators,
      metadata: this.metadata
    };
  }

  toContextString(includeMetadata = true) {
    const parts = [];

    if (includeMetadata) {
      let header = `File: ${this.filePath}`;
      if (this.lineStart && this.lineEnd) {
        header += ` (lines ${this.lineStart}-${this.lineEnd})`;
      }
      if (this.name) {
        header += `\n${this.chunkType}: ${this.name}`;
      }
      if (this.parentName) {
        header += ` in ${this.parentName}`;
      }
      parts.push(header);
    }

    parts.push(`\`\`\`${this.language}\n${this.content}\n\`\`\``);

    return parts.join("\n");
  }
}

class CodeSplitter {
  constructor(options = {}) {
    this.maxChunkSize = options.maxChunkSize || 1000;
    this.overlap = options.overlap || 100;
    this.minChunkSize = options.minChunkSize || 50;
  }

  splitFile(content, filePath, language) {
    const lines = content.split("\n");
    const chunks = [];
    const extension = this._getExtension(filePath);

    const structure = this._parseStructure(content, extension);

    for (const item of structure) {
      if (item.type === ChunkType.FUNCTION || item.type === ChunkType.CLASS) {
        const chunk = new CodeChunk({
          id: `${filePath}:${item.lineStart}-${item.lineEnd}`,
          content: item.content,
          filePath,
          language: this._mapLanguage(extension),
          chunkType: item.type,
          lineStart: item.lineStart,
          lineEnd: item.lineEnd,
          name: item.name,
          signature: item.signature
        });
        chunks.push(chunk);
      }
    }

    if (chunks.length === 0) {
      const textChunks = this._splitByLines(content, filePath, language);
      chunks.push(...textChunks);
    }

    return chunks;
  }

  _parseStructure(content, extension) {
    const items = [];
    const lines = content.split("\n");

    const patterns = this._getPatterns(extension);

    let currentItem = null;
    let braceCount = 0;
    let itemStartLine = 0;
    let itemContent = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      for (const pattern of patterns) {
        const match = line.match(pattern.regex);
        if (match) {
          if (currentItem) {
            items.push(this._finishItem(currentItem, itemContent, lines, itemStartLine, i - 1));
          }

          currentItem = {
            type: pattern.type,
            name: match[pattern.nameGroup || 1],
            signature: line.trim(),
            lineStart: lineNum
          };
          itemStartLine = i;
          itemContent = [line];
          braceCount = 0;
          break;
        }
      }

      if (currentItem) {
        braceCount += (line.match(/\{/g) || []).length;
        braceCount -= (line.match(/\}/g) || []).length;

        if (braceCount === 0 && currentItem.type !== ChunkType.FUNCTION) {
          itemContent.push(line);
          items.push(this._finishItem(currentItem, itemContent, lines, itemStartLine, i));
          currentItem = null;
        } else if (braceCount === 0 && line.includes("function")) {
          itemContent.push(line);
          items.push(this._finishItem(currentItem, itemContent, lines, itemStartLine, i));
          currentItem = null;
        } else {
          itemContent.push(line);
        }
      }
    }

    if (currentItem) {
      items.push(this._finishItem(currentItem, itemContent, lines, itemStartLine, lines.length - 1));
    }

    return items;
  }

  _finishItem(item, content, allLines, startIdx, endIdx) {
    const contentStr = content.join("\n");
    return {
      type: item.type,
      name: item.name,
      signature: item.signature,
      lineStart: item.lineStart,
      lineEnd: endIdx + 1,
      content: contentStr
    };
  }

  _getPatterns(extension) {
    const pythonPatterns = [
      { regex: /^(\s*)(def\s+\w+\s*\()/, type: ChunkType.FUNCTION, nameGroup: 2 },
      { regex: /^(\s*)(class\s+\w+)/, type: ChunkType.CLASS, nameGroup: 2 }
    ];

    const jsPatterns = [
      { regex: /^function\s+(\w+)/, type: ChunkType.FUNCTION },
      { regex: /^const\s+(\w+)\s*=\s*function/, type: ChunkType.FUNCTION },
      { regex: /^const\s+(\w+)\s*=\s*\([^)]*\)\s*=>/, type: ChunkType.FUNCTION },
      { regex: /^(\w+)\s*\([^)]*\)\s*\{$/, type: ChunkType.FUNCTION },
      { regex: /^class\s+(\w+)/, type: ChunkType.CLASS }
    ];

    const javaPatterns = [
      { regex: /^(public|private|protected)?\s*(static)?\s*(\w+)\s+(\w+)\s*\(/, type: ChunkType.FUNCTION },
      { regex: /^class\s+(\w+)/, type: ChunkType.CLASS }
    ];

    const phpPatterns = [
      { regex: /^function\s+(\w+)/, type: ChunkType.FUNCTION },
      { regex: /^class\s+(\w+)/, type: ChunkType.CLASS }
    ];

    const patterns = {
      ".py": pythonPatterns,
      ".js": jsPatterns,
      ".ts": jsPatterns,
      ".jsx": jsPatterns,
      ".tsx": jsPatterns,
      ".java": javaPatterns,
      ".php": phpPatterns
    };

    return patterns[extension] || jsPatterns;
  }

  _splitByLines(content, filePath, language) {
    const lines = content.split("\n");
    const chunks = [];
    let currentChunk = [];
    let currentSize = 0;
    let startLine = 1;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineSize = line.length + 1;

      if (currentSize + lineSize > this.maxChunkSize && currentChunk.length > 0) {
        chunks.push(new CodeChunk({
          id: `${filePath}:${startLine}-${i}`,
          content: currentChunk.join("\n"),
          filePath,
          language,
          chunkType: ChunkType.BLOCK,
          lineStart: startLine,
          lineEnd: i
        }));

        const overlapLines = currentChunk.slice(-Math.floor(this.overlap / 20)).join("\n");
        currentChunk = overlapLines ? [overlapLines] : [];
        currentSize = currentChunk.join("\n").length;
        startLine = i - (currentChunk.length - 1);
      }

      currentChunk.push(line);
      currentSize += lineSize;
    }

    if (currentChunk.length > 0) {
      chunks.push(new CodeChunk({
        id: `${filePath}:${startLine}-${lines.length}`,
        content: currentChunk.join("\n"),
        filePath,
        language,
        chunkType: ChunkType.BLOCK,
        lineStart: startLine,
        lineEnd: lines.length
      }));
    }

    return chunks;
  }

  _getExtension(filePath) {
    const match = filePath.match(/\.[^.]+$/);
    return match ? match[0] : "";
  }

  _mapLanguage(extension) {
    const map = {
      ".py": "python",
      ".js": "javascript",
      ".ts": "typescript",
      ".jsx": "jsx",
      ".tsx": "tsx",
      ".java": "java",
      ".php": "php",
      ".go": "go",
      ".rs": "rust",
      ".rb": "ruby",
      ".c": "c",
      ".cpp": "cpp",
      ".h": "c",
      ".hpp": "cpp",
      ".cs": "csharp",
      ".swift": "swift",
      ".kt": "kotlin"
    };
    return map[extension] || "text";
  }
}

export {
  ChunkType,
  CodeChunk,
  CodeSplitter
};