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
      { regex: /^(\s*)@/, type: ChunkType.COMMENT },
      { regex: /^(\s*)(async\s+def|def)\s+\w+\s*\(/, type: ChunkType.FUNCTION, nameGroup: 2 },
      { regex: /^(\s*)(class\s+\w+)/, type: ChunkType.CLASS, nameGroup: 2 }
    ];

    const jsPatterns = [
      { regex: /^(export\s+)?(async\s+)?function\s+(\w+)/, type: ChunkType.FUNCTION, nameGroup: 3 },
      { regex: /^(export\s+)?class\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 2 },
      { regex: /^(const|let|var)\s+(\w+)\s*=\s*(async\s*)?\(/, type: ChunkType.FUNCTION, nameGroup: 2 },
      { regex: /^\s*(\w+)\s*:\s*(async\s*)?\(/, type: ChunkType.FUNCTION, nameGroup: 1 },
      { regex: /^(\w+)\s*\([^)]*\)\s*\{$/, type: ChunkType.FUNCTION, nameGroup: 1 },
    ];

    const javaPatterns = [
      { regex: /^(public|private|protected)?\s*(static\s+)?class\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 3 },
      { regex: /^(public|private|protected)?\s*(static\s+)?[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*\{?\s*$/, type: ChunkType.FUNCTION, nameGroup: 3 },
    ];

    const goPatterns = [
      { regex: /^\s*func\s+(\w+)/, type: ChunkType.FUNCTION },
      { regex: /^\s*type\s+(\w+)\s+struct\b/, type: ChunkType.CLASS },
      { regex: /^\s*type\s+(\w+)\s+interface\b/, type: ChunkType.CLASS },
    ];

    const phpPatterns = [
      { regex: /^(abstract\s+|final\s+)?class\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 2 },
      { regex: /^(public|private|protected)?\s*function\s+(\w+)/, type: ChunkType.FUNCTION, nameGroup: 2 },
    ];

    const cPatterns = [
      { regex: /^(static\s+)?[\w\*\s]+\s+(\w+)\s*\([^;]*\)\s*\{?\s*$/, type: ChunkType.FUNCTION, nameGroup: 2 },
      { regex: /^(struct|typedef|enum)\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 2 },
    ];

    const cppPatterns = [
      { regex: /^(template\s*<.*>\s*)?[\w:<>\*\&\s]+\s+(\w+)\s*\([^;]*\)\s*(const)?\s*\{?\s*$/, type: ChunkType.FUNCTION, nameGroup: 2 },
      { regex: /^(class|struct|namespace)\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 2 },
    ];

    const csPatterns = [
      { regex: /^(public|private|protected|internal)?\s*(static\s+)?class\s+(\w+)/, type: ChunkType.CLASS, nameGroup: 3 },
      { regex: /^(public|private|protected|internal)?\s*(static\s+)?[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*\{?\s*$/, type: ChunkType.FUNCTION, nameGroup: 3 },
    ];

    const patterns = {
      ".py": pythonPatterns,
      ".js": jsPatterns,
      ".ts": jsPatterns,
      ".jsx": jsPatterns,
      ".tsx": jsPatterns,
      ".java": javaPatterns,
      ".go": goPatterns,
      ".php": phpPatterns,
      ".c": cPatterns,
      ".h": cPatterns,
      ".cpp": cppPatterns,
      ".hpp": cppPatterns,
      ".cs": csPatterns,
    };

    return patterns[extension] || jsPatterns;
  }

  /**
   * 从 AiCodeAudit 引入：语义边界切分
   * 将超大文件按函数/类边界切分成有意义的块
   */
  splitFileSemantic(content, filePath, language, maxTokenSize) {
    const extension = this._getExtension(filePath);
    const lines = content.split("\n");
    if (!lines.length) {
      return [
        new CodeChunk({
          id: `${filePath}:1-1`,
          content: "",
          filePath,
          language,
          chunkType: ChunkType.FILE,
          lineStart: 1,
          lineEnd: 1,
        }),
      ];
    }

    const sections = this._buildSemanticSections(lines, extension);
    if (!sections.length) {
      return this.splitFile(content, filePath, language);
    }

    const chunks = [];
    let currentLines = [];
    let currentTokens = 0;
    let currentStartLine = 1;
    const approxTokenSize = maxTokenSize || this.maxChunkSize;

    for (const section of sections) {
      const sectionText = section.lines.join("\n");
      const sectionTokens = this._estimateTokenCount(sectionText);

      if (sectionTokens > approxTokenSize) {
        if (currentLines.length > 0) {
          chunks.push(
            new CodeChunk({
              id: `${filePath}:${currentStartLine}-${section.startLine - 1}`,
              content: currentLines.join("\n"),
              filePath,
              language,
              chunkType: ChunkType.BLOCK,
              lineStart: currentStartLine,
              lineEnd: section.startLine - 1,
            })
          );
          currentLines = [];
          currentTokens = 0;
        }
        const subChunks = this._splitByLines(sectionText, filePath, language, section.startLine);
        chunks.push(...subChunks);
        currentStartLine = section.endLine + 1;
        continue;
      }

      if (currentLines.length > 0 && currentTokens + sectionTokens > approxTokenSize) {
        chunks.push(
          new CodeChunk({
            id: `${filePath}:${currentStartLine}-${section.startLine - 1}`,
            content: currentLines.join("\n"),
            filePath,
            language,
            chunkType: ChunkType.BLOCK,
            lineStart: currentStartLine,
            lineEnd: section.startLine - 1,
          })
        );
        currentLines = [];
        currentTokens = 0;
        currentStartLine = section.startLine;
      }

      if (currentLines.length === 0) {
        currentStartLine = section.startLine;
      }
      currentLines.push(...section.lines);
      currentTokens += sectionTokens;
    }

    if (currentLines.length > 0) {
      chunks.push(
        new CodeChunk({
          id: `${filePath}:${currentStartLine}-${lines.length}`,
          content: currentLines.join("\n"),
          filePath,
          language,
          chunkType: ChunkType.BLOCK,
          lineStart: currentStartLine,
          lineEnd: lines.length,
        })
      );
    }

    return chunks.length > 0 ? chunks : this.splitFile(content, filePath, language);
  }

  _buildSemanticSections(lines, extension) {
    const boundaries = this._findSemanticBoundaries(lines, extension);
    if (!boundaries.length || boundaries.length <= 1) return [];

    const sections = [];
    for (let i = 0; i < boundaries.length; i++) {
      const start = boundaries[i];
      const end = i + 1 < boundaries.length ? boundaries[i + 1] - 1 : lines.length;
      const sectionLines = lines.slice(start - 1, end);
      sections.push({ startLine: start, endLine: end, lines: sectionLines });
    }
    return sections;
  }

  _findSemanticBoundaries(lines, extension) {
    const patterns = this._getSemanticBoundaryPatterns(extension);
    if (!patterns.length) return [1];

    const boundaries = [1];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of patterns) {
        if (pattern.test(line)) {
          boundaries.push(i + 1);
          break;
        }
      }
    }
    return [...new Set(boundaries)].sort((a, b) => a - b);
  }

  _getSemanticBoundaryPatterns(extension) {
    const patterns = {
      ".py": [
        /^\s*@/,
        /^\s*(async\s+def|def|class)\b/,
      ],
      ".js": [
        /^\s*(export\s+)?(async\s+)?function\b/,
        /^\s*(export\s+)?class\b/,
        /^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(/,
        /^\s*\w+\s*:\s*(async\s*)?\(/,
      ],
      ".ts": [
        /^\s*(export\s+)?(async\s+)?function\b/,
        /^\s*(export\s+)?class\b/,
        /^\s*(export\s+)?interface\b/,
        /^\s*(export\s+)?type\b/,
        /^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(/,
      ],
      ".java": [
        /^\s*(public|private|protected)?\s*(static\s+)?class\b/,
        /^\s*(public|private|protected)?\s*(static\s+)?[\w<>\[\],\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$/,
      ],
      ".go": [
        /^\s*func\b/,
        /^\s*type\s+\w+\s+struct\b/,
        /^\s*type\s+\w+\s+interface\b/,
      ],
      ".php": [
        /^\s*(abstract\s+|final\s+)?class\b/,
        /^\s*(public|private|protected)?\s*function\b/,
      ],
      ".c": [
        /^\s*(static\s+)?[\w\*\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$/,
        /^\s*(struct|typedef|enum)\b/,
      ],
      ".cpp": [
        /^\s*(template\s*<.*>\s*)?[\w:<>\*\&\s]+\s+\w+\s*\([^;]*\)\s*(const)?\s*\{?\s*$/,
        /^\s*(class|struct|namespace)\b/,
      ],
      ".cs": [
        /^\s*(public|private|protected|internal)?\s*(static\s+)?class\b/,
        /^\s*(public|private|protected|internal)?\s*(static\s+)?[\w<>\[\],\s]+\s+\w+\s*\([^;]*\)\s*\{?\s*$/,
      ],
    };

    const key = extension.toLowerCase();
    if (key === ".jsx") return patterns[".js"];
    if (key === ".tsx") return patterns[".ts"];
    return patterns[key] || patterns[".js"];
  }

  _estimateTokenCount(text) {
    if (!text) return 0;
    const chineseChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
    const otherChars = text.replace(/[\u4e00-\u9fff]/g, "").length;
    return Math.ceil(chineseChars * 2 + otherChars * 0.3);
  }

  _splitByLines(content, filePath, language, startLineOffset = 1) {
    const lines = content.split("\n");
    const chunks = [];
    let currentChunk = [];
    let currentSize = 0;
    let startLine = startLineOffset;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineSize = line.length + 1;

      if (currentSize + lineSize > this.maxChunkSize && currentChunk.length > 0) {
        chunks.push(new CodeChunk({
          id: `${filePath}:${startLine}-${startLineOffset + i - 1}`,
          content: currentChunk.join("\n"),
          filePath,
          language,
          chunkType: ChunkType.BLOCK,
          lineStart: startLine,
          lineEnd: startLineOffset + i - 1
        }));

        const overlapLines = currentChunk.slice(-Math.floor(this.overlap / 20)).join("\n");
        currentChunk = overlapLines ? [overlapLines] : [];
        currentSize = currentChunk.join("\n").length;
        startLine = startLineOffset + i - (currentChunk.length - 1);
      }

      currentChunk.push(line);
      currentSize += lineSize;
    }

    if (currentChunk.length > 0) {
      chunks.push(new CodeChunk({
        id: `${filePath}:${startLine}-${startLineOffset + lines.length - 1}`,
        content: currentChunk.join("\n"),
        filePath,
        language,
        chunkType: ChunkType.BLOCK,
        lineStart: startLine,
        lineEnd: startLineOffset + lines.length - 1
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