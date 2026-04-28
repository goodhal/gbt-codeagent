import { EmbeddingsService, VectorStore } from "./embeddings.js";
import { CodeChunk, CodeSplitter } from "./splitter.js";

class RetrievalResult {
  constructor({
    chunkId,
    content,
    filePath,
    language,
    chunkType,
    lineStart,
    lineEnd,
    score,
    name = null,
    parentName = null,
    signature = null,
    securityIndicators = [],
    metadata = {}
  }) {
    this.chunkId = chunkId;
    this.content = content;
    this.filePath = filePath;
    this.language = language;
    this.chunkType = chunkType;
    this.lineStart = lineStart;
    this.lineEnd = lineEnd;
    this.score = score;
    this.name = name;
    this.parentName = parentName;
    this.signature = signature;
    this.securityIndicators = securityIndicators;
    this.metadata = metadata;
  }

  toJSON() {
    return {
      chunkId: this.chunkId,
      content: this.content,
      filePath: this.filePath,
      language: this.language,
      chunkType: this.chunkType,
      lineStart: this.lineStart,
      lineEnd: this.lineEnd,
      score: this.score,
      name: this.name,
      parentName: this.parentName,
      signature: this.signature,
      securityIndicators: this.securityIndicators
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

class CodeRetriever {
  constructor(options = {}) {
    this.embeddingsService = options.embeddingsService || new EmbeddingsService();
    this.vectorStore = new VectorStore(this.embeddingsService.provider.dimension);
    this.splitter = new CodeSplitter({
      maxChunkSize: options.maxChunkSize || 1000,
      overlap: options.overlap || 100
    });
    this.chunks = new Map();
    this.metadata = new Map();
  }

  async indexFile(filePath, content, language = null) {
    const extension = filePath.match(/\.[^.]+$/)?.[0] || "";
    const lang = language || this.splitter._mapLanguage(extension);

    const codeChunks = this.splitter.splitFile(content, filePath, lang);

    const ids = [];
    const texts = [];
    const metadatas = [];

    for (const chunk of codeChunks) {
      const id = chunk.id;
      ids.push(id);
      texts.push(chunk.content);
      metadatas.push({
        filePath: chunk.filePath,
        language: chunk.language,
        chunkType: chunk.chunkType,
        lineStart: chunk.lineStart,
        lineEnd: chunk.lineEnd,
        name: chunk.name,
        parentName: chunk.parentName,
        signature: chunk.signature
      });

      this.chunks.set(id, chunk);
    }

    await this.embeddingsService.embedTexts(texts, ids, metadatas);

    return {
      filePath,
      chunksIndexed: codeChunks.length
    };
  }

  async indexDirectory(dirPath, files) {
    const results = [];

    for (const file of files) {
      const filePath = file.path || `${dirPath}/${file.name}`;
      const content = file.content;

      try {
        const result = await this.indexFile(filePath, content);
        results.push(result);
      } catch (e) {
        results.push({
          filePath,
          error: e.message
        });
      }
    }

    return results;
  }

  async retrieve(query, options = {}) {
    const {
      k = 5,
      filter = {},
      minScore = 0.0
    } = options;

    const searchResults = await this.embeddingsService.searchWithScore(query, k * 2, minScore);

    const results = [];

    for (const result of searchResults) {
      const chunk = this.chunks.get(result.id);
      if (!chunk) continue;

      if (filter.language && chunk.language !== filter.language) continue;
      if (filter.chunkType && chunk.chunkType !== filter.chunkType) continue;
      if (filter.filePath && !chunk.filePath.includes(filter.filePath)) continue;

      results.push(new RetrievalResult({
        chunkId: chunk.id,
        content: chunk.content,
        filePath: chunk.filePath,
        language: chunk.language,
        chunkType: chunk.chunkType,
        lineStart: chunk.lineStart,
        lineEnd: chunk.lineEnd,
        score: result.score,
        name: chunk.name,
        parentName: chunk.parentName,
        signature: chunk.signature,
        securityIndicators: chunk.securityIndicators || [],
        metadata: result.metadata || {}
      }));

      if (results.length >= k) break;
    }

    return results;
  }

  async hybridRetrieve(query, options = {}) {
    const {
      k = 5,
      filter = {},
      semanticWeight = 0.7,
      keywordWeight = 0.3
    } = options;

    const semanticResults = await this.retrieve(query, { k, filter });

    const keywordMatches = this._keywordSearch(query, filter);

    const combined = new Map();

    for (const result of semanticResults) {
      const key = result.chunkId;
      combined.set(key, {
        ...result,
        finalScore: result.score * semanticWeight
      });
    }

    for (const result of keywordMatches) {
      const key = result.chunkId;
      if (combined.has(key)) {
        combined.get(key).finalScore += result.score * keywordWeight;
      } else {
        combined.set(key, {
          ...result,
          finalScore: result.score * keywordWeight
        });
      }
    }

    const sorted = Array.from(combined.values())
      .sort((a, b) => b.finalScore - a.finalScore)
      .slice(0, k);

    return sorted;
  }

  _keywordSearch(query, filter = {}) {
    const queryLower = query.toLowerCase();
    const queryTerms = queryLower.split(/\s+/).filter(t => t.length > 2);

    const results = [];

    for (const [id, chunk] of this.chunks) {
      if (filter.language && chunk.language !== filter.language) continue;
      if (filter.chunkType && chunk.chunkType !== filter.chunkType) continue;

      let score = 0;
      const contentLower = chunk.content.toLowerCase();
      const nameLower = (chunk.name || "").toLowerCase();

      for (const term of queryTerms) {
        if (contentLower.includes(term)) score += 1;
        if (nameLower.includes(term)) score += 2;
      }

      if (score > 0) {
        results.push(new RetrievalResult({
          chunkId: chunk.id,
          content: chunk.content,
          filePath: chunk.filePath,
          language: chunk.language,
          chunkType: chunk.chunkType,
          lineStart: chunk.lineStart,
          lineEnd: chunk.lineEnd,
          score: score / queryTerms.length,
          name: chunk.name,
          parentName: chunk.parentName,
          signature: chunk.signature,
          metadata: {}
        }));
      }
    }

    return results.sort((a, b) => b.score - a.score).slice(0, 10);
  }

  async searchByVulnerability(vulnType, options = {}) {
    const vulnQueries = {
      sql_injection: [
        "SQL query database execute",
        "SELECT WHERE INSERT UPDATE DELETE",
        "raw query ORM"
      ],
      command_injection: [
        "exec system shell command",
        "subprocess os.system",
        "eval runtime"
      ],
      xss: [
        "innerHTML document.write",
        "HTML output render",
        "user input display"
      ],
      path_traversal: [
        "file path open read",
        "directory traversal",
        "path.join resolve"
      ]
    };

    const queries = vulnQueries[vulnType] || [vulnType];

    const results = [];
    for (const query of queries) {
      const queryResults = await this.retrieve(query, options);
      results.push(...queryResults);
    }

    const unique = new Map();
    for (const result of results) {
      if (!unique.has(result.chunkId)) {
        unique.set(result.chunkId, result);
      }
    }

    return Array.from(unique.values()).sort((a, b) => b.score - a.score);
  }

  getChunk(chunkId) {
    return this.chunks.get(chunkId) || null;
  }

  getFileChunks(filePath) {
    const chunks = [];
    for (const chunk of this.chunks.values()) {
      if (chunk.filePath === filePath) {
        chunks.push(chunk);
      }
    }
    return chunks.sort((a, b) => a.lineStart - b.lineStart);
  }

  clear() {
    this.chunks.clear();
    this.metadata.clear();
  }

  getStats() {
    const byLanguage = {};
    const byType = {};

    for (const chunk of this.chunks.values()) {
      byLanguage[chunk.language] = (byLanguage[chunk.language] || 0) + 1;
      byType[chunk.chunkType] = (byType[chunk.chunkType] || 0) + 1;
    }

    return {
      totalChunks: this.chunks.size,
      byLanguage,
      byType
    };
  }

  async saveState() {
    const chunks = [];
    for (const chunk of this.chunks.values()) {
      chunks.push(chunk.toJSON());
    }
    return {
      chunks,
      stats: this.getStats()
    };
  }
}

export {
  RetrievalResult,
  CodeRetriever
};