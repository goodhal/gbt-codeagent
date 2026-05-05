/**
 * 向量数据库服务
 * 支持语义检索、持久化和相似度搜索
 */

import { promises as fs } from 'node:fs';
import path from 'path';
import crypto from 'node:crypto';

export class VectorStore {
  constructor(dimension = 1536, options = {}) {
    this.dimension = dimension;
    this.options = {
      metric: options.metric || 'cosine',
      persistPath: options.persistPath || null,
      ...options
    };
    this.vectors = new Map();
    this.metadata = new Map();
    this._index = null;
    this._dirty = false;
  }

  async initialize() {
    if (this.options.persistPath) {
      await this._loadFromDisk();
    }
    return this;
  }

  add(id, vector, metadata = {}) {
    if (vector.length !== this.dimension) {
      throw new Error(`Vector dimension mismatch: expected ${this.dimension}, got ${vector.length}`);
    }

    this.vectors.set(id, vector);
    this.metadata.set(id, {
      ...metadata,
      id,
      addedAt: new Date().toISOString()
    });
    this._dirty = true;

    return this;
  }

  addBatch(items) {
    for (const item of items) {
      this.add(item.id, item.vector, item.metadata || {});
    }
    return this;
  }

  get(id) {
    const vector = this.vectors.get(id);
    if (!vector) {
      return null;
    }
    return {
      id,
      vector,
      metadata: this.metadata.get(id)
    };
  }

  remove(id) {
    const existed = this.vectors.has(id);
    this.vectors.delete(id);
    this.metadata.delete(id);
    if (existed) {
      this._dirty = true;
    }
    return existed;
  }

  search(queryVector, k = 5, options = {}) {
    if (queryVector.length !== this.dimension) {
      throw new Error(`Query vector dimension mismatch: expected ${this.dimension}, got ${queryVector.length}`);
    }

    const { filter } = options;
    const scores = [];

    for (const [id, vector] of this.vectors) {
      if (filter && !this._matchesFilter(id, filter)) {
        continue;
      }

      const similarity = this._calculateSimilarity(queryVector, vector);
      scores.push({
        id,
        score: similarity,
        metadata: this.metadata.get(id)
      });
    }

    scores.sort((a, b) => b.score - a.score);
    return scores.slice(0, k);
  }

  async searchAsync(queryVector, k = 5, options = {}) {
    return new Promise((resolve) => {
      setImmediate(() => {
        resolve(this.search(queryVector, k, options));
      });
    });
  }

  searchByText(text, embedder, k = 5, options = {}) {
    const queryVector = embedder.embed(text);
    return this.search(queryVector, k, options);
  }

  _matchesFilter(id, filter) {
    if (!filter) return true;

    const meta = this.metadata.get(id);
    if (!meta) return false;

    for (const [key, value] of Object.entries(filter)) {
      if (meta[key] !== value) {
        return false;
      }
    }
    return true;
  }

  _calculateSimilarity(vecA, vecB) {
    switch (this.options.metric) {
      case 'cosine':
        return this._cosineSimilarity(vecA, vecB);
      case 'euclidean':
        return this._euclideanDistance(vecA, vecB);
      case 'dot':
        return this._dotProduct(vecA, vecB);
      default:
        return this._cosineSimilarity(vecA, vecB);
    }
  }

  _cosineSimilarity(vecA, vecB) {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < vecA.length; i++) {
      dotProduct += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }

    normA = Math.sqrt(normA);
    normB = Math.sqrt(normB);

    if (normA === 0 || normB === 0) {
      return 0;
    }

    return dotProduct / (normA * normB);
  }

  _euclideanDistance(vecA, vecB) {
    let sum = 0;
    for (let i = 0; i < vecA.length; i++) {
      const diff = vecA[i] - vecB[i];
      sum += diff * diff;
    }
    return Math.sqrt(sum);
  }

  _dotProduct(vecA, vecB) {
    let sum = 0;
    for (let i = 0; i < vecA.length; i++) {
      sum += vecA[i] * vecB[i];
    }
    return sum;
  }

  async persist() {
    if (!this.options.persistPath) {
      return false;
    }

    if (!this._dirty) {
      return true;
    }

    const data = {
      dimension: this.dimension,
      options: this.options,
      vectors: Array.from(this.vectors.entries()),
      metadata: Array.from(this.metadata.entries())
    };

    const dir = path.dirname(this.options.persistPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(
      this.options.persistPath,
      JSON.stringify(data),
      'utf-8'
    );

    this._dirty = false;
    return true;
  }

  async _loadFromDisk() {
    try {
      const content = await fs.readFile(this.options.persistPath, 'utf-8');
      const data = JSON.parse(content);

      this.dimension = data.dimension;
      this.options = { ...this.options, ...data.options };
      this.vectors = new Map(data.vectors);
      this.metadata = new Map(data.metadata);
      this._dirty = false;

      return true;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('[VectorStore] Failed to load from disk:', error);
      }
      return false;
    }
  }

  get size() {
    return this.vectors.size;
  }

  clear() {
    this.vectors.clear();
    this.metadata.clear();
    this._dirty = true;
  }

  getStats() {
    return {
      size: this.vectors.size,
      dimension: this.dimension,
      metric: this.options.metric,
      persistPath: this.options.persistPath
    };
  }
}

export class SemanticSearchEngine {
  constructor(vectorStore, embedder) {
    this.vectorStore = vectorStore;
    this.embedder = embedder;
  }

  async index(id, text, metadata = {}) {
    const vector = await this.embedder.embed(text);
    this.vectorStore.add(id, vector, { text, ...metadata });
    return this;
  }

  async indexBatch(items) {
    const embeddings = await this.embedder.embedBatch(items.map(i => i.text));

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      this.vectorStore.add(item.id, embeddings[i], {
        text: item.text,
        ...item.metadata
      });
    }

    return this;
  }

  async search(query, k = 5, options = {}) {
    const queryVector = await this.embedder.embed(query);
    return this.vectorStore.search(queryVector, k, options);
  }

  async searchWithFilter(query, filter, k = 5) {
    return this.search(query, k, { filter });
  }

  async findSimilar(text, k = 5) {
    return this.search(text, k);
  }

  async findSimilarById(id, k = 5) {
    const item = this.vectorStore.get(id);
    if (!item) {
      return [];
    }

    return this.vectorStore.search(item.vector, k, {
      filter: { id: { $ne: id } }
    });
  }
}

export class ChunkedVectorStore extends VectorStore {
  constructor(dimension = 1536, options = {}) {
    super(dimension, options);
    this.chunkSize = options.chunkSize || 1000;
    this.chunks = new Map();
  }

  addChunked(id, text, chunkSize = 500, overlap = 50, metadata = {}) {
    const chunks = this._createChunks(text, chunkSize, overlap);

    chunks.forEach((chunk, index) => {
      const chunkId = `${id}:${index}`;
      this.chunks.set(chunkId, {
        parentId: id,
        chunkIndex: index,
        totalChunks: chunks.length,
        text: chunk
      });
    });

    return chunks.length;
  }

  _createChunks(text, chunkSize, overlap) {
    const chunks = [];
    let start = 0;

    while (start < text.length) {
      let end = start + chunkSize;

      if (end < text.length) {
        const spaceIndex = text.lastIndexOf(' ', end);
        if (spaceIndex > start + chunkSize / 2) {
          end = spaceIndex;
        }
      }

      chunks.push(text.substring(start, end).trim());
      start = end - overlap;

      if (start >= text.length) {
        break;
      }
    }

    return chunks;
  }

  getChunks(parentId) {
    const chunks = [];
    for (const [chunkId, chunk] of this.chunks) {
      if (chunk.parentId === parentId) {
        chunks.push({
          id: chunkId,
          ...chunk
        });
      }
    }
    return chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);
  }
}

export function createVectorStore(options = {}) {
  return new VectorStore(options.dimension || 1536, options);
}

export function createSemanticSearchEngine(vectorStore, embedder) {
  return new SemanticSearchEngine(vectorStore, embedder);
}

let globalVectorStore = null;

export async function getGlobalVectorStore(options = {}) {
  if (!globalVectorStore) {
    globalVectorStore = new VectorStore(options.dimension || 1536, {
      persistPath: options.persistPath,
      ...options
    });
    await globalVectorStore.initialize();
  }
  return globalVectorStore;
}

export function resetGlobalVectorStore() {
  globalVectorStore = null;
}
