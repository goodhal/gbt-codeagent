class EmbeddingResult {
  constructor({ embedding, tokensUsed, model }) {
    this.embedding = embedding;
    this.tokensUsed = tokensUsed;
    this.model = model;
  }

  toJSON() {
    return {
      embedding: this.embedding,
      tokensUsed: this.tokensUsed,
      model: this.model
    };
  }
}

class BaseEmbeddingProvider {
  async embedText(text) {
    throw new Error("Not implemented");
  }

  async embedTexts(texts) {
    throw new Error("Not implemented");
  }

  get dimension() {
    throw new Error("Not implemented");
  }
}

class OpenAIEmbedding extends BaseEmbeddingProvider {
  constructor(options = {}) {
    super();
    this.apiKey = options.apiKey || process.env.OPENAI_API_KEY;
    this.baseUrl = options.baseUrl || "https://api.openai.com/v1";
    this.model = options.model || "text-embedding-3-small";
    this.dimensions = {
      "text-embedding-3-small": 1536,
      "text-embedding-3-large": 3072,
      "text-embedding-ada-002": 1536
    };
  }

  get dimension() {
    return this.dimensions[this.model] || 1536;
  }

  async embedText(text) {
    const results = await this.embedTexts([text]);
    return results[0];
  }

  async embedTexts(texts) {
    if (!texts || texts.length === 0) return [];

    const maxLength = 8191;
    const truncatedTexts = texts.map(t => t.slice(0, maxLength));

    const response = await fetch(`${this.baseUrl}/embeddings`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: this.model,
        input: truncatedTexts
      })
    });

    if (!response.ok) {
      throw new Error(`OpenAI Embedding API error: ${response.status}`);
    }

    const data = await response.json();

    return (data.data || []).map(item => new EmbeddingResult({
      embedding: item.embedding,
      tokensUsed: data.usage?.total_tokens || 0,
      model: this.model
    }));
  }
}

class LocalEmbedding extends BaseEmbeddingProvider {
  constructor(options = {}) {
    super();
    this.modelName = options.modelName || "sentence-transformers/all-MiniLM-L6-v2";
    this.dimension = options.dimension || 384;
  }

  get dimension() {
    return this.dimension;
  }

  async embedText(text) {
    const results = await this.embedTexts([text]);
    return results[0];
  }

  async embedTexts(texts) {
    if (!texts || texts.length === 0) return [];

    try {
      const response = await fetch("http://localhost:8080/embed", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ texts })
      });

      if (!response.ok) {
        throw new Error(`Local embedding service error: ${response.status}`);
      }

      const data = await response.json();
      return (data.embeddings || []).map(emb => new EmbeddingResult({
        embedding: emb,
        tokensUsed: Math.ceil(texts.join(" ").length / 4),
        model: this.modelName
      }));
    } catch (e) {
      console.error("[Embedding] Local embedding service unavailable — RAG search results will be unreliable!");
      console.error(`[Embedding] Error: ${e.message}`);
      return texts.map(() => new EmbeddingResult({
        embedding: this._randomVector(this.dimension),
        tokensUsed: 0,
        model: "fallback-random"
      }));
    }
  }

  _randomVector(dim) {
    const vec = [];
    let norm = 0;
    for (let i = 0; i < dim; i++) {
      const val = Math.random() * 2 - 1;
      vec.push(val);
      norm += val * val;
    }
    norm = Math.sqrt(norm);
    return vec.map(v => v / norm);
  }
}

class EmbeddingProviderFactory {
  static create(type, options = {}) {
    switch (type) {
      case "openai":
        return new OpenAIEmbedding(options);
      case "local":
        return new LocalEmbedding(options);
      default:
        return new OpenAIEmbedding(options);
    }
  }
}

class VectorStore {
  constructor(dimension = 1536) {
    this.dimension = dimension;
    this.vectors = new Map();
    this.metadata = new Map();
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
  }

  get(id) {
    return {
      vector: this.vectors.get(id),
      metadata: this.metadata.get(id)
    };
  }

  remove(id) {
    this.vectors.delete(id);
    this.metadata.delete(id);
  }

  search(queryVector, k = 5) {
    if (queryVector.length !== this.dimension) {
      throw new Error(`Query vector dimension mismatch`);
    }

    const scores = [];

    for (const [id, vector] of this.vectors) {
      const similarity = this._cosineSimilarity(queryVector, vector);
      scores.push({
        id,
        score: similarity,
        metadata: this.metadata.get(id)
      });
    }

    scores.sort((a, b) => b.score - a.score);
    return scores.slice(0, k);
  }

  _cosineSimilarity(a, b) {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  size() {
    return this.vectors.size;
  }

  clear() {
    this.vectors.clear();
    this.metadata.clear();
  }

  toJSON() {
    return {
      dimension: this.dimension,
      size: this.size(),
      vectors: Array.from(this.vectors.entries()),
      metadata: Array.from(this.metadata.entries())
    };
  }

  static fromJSON(json) {
    const store = new VectorStore(json.dimension);
    for (const [id, vector] of json.vectors) {
      store.vectors.set(id, vector);
    }
    for (const [id, metadata] of json.metadata) {
      store.metadata.set(id, metadata);
    }
    return store;
  }
}

class EmbeddingsService {
  constructor(options = {}) {
    this.providerType = options.providerType || "openai";
    this.provider = EmbeddingProviderFactory.create(this.providerType, options);
    this.vectorStore = new VectorStore(this.provider.dimension);
  }

  async embedText(text, id = null, metadata = {}) {
    const result = await this.provider.embedText(text);

    if (id) {
      this.vectorStore.add(id, result.embedding, {
        ...metadata,
        text: text.slice(0, 500)
      });
    }

    return result;
  }

  async embedTexts(texts, ids = null, metadatas = null) {
    const results = await this.provider.embedTexts(texts);

    if (ids) {
      for (let i = 0; i < results.length; i++) {
        this.vectorStore.add(ids[i], results[i].embedding, {
          ...(metadatas?.[i] || {}),
          text: texts[i].slice(0, 500)
        });
      }
    }

    return results;
  }

  async addDocument(id, text, metadata = {}) {
    const result = await this.embedText(text, id, metadata);
    return {
      id,
      embedding: result.embedding,
      metadata
    };
  }

  async search(query, k = 5) {
    const queryEmbedding = await this.provider.embedText(query);
    return this.vectorStore.search(queryEmbedding.embedding, k);
  }

  async searchWithScore(query, k = 5, minScore = 0.7) {
    const results = await this.search(query, k * 2);
    return results.filter(r => r.score >= minScore).slice(0, k);
  }

  getStore() {
    return this.vectorStore;
  }

  saveStore() {
    return this.vectorStore.toJSON();
  }

  loadStore(data) {
    this.vectorStore = VectorStore.fromJSON(data);
  }
}

const globalEmbeddingsService = new EmbeddingsService();

export {
  EmbeddingResult,
  BaseEmbeddingProvider,
  OpenAIEmbedding,
  LocalEmbedding,
  EmbeddingProviderFactory,
  VectorStore,
  EmbeddingsService,
  globalEmbeddingsService
};