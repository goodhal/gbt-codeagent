import { getGlobalVectorStore, createSemanticSearchEngine } from './vectorStore.js';

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
    this._dimension = options.dimension || 384;
  }

  get dimension() {
    return this._dimension;
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

class EmbeddingsService {
  constructor(options = {}) {
    this.providerType = options.providerType || "openai";
    this.provider = EmbeddingProviderFactory.create(this.providerType, options);
    this._vectorStore = null;
    this._searchEngine = null;
    this._initialized = false;
  }

  async initialize(options = {}) {
    if (this._initialized) {
      return this;
    }

    this._vectorStore = await getGlobalVectorStore({
      dimension: this.provider.dimension,
      persistPath: options.persistPath || './data/embeddings.json',
      ...options
    });

    this._searchEngine = createSemanticSearchEngine(this._vectorStore, this);

    this._initialized = true;
    return this;
  }

  async embedText(text) {
    const results = await this.embedTexts([text]);
    return results[0];
  }

  async embedTexts(texts) {
    if (!texts || texts.length === 0) return [];

    const maxLength = 8191;
    const truncatedTexts = texts.map(t => t.slice(0, maxLength));

    const results = await this.provider.embedTexts(truncatedTexts);
    return results.map((result, index) => ({
      ...result,
      originalText: texts[index]
    }));
  }

  async addDocument(id, text, metadata = {}) {
    if (!this._initialized) {
      await this.initialize();
    }

    const result = await this.embedText(text);
    await this._vectorStore.add(id, result.embedding, {
      ...metadata,
      text: text.slice(0, 500)
    });

    return {
      id,
      embedding: result.embedding,
      metadata
    };
  }

  async addDocuments(documents) {
    if (!this._initialized) {
      await this.initialize();
    }

    const texts = documents.map(d => d.text);
    const results = await this.embedTexts(texts);

    for (let i = 0; i < results.length; i++) {
      const doc = documents[i];
      await this._vectorStore.add(doc.id, results[i].embedding, {
        ...(doc.metadata || {}),
        text: doc.text.slice(0, 500)
      });
    }

    return results;
  }

  async search(query, k = 5) {
    if (!this._initialized) {
      await this.initialize();
    }

    if (!this._searchEngine) {
      throw new Error('Search engine not initialized');
    }

    return this._searchEngine.search(query, k);
  }

  async searchWithScore(query, k = 5, minScore = 0.7) {
    const results = await this.search(query, k * 2);
    return results.filter(r => r.score >= minScore).slice(0, k);
  }

  async persist() {
    if (!this._vectorStore) {
      return false;
    }
    return this._vectorStore.persist();
  }

  getStore() {
    return this._vectorStore;
  }

  getSearchEngine() {
    return this._searchEngine;
  }

  get dimension() {
    return this.provider.dimension;
  }

  get stats() {
    if (!this._vectorStore) {
      return { size: 0, dimension: this.provider.dimension };
    }
    return this._vectorStore.getStats();
  }
}

const globalEmbeddingsService = new EmbeddingsService();

export {
  EmbeddingResult,
  BaseEmbeddingProvider,
  OpenAIEmbedding,
  LocalEmbedding,
  EmbeddingProviderFactory,
  EmbeddingsService,
  globalEmbeddingsService
};
