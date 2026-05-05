import { ALL_VULNERABILITY_DOCS, KnowledgeCategory, Severity } from '../knowledge/index.js';
import { getGlobalVectorStore, createSemanticSearchEngine } from './vectorStore.js';

class SimpleRetriever {
  constructor(documents) {
    this.documents = documents;
    this._index = this._buildIndex();
  }

  _buildIndex() {
    const index = {};
    for (const doc of this.documents) {
      for (const tag of doc.tags) {
        const tagLower = tag.toLowerCase();
        if (!index[tagLower]) {
          index[tagLower] = [];
        }
        if (Array.isArray(index[tagLower])) {
          index[tagLower].push(doc);
        }
      }
    }
    return index;
  }

  search(query, topK = 5) {
    const lowerQuery = query.toLowerCase();
    const scores = [];
    const seen = new Set();

    for (const doc of this.documents) {
      if (seen.has(doc.id)) continue;

      let score = 0;

      if (doc.title.toLowerCase().includes(lowerQuery)) {
        score += 10;
      }

      if (doc.tags.some(tag => tag.toLowerCase().includes(lowerQuery))) {
        score += 5;
      }

      if (doc.cweIds && doc.cweIds.some(cwe => cwe.toLowerCase().includes(lowerQuery))) {
        score += 8;
      }

      const contentLower = doc.content.toLowerCase();
      const queryWords = lowerQuery.split(/\s+/);
      for (const word of queryWords) {
        if (contentLower.includes(word)) {
          score += 1;
        }
      }

      if (score > 0) {
        scores.push({ doc, score });
        seen.add(doc.id);
      }
    }

    scores.sort((a, b) => b.score - a.score);
    return scores.slice(0, topK).map(s => s.doc);
  }

  getByCategory(category) {
    return this.documents.filter(doc => doc.category === category);
  }

  getBySeverity(severity) {
    return this.documents.filter(doc => doc.severity === severity);
  }

  getById(id) {
    return this.documents.find(doc => doc.id === id);
  }

  getAllDocuments() {
    return this.documents;
  }
}

class RAGService {
  constructor() {
    this.retriever = new SimpleRetriever(ALL_VULNERABILITY_DOCS);
    this._vectorStore = null;
    this._searchEngine = null;
    this._vectorIndexed = false;
    this._initialized = false;
  }

  async initialize(options = {}) {
    if (this._initialized) {
      return this;
    }

    try {
      this._vectorStore = await getGlobalVectorStore({
        persistPath: options.vectorPersistPath || './data/rag_vectors.json'
      });

      if (options.embedder) {
        this._searchEngine = createSemanticSearchEngine(this._vectorStore, options.embedder);
      }

      if (!this._vectorIndexed && this._searchEngine) {
        await this._indexKnowledgeBase();
      }
    } catch (error) {
      console.warn('[RAGService] Vector store initialization failed:', error);
    }

    this._initialized = true;
    console.log(`[RAG服务] 已初始化，知识文档数量: ${ALL_VULNERABILITY_DOCS.length}`);
    return this;
  }

  async _indexKnowledgeBase() {
    try {
      const documents = this.retriever.getAllDocuments();
      const items = documents.map(doc => ({
        id: doc.id,
        text: `${doc.title}\n${doc.content}`,
        metadata: {
          title: doc.title,
          category: doc.category,
          severity: doc.severity,
          cweIds: doc.cweIds,
          tags: doc.tags
        }
      }));

      await this._searchEngine.indexBatch(items);
      await this._vectorStore.persist();
      this._vectorIndexed = true;
      console.log('[RAGService] Knowledge base indexed to vector store');
    } catch (error) {
      console.error('[RAGService] Failed to index knowledge base:', error);
    }
  }

  async query(query, topK = 5, options = {}) {
    if (!this._initialized) {
      await this.initialize();
    }

    const { useSemantic = true } = options;

    if (useSemantic && this._searchEngine) {
      try {
        const results = await this._searchEngine.search(query, topK);
        if (results.length > 0) {
          return results.map(r => {
            const doc = this.retriever.getById(r.id);
            return doc || { id: r.id, ...r.metadata };
          });
        }
      } catch (error) {
        console.warn('[RAGService] Semantic search failed, falling back to keyword:', error);
      }
    }

    return this.retriever.search(query, topK);
  }

  async queryByCategory(category) {
    if (!this._initialized) {
      await this.initialize();
    }
    return this.retriever.getByCategory(category);
  }

  async queryBySeverity(severity) {
    if (!this._initialized) {
      await this.initialize();
    }
    return this.retriever.getBySeverity(severity);
  }

  async queryById(id) {
    if (!this._initialized) {
      await this.initialize();
    }
    return this.retriever.getById(id);
  }

  async querySecurityKnowledge(query, options = {}) {
    const { language, severity, topK = 3, useSemantic = true } = options;

    let results = await this.query(query, topK * 2, { useSemantic });

    if (language) {
      const langLower = language.toLowerCase();
      results = results.filter(doc =>
        doc.tags && doc.tags.some(tag => tag.toLowerCase().includes(langLower))
      );
    }

    if (severity) {
      results = results.filter(doc => doc.severity === severity);
    }

    return results.slice(0, topK);
  }

  async buildAuditContext(options = {}) {
    const { language, fileCount = 4 } = options;

    if (!this._initialized) {
      await this.initialize();
    }

    const contextParts = [];

    contextParts.push('【安全知识参考】\n');

    const criticalDocs = await this.queryBySeverity(Severity.CRITICAL);
    if (criticalDocs.length > 0) {
      contextParts.push('🔴 高危漏洞模式：');
      for (const doc of criticalDocs.slice(0, 2)) {
        contextParts.push(`\n${doc.title} (${doc.gbtMapping || 'GB/T39412'})`);
        contextParts.push(doc.content.slice(0, 500) + '...\n');
      }
    }

    if (language) {
      const langDocs = await this.query(`${language} 安全`, 3);
      if (langDocs.length > 0) {
        contextParts.push('\n🟡 语言特定审计要点：');
        for (const doc of langDocs) {
          contextParts.push(`\n${doc.title}:`);
          contextParts.push(doc.content.slice(0, 300) + '...\n');
        }
      }
    }

    return contextParts.join('\n');
  }

  getVectorStore() {
    return this._vectorStore;
  }

  getSearchEngine() {
    return this._searchEngine;
  }
}

const ragService = new RAGService();

export { RAGService, SimpleRetriever, ragService };
