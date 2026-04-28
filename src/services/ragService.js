import { ALL_VULNERABILITY_DOCS, KnowledgeCategory, Severity } from '../knowledge/index.js';

class SimpleRetriever {
  constructor(documents) {
    this.documents = documents;
  }

  search(query, topK = 5) {
    const lowerQuery = query.toLowerCase();
    const scores = [];

    for (const doc of this.documents) {
      let score = 0;

      if (doc.title.toLowerCase().includes(lowerQuery)) {
        score += 10;
      }

      if (doc.tags.some(tag => tag.toLowerCase().includes(lowerQuery))) {
        score += 5;
      }

      if (doc.cweIds.some(cwe => cwe.toLowerCase().includes(lowerQuery))) {
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
}

class RAGService {
  constructor() {
    this.retriever = new SimpleRetriever(ALL_VULNERABILITY_DOCS);
    this._initialized = true;
  }

  async initialize() {
    this._initialized = true;
    console.log(`[RAG服务] 已初始化，知识文档数量: ${ALL_VULNERABILITY_DOCS.length}`);
    return this;
  }

  async query(query, topK = 5) {
    if (!this._initialized) {
      await this.initialize();
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
    const { language, severity, topK = 3 } = options;

    let results = await this.query(query, topK * 2);

    if (language) {
      const langLower = language.toLowerCase();
      results = results.filter(doc =>
        doc.tags.some(tag => tag.toLowerCase().includes(langLower))
      );
    }

    if (severity) {
      results = results.filter(doc => doc.severity === severity);
    }

    return results.slice(0, topK);
  }

  async buildAuditContext(options = {}) {
    const { language, fileCount = 4 } = options;

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
}

const ragService = new RAGService();

export { RAGService, SimpleRetriever, ragService };