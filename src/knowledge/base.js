const KnowledgeCategory = {
  VULNERABILITY: 'vulnerability',
  FRAMEWORK: 'framework',
  BEST_PRACTICE: 'best_practice'
};

const Severity = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

class KnowledgeDocument {
  constructor({ id, title, category, tags, severity, cweIds = [], owaspIds = [], gbtMapping = null, content }) {
    this.id = id;
    this.title = title;
    this.category = category;
    this.tags = tags;
    this.severity = severity;
    this.cweIds = cweIds;
    this.owaspIds = owaspIds;
    this.gbtMapping = gbtMapping;
    this.content = content;
  }

  matches(query) {
    const lowerQuery = query.toLowerCase();
    return (
      this.title.toLowerCase().includes(lowerQuery) ||
      this.content.toLowerCase().includes(lowerQuery) ||
      this.tags.some(tag => tag.toLowerCase().includes(lowerQuery)) ||
      this.cweIds.some(cwe => cwe.toLowerCase().includes(lowerQuery))
    );
  }
}

export { KnowledgeDocument, KnowledgeCategory, Severity };