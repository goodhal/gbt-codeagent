import { QueryEngine } from './queryEngine.js';

class SearchHandler {
  constructor(queryEngine = null) {
    this.queryEngine = queryEngine || new QueryEngine();
  }

  setQueryEngine(queryEngine) {
    this.queryEngine = queryEngine;
  }

  searchClassOnly(className) {
    if (!className || typeof className !== 'string') {
      return { success: false, error: 'className is required', data: [] };
    }

    try {
      const results = this.queryEngine.searchClassOnly(className);
      return {
        success: true,
        data: results.map(node => this.formatClassResult(node)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  searchClassMethod(className, methodName) {
    if (!className || typeof className !== 'string') {
      return { success: false, error: 'className is required', data: [] };
    }
    if (!methodName || typeof methodName !== 'string') {
      return { success: false, error: 'methodName is required', data: [] };
    }

    try {
      const results = this.queryEngine.smartSearchClassMethod(className, methodName);
      return {
        success: true,
        data: results.map(this.formatMethodResult.bind(this)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  searchClassField(className, fieldName) {
    if (!className || typeof className !== 'string') {
      return { success: false, error: 'className is required', data: [] };
    }
    if (!fieldName || typeof fieldName !== 'string') {
      return { success: false, error: 'fieldName is required', data: [] };
    }

    try {
      const results = this.queryEngine.enhancedSearchClassField(className, fieldName);
      return {
        success: true,
        data: results.map(this.formatFieldResult.bind(this)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  searchMethodByName(methodName) {
    if (!methodName || typeof methodName !== 'string') {
      return { success: false, error: 'methodName is required', data: [] };
    }

    try {
      const results = this.queryEngine.getMethodsByName(methodName);
      return {
        success: true,
        data: results.map(this.formatMethodResult.bind(this)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  searchFieldByName(fieldName) {
    if (!fieldName || typeof fieldName !== 'string') {
      return { success: false, error: 'fieldName is required', data: [] };
    }

    try {
      const results = this.queryEngine.getFieldsByName(fieldName);
      return {
        success: true,
        data: results.map(this.formatFieldResult.bind(this)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  searchByPattern(pattern) {
    if (!pattern || typeof pattern !== 'string') {
      return { success: false, error: 'pattern is required', data: [] };
    }

    try {
      const results = this.queryEngine.searchByPattern(pattern);
      return {
        success: true,
        data: results.map(node => this.formatClassResult(node)),
        count: results.length
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  getClassHierarchy(className, type = 'super') {
    if (!className || typeof className !== 'string') {
      return { success: false, error: 'className is required', data: [] };
    }
    if (!['super', 'sub'].includes(type)) {
      return { success: false, error: 'type must be "super" or "sub"', data: [] };
    }

    try {
      const results = this.queryEngine.getClassHierarchy(className, type);
      return {
        success: true,
        data: results.map(node => this.formatClassResult(node)),
        count: results.length,
        type: type
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  unifiedSearch(options = {}) {
    const { className, methodName, fieldName } = options;

    if (!className && !methodName && !fieldName) {
      return { success: false, error: 'At least one of className, methodName, or fieldName is required', data: [] };
    }

    try {
      const results = this.queryEngine.unifiedSearch({ className, methodName, fieldName });
      
      let formattedResults;
      if (methodName) {
        formattedResults = results.map(this.formatMethodResult.bind(this));
      } else if (fieldName) {
        formattedResults = results.map(this.formatFieldResult.bind(this));
      } else {
        formattedResults = results.map(node => this.formatClassResult(node));
      }

      return {
        success: true,
        data: formattedResults,
        count: results.length,
        searchType: methodName ? 'method' : fieldName ? 'field' : 'class'
      };
    } catch (error) {
      return { success: false, error: error.message, data: [] };
    }
  }

  getAllSuperClasses(className) {
    return this.getClassHierarchy(className, 'super');
  }

  getAllSubClasses(className) {
    return this.getClassHierarchy(className, 'sub');
  }

  getStats() {
    try {
      const stats = this.queryEngine.getStats();
      return { success: true, data: stats };
    } catch (error) {
      return { success: false, error: error.message, data: null };
    }
  }

  formatClassResult(node) {
    return {
      id: node.id,
      name: node.name,
      fullName: node.getFullName(),
      package: node.package,
      language: node.language,
      type: node.type,
      filePath: node.filePath,
      lineRange: { start: node.startLine, end: node.endLine },
      modifiers: node.modifiers,
      superClasses: node.superClasses.map(s => s.fullName),
      subClasses: node.subClasses.map(s => s.fullName),
      methodCount: node.methods.length,
      fieldCount: node.fields.length,
      methods: node.methods.map(m => ({
        name: m.name,
        signature: m.getSignature(),
        returnType: m.returnType,
        isStatic: m.isStatic,
        isPrivate: m.isPrivate
      })),
      fields: node.fields.map(f => ({
        name: f.name,
        type: f.type,
        isStatic: f.isStatic,
        isPrivate: f.isPrivate,
        isFinal: f.isFinal
      }))
    };
  }

  formatMethodResult(result) {
    const { className, method, sourceClass, isInherited } = result;
    return {
      className: className,
      methodName: method.name,
      signature: method.getSignature(),
      fullSignature: method.getFullSignature(),
      returnType: method.returnType,
      parameters: method.params.map(p => ({ name: p.name, type: p.type })),
      modifiers: method.modifiers,
      isStatic: method.isStatic,
      isPrivate: method.isPrivate,
      isProtected: method.isProtected,
      isPublic: method.isPublic,
      sourceClass: sourceClass,
      isInherited: isInherited,
      filePath: result.node?.filePath || '',
      lineRange: result.node ? { start: result.node.startLine, end: result.node.endLine } : null
    };
  }

  formatFieldResult(result) {
    const { className, field, sourceClass, isInherited } = result;
    return {
      className: className,
      fieldName: field.name,
      type: field.type,
      modifiers: field.modifiers,
      isStatic: field.isStatic,
      isPrivate: field.isPrivate,
      isProtected: field.isProtected,
      isPublic: field.isPublic,
      isFinal: field.isFinal,
      sourceClass: sourceClass,
      isInherited: isInherited,
      filePath: result.node?.filePath || '',
      lineRange: result.node ? { start: result.node.startLine, end: result.node.endLine } : null
    };
  }
}

export { SearchHandler };