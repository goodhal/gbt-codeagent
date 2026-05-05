import { UniversalASTNode, ASTIndex, ClassRef } from './astCommon.js';

class QueryEngine {
  constructor(astIndex = null) {
    this.astIndex = astIndex || new ASTIndex();
    this.searchCache = new Map();
  }

  setASTIndex(astIndex) {
    this.astIndex = astIndex;
    this.searchCache.clear();
  }

  searchClassOnly(className) {
    const cacheKey = `class:${className}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const results = this.astIndex.findClassesByName(className);
    this.searchCache.set(cacheKey, results);
    return results;
  }

  searchMethodInClass(className, methodName) {
    const cacheKey = `method:${className}:${methodName}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const classNode = this.astIndex.getClassByName(className);
    if (!classNode) {
      const results = this.searchClassOnly(className);
      if (results.length === 0) {
        this.searchCache.set(cacheKey, []);
        return [];
      }
      classNode = results[0];
    }

    const results = classNode.methods
      .filter(m => m.name === methodName)
      .map(m => ({ node: classNode, method: m }));

    this.searchCache.set(cacheKey, results);
    return results;
  }

  searchFieldInClass(className, fieldName) {
    const cacheKey = `field:${className}:${fieldName}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const classNode = this.astIndex.getClassByName(className);
    if (!classNode) {
      const results = this.searchClassOnly(className);
      if (results.length === 0) {
        this.searchCache.set(cacheKey, []);
        return [];
      }
      classNode = results[0];
    }

    const results = classNode.fields
      .filter(f => f.name === fieldName)
      .map(f => ({ node: classNode, field: f }));

    this.searchCache.set(cacheKey, results);
    return results;
  }

  smartSearchClassMethod(className, methodName) {
    const cacheKey = `smart:${className}:${methodName}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const results = [];
    
    const targetClass = this.astIndex.getClassByName(className);
    if (!targetClass) {
      this.searchCache.set(cacheKey, []);
      return [];
    }

    const visited = new Set();
    const queue = [targetClass];

    while (queue.length > 0) {
      const currentClass = queue.shift();
      const currentClassName = currentClass.getFullName();

      if (visited.has(currentClassName)) continue;
      visited.add(currentClassName);

      const methods = currentClass.methods.filter(m => m.name === methodName);
      for (const method of methods) {
        results.push({
          className: currentClassName,
          method: method,
          sourceClass: currentClassName,
          isInherited: currentClassName !== className
        });
      }

      for (const superClass of currentClass.superClasses) {
        const superClassNode = this.astIndex.getClassByName(superClass.fullName);
        if (superClassNode && !visited.has(superClass.fullName)) {
          queue.push(superClassNode);
        }
      }
    }

    this.searchCache.set(cacheKey, results);
    return results;
  }

  enhancedSearchClassField(className, fieldName) {
    const cacheKey = `enhanced:${className}:${fieldName}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const results = [];
    
    const targetClass = this.astIndex.getClassByName(className);
    if (!targetClass) {
      this.searchCache.set(cacheKey, []);
      return [];
    }

    const visited = new Set();
    const queue = [targetClass];

    while (queue.length > 0) {
      const currentClass = queue.shift();
      const currentClassName = currentClass.getFullName();

      if (visited.has(currentClassName)) continue;
      visited.add(currentClassName);

      const fields = currentClass.fields.filter(f => f.name === fieldName);
      for (const field of fields) {
        results.push({
          className: currentClassName,
          field: field,
          sourceClass: currentClassName,
          isInherited: currentClassName !== className
        });
      }

      for (const superClass of currentClass.superClasses) {
        const superClassNode = this.astIndex.getClassByName(superClass.fullName);
        if (superClassNode && !visited.has(superClass.fullName)) {
          queue.push(superClassNode);
        }
      }
    }

    this.searchCache.set(cacheKey, results);
    return results;
  }

  getAllSuperClasses(className) {
    const cacheKey = `super:${className}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const results = [];
    const visited = new Set();
    let currentClass = this.astIndex.getClassByName(className);

    while (currentClass && !visited.has(currentClass.getFullName())) {
      visited.add(currentClass.getFullName());
      for (const superClass of currentClass.superClasses) {
        if (!visited.has(superClass.fullName)) {
          const superClassNode = this.astIndex.getClassByName(superClass.fullName);
          if (superClassNode) {
            results.push(superClassNode);
            currentClass = superClassNode;
            break;
          }
        }
      }
      if (!currentClass || visited.has(currentClass.getFullName())) {
        break;
      }
    }

    this.searchCache.set(cacheKey, results);
    return results;
  }

  getAllSubClasses(className) {
    const cacheKey = `sub:${className}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const results = [];
    const visited = new Set();
    const queue = [className];

    while (queue.length > 0) {
      const currentName = queue.shift();
      if (visited.has(currentName)) continue;
      visited.add(currentName);

      for (const node of this.astIndex.nodes) {
        const nodeFullName = node.getFullName();
        if (visited.has(nodeFullName)) continue;

        const hasSuper = node.superClasses.some(s => 
          s.fullName === currentName || s.name === currentName
        );

        if (hasSuper) {
          results.push(node);
          queue.push(nodeFullName);
        }
      }
    }

    this.searchCache.set(cacheKey, results);
    return results;
  }

  unifiedSearch(options = {}) {
    const { className, methodName, fieldName } = options;

    if (methodName) {
      return this.smartSearchClassMethod(className || '', methodName);
    } else if (fieldName) {
      return this.enhancedSearchClassField(className || '', fieldName);
    } else if (className) {
      return this.searchClassOnly(className);
    }

    return [];
  }

  searchByPattern(pattern) {
    const cacheKey = `pattern:${pattern}`;
    if (this.searchCache.has(cacheKey)) {
      return this.searchCache.get(cacheKey);
    }

    const regex = new RegExp(pattern, 'gi');
    const results = [];

    for (const node of this.astIndex.nodes) {
      if (regex.test(node.name) || regex.test(node.getFullName())) {
        results.push(node);
      }
    }

    this.searchCache.set(cacheKey, results);
    return results;
  }

  getClassHierarchy(className, type = 'super') {
    if (type === 'sub') {
      return this.getAllSubClasses(className);
    }
    return this.getAllSuperClasses(className);
  }

  clearCache() {
    this.searchCache.clear();
  }

  getStats() {
    return {
      totalClasses: this.astIndex.nodes.length,
      totalMethods: this.astIndex.nodes.reduce((sum, n) => sum + n.methods.length, 0),
      totalFields: this.astIndex.nodes.reduce((sum, n) => sum + n.fields.length, 0),
      cacheEntries: this.searchCache.size
    };
  }
}

export { QueryEngine };