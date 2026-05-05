class ClassRef {
  constructor(name, packageName = '', isInterface = false) {
    this.name = name;
    this.packageName = packageName;
    this.isInterface = isInterface;
    this.fullName = packageName ? `${packageName}.${name}` : name;
  }

  toString() {
    return this.fullName;
  }
}

class FieldInfo {
  constructor(name, type, modifiers = []) {
    this.name = name;
    this.type = type;
    this.modifiers = modifiers;
    this.isStatic = modifiers.includes('static');
    this.isFinal = modifiers.includes('final');
    this.isPrivate = modifiers.includes('private');
    this.isProtected = modifiers.includes('protected');
    this.isPublic = modifiers.includes('public');
  }
}

class MethodInfo {
  constructor(name, returnType, params = [], modifiers = [], className = '') {
    this.name = name;
    this.returnType = returnType;
    this.params = params;
    this.modifiers = modifiers;
    this.className = className;
    this.isStatic = modifiers.includes('static');
    this.isPrivate = modifiers.includes('private');
    this.isProtected = modifiers.includes('protected');
    this.isPublic = modifiers.includes('public');
    this.isAbstract = modifiers.includes('abstract');
    this.isFinal = modifiers.includes('final');
  }

  getSignature() {
    const paramTypes = this.params.map(p => p.type).join(',');
    return `${this.name}(${paramTypes})`;
  }

  getFullSignature() {
    const paramTypes = this.params.map(p => p.type).join(',');
    const className = this.className ? `${this.className}.` : '';
    return `${className}${this.name}(${paramTypes})`;
  }
}

class UniversalASTNode {
  constructor() {
    this.id = '';
    this.language = '';
    this.type = '';
    this.name = '';
    this.package = '';
    this.superClasses = [];
    this.subClasses = [];
    this.fields = [];
    this.methods = [];
    this.methodParams = [];
    this.filePath = '';
    this.startLine = 0;
    this.endLine = 0;
    this.sourceCode = '';
    this.modifiers = [];
  }

  getFullName() {
    return this.package ? `${this.package}.${this.name}` : this.name;
  }

  addSuperClass(classRef) {
    if (!(classRef instanceof ClassRef)) {
      classRef = new ClassRef(classRef);
    }
    if (!this.superClasses.find(s => s.fullName === classRef.fullName)) {
      this.superClasses.push(classRef);
    }
  }

  addSubClass(classRef) {
    if (!(classRef instanceof ClassRef)) {
      classRef = new ClassRef(classRef);
    }
    if (!this.subClasses.find(s => s.fullName === classRef.fullName)) {
      this.subClasses.push(classRef);
    }
  }

  addField(fieldInfo) {
    if (!(fieldInfo instanceof FieldInfo)) {
      fieldInfo = new FieldInfo(fieldInfo.name, fieldInfo.type, fieldInfo.modifiers || []);
    }
    this.fields.push(fieldInfo);
  }

  addMethod(methodInfo) {
    if (!(methodInfo instanceof MethodInfo)) {
      methodInfo = new MethodInfo(
        methodInfo.name,
        methodInfo.returnType,
        methodInfo.params || [],
        methodInfo.modifiers || [],
        this.name
      );
    }
    this.methods.push(methodInfo);
  }
}

class ASTIndex {
  constructor() {
    this.nodes = [];
    this.classIndex = new Map();
    this.packageIndex = new Map();
    this.methodIndex = new Map();
    this.fieldIndex = new Map();
    this.fileIndex = new Map();
    this.version = '1.0';
    this.projectId = '';
    this.createdAt = new Date().toISOString();
  }

  addNode(node) {
    if (!(node instanceof UniversalASTNode)) {
      const newNode = new UniversalASTNode();
      Object.assign(newNode, node);
      node = newNode;
    }
    this.nodes.push(node);
    
    const fullName = node.getFullName();
    this.classIndex.set(fullName, node);
    
    if (node.package) {
      if (!this.packageIndex.has(node.package)) {
        this.packageIndex.set(node.package, []);
      }
      this.packageIndex.get(node.package).push(node);
    }
    
    if (node.filePath) {
      if (!this.fileIndex.has(node.filePath)) {
        this.fileIndex.set(node.filePath, []);
      }
      this.fileIndex.get(node.filePath).push(node);
    }
    
    for (const method of node.methods) {
      const methodKey = method.getFullSignature();
      if (!this.methodIndex.has(methodKey)) {
        this.methodIndex.set(methodKey, []);
      }
      this.methodIndex.get(methodKey).push({ node, method });
    }
    
    for (const field of node.fields) {
      const fieldKey = `${fullName}.${field.name}`;
      if (!this.fieldIndex.has(fieldKey)) {
        this.fieldIndex.set(fieldKey, []);
      }
      this.fieldIndex.get(fieldKey).push({ node, field });
    }
  }

  getClassByName(className) {
    return this.classIndex.get(className);
  }

  findClassesByName(className) {
    const results = [];
    for (const [name, node] of this.classIndex) {
      if (name.endsWith(`.${className}`) || name === className) {
        results.push(node);
      }
    }
    return results;
  }

  getMethodsByName(methodName) {
    const results = [];
    for (const [signature, entries] of this.methodIndex) {
      if (signature.startsWith(`${methodName}(`)) {
        results.push(...entries);
      }
    }
    return results;
  }

  getFieldsByName(fieldName) {
    const results = [];
    for (const [key, entries] of this.fieldIndex) {
      if (key.endsWith(`.${fieldName}`)) {
        results.push(...entries);
      }
    }
    return results;
  }

  getClassesByPackage(packageName) {
    return this.packageIndex.get(packageName) || [];
  }

  getClassesByFile(filePath) {
    return this.fileIndex.get(filePath) || [];
  }

  toJSON() {
    return {
      version: this.version,
      projectId: this.projectId,
      createdAt: this.createdAt,
      nodes: this.nodes
    };
  }

  static fromJSON(data) {
    const index = new ASTIndex();
    index.version = data.version || '1.0';
    index.projectId = data.projectId || '';
    index.createdAt = data.createdAt || new Date().toISOString();
    
    for (const nodeData of data.nodes || []) {
      const node = new UniversalASTNode();
      Object.assign(node, nodeData);
      node.superClasses = node.superClasses.map(s => 
        s instanceof ClassRef ? s : new ClassRef(s.name, s.packageName, s.isInterface)
      );
      node.subClasses = node.subClasses.map(s => 
        s instanceof ClassRef ? s : new ClassRef(s.name, s.packageName, s.isInterface)
      );
      node.fields = node.fields.map(f => 
        f instanceof FieldInfo ? f : new FieldInfo(f.name, f.type, f.modifiers)
      );
      node.methods = node.methods.map(m => 
        m instanceof MethodInfo ? m : new MethodInfo(
          m.name, m.returnType, m.params, m.modifiers, m.className
        )
      );
      index.addNode(node);
    }
    
    return index;
  }
}

export {
  ClassRef,
  FieldInfo,
  MethodInfo,
  UniversalASTNode,
  ASTIndex
};