import assert from 'assert';
import { ClassRef, FieldInfo, MethodInfo, UniversalASTNode, ASTIndex } from '../src/utils/astCommon.js';
import { QueryEngine } from '../src/utils/queryEngine.js';
import { SearchHandler } from '../src/utils/searchHandler.js';
import { ASTPersistenceManager } from '../src/utils/astPersistence.js';

describe('AST Common Utils', function() {
  describe('ClassRef', function() {
    it('should create a ClassRef with full name', function() {
      const ref = new ClassRef('MyClass', 'com.example');
      assert.strictEqual(ref.name, 'MyClass');
      assert.strictEqual(ref.packageName, 'com.example');
      assert.strictEqual(ref.fullName, 'com.example.MyClass');
      assert.strictEqual(ref.isInterface, false);
    });

    it('should create a ClassRef without package', function() {
      const ref = new ClassRef('MyClass');
      assert.strictEqual(ref.fullName, 'MyClass');
    });

    it('should create an interface reference', function() {
      const ref = new ClassRef('MyInterface', 'com.example', true);
      assert.strictEqual(ref.isInterface, true);
    });
  });

  describe('FieldInfo', function() {
    it('should create a FieldInfo with modifiers', function() {
      const field = new FieldInfo('myField', 'String', ['private', 'static', 'final']);
      assert.strictEqual(field.name, 'myField');
      assert.strictEqual(field.type, 'String');
      assert.strictEqual(field.isStatic, true);
      assert.strictEqual(field.isFinal, true);
      assert.strictEqual(field.isPrivate, true);
    });
  });

  describe('MethodInfo', function() {
    it('should create a MethodInfo with signature', function() {
      const method = new MethodInfo('myMethod', 'void', 
        [{ name: 'param1', type: 'String' }, { name: 'param2', type: 'int' }],
        ['public', 'static'],
        'MyClass'
      );
      assert.strictEqual(method.name, 'myMethod');
      assert.strictEqual(method.returnType, 'void');
      assert.strictEqual(method.getSignature(), 'myMethod(String,int)');
      assert.strictEqual(method.getFullSignature(), 'MyClass.myMethod(String,int)');
    });
  });

  describe('UniversalASTNode', function() {
    it('should create a node with super classes', function() {
      const node = new UniversalASTNode();
      node.name = 'MyClass';
      node.package = 'com.example';
      
      node.addSuperClass(new ClassRef('ParentClass', 'com.example'));
      assert.strictEqual(node.superClasses.length, 1);
      assert.strictEqual(node.superClasses[0].fullName, 'com.example.ParentClass');
      assert.strictEqual(node.getFullName(), 'com.example.MyClass');
    });

    it('should add methods and fields', function() {
      const node = new UniversalASTNode();
      node.name = 'MyClass';
      
      node.addField(new FieldInfo('myField', 'String'));
      node.addMethod(new MethodInfo('myMethod', 'void'));
      
      assert.strictEqual(node.fields.length, 1);
      assert.strictEqual(node.methods.length, 1);
    });
  });

  describe('ASTIndex', function() {
    it('should index nodes by class name', function() {
      const index = new ASTIndex();
      const node = new UniversalASTNode();
      node.name = 'MyClass';
      node.package = 'com.example';
      
      index.addNode(node);
      const found = index.getClassByName('com.example.MyClass');
      
      assert.ok(found);
      assert.strictEqual(found.name, 'MyClass');
    });

    it('should find classes by name pattern', function() {
      const index = new ASTIndex();
      
      const node1 = new UniversalASTNode();
      node1.name = 'MyClass';
      node1.package = 'com.example';
      
      const node2 = new UniversalASTNode();
      node2.name = 'MyClass';
      node2.package = 'com.other';
      
      index.addNode(node1);
      index.addNode(node2);
      
      const results = index.findClassesByName('MyClass');
      assert.strictEqual(results.length, 2);
    });

    it('should serialize and deserialize correctly', function() {
      const index = new ASTIndex();
      index.projectId = 'test-project';
      
      const node = new UniversalASTNode();
      node.name = 'MyClass';
      node.package = 'com.example';
      node.addField(new FieldInfo('myField', 'String'));
      node.addMethod(new MethodInfo('myMethod', 'void'));
      node.addSuperClass(new ClassRef('Parent', 'com.example'));
      
      index.addNode(node);
      
      const json = index.toJSON();
      const restored = ASTIndex.fromJSON(json);
      
      assert.strictEqual(restored.projectId, 'test-project');
      assert.strictEqual(restored.nodes.length, 1);
      assert.strictEqual(restored.nodes[0].name, 'MyClass');
      assert.strictEqual(restored.nodes[0].fields.length, 1);
      assert.strictEqual(restored.nodes[0].methods.length, 1);
      assert.strictEqual(restored.nodes[0].superClasses.length, 1);
    });
  });
});

describe('QueryEngine', function() {
  let queryEngine;
  let astIndex;

  beforeEach(function() {
    astIndex = new ASTIndex();
    
    const parentNode = new UniversalASTNode();
    parentNode.name = 'ParentClass';
    parentNode.package = 'com.example';
    parentNode.addMethod(new MethodInfo('parentMethod', 'void'));
    astIndex.addNode(parentNode);
    
    const childNode = new UniversalASTNode();
    childNode.name = 'ChildClass';
    childNode.package = 'com.example';
    childNode.addSuperClass(new ClassRef('ParentClass', 'com.example'));
    childNode.addMethod(new MethodInfo('childMethod', 'void'));
    astIndex.addNode(childNode);
    
    queryEngine = new QueryEngine(astIndex);
  });

  it('should search for a class', function() {
    const results = queryEngine.searchClassOnly('com.example.ChildClass');
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].name, 'ChildClass');
  });

  it('should get all super classes', function() {
    const results = queryEngine.getAllSuperClasses('com.example.ChildClass');
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].name, 'ParentClass');
  });

  it('should get all sub classes', function() {
    const results = queryEngine.getAllSubClasses('com.example.ParentClass');
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].name, 'ChildClass');
  });

  it('should search for methods in class hierarchy', function() {
    const results = queryEngine.smartSearchClassMethod('com.example.ChildClass', 'parentMethod');
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].method.name, 'parentMethod');
    assert.strictEqual(results[0].isInherited, true);
  });
});

describe('SearchHandler', function() {
  let searchHandler;
  let queryEngine;
  let astIndex;

  beforeEach(function() {
    astIndex = new ASTIndex();
    
    const node = new UniversalASTNode();
    node.name = 'MyClass';
    node.package = 'com.example';
    node.filePath = '/path/to/MyClass.java';
    node.startLine = 1;
    node.endLine = 50;
    node.addField(new FieldInfo('myField', 'String'));
    node.addMethod(new MethodInfo('myMethod', 'void'));
    astIndex.addNode(node);
    
    queryEngine = new QueryEngine(astIndex);
    searchHandler = new SearchHandler(queryEngine);
  });

  it('should search class and return formatted result', function() {
    const result = searchHandler.searchClassOnly('com.example.MyClass');
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.count, 1);
    assert.strictEqual(result.data[0].name, 'MyClass');
    assert.strictEqual(result.data[0].fullName, 'com.example.MyClass');
  });

  it('should handle invalid input gracefully', function() {
    const result = searchHandler.searchClassOnly(null);
    assert.strictEqual(result.success, false);
    assert.ok(result.error);
  });

  it('should return empty results for non-existent class', function() {
    const result = searchHandler.searchClassOnly('NonExistent');
    assert.strictEqual(result.success, true);
    assert.strictEqual(result.count, 0);
  });
});

describe('ASTPersistenceManager', function() {
  let persistenceManager;
  let astIndex;

  beforeEach(function() {
    persistenceManager = new ASTPersistenceManager({
      enabled: true,
      cacheDir: './test-cache'
    });
    
    astIndex = new ASTIndex();
    const node = new UniversalASTNode();
    node.name = 'TestClass';
    node.package = 'com.test';
    astIndex.addNode(node);
  });

  afterEach(function() {
    persistenceManager.clearAll();
  });

  it('should save and load AST index', function() {
    const saved = persistenceManager.saveASTIndex(astIndex, 'test-project');
    assert.strictEqual(saved, true);
    
    const loaded = persistenceManager.loadASTIndex('test-project');
    assert.ok(loaded);
    assert.strictEqual(loaded.nodes.length, 1);
    assert.strictEqual(loaded.nodes[0].name, 'TestClass');
  });

  it('should invalidate cache', function() {
    persistenceManager.saveASTIndex(astIndex, 'test-project');
    assert.strictEqual(persistenceManager.exists('test-project'), true);
    
    persistenceManager.invalidate('test-project');
    assert.strictEqual(persistenceManager.exists('test-project'), false);
  });

  it('should return null when cache not found', function() {
    const loaded = persistenceManager.loadASTIndex('non-existent');
    assert.strictEqual(loaded, null);
  });
});