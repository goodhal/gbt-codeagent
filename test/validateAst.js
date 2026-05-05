import assert from 'assert';
import { ClassRef, FieldInfo, MethodInfo, UniversalASTNode, ASTIndex } from '../src/utils/astCommon.js';
import { QueryEngine } from '../src/utils/queryEngine.js';
import { SearchHandler } from '../src/utils/searchHandler.js';
import { ASTPersistenceManager } from '../src/utils/astPersistence.js';

console.log('=== AST Utils Validation ===\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (error) {
    console.log(`✗ ${name}`);
    console.log(`  Error: ${error.message}`);
    failed++;
  }
}

test('ClassRef should create with full name', () => {
  const ref = new ClassRef('MyClass', 'com.example');
  assert.strictEqual(ref.name, 'MyClass');
  assert.strictEqual(ref.packageName, 'com.example');
  assert.strictEqual(ref.fullName, 'com.example.MyClass');
});

test('FieldInfo should create with modifiers', () => {
  const field = new FieldInfo('myField', 'String', ['private', 'static']);
  assert.strictEqual(field.name, 'myField');
  assert.strictEqual(field.isStatic, true);
});

test('MethodInfo should generate signature', () => {
  const method = new MethodInfo('myMethod', 'void', 
    [{ name: 'param1', type: 'String' }], ['public'], 'MyClass');
  assert.strictEqual(method.getSignature(), 'myMethod(String)');
  assert.strictEqual(method.getFullSignature(), 'MyClass.myMethod(String)');
});

test('UniversalASTNode should manage superclasses', () => {
  const node = new UniversalASTNode();
  node.name = 'MyClass';
  node.package = 'com.example';
  node.addSuperClass(new ClassRef('Parent', 'com.example'));
  assert.strictEqual(node.superClasses.length, 1);
  assert.strictEqual(node.getFullName(), 'com.example.MyClass');
});

test('ASTIndex should index and retrieve nodes', () => {
  const index = new ASTIndex();
  const node = new UniversalASTNode();
  node.name = 'MyClass';
  node.package = 'com.example';
  index.addNode(node);
  
  const found = index.getClassByName('com.example.MyClass');
  assert.ok(found);
  assert.strictEqual(found.name, 'MyClass');
});

test('ASTIndex should serialize/deserialize correctly', () => {
  const index = new ASTIndex();
  index.projectId = 'test';
  
  const node = new UniversalASTNode();
  node.name = 'TestClass';
  node.package = 'com.test';
  node.addField(new FieldInfo('myField', 'String'));
  index.addNode(node);
  
  const json = index.toJSON();
  const restored = ASTIndex.fromJSON(json);
  
  assert.strictEqual(restored.nodes.length, 1);
  assert.strictEqual(restored.nodes[0].fields.length, 1);
});

test('QueryEngine should search classes', () => {
  const index = new ASTIndex();
  const node = new UniversalASTNode();
  node.name = 'MyClass';
  node.package = 'com.example';
  index.addNode(node);
  
  const engine = new QueryEngine(index);
  const results = engine.searchClassOnly('com.example.MyClass');
  assert.strictEqual(results.length, 1);
});

test('QueryEngine should find class hierarchy', () => {
  const index = new ASTIndex();
  
  const parent = new UniversalASTNode();
  parent.name = 'Parent';
  parent.package = 'com.example';
  index.addNode(parent);
  
  const child = new UniversalASTNode();
  child.name = 'Child';
  child.package = 'com.example';
  child.addSuperClass(new ClassRef('Parent', 'com.example'));
  index.addNode(child);
  
  const engine = new QueryEngine(index);
  const supers = engine.getAllSuperClasses('com.example.Child');
  const subs = engine.getAllSubClasses('com.example.Parent');
  
  assert.strictEqual(supers.length, 1);
  assert.strictEqual(subs.length, 1);
});

test('SearchHandler should return formatted results', () => {
  const index = new ASTIndex();
  const node = new UniversalASTNode();
  node.name = 'MyClass';
  node.package = 'com.example';
  index.addNode(node);
  
  const engine = new QueryEngine(index);
  const handler = new SearchHandler(engine);
  
  const result = handler.searchClassOnly('com.example.MyClass');
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.count, 1);
});

test('SearchHandler should handle invalid input', () => {
  const engine = new QueryEngine();
  const handler = new SearchHandler(engine);
  
  const result = handler.searchClassOnly(null);
  assert.strictEqual(result.success, false);
});

test('ASTPersistenceManager should save/load', () => {
  const persistence = new ASTPersistenceManager({
    enabled: true,
    cacheDir: './test-cache'
  });
  
  const index = new ASTIndex();
  const node = new UniversalASTNode();
  node.name = 'TestClass';
  index.addNode(node);
  
  const saved = persistence.saveASTIndex(index, 'test-persist');
  assert.strictEqual(saved, true);
  
  const loaded = persistence.loadASTIndex('test-persist');
  assert.ok(loaded);
  assert.strictEqual(loaded.nodes.length, 1);
  
  persistence.clearAll();
});

console.log('\n=== Validation Results ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\nAll tests passed!');
}