import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ASTIndex } from './astCommon.js';

class ASTPersistenceManager {
  constructor(options = {}) {
    this.enabled = options.enabled !== undefined ? options.enabled : true;
    this.cacheDir = options.cacheDir || './cache';
    this.rebuildOnStartup = options.rebuildOnStartup || false;
    this.ttl = options.ttl || 86400000;
    this.init();
  }

  init() {
    if (!this.enabled) return;
    
    try {
      if (!fs.existsSync(this.cacheDir)) {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      }
      const astCacheDir = path.join(this.cacheDir, 'ast');
      if (!fs.existsSync(astCacheDir)) {
        fs.mkdirSync(astCacheDir, { recursive: true });
      }
    } catch (error) {
      console.warn(`Failed to initialize cache directory: ${error.message}`);
      this.enabled = false;
    }
  }

  generateCacheKey(projectId) {
    const hash = crypto.createHash('sha256');
    hash.update(projectId);
    return hash.digest('hex').substring(0, 32);
  }

  getCacheFilePath(projectId) {
    const cacheKey = this.generateCacheKey(projectId);
    return path.join(this.cacheDir, 'ast', `${cacheKey}_ast_index.json`);
  }

  getHierarchyCacheFilePath(projectId) {
    const cacheKey = this.generateCacheKey(projectId);
    return path.join(this.cacheDir, 'ast', `${cacheKey}_class_hierarchy.json`);
  }

  saveASTIndex(astIndex, projectId) {
    if (!this.enabled) return false;

    try {
      const filePath = this.getCacheFilePath(projectId);
      const data = astIndex.toJSON();
      data.projectId = projectId;
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      return true;
    } catch (error) {
      console.warn(`Failed to save AST cache: ${error.message}`);
      return false;
    }
  }

  loadASTIndex(projectId) {
    if (!this.enabled) return null;
    if (this.rebuildOnStartup) return null;

    try {
      const filePath = this.getCacheFilePath(projectId);
      if (!fs.existsSync(filePath)) {
        return null;
      }

      const stats = fs.statSync(filePath);
      const now = Date.now();
      if (now - stats.mtime.getTime() > this.ttl) {
        console.info(`AST cache expired for project ${projectId}`);
        return null;
      }

      const data = fs.readFileSync(filePath, 'utf8');
      const astIndex = ASTIndex.fromJSON(JSON.parse(data));
      return astIndex;
    } catch (error) {
      console.warn(`Failed to load AST cache: ${error.message}`);
      return null;
    }
  }

  saveClassHierarchy(hierarchy, projectId) {
    if (!this.enabled) return false;

    try {
      const filePath = this.getHierarchyCacheFilePath(projectId);
      fs.writeFileSync(filePath, JSON.stringify(hierarchy, null, 2));
      return true;
    } catch (error) {
      console.warn(`Failed to save class hierarchy cache: ${error.message}`);
      return false;
    }
  }

  loadClassHierarchy(projectId) {
    if (!this.enabled) return null;

    try {
      const filePath = this.getHierarchyCacheFilePath(projectId);
      if (!fs.existsSync(filePath)) {
        return null;
      }

      const stats = fs.statSync(filePath);
      const now = Date.now();
      if (now - stats.mtime.getTime() > this.ttl) {
        console.info(`Class hierarchy cache expired for project ${projectId}`);
        return null;
      }

      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      console.warn(`Failed to load class hierarchy cache: ${error.message}`);
      return null;
    }
  }

  exists(projectId) {
    if (!this.enabled) return false;
    
    try {
      const filePath = this.getCacheFilePath(projectId);
      return fs.existsSync(filePath);
    } catch (error) {
      return false;
    }
  }

  invalidate(projectId) {
    if (!this.enabled) return false;

    try {
      const filePath = this.getCacheFilePath(projectId);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      const hierarchyPath = this.getHierarchyCacheFilePath(projectId);
      if (fs.existsSync(hierarchyPath)) {
        fs.unlinkSync(hierarchyPath);
      }
      return true;
    } catch (error) {
      console.warn(`Failed to invalidate cache: ${error.message}`);
      return false;
    }
  }

  clearAll() {
    if (!this.enabled) return false;

    try {
      const astCacheDir = path.join(this.cacheDir, 'ast');
      if (fs.existsSync(astCacheDir)) {
        const files = fs.readdirSync(astCacheDir);
        for (const file of files) {
          fs.unlinkSync(path.join(astCacheDir, file));
        }
      }
      return true;
    } catch (error) {
      console.warn(`Failed to clear cache: ${error.message}`);
      return false;
    }
  }

  getCacheStats() {
    if (!this.enabled) return { enabled: false, cacheCount: 0, totalSize: 0 };

    try {
      const astCacheDir = path.join(this.cacheDir, 'ast');
      if (!fs.existsSync(astCacheDir)) {
        return { enabled: true, cacheCount: 0, totalSize: 0 };
      }

      const files = fs.readdirSync(astCacheDir);
      let totalSize = 0;
      for (const file of files) {
        const filePath = path.join(astCacheDir, file);
        const stats = fs.statSync(filePath);
        totalSize += stats.size;
      }

      return {
        enabled: true,
        cacheCount: files.length,
        totalSize: totalSize,
        cacheDir: this.cacheDir
      };
    } catch (error) {
      return { enabled: true, cacheCount: 0, totalSize: 0, error: error.message };
    }
  }

  setTTL(ttl) {
    this.ttl = ttl;
  }

  enable() {
    this.enabled = true;
    this.init();
  }

  disable() {
    this.enabled = false;
  }
}

export { ASTPersistenceManager };