/**
 * 文件内容缓存
 *
 * 请求级缓存：同一审计流程中多个扫描器（QuickScan、Taint、ExternalTool、LLM）
 * 共享缓存的文件内容，避免重复读盘。
 *
 * 用法：
 *   const content = await cachedRead(filePath);
 *   第一次读取后，后续同路径读取从内存返回。
 *
 * 审计流程开始前调用 resetFileCache() 清空缓存，确保新鲜度。
 */

/** @type {Map<string, string>} */
const _cache = new Map();

/**
 * 带缓存的文件读取
 * 首次读取走 fs.readFile，之后返回缓存内容
 * @param {Function} fsRead - fs.readFile 的异步包装
 * @param {string} filePath - 文件绝对路径
 * @returns {Promise<string>} 文件内容
 */
export async function cachedRead(fsRead, filePath) {
  const cached = _cache.get(filePath);
  if (cached !== undefined) return cached;

  const content = await fsRead(filePath, "utf8");
  _cache.set(filePath, content);
  return content;
}

/**
 * 批量缓存文件内容（供 collectFilesWithContent 等批量场景使用）
 * @param {Array<{path:string, content:string}>} files
 */
export function cacheFiles(files) {
  for (const f of files) {
    if (f.path && f.content !== undefined) {
      _cache.set(f.path, f.content);
    }
  }
}

/**
 * 从缓存取文件内容
 * @param {string} filePath
 * @returns {string|undefined}
 */
export function getCached(filePath) {
  return _cache.get(filePath);
}

/**
 * 清空缓存（每次新审计前调用）
 */
export function resetFileCache() {
  _cache.clear();
}
