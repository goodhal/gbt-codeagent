/**
 * CommentWorkerPool — 有界并发 Worker Pool
 * 
 * 借鉴 open-code-review 的异步后处理设计：
 * 将耗时的验证/后处理任务提交到固定大小的 worker pool，上限控制并发，
 * 主流程不阻塞等待单条结果，而是在全部提交后统一收集。
 * 
 * 用法：
 *   const pool = new CommentWorkerPool(8);
 *   for (const finding of findings) {
 *     pool.submit(() => validationService.verifyVulnerabilityPath(finding, root));
 *   }
 *   const results = await pool.awaitAll();
 */

import { EventEmitter } from 'node:events';

class CommentWorkerPool extends EventEmitter {
  /**
   * @param {number} [workerCount=8] - 最大并发 worker 数
   */
  constructor(workerCount = 8) {
    super();
    this.maxWorkers = Math.max(1, workerCount);
    this._activeCount = 0;
    this._pending = [];        // { task, resolve, reject, label }
    this._results = [];
    this._errors = [];
    this._settled = false;
    this._draining = false;
  }

  /**
   * 提交一个异步任务到 worker pool
   * @param {Function} task - 异步函数，返回结果或抛出错误
   * @param {string} [label=''] - 任务标签（用于日志）
   * @returns {Promise} 任务完成后 resolve，不阻塞调用方
   */
  submit(task, label = '') {
    if (this._settled) {
      throw new Error('WorkerPool 已结束，无法提交新任务');
    }

    return new Promise((resolve, reject) => {
      this._pending.push({ task, resolve, reject, label });
      this._drain();
    });
  }

  /**
   * 提交并忽略结果（fire-and-forget，用于纯副作用任务）
   */
  submitFireAndForget(task, label = '') {
    this.submit(task, label).catch(err => {
      this._errors.push({ label, error: err.message });
      this.emit('error', { label, error: err });
    });
  }

  /**
   * 等待所有已提交任务完成
   * @returns {Promise<Array>} 所有成功任务的结果
   */
  async awaitAll() {
    this._settled = true;

    // 等待所有 pending 任务被消费
    while (this._activeCount > 0 || this._pending.length > 0) {
      await new Promise(r => setTimeout(r, 10));
    }

    return {
      results: this._results,
      errors: this._errors,
      total: this._results.length + this._errors.length,
    };
  }

  /** 当前活跃 worker 数 */
  get activeCount() {
    return this._activeCount;
  }

  /** 队列中等待的任务数 */
  get pendingCount() {
    return this._pending.length;
  }

  /**
   * 内部：从队列取出任务执行，直到达到并发上限或队列空
   */
  _drain() {
    if (this._draining) return;
    this._draining = true;

    const pump = () => {
      while (this._activeCount < this.maxWorkers && this._pending.length > 0) {
        const { task, resolve, reject, label } = this._pending.shift();
        this._activeCount++;

        const startTime = Date.now();

        task()
          .then(result => {
            this._results.push(result);
            resolve(result);
            this.emit('done', { label, durationMs: Date.now() - startTime });
          })
          .catch(err => {
            this._errors.push({ label, error: err.message });
            reject(err);
            this.emit('error', { label, error: err });
          })
          .finally(() => {
            this._activeCount--;
            // 递归补充：完成一个后立即从队列取下一个
            pump();
          });
      }
      this._draining = false;
    };

    pump();
  }
}

export { CommentWorkerPool };
