/**
 * Worker 池管理器
 * 管理多个 Worker 线程，处理 CPU 密集任务
 */

import { Worker } from 'node:worker_threads';
import path from 'path';

export class WorkerPool {
  constructor({ maxWorkers = 4, workerPath } = {}) {
    this.maxWorkers = maxWorkers;
    this.workerPath = workerPath || path.join(path.dirname(import.meta.url), 'analyzerWorker.js');
    this.workers = [];
    this.taskQueue = [];
    this.idleWorkers = [];
    this.taskIdCounter = 0;
    this._init();
  }

  async _init() {
    for (let i = 0; i < this.maxWorkers; i++) {
      await this._createWorker();
    }
    console.log(`[WorkerPool] 已创建 ${this.maxWorkers} 个 Worker`);
  }

  async _createWorker() {
    return new Promise((resolve) => {
      const worker = new Worker(this.workerPath);
      
      worker.on('message', (message) => {
        if (message.type === 'ready') {
          this.idleWorkers.push(worker);
          this._processQueue();
          resolve();
        } else if (message.id) {
          const task = this.taskQueue.find(t => t.id === message.id);
          if (task) {
            this.taskQueue = this.taskQueue.filter(t => t.id !== message.id);
            this.idleWorkers.push(worker);
            
            if (message.success) {
              task.resolve(message.results);
            } else {
              task.reject(new Error(message.error));
            }
            
            this._processQueue();
          }
        }
      });
      
      worker.on('error', (error) => {
        console.error('[WorkerPool] Worker 错误:', error);
        this._replaceWorker(worker);
      });
      
      worker.on('exit', (code) => {
        console.log(`[WorkerPool] Worker 退出，代码: ${code}`);
        if (code !== 0) {
          this._replaceWorker(worker);
        }
      });
      
      this.workers.push(worker);
    });
  }

  _replaceWorker(oldWorker) {
    const index = this.workers.indexOf(oldWorker);
    if (index !== -1) {
      this.workers.splice(index, 1);
      this.idleWorkers = this.idleWorkers.filter(w => w !== oldWorker);
      oldWorker.terminate();
      this._createWorker();
    }
  }

  _processQueue() {
    while (this.idleWorkers.length > 0 && this.taskQueue.length > 0) {
      const worker = this.idleWorkers.shift();
      const task = this.taskQueue.shift();
      
      worker.postMessage({
        id: task.id,
        type: task.type,
        payload: task.payload
      });
    }
  }

  async execute(taskType, payload) {
    return new Promise((resolve, reject) => {
      const taskId = ++this.taskIdCounter;
      const task = {
        id: taskId,
        type: taskType,
        payload,
        resolve,
        reject
      };
      
      if (this.idleWorkers.length > 0) {
        const worker = this.idleWorkers.shift();
        worker.postMessage({
          id: taskId,
          type: taskType,
          payload
        });
      } else {
        this.taskQueue.push(task);
      }
    });
  }

  async analyzeCode(code, language, rules) {
    return this.execute('analyze', { code, language, rules });
  }

  async runTaintAnalysis(code, language, sources, sinks) {
    return this.execute('taint', { code, language, sources, sinks });
  }

  async destroy() {
    for (const worker of this.workers) {
      worker.terminate();
    }
    this.workers = [];
    this.idleWorkers = [];
    this.taskQueue = [];
    console.log('[WorkerPool] 已销毁所有 Worker');
  }

  getStats() {
    return {
      totalWorkers: this.workers.length,
      idleWorkers: this.idleWorkers.length,
      pendingTasks: this.taskQueue.length
    };
  }
}

let workerPoolInstance = null;

export function createWorkerPool(options = {}) {
  if (!workerPoolInstance) {
    workerPoolInstance = new WorkerPool(options);
  }
  return workerPoolInstance;
}

export function getWorkerPool() {
  return workerPoolInstance;
}
