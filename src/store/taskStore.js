import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export function createTaskStore({ workspaceDir } = {}) {
  const tasks = new Map();
  const tasksDir = workspaceDir ? path.join(workspaceDir, "tasks") : null;

  // 初始化任务目录
  async function initTasksDir() {
    if (tasksDir) {
      await fs.mkdir(tasksDir, { recursive: true });
    }
  }

  // 保存任务到磁盘
  async function persistTask(task) {
    if (!tasksDir) return;
    try {
      const taskFile = path.join(tasksDir, `${task.id}.json`);
      await fs.writeFile(taskFile, JSON.stringify(task, null, 2), "utf8");
    } catch (error) {
      console.error(`Failed to persist task ${task.id}:`, error.message);
    }
  }

  // 从磁盘加载任务
  async function loadPersistedTasks() {
    if (!tasksDir) return;
    try {
      const files = await fs.readdir(tasksDir);
      for (const file of files) {
        if (file.endsWith(".json")) {
          try {
            const taskFile = path.join(tasksDir, file);
            const content = await fs.readFile(taskFile, "utf8");
            const task = JSON.parse(content);

            if (task.status === "running") {
              task.status = "paused";
              task.message = task.message || "服务器重启，任务已暂停";
              task.updatedAt = new Date().toISOString();
              task.progress = {
                ...task.progress,
                stage: "paused",
                label: "服务器重启，任务已暂停，可手动恢复"
              };
              await fs.writeFile(taskFile, JSON.stringify(task, null, 2), "utf8");
              console.log(`[taskStore] 将 running 任务 ${task.id} 自动转为 paused（服务器重启恢复）`);
            }

            tasks.set(task.id, task);
            console.log(`Loaded task ${task.id} (status: ${task.status}) from disk`);
          } catch (error) {
            console.error(`Failed to load task from ${file}:`, error.message);
          }
        }
      }
    } catch (error) {
      // 目录不存在时忽略
    }
  }

  // 清理已完成的任务文件
  async function cleanupTaskFile(taskId) {
    if (!tasksDir) return;
    try {
      const taskFile = path.join(tasksDir, `${taskId}.json`);
      await fs.unlink(taskFile);
    } catch (error) {
      // 文件不存在时忽略
    }
  }

  // 初始化时加载持久化的任务
  initTasksDir().then(() => loadPersistedTasks());

  return {
    async createTask(input = {}) {
      const sourceType = input.sourceType || "github";
      let query;
      if (input.query) {
        query = input.query;
      } else if (sourceType === "zip-upload") {
        query = "ZIP 代码包上传";
      } else if (sourceType === "local") {
        query = "本地仓库导入";
      } else if (sourceType === "git-url") {
        query = "Git 仓库导入";
      } else {
        query = 'topic:cms OR "headless cms" OR "content management system"';
      }
      const task = {
        id: crypto.randomUUID(),
        status: "queued",
        phase: "queued",
        message: "Task accepted.",
        createdAt: new Date().toISOString(),
        sourceType,
        query,
        cmsType: input.cmsType || "all",
        industry: input.industry || "all",
        localRepoPaths: Array.isArray(input.localRepoPaths) ? input.localRepoPaths : [],
        gitUrls: Array.isArray(input.gitUrls) ? input.gitUrls : [],
        minAdoption: Number(input.minAdoption || 100),
        useMemory: input.useMemory !== false,
        selectedSkillIds: Array.isArray(input.selectedSkillIds) ? input.selectedSkillIds : [],
        zipFiles: Array.isArray(input.zipFiles) ? input.zipFiles : [],
        scoutResult: null,
        selectedProjectIds: [],
        auditResult: null,
        report: null,
        progress: {
          stage: "queued",
          label: "等待开始",
          detail: "",
          percent: 0,
          current: 0,
          total: 0
        },
        memorySnapshot: null,
        memorySummary: null,
        error: null
      };
      tasks.set(task.id, task);
      await persistTask(task);
      return task;
    },

    listTasks() {
      return Array.from(tasks.values()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    getTask(id) {
      return tasks.get(id) || null;
    },

    async updateTask(id, patch) {
      const task = tasks.get(id);
      if (!task) {
        return null;
      }
      Object.assign(task, patch, { updatedAt: new Date().toISOString() });
      await persistTask(task);
      return task;
    },

    async completeTask(id, patch) {
      const result = await this.updateTask(id, { ...patch, status: "completed" });
      return result;
    },

    async failTask(id, error) {
      const result = await this.updateTask(id, {
        status: "failed",
        phase: "failed",
        message: "Task failed.",
        error
      });
      return result;
    },

    async resumeTask(id) {
      const task = tasks.get(id);
      if (!task) {
        return null;
      }
      if (task.status !== "paused") {
        return null;
      }
      task.status = "running";
      task.error = null;
      task.updatedAt = new Date().toISOString();

      // 保持原有进度，只更新状态为 running
      await persistTask(task);
      return task;
    },

    async pauseTask(id) {
      const task = tasks.get(id);
      if (!task) {
        return null;
      }
      if (task.status !== "running") {
        return null;
      }
      task.status = "paused";
      task.updatedAt = new Date().toISOString();
      task.message = "任务已暂停";

      await persistTask(task);
      return task;
    },

    async stopTask(id) {
      const task = tasks.get(id);
      if (!task) {
        return null;
      }
      if (task.status === "completed" || task.status === "failed" || task.status === "cancelled") {
        return null;
      }
      task.status = "cancelled";
      task.phase = "cancelled";
      task.updatedAt = new Date().toISOString();
      task.message = "任务已取消";
      task.progress = {
        stage: "cancelled",
        label: "任务已取消",
        detail: "",
        percent: 0,
        current: 0,
        total: 0
      };

      await persistTask(task);
      return task;
    },

    async deleteTask(id) {
      tasks.delete(id);
      await cleanupTaskFile(id);
    }
  };
}
