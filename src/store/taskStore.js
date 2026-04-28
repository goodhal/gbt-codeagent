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
      const task = {
        id: crypto.randomUUID(),
        status: "queued",
        phase: "queued",
        message: "Task accepted.",
        createdAt: new Date().toISOString(),
        sourceType: input.sourceType || "github",
        query: input.query || 'topic:cms OR "headless cms" OR "content management system"',
        cmsType: input.cmsType || "all",
        industry: input.industry || "all",
        localRepoPaths: Array.isArray(input.localRepoPaths) ? input.localRepoPaths : [],
        minAdoption: Number(input.minAdoption || 100),
        useMemory: input.useMemory !== false,
        selectedSkillIds: Array.isArray(input.selectedSkillIds) ? input.selectedSkillIds : [],
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
      // 重置任务状态为运行中
      task.status = "running";
      task.error = null;
      task.updatedAt = new Date().toISOString();
      
      // 根据当前阶段设置进度
      if (task.phase === "target-selection") {
        task.progress = {
          stage: "target-selection",
          label: "继续选择目标",
          detail: `${task.selectedProjectIds.length} 个目标已选择`,
          percent: 50,
          current: task.selectedProjectIds.length,
          total: task.scoutResult?.projects?.length || 0
        };
      } else if (task.phase === "audit") {
        const auditResult = task.auditResult;
        if (auditResult && auditResult.projects) {
          const completedProjects = auditResult.projects.filter(p => p.findings?.length > 0).length;
          task.progress = {
            stage: "audit",
            label: "继续审计",
            detail: `${completedProjects} / ${auditResult.projects.length} 个项目已完成`,
            percent: Math.round((completedProjects / auditResult.projects.length) * 100),
            current: completedProjects,
            total: auditResult.projects.length
          };
        }
      }
      
      await persistTask(task);
      return task;
    },

    async deleteTask(id) {
      tasks.delete(id);
      await cleanupTaskFile(id);
    }
  };
}
