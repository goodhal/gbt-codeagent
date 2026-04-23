import crypto from "node:crypto";

export function createTaskStore() {
  const tasks = new Map();

  return {
    createTask(input = {}) {
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
      return task;
    },

    listTasks() {
      return Array.from(tasks.values()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    getTask(id) {
      return tasks.get(id) || null;
    },

    updateTask(id, patch) {
      const task = tasks.get(id);
      if (!task) {
        return null;
      }
      Object.assign(task, patch, { updatedAt: new Date().toISOString() });
      return task;
    },

    completeTask(id, patch) {
      return this.updateTask(id, { ...patch, status: "completed" });
    },

    failTask(id, error) {
      return this.updateTask(id, {
        status: "failed",
        phase: "failed",
        message: "Task failed.",
        error
      });
    }
  };
}
