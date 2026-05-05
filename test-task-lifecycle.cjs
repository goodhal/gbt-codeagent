const http = require('http');

const BASE_URL = 'http://127.0.0.1:3001';

function api(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const reqOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    req.end();
  });
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function testTaskLifecycle() {
  console.log('=== 任务生命周期测试 ===\n');

  // 1. 创建任务（使用 GitHub 搜索）
  console.log('[测试] 1. 创建任务...');
  const createResult = await api('/api/tasks', {
    method: 'POST',
    body: {
      sourceType: "github",
      query: "Spring Framework",
      cmsType: "all",
      industry: "all",
      localRepoPaths: [],
      gitUrls: [],
      minAdoption: 100,
      useMemory: false,
      useReAct: false,
      selectedSkillIds: ["gbt-code-audit"]
    }
  });

  if (createResult.error) {
    console.log('[测试] 创建任务失败:', createResult.error);
    return;
  }

  const taskId = createResult.id;
  console.log(`[测试] 任务创建成功: ${taskId}`);
  console.log(`[测试] 任务状态: ${createResult.status}`);

  // 2. 等待任务进入目标选择阶段
  console.log('\n[测试] 2. 等待任务进入目标选择阶段...');
  let task = null;
  let attempts = 0;
  while (attempts < 60) {
    await delay(1000);
    task = await api(`/api/tasks/${taskId}`);
    console.log(`[测试] 等待中... 状态=${task.status}, 阶段=${task.phase}`);
    
    if (task.phase === 'target-selection' && task.scoutResult?.projects?.length > 0) {
      console.log(`[测试] 任务已进入目标选择阶段，发现 ${task.scoutResult.projects.length} 个项目!`);
      break;
    }
    if (task.status === 'failed') {
      console.log('[测试] 任务失败');
      console.log('[测试] 错误详情:', task.error);
      return;
    }
    attempts++;
  }

  if (!task || task.status === 'failed' || !task.scoutResult?.projects?.length) {
    console.log('[测试] 无法获取项目列表，结束测试');
    return;
  }

  // 3. 开始审计（选择第一个项目）
  console.log('\n[测试] 3. 开始审计...');
  const projectId = task.scoutResult.projects[0].id;
  const auditResult = await api(`/api/tasks/${taskId}/audit`, {
    method: 'POST',
    body: {
      selectedProjectIds: [projectId]
    }
  });
  console.log(`[测试] 开始审计请求已发送`);

  // 4. 等待审计开始
  console.log('\n[测试] 4. 等待审计开始...');
  attempts = 0;
  while (attempts < 120) {
    await delay(1000);
    task = await api(`/api/tasks/${taskId}`);
    console.log(`[测试] 等待中... 状态=${task.status}, 阶段=${task.phase}, 进度=${task.progress?.percent || 0}%`);
    
    if (task.status === 'running' && (task.phase === 'audit-analyst')) {
      console.log('[测试] 审计已开始!');
      break;
    }
    if (task.status === 'completed' || task.status === 'failed') {
      console.log('[测试] 任务已结束');
      break;
    }
    attempts++;
  }

  if (task.status !== 'running' || task.phase !== 'audit-analyst') {
    console.log('[测试] 审计未开始或已结束');
    console.log('[测试] 最终状态:', task.status, task.phase);
    // 清理
    await api(`/api/tasks/${taskId}`, { method: 'DELETE' });
    return;
  }

  // 5. 暂停任务
  console.log('\n[测试] 5. 暂停任务...');
  const pauseResult = await api(`/api/tasks/${taskId}/pause`, { method: 'POST' });
  console.log(`[测试] 暂停API返回: ${JSON.stringify(pauseResult)}`);

  await delay(2000);
  task = await api(`/api/tasks/${taskId}`);
  console.log(`[测试] 暂停后状态: ${task.status}, 阶段=${task.phase}`);

  // 保存审计结果用于对比
  const pausedAuditResult = task.auditResult;
  console.log(`[测试] 暂停时已有审计结果: ${pausedAuditResult ? '是' : '否'}`);

  // 6. 恢复任务
  console.log('\n[测试] 6. 恢复任务...');
  const resumeResult = await api(`/api/tasks/${taskId}/resume`, { method: 'POST' });
  console.log(`[测试] 恢复API返回: status=${resumeResult.status}, phase=${resumeResult.phase}`);

  await delay(2000);
  task = await api(`/api/tasks/${taskId}`);
  console.log(`[测试] 恢复后状态: ${task.status}, 阶段=${task.phase}`);

  // 7. 等待一段时间后取消
  console.log('\n[测试] 7. 等待后取消任务...');
  await delay(5000);
  const stopResult = await api(`/api/tasks/${taskId}/stop`, { method: 'POST' });
  console.log(`[测试] 取消API返回: ${JSON.stringify(stopResult)}`);

  await delay(1000);
  task = await api(`/api/tasks/${taskId}`);
  console.log(`[测试] 取消后状态: ${task.status}`);

  // 8. 测试重新审计（针对已取消任务）
  console.log('\n[测试] 8. 重新审计...');
  const restartResult = await api(`/api/tasks/${taskId}/restart`, { method: 'POST' });
  if (restartResult.error) {
    console.log(`[测试] 重新审计失败: ${restartResult.error}`);
  } else {
    console.log(`[测试] 重新审计成功: 新任务ID=${restartResult.id}, 状态=${restartResult.status}`);
  }

  // 9. 清理
  console.log('\n[测试] 9. 清理测试任务...');
  await delay(2000);
  await api(`/api/tasks/${taskId}`, { method: 'DELETE' });
  if (restartResult.id) {
    await api(`/api/tasks/${restartResult.id}`, { method: 'DELETE' });
  }
  console.log('[测试] 清理完成');

  console.log('\n=== 测试完成 ===');
}

testTaskLifecycle().catch(console.error);
