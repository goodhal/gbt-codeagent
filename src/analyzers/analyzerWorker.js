/**
 * 分析器 Worker 线程
 * 处理 CPU 密集的规则匹配任务
 */

import { parentPort, workerData } from 'node:worker_threads';

async function analyzeCode({ code, language, rules }) {
  const findings = [];
  
  for (const rule of rules) {
    if (rule.languages && !rule.languages.includes(language)) {
      continue;
    }

    if (rule.riskPatterns) {
      for (const patternConfig of rule.riskPatterns) {
        try {
          const pattern = new RegExp(patternConfig.pattern, 'g');
          let match;
          const lines = code.split('\n');
          
          for (let i = 0; i < lines.length; i++) {
            if (pattern.test(lines[i])) {
              findings.push({
                ruleId: rule.id || rule.description,
                type: rule.description,
                severity: rule.severity || 'MEDIUM',
                cwe: rule.cwe,
                line: i + 1,
                column: 0,
                description: patternConfig.description || rule.description,
                match: lines[i].trim(),
                remediation: rule.remediation || '需要进一步审查'
              });
            }
          }
        } catch (error) {
          console.error(`[Worker] 正则匹配失败: ${patternConfig.pattern}`, error.message);
        }
      }
    }
  }

  return findings;
}

async function runTaintAnalysis({ code, language, sources, sinks }) {
  const findings = [];
  const lines = code.split('\n');
  
  for (const sink of sinks) {
    if (sink.language !== language) continue;
    
    const sinkPattern = new RegExp(sink.pattern, 'g');
    
    for (let i = 0; i < lines.length; i++) {
      if (sinkPattern.test(lines[i])) {
        const nearbySources = sources.filter(s => 
          s.language === language && 
          Math.abs(s.line - (i + 1)) <= 50
        );
        
        if (nearbySources.length > 0) {
          findings.push({
            ruleId: sink.id,
            type: 'TAINT_ANALYSIS',
            severity: sink.severity || 'HIGH',
            line: i + 1,
            column: 0,
            description: `污点从 ${nearbySources[0].name} 传播到危险函数 ${sink.name}`,
            match: lines[i].trim(),
            remediation: sink.remediation || '验证输入数据',
            source: nearbySources[0],
            sink: sink
          });
        }
      }
    }
  }
  
  return findings;
}

parentPort.on('message', async (task) => {
  try {
    let results;
    
    switch (task.type) {
      case 'analyze':
        results = await analyzeCode(task.payload);
        break;
      case 'taint':
        results = await runTaintAnalysis(task.payload);
        break;
      default:
        throw new Error(`未知任务类型: ${task.type}`);
    }
    
    parentPort.postMessage({
      id: task.id,
      success: true,
      results
    });
  } catch (error) {
    parentPort.postMessage({
      id: task.id,
      success: false,
      error: error.message
    });
  }
});

parentPort.postMessage({ type: 'ready' });
