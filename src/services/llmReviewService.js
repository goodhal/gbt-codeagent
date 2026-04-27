import { promises as fs } from "node:fs";
import path from "node:path";

const MAX_BATCHES = 8;
const MAX_FILES_PER_BATCH = 6;
const MAX_CHARS_PER_BATCH = 32_000;

export class DefensiveLlmReviewer {
  async reviewProject({ project, selectedSkills, heuristicFindings, llmConfig, onProgress }) {
    if (!llmConfig?.apiKey) {
      return {
        status: "skipped",
        called: false,
        skipReason: "missing-api-key",
        summary: "未配置可用的 LLM API Key，本次没有调用大模型进行二次复核。",
        findings: [],
        warnings: []
      };
    }

    const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
    const files = await collectFiles(sourceRoot);
    if (!files.length) {
      return {
        status: "skipped",
        called: false,
        skipReason: "no-local-files",
        summary: "当前目标没有生成可供大模型复核的本地审计镜像，因此没有实际调用大模型。",
        findings: [],
        warnings: []
      };
    }

    const prioritizedFiles = rankFiles(files, heuristicFindings, selectedSkills);
    const batches = buildBatches(prioritizedFiles);
    const findings = [];
    const warnings = [];
    let reviewedFiles = 0;
    let reviewedBatches = 0;

    onProgress?.({
      type: "llm-start",
      totalFiles: prioritizedFiles.length,
      totalBatches: Math.min(batches.length, MAX_BATCHES),
      reviewedFiles: 0,
      reviewedBatches: 0,
      label: `正在准备 LLM 复核：${project.name}`
    });

    for (const [batchIndex, batch] of batches.slice(0, MAX_BATCHES).entries()) {
      onProgress?.({
        type: "llm-batch",
        currentBatch: batchIndex + 1,
        totalBatches: Math.min(batches.length, MAX_BATCHES),
        batchSize: batch.length,
        reviewedFiles,
        reviewedBatches,
        totalFiles: prioritizedFiles.length,
        label: `正在进行 LLM 复核：第 ${batchIndex + 1} / ${Math.min(batches.length, MAX_BATCHES)} 批`
      });

      try {
        const responseText = await requestStructuredReview({
          llmConfig,
          systemPrompt: buildSystemPrompt(selectedSkills),
          userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings, batch })
        });
        const parsed = parseJsonResponse(responseText);
        const normalized = normalizeFindings(parsed?.findings, selectedSkills);
        findings.push(...normalized);
        reviewedFiles += batch.length;
        reviewedBatches += 1;
        onProgress?.({
          type: "llm-batch-complete",
          currentBatch: batchIndex + 1,
          totalBatches: Math.min(batches.length, MAX_BATCHES),
          batchSize: batch.length,
          reviewedFiles,
          reviewedBatches,
          totalFiles: prioritizedFiles.length,
          label: `LLM 已完成第 ${batchIndex + 1} 批复核`
        });
      } catch (error) {
        warnings.push(error instanceof Error ? error.message : String(error));
        onProgress?.({
          type: "llm-batch-error",
          currentBatch: batchIndex + 1,
          totalBatches: Math.min(batches.length, MAX_BATCHES),
          batchSize: batch.length,
          reviewedFiles,
          reviewedBatches,
          totalFiles: prioritizedFiles.length,
          label: `LLM 第 ${batchIndex + 1} 批复核出现错误`
        });
      }
    }

    const dedupedFindings = dedupeFindings(findings).slice(0, 12);
    const truncated = prioritizedFiles.length > batches.slice(0, MAX_BATCHES).flat().length;

    return {
      status: warnings.length && !reviewedBatches ? "failed" : warnings.length ? "partial" : "completed",
      called: true,
      skipReason: "",
      providerId: llmConfig.providerId,
      model: llmConfig.model,
      reviewedFiles,
      totalCandidateFiles: prioritizedFiles.length,
      reviewedBatches,
      skillsUsed: selectedSkills.map((skill) => skill.id),
      summary: buildSummary({ reviewedFiles, reviewedBatches, findings: dedupedFindings, truncated }),
      warnings,
      findings: dedupedFindings.map((finding) => ({ ...finding, source: "llm" }))
    };
  }
}

async function requestStructuredReview({ llmConfig, systemPrompt, userPrompt }) {
  if (llmConfig.compatibility === "anthropic") {
    const response = await fetch(`${stripTrailingSlash(llmConfig.baseUrl)}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": llmConfig.apiKey,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: llmConfig.model,
        max_tokens: 1800,
        temperature: 0.1,
        system: systemPrompt,
        messages: [{ role: "user", content: userPrompt }]
      })
    });

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Anthropic 返回 ${response.status}`);
    }

    const data = await response.json();
    return (data.content || []).map((item) => item.text || "").join("\n");
  }

  if (llmConfig.compatibility === "gemini") {
    const response = await fetch(
      `${stripTrailingSlash(llmConfig.baseUrl)}/v1beta/models/${encodeURIComponent(llmConfig.model)}:generateContent?key=${encodeURIComponent(llmConfig.apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: "user", parts: [{ text: userPrompt }] }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1800
          }
        })
      }
    );

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Gemini 返回 ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.map((item) => item.text || "").join("\n") || "";
  }

  const response = await fetch(`${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${llmConfig.apiKey}`
    },
    body: JSON.stringify({
      model: llmConfig.model,
      temperature: 0.1,
      max_tokens: 1800,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ]
    })
  });

  if (!response.ok) {
    throw new Error(`LLM 复核失败：模型端点返回 ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || "";
}

function buildSystemPrompt(selectedSkills) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    "你是一个防御性代码审计助手。",
    "只输出风险说明、证据、影响、修复建议和安全验证建议。",
    "不要提供利用步骤、payload、绕过思路、攻击链构造或 weaponization 细节。",
    "如果证据不足，就降低置信度或不要报出该问题。",
    "请只返回 JSON 对象，不要输出额外说明。"
  ];

  if (isGbtAudit) {
    prompt = prompt.concat([
      "",
      "【GB/T 国标代码安全审计要求】",
      "",
      "审计原则：",
      "- 独立性优先：LLM 审计必须完全独立于快速扫描，不查看快速扫描结果",
      "- 全面覆盖：审计应全面覆盖所有安全问题，不自我设限",
      "- 国标为准绳：漏洞定性和分类严格遵循 GB/T 标准",
      "",
      "三层审计分工：",
      "- 快速扫描（代码负责）：高风险函数调用，如命令注入、SQL注入、缓冲区溢出等",
      "- LLM审计（LLM负责）：需要上下文分析的漏洞，如业务逻辑、输入验证、认证安全等",
      "- LLM审查（LLM负责）：复杂业务逻辑漏洞、漏洞验证、最终决策",
      "",
      "LLM审计重点（需要上下文分析的漏洞）：",
      "- 输入验证问题：关键状态数据被外部可控、数据真实性验证不足",
      "- 业务逻辑问题：条件比较不充分、条件语句缺失默认情况、死代码",
      "- 认证安全问题：身份鉴别过程暴露多余信息、身份鉴别被绕过",
      "- 并发安全问题：未加限制的外部可访问锁、共享资源的并发安全",
      "- 会话安全问题：不同会话间信息泄露、发布未完成初始化的对象",
      "- 内存安全问题：忽略字符串串尾符、对环境变量长度做出假设",
      "- 资源安全问题：重复释放资源、资源或变量不安全初始化",
      "",
      "质量要求：",
      "- 问题描述：必须说明漏洞成因、攻击方式、潜在风险，字数≥20",
      "- 修复方案：必须提供具体修复方法、修复原理、代码示例或API建议，字数≥30",
      "- 严重等级：必须符合漏洞实际危害，考虑上下文和可利用性",
      "- 国标映射：必须提供准确的国标映射格式",
      "",
      "禁止行为：",
      "- 禁止查看快速扫描结果（违反独立性）",
      "- 禁止使用关键字搜索发现漏洞（违反分工原则）",
      "- 禁止自我设限审计范围（违反全面性）",
      "- 禁止凭记忆填写行号（违反准确性）",
      "",
      "支持的国标标准：",
      "- GB/T 34943-2017：C/C++ 语言源代码漏洞测试规范",
      "- GB/T 34944-2017：Java 语言源代码漏洞测试规范",
      "- GB/T 34946-2017：C# 语言源代码漏洞测试规范",
      "- GB/T 39412-2020：网络安全技术 源代码漏洞检测规则",
      "",
      "支持的漏洞类型：",
      "- 严重漏洞：认证绕过、权限缺失、关键状态数据被外部可控",
      "- 高危漏洞：CSRF、会话固定、开放重定向、文件上传、并发安全、整数溢出、格式化字符串",
      "- 中危漏洞：信息泄露、输入验证不足、异常处理不当、资源管理问题、认证信息暴露、信任边界违反、HTTP头注入、Referer认证"
    ]);
  }

  prompt.push("");
  prompt.push("关注的审计 Skill：");
  const skills = selectedSkills.map((skill) => `- ${skill.name}: ${skill.reviewPrompt}`).join("\n");
  prompt.push(skills);

  return prompt.join("\n");
}

function buildUserPrompt({ project, selectedSkills, heuristicFindings, batch }) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    `项目名称：${project.name}`,
    `审计镜像路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
    `来源模式：${project.sourceType}`
  ];

  if (isGbtAudit) {
    prompt = prompt.concat([
      "",
      "【GB/T 国标代码安全审计】",
      "",
      "审计要求：",
      "- 逐行阅读源代码，理解代码上下文和业务逻辑",
      "- 重点关注需要上下文分析的漏洞（业务逻辑、输入验证、认证安全等）",
      "- 不重复检测快速扫描已覆盖的高风险函数调用（命令注入、SQL注入、缓冲区溢出等）",
      "- 每个发现必须包含准确的国标映射、CVSS评分和详细修复方案",
      "",
      "输出格式要求：",
      "- title: 漏洞标题，简明扼要",
      "- severity: 严重等级（high/medium/low），根据实际危害评估",
      "- confidence: 置信度（0.0-1.0），基于证据充分性评估",
      "- location: 文件路径和行号，必须准确",
      "- skillId: 'gbt-code-audit'",
      "- vulnType: 漏洞类型（如 AUTH_BYPASS、MISSING_ACCESS_CONTROL、INFO_LEAK 等）",
      "- cwe: CWE编号（如 CWE-287、CWE-862 等）",
      "- gbtMapping: 国标映射（如 'GB/T39412-6.3.1.2 身份鉴别被绕过'）",
      "- cvssScore: CVSS评分（0.0-10.0），根据漏洞危害评估",
      "- language: 编程语言",
      "- evidence: 证据描述，说明在代码中发现的问题，字数≥20",
      "- impact: 影响描述，说明漏洞的危害和潜在风险，字数≥20",
      "- remediation: 修复方案，必须包含具体代码示例、API名称或配置参数，字数≥30",
      "- safeValidation: 安全验证建议，说明如何验证修复效果",
      "",
      "禁止内容：",
      "- 修复方案禁止：'根据国标要求修复'、'消除安全隐患'、'使用安全的方法'、'加强验证'、'进行过滤'等模糊表述",
      "- 修复方案必须包含：具体代码示例（如 PreparedStatement ps = conn.prepareStatement(sql);）或具体API名称（如 Cipher.getInstance(\"AES/GCM/NoPadding\")）",
      "",
      "严格返回如下 JSON：",
      '{ "findings": [ { "title": "", "severity": "low|medium|high", "confidence": 0.0, "location": "", "skillId": "gbt-code-audit", "vulnType": "", "cwe": "", "gbtMapping": "", "cvssScore": 0.0, "language": "", "evidence": "", "impact": "", "remediation": "", "safeValidation": "" } ] }'
    ]);
  } else {
    const heuristicSummary = heuristicFindings.slice(0, 8).map((finding) => `- ${finding.title} @ ${finding.location}`).join("\n") || "- 当前规则层未提供额外提示";
    const skills = selectedSkills.map((skill) => `${skill.id}: ${skill.description}`).join("\n");
    
    prompt = prompt.concat([
      "",
      `已启用 Skill：\n${skills}`,
      `规则层提示：\n${heuristicSummary}`,
      "请审阅下面的本地源码片段，输出不超过 3 条高置信度结果。",
      "严格返回如下 JSON：",
      '{ "findings": [ { "title": "", "severity": "low|medium|high", "confidence": 0.0, "location": "", "skillId": "", "evidence": "", "impact": "", "remediation": "", "safeValidation": "" } ] }'
    ]);
  }

  const snippets = batch.map((file) => `FILE: ${file.relativePath}\n\`\`\`${file.language}\n${file.content}\n\`\`\``).join("\n\n");
  prompt.push("");
  prompt.push(snippets);

  return prompt.join("\n\n");
}

async function collectFiles(root) {
  try {
    const output = [];
    await walk(root, root, output);
    return output;
  } catch {
    return [];
  }
}

async function walk(root, currentPath, output) {
  const entries = await fs.readdir(currentPath, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      await walk(root, target, output);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const language = inferFenceLanguage(target);
    if (!language) {
      continue;
    }

    const content = await fs.readFile(target, "utf8");
    output.push({
      fullPath: target,
      relativePath: path.relative(root, target).replaceAll("\\", "/"),
      content,
      language
    });
  }
}

function rankFiles(files, heuristicFindings, selectedSkills) {
  const locationHints = new Set(heuristicFindings.map((finding) => finding.location).filter(Boolean));
  const keywordHints = selectedSkills.flatMap((skill) =>
    skill.reviewPrompt.toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter((token) => token.length > 3)
  );

  return [...files]
    .map((file) => {
      const loweredPath = file.relativePath.toLowerCase();
      let score = Math.min(file.content.length / 400, 50);
      if (locationHints.has(file.relativePath)) {
        score += 120;
      }
      if (/(auth|permission|policy|access|role|admin|upload|secret|query|config|service|controller)/.test(loweredPath)) {
        score += 60;
      }
      for (const keyword of keywordHints) {
        if (loweredPath.includes(keyword)) {
          score += 5;
        }
      }
      return { ...file, score };
    })
    .sort((a, b) => b.score - a.score);
}

function buildBatches(files) {
  const batches = [];
  let currentBatch = [];
  let currentChars = 0;

  for (const file of files) {
    const snippetLength = file.content.length + file.relativePath.length;
    if (currentBatch.length && (currentBatch.length >= MAX_FILES_PER_BATCH || currentChars + snippetLength > MAX_CHARS_PER_BATCH)) {
      batches.push(currentBatch);
      currentBatch = [];
      currentChars = 0;
    }

    currentBatch.push(file);
    currentChars += snippetLength;
  }

  if (currentBatch.length) {
    batches.push(currentBatch);
  }

  return batches;
}

function parseJsonResponse(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) {
    return { findings: [] };
  }

  const fenceMatch = trimmed.match(/```json\s*([\s\S]*?)```/i);
  const candidate = fenceMatch?.[1]?.trim() || trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    const objectMatch = candidate.match(/\{[\s\S]*\}/);
    if (!objectMatch) {
      throw new Error("LLM 返回内容不是可解析的 JSON。");
    }
    return JSON.parse(objectMatch[0]);
  }
}

function normalizeFindings(findings, selectedSkills) {
  const validSkillIds = new Set(selectedSkills.map((skill) => skill.id));
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  if (!Array.isArray(findings)) {
    return [];
  }

  return findings
    .map((finding) => {
      const normalized = {
        title: safeString(finding.title, "LLM 复核发现"),
        severity: normalizeSeverity(finding.severity),
        confidence: clampConfidence(finding.confidence),
        location: safeString(finding.location, "n/a"),
        skillId: validSkillIds.has(finding.skillId) ? finding.skillId : selectedSkills[0]?.id || "access-control",
        evidence: safeString(finding.evidence, "模型复核认为这里存在值得继续人工确认的实现迹象。"),
        impact: safeString(finding.impact, "该实现如果在真实部署中成立，可能扩大管理面、数据面或配置暴露面。"),
        remediation: safeString(finding.remediation, "建议结合服务端收口、权限校验和配置默认值治理进行修复。"),
        safeValidation: safeString(finding.safeValidation, "建议在本地或测试环境里补充代码走读与单元测试来确认边界。")
      };

      if (isGbtAudit && finding.skillId === "gbt-code-audit") {
        normalized.vulnType = safeString(finding.vulnType, "UNKNOWN");
        normalized.cwe = safeString(finding.cwe, "CWE-000");
        normalized.gbtMapping = safeString(finding.gbtMapping, "GB/T39412-2020 通用基线");
        normalized.cvssScore = clampCvssScore(finding.cvssScore);
        normalized.language = safeString(finding.language, "unknown");
      }

      return normalized;
    })
    .filter((finding) => finding.confidence >= 0.55);
}

function dedupeFindings(findings) {
  const seen = new Set();
  const output = [];

  for (const finding of findings) {
    const key = `${finding.title}::${finding.location}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push(finding);
  }

  return output.sort((a, b) => severityScore(b.severity) - severityScore(a.severity) || b.confidence - a.confidence);
}

function buildSummary({ reviewedFiles, reviewedBatches, findings, truncated }) {
  const parts = [`LLM 已对 ${reviewedBatches} 个批次、${reviewedFiles} 个本地源码文件进行了二次复核。`];
  if (findings.length) {
    parts.push(`最终保留 ${findings.length} 条较高置信度的模型复核结果。`);
  } else {
    parts.push("模型没有额外保留到足够高置信度的问题。");
  }
  if (truncated) {
    parts.push("由于镜像较大，本次优先复核了高信号文件，未覆盖全部镜像文件。");
  }
  return parts.join("");
}

function inferFenceLanguage(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  if (basename === ".env" || basename.startsWith(".env.")) {
    return "dotenv";
  }

  return {
    ".ts": "ts",
    ".tsx": "tsx",
    ".js": "js",
    ".jsx": "jsx",
    ".mjs": "js",
    ".cjs": "js",
    ".php": "php",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".xml": "xml"
  }[path.extname(filePath).toLowerCase()] || "";
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function normalizeSeverity(value) {
  return value === "high" || value === "medium" ? value : "low";
}

function clampConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0.65;
  }
  if (numeric < 0) {
    return 0;
  }
  if (numeric > 1) {
    return 1;
  }
  return numeric;
}

function safeString(value, fallback) {
  const text = String(value || "").trim();
  return text || fallback;
}

function severityScore(value) {
  return value === "high" ? 3 : value === "medium" ? 2 : 1;
}

function clampCvssScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 5.0;
  }
  if (numeric < 0) {
    return 0.0;
  }
  if (numeric > 10) {
    return 10.0;
  }
  return Math.round(numeric * 10) / 10;
}
