import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_QUERY = 'topic:cms OR "headless cms" OR "content management system"';
const SAMPLE_REPOS = [
  {
    full_name: "strapi/strapi",
    html_url: "https://github.com/strapi/strapi",
    description: "Open-source headless CMS.",
    stargazers_count: 67000,
    forks_count: 8600,
    language: "TypeScript",
    updated_at: "2026-04-05T08:00:00Z",
    pushed_at: "2026-04-08T06:20:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "nodejs"]
  },
  {
    full_name: "directus/directus",
    html_url: "https://github.com/directus/directus",
    description: "Composable data platform and headless CMS.",
    stargazers_count: 31000,
    forks_count: 4200,
    language: "TypeScript",
    updated_at: "2026-04-06T12:00:00Z",
    pushed_at: "2026-04-08T09:10:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "content-api"]
  },
  {
    full_name: "keystonejs/keystone",
    html_url: "https://github.com/keystonejs/keystone",
    description: "The most powerful headless CMS for Node.js.",
    stargazers_count: 9700,
    forks_count: 1200,
    language: "TypeScript",
    updated_at: "2026-04-04T15:30:00Z",
    pushed_at: "2026-04-08T11:45:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "graphql"]
  },
  {
    full_name: "payloadcms/payload",
    html_url: "https://github.com/payloadcms/payload",
    description: "TypeScript headless CMS and application framework.",
    stargazers_count: 34000,
    forks_count: 2100,
    language: "TypeScript",
    updated_at: "2026-04-07T10:00:00Z",
    pushed_at: "2026-04-08T18:20:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "typescript"]
  },
  {
    full_name: "appwrite/appwrite",
    html_url: "https://github.com/appwrite/appwrite",
    description: "Build like a team of hundreds with a full platform and admin control plane.",
    stargazers_count: 47000,
    forks_count: 4200,
    language: "TypeScript",
    updated_at: "2026-04-02T10:00:00Z",
    pushed_at: "2026-04-07T18:20:00Z",
    default_branch: "main",
    topics: ["cms", "admin-panel", "backend"]
  }
];

const CMS_KEYWORDS = [
  "cms",
  "headless",
  "content management",
  "content platform",
  "blog",
  "admin panel",
  "publishing",
  "webcms",
  "digital experience",
  "editorial"
];

const SEARCH_PROFILES = [
  { label: "cms-ts", query: "topic:cms language:TypeScript archived:false" },
  { label: "headless-js", query: '"headless cms" language:JavaScript archived:false' },
  { label: "headless-ts", query: '"headless cms" language:TypeScript archived:false' },
  { label: "cms-php", query: "topic:cms language:PHP archived:false" },
  { label: "content-platform", query: '"content management system" archived:false stars:>20' }
];

const REVIEWABLE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".php",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".xml",
  ".graphql",
  ".gql"
]);

const IGNORED_SEGMENTS = [
  "node_modules/",
  "dist/",
  "build/",
  "coverage/",
  ".next/",
  ".nuxt/",
  "vendor/",
  "fixtures/",
  "__snapshots__/",
  "storybook-static/",
  "public/build/"
];

const DISCOVERY_FILE_LIMIT = 16;
const DISCOVERY_MAX_FILE_SIZE = 120_000;
const AUDIT_MIRROR_FILE_LIMIT = 72;
const AUDIT_MIRROR_MAX_FILE_SIZE = 180_000;
const AUDIT_MIRROR_MAX_TOTAL_BYTES = 4_500_000;
const FETCH_RETRY_LIMIT = 3;

export class FrameworkScoutAgent {
  constructor({ downloadsDir, getGithubConfig }) {
    this.downloadsDir = downloadsDir;
    this.getGithubConfig = getGithubConfig || (() => ({}));
  }

  async run({ query }) {
    const source = await this.fetchTrendingFrameworks(query);
    const projects = [];

    for (const repo of source) {
      projects.push(await this.materializeProject(repo));
    }

    return {
      sourceMode: source === SAMPLE_REPOS ? "sample-fallback" : "live-github",
      query: normalizeCmsQuery(query),
      discoveredAt: new Date().toISOString(),
      summary: `已发现 ${projects.length} 个候选开源 CMS。选择目标后会先下载审计镜像，再执行规则层和 LLM 复核。`,
      projects
    };
  }

  async ensureProjectSample(project) {
    await this.saveSourceSnapshot(project, { mode: "discovery-sample" });
    return project;
  }

  async ensureProjectMirror(project, options = {}) {
    const sourceRoot = await this.saveSourceSnapshot(project, { mode: "audit-mirror", ...options });
    project.localPath = sourceRoot;
    project.auditMirrorReady = true;
    return project;
  }

  async fetchTrendingFrameworks(query) {
    try {
      const github = await this.getGithubConfig();
      const collected = new Map();
      let successCount = 0;

      for (const searchQuery of buildSearchQueries(query, github.ownerFilter)) {
        const q = encodeURIComponent(searchQuery);
        const response = await this.fetchGithubResource(
          `https://api.github.com/search/repositories?q=${q}&sort=stars&order=desc&per_page=30`,
          github.token
        );

        if (!response.ok) {
          continue;
        }

        successCount += 1;
        const data = await response.json();
        const items = Array.isArray(data.items) ? data.items : [];

        for (const repo of items) {
          if (!isCmsLike(repo)) {
            continue;
          }
          const current = collected.get(repo.full_name);
          if (!current || scoreRepo(repo) > scoreRepo(current)) {
            collected.set(repo.full_name, repo);
          }
        }
      }

      if (!successCount) {
        throw new Error("GitHub search failed");
      }

      const filtered = Array.from(collected.values())
        .sort((a, b) => scoreRepo(b) - scoreRepo(a))
        .slice(0, 60);

      return filtered.length ? filtered : SAMPLE_REPOS;
    } catch {
      return SAMPLE_REPOS;
    }
  }

  async materializeProject(repo) {
    const [owner, name] = repo.full_name.split("/");
    const estimatedLiveUsage = this.estimateLiveUsage(repo);
    const archiveFileName = `${owner}__${name}.json`;

    return {
      id: `${owner}-${name}`,
      sourceType: "github",
      name,
      owner,
      repoUrl: repo.html_url,
      localPath: "",
      description: repo.description,
      language: repo.language || "Unknown",
      defaultBranch: repo.default_branch || "main",
      updatedAt: repo.updated_at,
      pushedAt: repo.pushed_at,
      downloadArtifact: archiveFileName,
      adoptionSignals: {
        stars: repo.stargazers_count || 0,
        forks: repo.forks_count || 0,
        estimatedLiveUsage
      }
    };
  }

  estimateLiveUsage(repo) {
    const stars = repo.stargazers_count || 0;
    const forks = repo.forks_count || 0;
    const topicBoost = isCmsLike(repo) ? 40 : 0;
    return Math.round(stars * 0.018 + forks * 0.28 + topicBoost);
  }

  async saveSourceSnapshot(project, { mode, onProgress }) {
    const sourceRoot = path.join(this.downloadsDir, project.id);
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.mkdir(sourceRoot, { recursive: true });

    const mirroredFiles = mode === "audit-mirror"
      ? await this.downloadAuditMirror(project, sourceRoot, onProgress)
      : await this.downloadSourceSample(project, sourceRoot, onProgress);

    const payload = {
      project: {
        ...project,
        localPath: mode === "audit-mirror" ? sourceRoot : project.localPath
      },
      snapshotAt: new Date().toISOString(),
      sourceRoot,
      mirrorMode: mode,
      mirroredFiles,
      note: mode === "audit-mirror"
        ? "This is a defensive audit mirror used for local rule review and LLM review after manual target selection."
        : "This is a defensive discovery sample used to preview candidate repositories before audit."
    };

    const target = path.join(this.downloadsDir, project.downloadArtifact);
    await fs.writeFile(target, JSON.stringify(payload, null, 2), "utf8");
    return sourceRoot;
  }

  async downloadSourceSample(project, sourceRoot, onProgress) {
    try {
      const github = await this.getGithubConfig();
      const tree = await this.fetchProjectTree(project, github.token);
      const candidateFiles = tree
        .filter((entry) => shouldIncludePath(entry.path))
        .filter((entry) => (entry.size || 0) > 0 && (entry.size || 0) <= DISCOVERY_MAX_FILE_SIZE)
        .sort((a, b) => rankPath(b.path) - rankPath(a.path))
        .slice(0, DISCOVERY_FILE_LIMIT);

      const downloaded = await this.downloadEntries(project, candidateFiles, sourceRoot, github.token, {
        maxFiles: DISCOVERY_FILE_LIMIT,
        maxTotalBytes: AUDIT_MIRROR_MAX_TOTAL_BYTES,
        onProgress
      });

      if (!downloaded.length) {
        await this.writeFallbackSourceSample(project, sourceRoot);
        return [{ path: "SAFE_SAMPLE.md", size: 0 }];
      }

      return downloaded;
    } catch {
      await this.writeFallbackSourceSample(project, sourceRoot);
      return [{ path: "SAFE_SAMPLE.md", size: 0 }];
    }
  }

  async downloadAuditMirror(project, sourceRoot, onProgress) {
    try {
      const github = await this.getGithubConfig();
      const tree = await this.fetchProjectTree(project, github.token);
      const candidateFiles = tree
        .filter((entry) => shouldMirrorPath(entry.path))
        .filter((entry) => (entry.size || 0) > 0 && (entry.size || 0) <= AUDIT_MIRROR_MAX_FILE_SIZE)
        .sort((a, b) => rankMirrorPath(b.path) - rankMirrorPath(a.path) || (a.size || 0) - (b.size || 0))
        .slice(0, AUDIT_MIRROR_FILE_LIMIT * 2);

      const downloaded = await this.downloadEntries(project, candidateFiles, sourceRoot, github.token, {
        maxFiles: AUDIT_MIRROR_FILE_LIMIT,
        maxTotalBytes: AUDIT_MIRROR_MAX_TOTAL_BYTES,
        onProgress
      });

      if (!downloaded.length) {
        await this.writeFallbackSourceSample(project, sourceRoot);
        return [{ path: "SAFE_SAMPLE.md", size: 0 }];
      }

      return downloaded;
    } catch {
      await this.writeFallbackSourceSample(project, sourceRoot);
      return [{ path: "SAFE_SAMPLE.md", size: 0 }];
    }
  }

  async fetchProjectTree(project, token) {
    const refs = await this.resolveTreeRefs(project, token);

    for (const ref of refs) {
      const treeUrl = `https://api.github.com/repos/${project.owner}/${project.name}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
      const treeResponse = await this.fetchGithubResource(treeUrl, token);
      if (!treeResponse.ok) {
        continue;
      }

      const treeData = await treeResponse.json();
      project.defaultBranch = ref;
      return (treeData.tree || []).filter((entry) => entry.type === "blob");
    }

    throw new Error("Tree fetch failed");
  }

  async downloadEntries(project, entries, sourceRoot, token, { maxFiles, maxTotalBytes, onProgress }) {
    const downloaded = [];
    let totalBytes = 0;
    const totalCandidates = Math.min(entries.length, maxFiles);
    let processedCandidates = 0;

    for (const entry of entries) {
      if (downloaded.length >= maxFiles) {
        break;
      }

      try {
        const text = await this.fetchRawFile(project, entry.path, token);
        if (!text) {
          processedCandidates += 1;
          onProgress?.({
            type: "mirror-file",
            projectId: project.id,
            downloaded: downloaded.length,
            processed: processedCandidates,
            total: totalCandidates,
            currentPath: entry.path
          });
          continue;
        }

        const byteLength = Buffer.byteLength(text, "utf8");
        if (downloaded.length && totalBytes + byteLength > maxTotalBytes) {
          processedCandidates += 1;
          onProgress?.({
            type: "mirror-file",
            projectId: project.id,
            downloaded: downloaded.length,
            processed: processedCandidates,
            total: totalCandidates,
            currentPath: entry.path
          });
          continue;
        }

        const target = path.join(sourceRoot, ...entry.path.split("/"));
        await fs.mkdir(path.dirname(target), { recursive: true });
        await fs.writeFile(target, text, "utf8");

        downloaded.push({ path: entry.path, size: byteLength });
        totalBytes += byteLength;
        processedCandidates += 1;
        onProgress?.({
          type: "mirror-file",
          projectId: project.id,
          downloaded: downloaded.length,
          processed: processedCandidates,
          total: totalCandidates,
          currentPath: entry.path
        });
      } catch {
        processedCandidates += 1;
        onProgress?.({
          type: "mirror-file",
          projectId: project.id,
          downloaded: downloaded.length,
          processed: processedCandidates,
          total: totalCandidates,
          currentPath: entry.path
        });
      }
    }

    return downloaded;
  }

  async fetchRawFile(project, filePath, token) {
    const contentUrl = `https://raw.githubusercontent.com/${project.owner}/${project.name}/${project.defaultBranch}/${filePath}`;
    try {
      const contentResponse = await this.fetchRawResource(contentUrl, token);
      if (!contentResponse.ok) {
        return "";
      }
      return contentResponse.text();
    } catch {
      return "";
    }
  }

  async resolveTreeRefs(project, token) {
    const refs = [project.defaultBranch, "main", "master", "develop", "next"];

    try {
      const repoResponse = await this.fetchGithubResource(`https://api.github.com/repos/${project.owner}/${project.name}`, token);
      if (repoResponse.ok) {
        const repoData = await repoResponse.json();
        if (repoData.default_branch) {
          refs.unshift(repoData.default_branch);
        }
      }
    } catch {
      // Ignore metadata lookup failure and fall back to common branch names.
    }

    return [...new Set(refs.filter(Boolean))];
  }

  async fetchGithubResource(url, token) {
    let lastError = null;

    for (let attempt = 0; attempt < FETCH_RETRY_LIMIT; attempt += 1) {
      try {
        let response = await fetch(url, { headers: this.buildGithubHeaders(token) });
        if (response.status === 401 && token) {
          response = await fetch(url, { headers: this.buildGithubHeaders("") });
        }
        return response;
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("GitHub request failed");
  }

  async fetchRawResource(url, token) {
    let lastError = null;

    for (let attempt = 0; attempt < FETCH_RETRY_LIMIT; attempt += 1) {
      try {
        let response = await fetch(url, { headers: this.buildRawHeaders(token) });
        if (!response.ok && token) {
          response = await fetch(url, { headers: this.buildRawHeaders("") });
        }
        return response;
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("Raw file request failed");
  }

  buildGithubHeaders(token) {
    const headers = {
      "User-Agent": "safe-framework-audit-agents",
      Accept: "application/vnd.github+json"
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return headers;
  }

  buildRawHeaders(token) {
    return { "User-Agent": "safe-framework-audit-agents" };
  }

  async writeFallbackSourceSample(project, sourceRoot) {
    const fallback = [
      `# ${project.owner}/${project.name}`,
      "",
      "Safe source mirroring was unavailable for this repository in the current environment.",
      "Use the metadata snapshot for triage, then rerun in an environment with GitHub raw/tree access if you want code-backed review."
    ].join("\n");

    await fs.mkdir(sourceRoot, { recursive: true });
    await fs.writeFile(path.join(sourceRoot, "SAFE_SAMPLE.md"), fallback, "utf8");
  }
}

function normalizeCmsQuery(query) {
  const raw = String(query || "").trim();
  if (!raw) {
    return DEFAULT_QUERY;
  }
  if (/cms|content management|headless/i.test(raw)) {
    return raw;
  }
  return `${raw} (topic:cms OR "headless cms" OR "content management")`;
}

function buildSearchQueries(query, ownerFilter) {
  const ownerQualifier = ownerFilter ? ` user:${ownerFilter}` : "";
  const normalized = normalizeCmsQuery(query);

  if (normalized !== DEFAULT_QUERY) {
    return [
      `${normalized}${ownerQualifier} archived:false`,
      `topic:cms${ownerQualifier} archived:false`,
      `"headless cms"${ownerQualifier} archived:false`
    ];
  }

  return SEARCH_PROFILES.map((profile) => `${profile.query}${ownerQualifier}`);
}

function isCmsLike(repo) {
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  return CMS_KEYWORDS.some((keyword) => text.includes(keyword));
}

function scoreRepo(repo) {
  const stars = repo.stargazers_count || 0;
  const forks = repo.forks_count || 0;
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  const keywordBoost = CMS_KEYWORDS.reduce((sum, keyword) => sum + (text.includes(keyword) ? 2000 : 0), 0);
  const freshnessBoost = calculateFreshnessBoost(repo.pushed_at || repo.updated_at);
  return stars * 1.05 + forks * 2.15 + keywordBoost + freshnessBoost;
}

function shouldIncludePath(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(segment))) {
    return false;
  }

  const interestingNames = [
    "auth",
    "login",
    "session",
    "permission",
    "policy",
    "upload",
    "storage",
    "admin",
    "config",
    "controller",
    "route",
    "api",
    "middleware",
    "access",
    "rbac",
    "role",
    "plugin",
    "bootstrap",
    "seed",
    "collection",
    "schema"
  ];

  return REVIEWABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase()) && interestingNames.some((name) => lowered.includes(name));
}

function shouldMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(segment))) {
    return false;
  }

  if (!REVIEWABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase())) {
    return false;
  }

  return /(auth|permission|policy|access|role|admin|upload|secret|config|route|controller|service|plugin|bootstrap|seed|schema|collection|api|middleware|query|db|database|graphql|resolver)/.test(lowered);
}

function rankPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = 0;

  for (const keyword of ["auth", "permission", "policy", "access", "admin", "route", "upload", "rbac", "role", "bootstrap", "seed"]) {
    if (lowered.includes(keyword)) {
      score += 3;
    }
  }

  for (const keyword of ["config", "schema", "plugin", "middleware", "api", "controller", "collection"]) {
    if (lowered.includes(keyword)) {
      score += 2;
    }
  }

  return score;
}

function rankMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = rankPath(filePath);

  for (const keyword of ["service", "query", "database", "db", "resolver", "graphql"]) {
    if (lowered.includes(keyword)) {
      score += 2;
    }
  }

  if (/\.(ts|tsx|js|jsx|php|py)$/.test(lowered)) {
    score += 1;
  }

  if (/config|bootstrap|route|controller|service/.test(lowered)) {
    score += 2;
  }

  return score;
}

function calculateFreshnessBoost(isoValue) {
  if (!isoValue) {
    return 0;
  }

  const pushedAt = Date.parse(isoValue);
  if (!Number.isFinite(pushedAt)) {
    return 0;
  }

  const ageInDays = (Date.now() - pushedAt) / (1000 * 60 * 60 * 24);
  if (ageInDays <= 30) {
    return 1800;
  }
  if (ageInDays <= 90) {
    return 900;
  }
  if (ageInDays <= 180) {
    return 300;
  }
  return 0;
}
