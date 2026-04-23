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
    full_name: "wagtail/wagtail",
    html_url: "https://github.com/wagtail/wagtail",
    description: "A Django content management system focused on flexibility and user experience.",
    stargazers_count: 20000,
    forks_count: 4500,
    language: "Python",
    updated_at: "2026-04-07T10:00:00Z",
    pushed_at: "2026-04-08T18:20:00Z",
    default_branch: "main",
    topics: ["cms", "enterprise", "editorial"]
  }
];

const SEARCH_PROFILES = [
  { label: "cms-ts", query: "topic:cms language:TypeScript archived:false" },
  { label: "headless-js", query: '"headless cms" language:JavaScript archived:false' },
  { label: "headless-ts", query: '"headless cms" language:TypeScript archived:false' },
  { label: "cms-php", query: "topic:cms language:PHP archived:false" },
  { label: "content-platform", query: '"content management system" archived:false stars:>20' }
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

const CMS_TYPE_KEYWORDS = {
  all: [],
  headless: ["headless", "api-first", "content api", "content-api"],
  blog: ["blog", "publishing", "editorial", "news"],
  ecommerce: ["ecommerce", "e-commerce", "shop", "storefront", "shopping"],
  enterprise: ["enterprise", "digital experience", "portal", "dxp"],
  education: ["lms", "education", "learning", "course"],
  flatfile: ["flat-file", "flat file", "markdown"]
};

const INDUSTRY_KEYWORDS = {
  all: [],
  education: ["education", "learning", "course", "student", "campus"],
  ecommerce: ["ecommerce", "store", "shop", "product", "catalog"],
  media: ["media", "editorial", "news", "publishing", "magazine"],
  enterprise: ["enterprise", "portal", "workflow", "business"],
  government: ["government", "public sector", "civic", "municipal"],
  community: ["forum", "community", "member", "social"]
};

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

  async run({ query, cmsType = "all", industry = "all", minAdoption = 0 }) {
    const source = await this.fetchTrendingFrameworks(query);
    const projects = [];

    for (const repo of source) {
      const project = await this.materializeProject(repo);
      if (!matchesProjectFilters(project, { cmsType, industry, minAdoption })) {
        continue;
      }
      projects.push(project);
    }

    return {
      sourceMode: source === SAMPLE_REPOS ? "sample-fallback" : "live-github",
      query: normalizeCmsQuery(query),
      cmsType,
      industry,
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
    const traits = inferProjectTraits(repo);

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
      cmsType: traits.cmsType,
      industries: traits.industries,
      tags: traits.tags,
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
      // ignore
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

  buildRawHeaders() {
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

function inferProjectTraits(repo) {
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  const cmsType = Object.entries(CMS_TYPE_KEYWORDS).find(([key, values]) => key !== "all" && values.some((value) => text.includes(value)))?.[0] || "generic";
  const industries = Object.entries(INDUSTRY_KEYWORDS)
    .filter(([key, values]) => key !== "all" && values.some((value) => text.includes(value)))
    .map(([key]) => key);
  const tags = Array.from(new Set([...(repo.topics || []), cmsType, ...(industries.length ? industries : ["general"])]));
  return { cmsType, industries: industries.length ? industries : ["general"], tags };
}

function matchesProjectFilters(project, { cmsType, industry, minAdoption }) {
  if (Number(project.adoptionSignals?.estimatedLiveUsage || 0) < Number(minAdoption || 0)) {
    return false;
  }
  if (cmsType && cmsType !== "all" && project.cmsType !== cmsType) {
    return false;
  }
  if (industry && industry !== "all" && !(project.industries || []).includes(industry)) {
    return false;
  }
  return true;
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

  return REVIEWABLE_EXTENSIONS.has(path.extname(lowered)) && interestingNames.some((token) => lowered.includes(token));
}

function shouldMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(segment))) {
    return false;
  }

  const boostedSegments = [
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
    "graphql",
    "bootstrap",
    "seed",
    "schema",
    "security"
  ];

  return REVIEWABLE_EXTENSIONS.has(path.extname(lowered)) && boostedSegments.some((token) => lowered.includes(token));
}

function rankPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = 0;
  if (/auth|permission|policy|access|role/.test(lowered)) score += 90;
  if (/upload|storage|asset/.test(lowered)) score += 75;
  if (/admin|route|controller|middleware|graphql|api/.test(lowered)) score += 60;
  if (/config|bootstrap|seed|schema/.test(lowered)) score += 40;
  return score;
}

function rankMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = rankPath(filePath);
  if (/test|spec/.test(lowered)) score -= 30;
  if (/users-permissions|authentication|graphql/.test(lowered)) score += 45;
  return score;
}

function calculateFreshnessBoost(dateValue) {
  if (!dateValue) {
    return 0;
  }
  const ageMs = Date.now() - new Date(dateValue).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  if (ageDays <= 14) return 4000;
  if (ageDays <= 45) return 2200;
  if (ageDays <= 90) return 900;
  return 0;
}
