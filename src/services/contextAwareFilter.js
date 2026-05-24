import { promises as fs } from "node:fs";
import path from "node:path";

const GUARD_WINDOW_LINES = 5;

const GUARD_PATTERNS = {
  COMMAND_INJECTION: [
    /\"[^\"]*\"\s*\+?\s*\"[^\"]*\"/,
    /Array\.(from|of|isArray)/
  ],
  SQL_INJECTION: [
    /PreparedStatement|prepareStatement|createQuery\s*\([^)]*\.class/,
    /\?[\s,)]/,
    /setParameter|setString|setInt|setLong/,
    /NamedParameterJdbcTemplate|JdbcTemplate\s*\(\s*dataSource/
  ],
  CODE_INJECTION: [
    /\.replace\s*\(.*pattern/i,
    /\.sanitize|\.escape|htmlspecialchars|strip_tags/,
    /JSON\.parse\s*\(/
  ],
  XSS: [
    /\.textContent\s*=|\.innerText\s*=/,
    /\.replace\s*\(.*<[^>]*>/,
    /escapeHtml|sanitizeHtml|DOMPurify|xss-filters/,
    /text\/plain|Content-Security-Policy/
  ],
  PATH_TRAVERSAL: [
    /\.normalize\s*\(/,
    /\.resolve\s*\(/,
    /path\.join\s*\(/i,
    /SecurityManager|AccessController\.checkPermission/,
    /basename\s*\(|path\.basename/i
  ],
  DESERIALIZATION: [
    /ValidatingObjectInputStream|LookAheadObjectInputStream/,
    /resolveClass\s*\(/,
    /setAcceptClasses|setRejectClasses|setAllowedTypes/,
    /ObjectInputFilter|serialFilter|jdk\.serialFilter/,
    /useSafeClasses|safeDeserialization|enableSafeMode/
  ],
  SSRF: [
    /ALLOWED_HOSTS|ALLOWED_DOMAINS|whitelist|blocklist/,
    /\.startsWith\s*\(\s*['"]\/api\/|\.includes\s*\(\s*['"]\/internal/,
    /isSafeUrl|validateUrl|checkHost|isInternal/,
    /InetAddress\.getByName|isLoopbackAddress|isSiteLocalAddress/
  ],
  HARD_CODE_PASSWORD: [
    /process\.env\.|os\.environ|System\.getenv|getenv\s*\(/,
    /config\[|config\.get\s*\(|getConfig\s*\(|\.env\./,
    /keyVault|secretManager|vault|credentialsFromFile/,
    /@Value\s*\(\s*\"\$\{/
  ],
  XXE: [
    /setFeature\s*\(.*disallow-doctype|setFeature\s*\(.*external-general-entities/,
    /setFeature\s*\(.*external-parameter-entities|setFeature\s*\(.*load-external-dtd/,
    /XMLConstants\.FEATURE_SECURE_PROCESSING/,
    /setExpandEntityReferences\s*\(\s*false/
  ],
  CORS_MISCONFIGURATION: [
    /ALLOWED_ORIGINS|allowedOrigins|CORS_ORIGIN_WHITELIST/,
    /originWhitelist|corsWhitelist|corsAllowedOrigins/,
    /@CrossOrigin\s*\(\s*origins\s*=\s*\"[^\"]+\"/,
    /corsConfigurationSource\s*\(/
  ]
};

const STRING_LITERAL_PATTERN = /^["'][^"'{}]*["']\s*$/;
const METHOD_CALL_PATTERN = /^\s*\w+\s*\(\s*["'][^"']*["']\s*\)\s*$/;

function getGuardWindow(lines, lineIndex) {
  const start = Math.max(0, lineIndex - GUARD_WINDOW_LINES);
  const end = Math.min(lines.length, lineIndex + GUARD_WINDOW_LINES + 1);
  return lines.slice(start, end).join('\n');
}

export function isStringLiteralArg(lineContent) {
  const trimmed = lineContent.trim();
  if (STRING_LITERAL_PATTERN.test(trimmed)) return true;
  if (METHOD_CALL_PATTERN.test(trimmed)) return true;
  return false;
}

export function hasGuardPattern(windowText, vulnType) {
  const patterns = GUARD_PATTERNS[vulnType];
  if (!patterns || patterns.length === 0) return false;
  return patterns.some(regex => regex.test(windowText));
}

export function isTestOrMockFile(filePath) {
  if (!filePath) return false;
  const lower = filePath.toLowerCase();
  return /[\\/](test|tests|__tests__|spec|mock|fixture|example|sample|demo|stub|placeholder|dummy)[\\/]/.test(lower)
    || /\.(test|spec|mock)\./.test(lower);
}

export function evaluateGuardContext(lines, lineIndex, vulnType) {
  const windowText = getGuardWindow(lines, lineIndex);
  const lineContent = lines[lineIndex]?.trim() || '';

  const results = {
    hasStringLiteralArg: isStringLiteralArg(lineContent),
    hasGuardPattern: hasGuardPattern(windowText, vulnType),
    isTestFile: false,
    confidence: 1.0,
    notes: []
  };

  if (results.hasStringLiteralArg) {
    results.notes.push('argument_appears_to_be_string_literal');
  }
  if (results.hasGuardPattern) {
    results.notes.push('security_guard_pattern_detected');
  }

  if (results.hasStringLiteralArg && !results.hasGuardPattern) {
    results.confidence = 0.2;
    results.notes.push('probably_false_positive_string_arg');
  }
  if (results.hasGuardPattern && !results.hasStringLiteralArg) {
    results.confidence = 0.3;
    results.notes.push('mitigated_by_guard');
  }
  if (results.hasStringLiteralArg && results.hasGuardPattern) {
    results.confidence = 0.1;
    results.notes.push('doubly_mitigated');
  }

  return results;
}

export async function enhanceFindingsWithContext(findings, sourceRoot) {
  const fileCache = new Map();

  async function readFileLines(filePath) {
    try {
      const fullPath = path.resolve(sourceRoot, filePath);
      const content = await fs.readFile(fullPath, 'utf8');
      return content.split('\n');
    } catch {
      return [];
    }
  }

  // 收集唯一文件路径，并发批量读取
  const uniquePaths = [...new Set(
    findings
      .map(f => f.location || f.file || '')
      .filter(p => p && !isTestOrMockFile(p))
  )];

  const readResults = await Promise.all(
    uniquePaths.map(async (filePath) => {
      const lines = await readFileLines(filePath);
      return { filePath, lines };
    })
  );

  for (const { filePath, lines } of readResults) {
    fileCache.set(filePath, lines);
  }

  const getFileLines = (filePath) => fileCache.get(filePath) || [];

  const enhanced = [];
  for (const finding of findings) {
    const filePath = finding.location || finding.file || '';
    const lineNum = finding.line || finding.location?.line || 0;
    const vulnType = finding.vulnType || finding.type || '';

    if (isTestOrMockFile(filePath)) {
      enhanced.push({
        ...finding,
        confidence: Math.min(finding.confidence || 0.8, 0.15),
        guardContext: { isTestFile: true, confidence: 0.15, notes: ['test_or_mock_file'] }
      });
      continue;
    }

    if (!filePath || lineNum < 1) {
      enhanced.push(finding);
      continue;
    }

    const lines = await getFileLines(filePath);
    if (lines.length === 0) {
      enhanced.push(finding);
      continue;
    }

    const lineIndex = lineNum - 1;
    if (lineIndex >= lines.length) {
      enhanced.push(finding);
      continue;
    }

    const guardResult = evaluateGuardContext(lines, lineIndex, vulnType);
    const adjustedConfidence = Math.min(
      finding.confidence || 0.8,
      guardResult.confidence
    );

    enhanced.push({
      ...finding,
      confidence: adjustedConfidence,
      guardContext: guardResult
    });
  }

  return enhanced;
}
