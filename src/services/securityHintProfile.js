/**
 * 安全线索画像系统
 * 从 AiCodeAudit 引入：对代码中的安全信号做多语言分类画像
 * 用于后续风险候选预筛选和依赖上下文增强
 */

const COMMON_SECURITY_HINT_PATTERNS = {
  inputSources: [
    /\b(upload|file|filename|filepath|path|callback|redirect)\b/i,
  ],
  dangerousSinks: [
    /\b(eval|exec)\b/i,
    /\b(select|insert|update|delete)\b.*(\+|format\(|f"|sprintf\()/i,
    /\b(innerHTML|dangerouslySetInnerHTML|document\.write)\b/i,
  ],
  safetySignals: [
    /\b(whitelist|allowlist)\b/i,
    /\b(parameterized|prepared|placeholder)\b/i,
  ],
  validationSignals: [
    /\b(validate|sanitize|escape|check|verify|guard|filter)\b/i,
    /\b(auth|authorize|permission|acl|role|requiredLogin|requiredAuth)\b/i,
    /\b(is_safe|safe_path|normalized|canonical)\b/i,
  ],
};

export const LANGUAGE_SECURITY_HINT_PATTERNS = {
  ".py": {
    inputSources: [
      /\brequest\.(args|form|json|values|files)\b/i,
      /\b(input|sys\.argv|os\.environ|getenv)\b/i,
    ],
    dangerousSinks: [
      /\b(subprocess\.(run|Popen|call)|os\.system)\b/i,
      /\b(pickle\.load|pickle\.loads|yaml\.load)\b/i,
      /\b(requests\.(get|post|request))\b/i,
      /\b(open|Path\.open|read_text|write_text)\b/i,
      /\b(sqlite3|pymysql|psycopg2|sqlalchemy)\b/i,
    ],
    safetySignals: [
      /\b(yaml\.safe_load|html\.escape|markupsafe\.escape)\b/i,
      /\b(pathlib\.Path|resolve\(\))\b/i,
      /\b(subprocess\.(run|Popen)\s*\(\s*\[)\b/i,
    ],
    validationSignals: [
      /\b(pydantic|validator|marshmallow|schema\.load)\b/i,
    ],
  },
  ".js": {
    inputSources: [
      /\b(req|request)\.(query|body|params|headers|files)\b/i,
      /\b(process\.env|window\.location|document\.location)\b/i,
    ],
    dangerousSinks: [
      /\b(child_process\.(exec|spawn|execSync))\b/i,
      /\b(require\s*\(|import\s*\()\b/i,
      /\b(fetch|axios\.(get|post|request))\b/i,
      /\b(fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream))\b/i,
    ],
    safetySignals: [
      /\b(path\.normalize|path\.resolve)\b/i,
      /\b(DOMPurify|validator\.)\b/i,
    ],
    validationSignals: [
      /\b(zod|joi|yup|express-validator)\b/i,
    ],
  },
  ".ts": {
    inputSources: [
      /\b(req|request)\.(query|body|params|headers|files)\b/i,
      /\b(process\.env)\b/i,
    ],
    dangerousSinks: [
      /\b(child_process\.(exec|spawn|execSync))\b/i,
      /\b(fetch|axios\.(get|post|request))\b/i,
      /\b(fs\.(readFile|readFileSync|writeFile|writeFileSync))\b/i,
    ],
    safetySignals: [
      /\b(path\.normalize|path\.resolve)\b/i,
    ],
    validationSignals: [
      /\b(zod|joi|class-validator|nestjs\/common)\b/i,
    ],
  },
  ".java": {
    inputSources: [
      /\b(request\.getParameter|@RequestParam|@PathVariable|@RequestBody)\b/i,
      /\b(System\.getenv|MultipartFile)\b/i,
    ],
    dangerousSinks: [
      /\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b/i,
      /\b(HttpURLConnection|RestTemplate|WebClient)\b/i,
      /\b(FileInputStream|FileOutputStream|Files\.(read|write))\b/i,
      /\b(Statement|createStatement|executeQuery|executeUpdate)\b/i,
    ],
    safetySignals: [
      /\b(PreparedStatement|@PreAuthorize|hasRole)\b/i,
      /\b(Paths\.get|normalize\(\)|toRealPath\(\))\b/i,
    ],
    validationSignals: [
      /\b(@Valid|Validator|BindingResult)\b/i,
    ],
  },
  ".go": {
    inputSources: [
      /\b(r\.URL\.Query|FormValue|PostFormValue|ShouldBindJSON|BindJSON)\b/i,
      /\b(os\.Getenv|c\.Param|c\.Query|c\.PostForm)\b/i,
    ],
    dangerousSinks: [
      /\b(exec\.Command|sql\.DB|QueryRow|Query|Exec)\b/i,
      /\b(http\.Get|http\.Post|client\.Do)\b/i,
      /\b(os\.Open|os\.Create|ioutil\.ReadFile|os\.WriteFile)\b/i,
      /\b(template\.HTML|text\/template)\b/i,
    ],
    safetySignals: [
      /\b(html\/template|filepath\.Clean|filepath\.Join)\b/i,
      /\b(PrepareContext|QueryContext|ExecContext)\b/i,
    ],
    validationSignals: [
      /\b(validator\.New|ShouldBind|binding:)\b/i,
    ],
  },
  ".php": {
    inputSources: [
      /\b(_GET|_POST|_REQUEST|_FILES|_COOKIE|_SERVER|_ENV)\b/i,
    ],
    dangerousSinks: [
      /\b(include|include_once|require|require_once)\b/i,
      /\b(system|exec|shell_exec|passthru|proc_open)\b/i,
      /\b(mysqli_query|query|exec|PDO)\b/i,
      /\b(file_get_contents|fopen|fwrite|readfile)\b/i,
      /\b(unserialize)\b/i,
    ],
    safetySignals: [
      /\b(PDO::prepare|prepare\s*\(|realpath|basename)\b/i,
    ],
    validationSignals: [
      /\b(filter_input|htmlspecialchars|preg_match)\b/i,
    ],
  },
  ".c": {
    inputSources: [
      /\b(argv|getenv|recv|read|fgets|scanf)\b/i,
    ],
    dangerousSinks: [
      /\b(system|popen|execl|execv|sprintf|strcpy|strcat|gets)\b/i,
      /\b(fopen|open|write|read)\b/i,
    ],
    safetySignals: [
      /\b(snprintf|strncpy|realpath)\b/i,
    ],
    validationSignals: [
      /\b(strlen|sizeof|strncmp|memcmp)\b/i,
    ],
  },
  ".cpp": {
    inputSources: [
      /\b(argv|getenv|recv|read|std::cin)\b/i,
    ],
    dangerousSinks: [
      /\b(system|popen|sprintf|strcpy|strcat)\b/i,
      /\b(std::ifstream|std::ofstream|fstream)\b/i,
    ],
    safetySignals: [
      /\b(snprintf|std::filesystem::canonical|std::array)\b/i,
    ],
    validationSignals: [
      /\b(std::regex|std::clamp|size\(\))\b/i,
    ],
  },
  ".cs": {
    inputSources: [
      /\b(Request\.(Query|Form|Body|Headers)|IFormFile)\b/i,
      /\b(Environment\.GetEnvironmentVariable)\b/i,
    ],
    dangerousSinks: [
      /\b(Process\.Start|SqlCommand|ExecuteReader|ExecuteNonQuery)\b/i,
      /\b(File\.(ReadAllText|WriteAllText|OpenRead|OpenWrite))\b/i,
      /\b(HttpClient\.(GetAsync|PostAsync|SendAsync))\b/i,
    ],
    safetySignals: [
      /\b(Path\.GetFullPath|Path\.Combine|SqlParameter)\b/i,
      /\b(Authorize|RequireRole)\b/i,
    ],
    validationSignals: [
      /\b(ModelState\.IsValid|DataAnnotations|FluentValidation)\b/i,
    ],
  },
};

function extKey(ext) {
  if (!ext) return null;
  const normalized = ext.toLowerCase();
  if (normalized === ".jsx") return ".js";
  if (normalized === ".tsx") return ".ts";
  return normalized;
}

function getLanguagePatterns(extension) {
  const key = extKey(extension);
  if (!key) return null;
  const langPatterns = LANGUAGE_SECURITY_HINT_PATTERNS[key];
  if (!langPatterns) return null;
  return {
    inputSources: [...(langPatterns.inputSources || []), ...COMMON_SECURITY_HINT_PATTERNS.inputSources],
    dangerousSinks: [...(langPatterns.dangerousSinks || []), ...COMMON_SECURITY_HINT_PATTERNS.dangerousSinks],
    safetySignals: [...(langPatterns.safetySignals || []), ...COMMON_SECURITY_HINT_PATTERNS.safetySignals],
    validationSignals: [...(langPatterns.validationSignals || []), ...COMMON_SECURITY_HINT_PATTERNS.validationSignals],
  };
}

export function getSecurityHintProfile(code, extension) {
  const patterns = getLanguagePatterns(extension);
  const profile = {
    inputSources: [],
    dangerousSinks: [],
    safetySignals: [],
    validationSignals: [],
    inputCount: 0,
    sinkCount: 0,
    safetyCount: 0,
    validationCount: 0,
    hasInput: false,
    hasSink: false,
    hasSafety: false,
    hasValidation: false,
  };

  if (!patterns) return profile;

  for (const pattern of patterns.inputSources) {
    const matches = code.match(pattern);
    if (matches) {
      profile.inputSources.push(matches[0]);
    }
  }
  for (const pattern of patterns.dangerousSinks) {
    const matches = code.match(pattern);
    if (matches) {
      profile.dangerousSinks.push(matches[0]);
    }
  }
  for (const pattern of patterns.safetySignals) {
    const matches = code.match(pattern);
    if (matches) {
      profile.safetySignals.push(matches[0]);
    }
  }
  for (const pattern of patterns.validationSignals) {
    const matches = code.match(pattern);
    if (matches) {
      profile.validationSignals.push(matches[0]);
    }
  }

  profile.inputCount = profile.inputSources.length;
  profile.sinkCount = profile.dangerousSinks.length;
  profile.safetyCount = profile.safetySignals.length;
  profile.validationCount = profile.validationSignals.length;
  profile.hasInput = profile.inputCount > 0;
  profile.hasSink = profile.sinkCount > 0;
  profile.hasSafety = profile.safetyCount > 0;
  profile.hasValidation = profile.validationCount > 0;

  return profile;
}

export function securityHintScore(profile) {
  if (!profile) return 0;
  let score = 0;
  score += profile.inputCount * 8;
  score += profile.sinkCount * 10;
  score += profile.validationCount * 3;
  score += profile.safetyCount * 2;
  return score;
}

