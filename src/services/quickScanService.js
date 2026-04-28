import { promises as fs } from "node:fs";
import path from "node:path";

const LANGUAGE_EXTENSIONS = {
  "java": [".java"],
  "python": [".py", ".pyw"],
  "cpp": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
  "csharp": [".cs"],
  "go": [".go"],
  "javascript": [".js", ".jsx", ".mjs", ".cjs"],
  "typescript": [".ts", ".tsx"],
  "php": [".php", ".phtml", ".php3", ".php4", ".php5"],
  "ruby": [".rb", ".rbw"],
  "rust": [".rs"],
  "kotlin": [".kt", ".kts"],
  "swift": [".swift"],
  "scala": [".scala", ".sc"],
  "perl": [".pl", ".pm", ".t"],
  "lua": [".lua"],
  "shell": [".sh", ".bash", ".zsh"]
};

const QUICK_SCAN_PATTERNS = {
  java: [
    { pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /ProcessBuilder\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /ProcessImpl\.start/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /String\s+sql\s*=\s*"/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /Statement\.execute/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /ORDER BY.*\+/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /HibernateTemplate\.execute\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "高危" },
    { pattern: /entityManager\.createQuery\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "高危" },
    { pattern: /createNativeQuery\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "高危" },
    { pattern: /JdbcTemplate\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "高危" },
    { pattern: /XPath.*\+/, vulnType: "XPATH_INJECTION", cwe: "CWE-643", severity: "高危" },
    { pattern: /XPathFactory\.newInstance\s*\(/, vulnType: "XPATH_INJECTION", cwe: "CWE-643", severity: "高危" },
    { pattern: /xpath\.evaluate\s*\(/, vulnType: "XPATH_INJECTION", cwe: "CWE-643", severity: "高危" },
    { pattern: /password\s*=\s*"[^"]{3,}"/, vulnType: "HARD_CODE_PASSWORD", cwe: "CWE-259", severity: "严重" },
    { pattern: /new\s+File\s*\(\s*/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /FileInputStream\s*\(\s*/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /Files\.lines\s*\(\s*filePath\s*\)/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /Files\.readAllBytes\s*\(/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /StreamUtils\.copy\s*\(/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /ScriptEngine.*eval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /GroovyShell\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /shell\.evaluate\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /System\.load\s*\(/, vulnType: "PROCESS_CONTROL", cwe: "CWE-114", severity: "高危" },
    { pattern: /MessageDigest.*getInstance.*MD5/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /MessageDigest.*getInstance.*SHA1/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /Cipher.*getInstance.*DES/, vulnType: "WEAK_CRYPTO", cwe: "CWE-327", severity: "高危" },
    { pattern: /new\s+Random\s*\(\s*\)/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" },
    { pattern: /SecureRandom\s*\(\s*\)/, vulnType: "WEAK_RANDOM", cwe: "CWE-338", severity: "中危" },
    { pattern: /println.*password/, vulnType: "INFO_LEAK", cwe: "CWE-532", severity: "中危" },
    { pattern: /session\.put\s*\(/, vulnType: "SESSION_FIXATION", cwe: "CWE-384", severity: "高危" },
    { pattern: /Cookie.*=.*=/, vulnType: "COOKIE_MANIPULATION", cwe: "CWE-565", severity: "高危" },
    { pattern: /referer.*contains/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /referer\.startsWith\s*\(/, vulnType: "REFERER_AUTH_BYPASS", cwe: "CWE-293", severity: "高危" },
    { pattern: /request\.getHeader\s*\(\s*"referer"/, vulnType: "REFERER_AUTH_BYPASS", cwe: "CWE-293", severity: "高危" },
    { pattern: /code_verify/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /stepData\.put\s*\(/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /orderStatusMap\.get\s*\(/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /paymentStatusMap\.get\s*\(/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /status\.isPaid\s*=/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "高危" },
    { pattern: /SecurityContextHolder\.getContext\s*\(/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "中危" },
    { pattern: /REAL_USERNAMES\.contains\s*\(/, vulnType: "AUTH_INFO_EXPOSURE", cwe: "CWE-204", severity: "中危" },
    { pattern: /userMapper\.getAllByUsername\s*\(/, vulnType: "IDOR", cwe: "CWE-639", severity: "高危" },
    { pattern: /byte\[.*\]\s*=\s*new\s+byte\[.*size/, vulnType: "UNCONTROLLED_MEMORY", cwe: "CWE-770", severity: "高危" },
    { pattern: /catch\s*\(\s*Exception\s*\)\s*\{\s*\}/, vulnType: "IMPROPER_EXCEPTION_HANDLING", cwe: "CWE-703", severity: "高危" },
    { pattern: /password\.length\s*\(\s*\)\s*>=\s*4/, vulnType: "WEAK_PASSWORD_POLICY", cwe: "CWE-521", severity: "中危" },
    { pattern: /http:\/\/api\./, vulnType: "PLAINTEXT_TRANSMISSION", cwe: "CWE-319", severity: "严重" },
    { pattern: /return\s+"redirect:"/, vulnType: "OPEN_REDIRECT", cwe: "CWE-601", severity: "高危" },
    { pattern: /response\.sendRedirect\s*\(/, vulnType: "OPEN_REDIRECT", cwe: "CWE-601", severity: "高危" },
    { pattern: /ModelAndView\s*\(\s*"redirect:"/, vulnType: "OPEN_REDIRECT", cwe: "CWE-601", severity: "高危" },
    { pattern: /headers\.setLocation\s*\(/, vulnType: "OPEN_REDIRECT", cwe: "CWE-601", severity: "高危" },
    { pattern: /response\.setHeader\s*\(\s*"Location"/, vulnType: "OPEN_REDIRECT", cwe: "CWE-601", severity: "高危" },
    { pattern: /XMLDecoder\s*\(/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /ObjectInputStream\s*\(/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /enableDefaultTyping\s*\(/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /XStream\s*\(\s*\)/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /JSON\.parseObject\s*\(/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "高危" },
    { pattern: /XMLReaderFactory\.createXMLReader\s*\(/, vulnType: "XXE", cwe: "CWE-611", severity: "高危" },
    { pattern: /SAXParserFactory\.newInstance\s*\(/, vulnType: "XXE", cwe: "CWE-611", severity: "高危" },
    { pattern: /DocumentBuilderFactory\.newInstance\s*\(/, vulnType: "XXE", cwe: "CWE-611", severity: "高危" },
    { pattern: /logger\.error\s*\(/, vulnType: "LOG_INJECTION", cwe: "CWE-93", severity: "高危" },
    { pattern: /NoOpPasswordEncoder\.getInstance\s*\(/, vulnType: "PLAINTEXT_PASSWORD", cwe: "CWE-256", severity: "严重" },
    { pattern: /Access-Control-Allow-Origin.*\*/, vulnType: "CORS_MISCONFIGURATION", cwe: "CWE-942", severity: "高危" },
    { pattern: /Access-Control-Allow-Credentials.*true/, vulnType: "CORS_MISCONFIGURATION", cwe: "CWE-942", severity: "高危" },
    { pattern: /response\.setHeader\s*\(\s*"Access-Control-Allow-Origin"/, vulnType: "CORS_MISCONFIGURATION", cwe: "CWE-942", severity: "高危" },
    { pattern: /request\.getHeader\s*\(\s*"origin"/, vulnType: "CORS_MISCONFIGURATION", cwe: "CWE-942", severity: "高危" },
    { pattern: /session\.getAttribute\s*\(\s*"csrfToken"/, vulnType: "CSRF", cwe: "CWE-352", severity: "高危" },
    { pattern: /StandardEvaluationContext\s*\(/, vulnType: "SPEL_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /URL\s+u\s*=\s*new\s+URL\s*\(/, vulnType: "SSRF", cwe: "CWE-918", severity: "严重" },
    { pattern: /URLConnection\s+conn\s*=\s*u\.openConnection/, vulnType: "SSRF", cwe: "CWE-918", severity: "严重" },
    { pattern: /response\.getWriter\(\)\.print\s*\(/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /response\.getWriter\(\)\.write\s*\(/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /response\.setContentType\s*\(\s*"text\/html"/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /Thread\.sleep\s*\(/, vulnType: "RACE_CONDITION", cwe: "CWE-362", severity: "高危" },
    { pattern: /AtomicReference\.get\s*\(/, vulnType: "RACE_CONDITION", cwe: "CWE-362", severity: "中危" },
    { pattern: /userMoney\.get\s*\(/, vulnType: "RACE_CONDITION", cwe: "CWE-362", severity: "中危" },
    { pattern: /Integer\.parseInt\s*\(.*\*/, vulnType: "INTEGER_OVERFLOW", cwe: "CWE-190", severity: "高危" },
    { pattern: /Double\.parseDouble\s*\(.*\*/, vulnType: "INTEGER_OVERFLOW", cwe: "CWE-190", severity: "高危" },
    { pattern: /return\s+"vul\/ssti\/"/, vulnType: "SSTI", cwe: "CWE-94", severity: "高危" },
    { pattern: /model\.addAttribute\s*\(\s*"templateContent"/, vulnType: "SSTI", cwe: "CWE-94", severity: "高危" }
  ],
  python: [
    { pattern: /os\.system\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /subprocess\.\w+\s*\(.*shell\s*=\s*True/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /subprocess\.Popen\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /\bexec\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /\beval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /pickle\.load/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /yaml\.load\s*\(/, vulnType: "DESERIALIZATION", cwe: "CWE-502", severity: "严重" },
    { pattern: /urllib\.request\.urlopen\s*\(/, vulnType: "SSRF", cwe: "CWE-918", severity: "严重" },
    { pattern: /password\s*=\s*"/, vulnType: "HARD_CODE_PASSWORD", cwe: "CWE-259", severity: "严重" },
    { pattern: /hashlib\.md5/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /hashlib\.sha1/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /random\.rand/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" },
    { pattern: /logging\.info.*password/, vulnType: "INFO_LEAK", cwe: "CWE-532", severity: "中危" },
    { pattern: /is_admin\s*=\s*user_input/, vulnType: "AUTH_BYPASS", cwe: "CWE-287", severity: "严重" },
    { pattern: /while True:/, vulnType: "INFINITE_LOOP", cwe: "CWE-835", severity: "高危" },
    { pattern: /except:\s*pass/, vulnType: "IMPROPER_EXCEPTION_HANDLING", cwe: "CWE-703", severity: "高危" },
    { pattern: /execute\(.*f"/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /open\(.*filename/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" }
  ],
  cpp: [
    { pattern: /system\s*\(\s*[^)]*\+/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /popen\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /strcpy\s*\(/, vulnType: "BUFFER_OVERFLOW", cwe: "CWE-120", severity: "严重" },
    { pattern: /gets\s*\(/, vulnType: "BUFFER_OVERFLOW", cwe: "CWE-120", severity: "严重" },
    { pattern: /scanf\s*\(/, vulnType: "BUFFER_OVERFLOW", cwe: "CWE-120", severity: "严重" },
    { pattern: /printf\s*\(\s*\w+\s*\)/, vulnType: "FORMAT_STRING", cwe: "CWE-134", severity: "高危" },
    { pattern: /malloc\s*\(\s*\w+\s*\*\s*\d+/, vulnType: "INTEGER_OVERFLOW", cwe: "CWE-190", severity: "高危" },
    { pattern: /password\s*=\s*"[^"]{3,}"/, vulnType: "HARD_CODE_PASSWORD", cwe: "CWE-259", severity: "严重" },
    { pattern: /DES_set_key/, vulnType: "WEAK_CRYPTO", cwe: "CWE-327", severity: "高危" },
    { pattern: /SHA1\s*\(/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /rand\s*\(\s*\)/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" },
    { pattern: /LoadLibrary\s*\(/, vulnType: "PROCESS_CONTROL", cwe: "CWE-114", severity: "高危" },
    { pattern: /dlopen\s*\(/, vulnType: "PROCESS_CONTROL", cwe: "CWE-114", severity: "高危" }
  ],
  csharp: [
    { pattern: /Process\.Start\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /SqlCommand.*\+/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /ORDER BY.*\+/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /XPath.*\+/, vulnType: "XPATH_INJECTION", cwe: "CWE-643", severity: "高危" },
    { pattern: /password\s*=\s*"[^"]{3,}"/, vulnType: "HARD_CODE_PASSWORD", cwe: "CWE-259", severity: "严重" },
    { pattern: /DES\.Create\s*\(\)/, vulnType: "WEAK_CRYPTO", cwe: "CWE-327", severity: "高危" },
    { pattern: /SHA1\.Create\s*\(\)/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /Random\s*=\s*new\s+Random\s*\(\s*\)/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" },
    { pattern: /Assembly\.LoadFrom\s*\(/, vulnType: "PROCESS_CONTROL", cwe: "CWE-114", severity: "高危" },
    { pattern: /Trace\.WriteLine.*password/, vulnType: "INFO_LEAK", cwe: "CWE-532", severity: "中危" },
    { pattern: /session\[.*\]\s*=\s*username/, vulnType: "SESSION_FIXATION", cwe: "CWE-384", severity: "高危" },
    { pattern: /Cookie.*=.*=/, vulnType: "COOKIE_MANIPULATION", cwe: "CWE-565", severity: "高危" },
    { pattern: /resp\.Write\s*\(/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" }
  ],
  javascript: [
    { pattern: /eval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /Function\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /innerHTML\s*=/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /document\.write\s*\(/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /require\s*\(\s*child_process\s*\)/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" },
    { pattern: /exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" },
    { pattern: /spawn\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" }
  ],
  typescript: [
    { pattern: /eval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /innerHTML\s*=/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /document\.write\s*\(/, vulnType: "XSS", cwe: "CWE-79", severity: "高危" },
    { pattern: /require\s*\(\s*child_process\s*\)/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" },
    { pattern: /exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" },
    { pattern: /spawn\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "高危" }
  ],
  go: [
    { pattern: /exec\.Command\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /os\.Exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /crypto\/md5/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /crypto\/sha1/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /math\/rand/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" }
  ],
  php: [
    { pattern: /exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /system\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /passthru\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /eval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /mysql_query\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /mysqli_query\s*\(/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /\$sql\s*=/, vulnType: "SQL_INJECTION", cwe: "CWE-89", severity: "严重" },
    { pattern: /include\s*\(/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /require\s*\(/, vulnType: "PATH_TRAVERSAL", cwe: "CWE-22", severity: "高危" },
    { pattern: /md5\s*\(/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /sha1\s*\(/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /rand\s*\(/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" },
    { pattern: /echo\s*\$.*password/, vulnType: "INFO_LEAK", cwe: "CWE-532", severity: "中危" }
  ],
  ruby: [
    { pattern: /system\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /exec\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /eval\s*\(/, vulnType: "CODE_INJECTION", cwe: "CWE-94", severity: "严重" },
    { pattern: /open\s*\(/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /Digest::MD5/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /Digest::SHA1/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /rand\s*\(/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" }
  ],
  rust: [
    { pattern: /std::process::Command::new/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /Command::new/, vulnType: "COMMAND_INJECTION", cwe: "CWE-78", severity: "严重" },
    { pattern: /md5\s*\(/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /sha1\s*\(/, vulnType: "WEAK_HASH", cwe: "CWE-328", severity: "高危" },
    { pattern: /rand\s*\(/, vulnType: "PREDICTABLE_RANDOM", cwe: "CWE-338", severity: "高危" }
  ]
};

const GBT_MAPPING = {
  "COMMAND_INJECTION": {
    "java": "GB/T34944-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
    "python": "GB/T39412-6.1.1.6 命令行注入",
    "cpp": "GB/T34943-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
    "csharp": "GB/T34946-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入",
    "default": "GB/T39412-6.1.1.6 命令行注入"
  },
  "SQL_INJECTION": {
    "java": "GB/T34944-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
    "python": "GB/T39412-8.3.2 SQL注入",
    "cpp": "GB/T34943-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
    "csharp": "GB/T34946-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入",
    "default": "GB/T39412-8.3.2 SQL注入"
  },
  "CODE_INJECTION": {
    "java": "GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
    "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
    "cpp": "GB/T34943-6.2.3.5 进程控制；GB/T39412-7.3.6 暴露危险的方法或函数",
    "csharp": "GB/T34946-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
    "default": "GB/T39412-7.3.6 暴露危险的方法或函数"
  },
  "SPEL_INJECTION": {
    "java": "GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
    "default": "GB/T39412-7.3.6 暴露危险的方法或函数"
  },
  "SSTI": {
    "java": "GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数",
    "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
    "default": "GB/T39412-7.3.6 暴露危险的方法或函数"
  },
  "PATH_TRAVERSAL": {
    "java": "GB/T34944-6.2.3.1 相对路径遍历；GB/T34944-6.2.3.2 绝对路径遍历",
    "python": "GB/T39412-6.1.1.1 输入验证不足",
    "cpp": "GB/T34943-6.2.3.1 相对路径遍历；GB/T34943-6.2.3.2 绝对路径遍历",
    "csharp": "GB/T34946-6.2.3.1 相对路径遍历；GB/T34946-6.2.3.2 绝对路径遍历",
    "default": "GB/T39412-6.1.1.1 输入验证不足"
  },
  "HARD_CODE_PASSWORD": {
    "java": "GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "python": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "cpp": "GB/T34943-6.2.7.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "csharp": "GB/T34946-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "default": "GB/T39412-6.2.1.3 使用安全相关的硬编码"
  },
  "PLAINTEXT_PASSWORD": {
    "java": "GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "default": "GB/T39412-6.2.1.3 使用安全相关的硬编码"
  },
  "WEAK_CRYPTO": {
    "java": "GB/T34944-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "cpp": "GB/T34943-6.2.7.5 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "csharp": "GB/T34946-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "default": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定"
  },
  "WEAK_HASH": {
    "java": "GB/T34944-6.2.6.8 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "python": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "cpp": "GB/T34943-6.2.7.6 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "csharp": "GB/T34946-6.2.6.8 可逆的散列算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定",
    "default": "GB/T39412-6.2.1.1 密码安全不符合国密管理规定"
  },
  "PREDICTABLE_RANDOM": {
    "java": "GB/T34944-6.2.6.10 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
    "python": "GB/T39412-6.2.1.2 随机数安全",
    "cpp": "GB/T34943-6.2.7.8 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
    "csharp": "GB/T34946-6.2.6.10 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
    "default": "GB/T39412-6.2.1.2 随机数安全"
  },
  "WEAK_RANDOM": {
    "java": "GB/T34944-6.2.6.10 不充分的随机数；GB/T39412-6.2.1.2 随机数安全",
    "default": "GB/T39412-6.2.1.2 随机数安全"
  },
  "DESERIALIZATION": {
    "java": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
    "python": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
    "cpp": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
    "csharp": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘",
    "default": "GB/T39412-7.1.5 存储不可序列化的对象到磁盘"
  },
  "SSRF": {
    "java": "GB/T39412-6.1.1.1 输入验证不足",
    "python": "GB/T39412-6.1.1.1 输入验证不足",
    "cpp": "GB/T39412-6.1.1.1 输入验证不足",
    "csharp": "GB/T39412-6.1.1.1 输入验证不足",
    "default": "GB/T39412-6.1.1.1 输入验证不足"
  },
  "XXE": {
    "java": "GB/T39412-6.1.1.1 输入验证不足",
    "python": "GB/T39412-6.1.1.1 输入验证不足",
    "default": "GB/T39412-6.1.1.1 输入验证不足"
  },
  "AUTH_BYPASS": {
    "java": "GB/T34944-6.2.6.4 依赖referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过",
    "python": "GB/T39412-6.3.1.2 身份鉴别被绕过",
    "cpp": "GB/T39412-6.3.1.2 身份鉴别被绕过",
    "csharp": "GB/T34946-6.2.6.4 依赖Referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过",
    "default": "GB/T39412-6.3.1.2 身份鉴别被绕过"
  },
  "REFERER_AUTH_BYPASS": {
    "java": "GB/T34944-6.2.6.4 依赖referer字段进行身份鉴别",
    "csharp": "GB/T34946-6.2.6.4 依赖Referer字段进行身份鉴别",
    "default": "GB/T39412-6.3.1.2 身份鉴别被绕过"
  },
  "AUTH_INFO_EXPOSURE": {
    "java": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息",
    "default": "GB/T39412-6.3.1.1 身份鉴别过程暴露多余信息"
  },
  "IDOR": {
    "java": "GB/T39412-6.3.3.1 不安全的直接对象引用",
    "default": "GB/T39412-6.3.3.1 不安全的直接对象引用"
  },
  "INFO_LEAK": {
    "java": "GB/T34944-6.2.3.7 信息通过错误消息泄露；GB/T34944-6.2.3.8 信息通过服务器日志文件泄露",
    "python": "GB/T39412-6.2.2.1 敏感信息暴露",
    "cpp": "GB/T34943-6.2.3.9 信息通过错误消息泄露；GB/T34943-6.2.3.10 信息通过服务器日志文件泄露",
    "csharp": "GB/T34946-6.2.3.7 信息通过错误消息泄露；GB/T34946-6.2.3.8 信息通过服务器日志文件泄露",
    "default": "GB/T39412-6.2.2.1 敏感信息暴露"
  },
  "LOG_INJECTION": {
    "java": "GB/T39412-6.4.1 对输出日志中特殊元素处理",
    "default": "GB/T39412-6.4.1 对输出日志中特殊元素处理"
  },
  "SESSION_FIXATION": {
    "java": "GB/T34944-6.2.7.1 会话固定",
    "python": "GB/T39412-7.2.1 不同会话间信息泄露",
    "cpp": "GB/T39412-7.2.1 不同会话间信息泄露",
    "csharp": "GB/T34946-6.2.7.1 会话固定",
    "default": "GB/T39412-7.2.1 不同会话间信息泄露"
  },
  "COOKIE_MANIPULATION": {
    "java": "GB/T34944-6.2.6.5 Cookie中的敏感信息明文存储",
    "python": "GB/T39412-6.2.2.1 敏感信息暴露",
    "cpp": "GB/T39412-6.2.2.1 敏感信息暴露",
    "csharp": "GB/T34946-6.2.6.5 Cookie中的敏感信息明文存储",
    "default": "GB/T39412-6.2.2.1 敏感信息暴露"
  },
  "XSS": {
    "java": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
    "python": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
    "cpp": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
    "csharp": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
    "javascript": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击",
    "default": "GB/T39412-6.1.2.1 跨站脚本(XSS)攻击"
  },
  "XPATH_INJECTION": {
    "java": "GB/T34944-6.2.3.12 XPath注入",
    "csharp": "GB/T34946-6.2.3.12 XPath注入",
    "default": "GB/T39412-6.1.1.1 输入验证不足"
  },
  "BUFFER_OVERFLOW": {
    "java": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
    "python": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
    "cpp": "GB/T34943-6.2.3.6 缓冲区溢出",
    "csharp": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
    "default": "GB/T39412-8.2.6 内存缓冲区边界操作越界"
  },
  "FORMAT_STRING": {
    "java": "GB/T39412-7.3.1 格式化字符串",
    "python": "GB/T39412-7.3.1 格式化字符串",
    "cpp": "GB/T34943-6.2.3.7 格式化字符串漏洞",
    "csharp": "GB/T39412-7.3.1 格式化字符串",
    "default": "GB/T39412-7.3.1 格式化字符串"
  },
  "PROCESS_CONTROL": {
    "java": "GB/T34944-6.2.3.6 进程控制",
    "python": "GB/T39412-7.3.6 暴露危险的方法或函数",
    "cpp": "GB/T34943-6.2.3.5 进程控制",
    "csharp": "GB/T34946-6.2.3.6 进程控制",
    "default": "GB/T39412-7.3.6 暴露危险的方法或函数"
  },
  "IMPROPER_EXCEPTION_HANDLING": {
    "java": "GB/T39412-7.4.1 异常处理不当",
    "python": "GB/T39412-7.4.1 异常处理不当",
    "cpp": "GB/T39412-7.4.1 异常处理不当",
    "csharp": "GB/T39412-7.4.1 异常处理不当",
    "default": "GB/T39412-7.4.1 异常处理不当"
  },
  "INFINITE_LOOP": {
    "java": "GB/T39412-8.1.8 无限循环",
    "python": "GB/T39412-8.1.8 无限循环",
    "cpp": "GB/T39412-8.1.8 无限循环",
    "csharp": "GB/T39412-8.1.8 无限循环",
    "default": "GB/T39412-8.1.8 无限循环"
  },
  "OPEN_REDIRECT": {
    "java": "GB/T39412-6.1.2.3 URL重定向向不可信站点",
    "python": "GB/T39412-6.1.2.3 URL重定向向不可信站点",
    "default": "GB/T39412-6.1.2.3 URL重定向向不可信站点"
  },
  "CORS_MISCONFIGURATION": {
    "java": "GB/T39412-6.3.2.2 跨域资源共享配置不当",
    "default": "GB/T39412-6.3.2.2 跨域资源共享配置不当"
  },
  "CSRF": {
    "java": "GB/T39412-6.3.3.2 跨站请求伪造",
    "python": "GB/T39412-6.3.3.2 跨站请求伪造",
    "default": "GB/T39412-6.3.3.2 跨站请求伪造"
  },
  "RACE_CONDITION": {
    "java": "GB/T39412-7.2.3 共享资源的并发安全",
    "python": "GB/T39412-7.2.3 共享资源的并发安全",
    "default": "GB/T39412-7.2.3 共享资源的并发安全"
  },
  "INTEGER_OVERFLOW": {
    "java": "GB/T39412-6.1.1.12 数值赋值越界",
    "cpp": "GB/T34943-6.2.3.11 整数溢出",
    "default": "GB/T39412-6.1.1.12 数值赋值越界"
  },
  "UNCONTROLLED_MEMORY": {
    "java": "GB/T39412-8.2.6 内存缓冲区边界操作越界",
    "default": "GB/T39412-8.2.6 内存缓冲区边界操作越界"
  },
  "WEAK_PASSWORD_POLICY": {
    "java": "GB/T39412-6.2.1.3 使用安全相关的硬编码",
    "default": "GB/T39412-6.2.1.3 使用安全相关的硬编码"
  },
  "PLAINTEXT_TRANSMISSION": {
    "java": "GB/T39412-6.2.2.1 敏感信息暴露",
    "default": "GB/T39412-6.2.2.1 敏感信息暴露"
  }
};

export class QuickScanService {
  constructor() {
    this.patterns = QUICK_SCAN_PATTERNS;
    this.gbtMapping = GBT_MAPPING;
    this.vulnCounter = {};
  }

  getVulnId(vulnType, severity) {
    const severityPrefixMap = {
      "严重": "C",
      "高危": "H",
      "中危": "M",
      "低危": "L"
    };
    
    const typeCodeMap = {
      "COMMAND_INJECTION": "CMD",
      "SQL_INJECTION": "SQL",
      "CODE_INJECTION": "CODE",
      "SPEL_INJECTION": "SPEL",
      "SSTI": "SSTI",
      "PATH_TRAVERSAL": "PATH",
      "HARD_CODE_PASSWORD": "PASS",
      "PLAINTEXT_PASSWORD": "PASS",
      "HARD_CODE_SECRET": "SEC",
      "WEAK_CRYPTO": "CRYPTO",
      "WEAK_HASH": "HASH",
      "NO_SALT_HASH": "HASH",
      "PREDICTABLE_RANDOM": "RAND",
      "WEAK_RANDOM": "RAND",
      "FIXED_IV": "IV",
      "RSA_PADDING": "RSA",
      "DESERIALIZATION": "DES",
      "SSRF": "SSRF",
      "XXE": "XXE",
      "AUTH_BYPASS": "AUTH",
      "REFERER_AUTH_BYPASS": "AUTH",
      "AUTH_INFO_EXPOSURE": "AUTH",
      "MISSING_ACCESS_CONTROL": "AUTH",
      "IDOR": "IDOR",
      "INFO_LEAK": "INFO",
      "LOG_INJECTION": "LOG",
      "SESSION_FIXATION": "SESS",
      "COOKIE_MANIPULATION": "COOKIE",
      "XSS": "XSS",
      "XPATH_INJECTION": "XPATH",
      "BUFFER_OVERFLOW": "BUF",
      "FORMAT_STRING": "FMT",
      "INTEGER_OVERFLOW": "INT",
      "PROCESS_CONTROL": "PROC",
      "FILE_UPLOAD": "UPLOAD",
      "FILE_READ": "READ",
      "OPEN_REDIRECT": "REDIR",
      "CREDENTIAL_EXPOSURE": "CRED",
      "CSRF": "CSRF",
      "RACE_CONDITION": "RACE",
      "UNCONTROLLED_MEMORY": "MEM",
      "IMPROPER_EXCEPTION_HANDLING": "EXC",
      "INFINITE_LOOP": "LOOP",
      "RESOURCE_EXHAUSTION": "RES",
      "WEAK_PASSWORD_POLICY": "POL",
      "PLAINTEXT_TRANSMISSION": "TRANS",
      "TRUST_BOUNDARY_VIOLATION": "TRUST",
      "SESSION_TIMEOUT": "TIMEOUT",
      "DNS_TRUST": "DNS",
      "COOKIE_AUTH_BYPASS": "COOKIE",
      "STACK_TRACE_LEAK": "STACK",
      "ERROR_MSG_LEAK": "ERR",
      "PARAMETER_TAMPERING": "PARAM",
      "PERSISTENT_COOKIE": "COOKIE",
      "COOKIE_SECURE_MISSING": "COOKIE",
      "UNRESTRICTED_UPLOAD": "UPLOAD",
      "SENSITIVE_SERIALIZATION": "SER",
      "SENSITIVE_FIELD": "FIELD",
      "SESSION_INFO_LEAK": "SESS",
      "PASSWORD_DISPLAY": "PWD",
      "PERSONAL_INFO_EXPOSURE": "PII",
      "SENSITIVE_OPERATION": "OP",
      "UNINITIALIZED_OBJECT": "OBJ",
      "THREAD_LOCAL_LEAK": "THREAD",
      "DOUBLE_FREE": "FREE",
      "USE_AFTER_FREE": "UAF",
      "TEMP_FILE_EXPOSURE": "TEMP",
      "MEMORY_LEAK": "MEM",
      "CORS_MISCONFIGURATION": "CORS"
    };
    
    const prefix = severityPrefixMap[severity] || "L";
    const typeCode = typeCodeMap[vulnType] || "VULN";
    
    if (!this.vulnCounter[prefix]) {
      this.vulnCounter[prefix] = {};
    }
    if (!this.vulnCounter[prefix][typeCode]) {
      this.vulnCounter[prefix][typeCode] = 0;
    }
    this.vulnCounter[prefix][typeCode]++;
    
    return `${prefix}-${typeCode}-${String(this.vulnCounter[prefix][typeCode]).padStart(3, "0")}`;
  }

  calculateCVSSDetailed(vulnType, severity) {
    const cvssConfig = {
      "COMMAND_INJECTION": { reachability: 3, impact: 3, complexity: 3 },
      "SQL_INJECTION": { reachability: 3, impact: 3, complexity: 3 },
      "CODE_INJECTION": { reachability: 3, impact: 3, complexity: 3 },
      "SPEL_INJECTION": { reachability: 3, impact: 3, complexity: 3 },
      "SSTI": { reachability: 3, impact: 3, complexity: 3 },
      "DESERIALIZATION": { reachability: 3, impact: 3, complexity: 2 },
      "SSRF": { reachability: 3, impact: 2, complexity: 2 },
      "XXE": { reachability: 3, impact: 3, complexity: 2 },
      "PATH_TRAVERSAL": { reachability: 3, impact: 2, complexity: 2 },
      "XSS": { reachability: 3, impact: 2, complexity: 2 },
      "HARD_CODE_PASSWORD": { reachability: 3, impact: 2, complexity: 3 },
      "PLAINTEXT_PASSWORD": { reachability: 3, impact: 2, complexity: 3 },
      "HARD_CODE_SECRET": { reachability: 3, impact: 3, complexity: 3 },
      "WEAK_CRYPTO": { reachability: 2, impact: 2, complexity: 1 },
      "WEAK_HASH": { reachability: 2, impact: 2, complexity: 1 },
      "NO_SALT_HASH": { reachability: 2, impact: 2, complexity: 1 },
      "PREDICTABLE_RANDOM": { reachability: 2, impact: 2, complexity: 2 },
      "WEAK_RANDOM": { reachability: 2, impact: 2, complexity: 2 },
      "FIXED_IV": { reachability: 2, impact: 2, complexity: 1 },
      "RSA_PADDING": { reachability: 2, impact: 2, complexity: 1 },
      "AUTH_BYPASS": { reachability: 3, impact: 3, complexity: 2 },
      "REFERER_AUTH_BYPASS": { reachability: 3, impact: 2, complexity: 2 },
      "AUTH_INFO_EXPOSURE": { reachability: 2, impact: 1, complexity: 1 },
      "IDOR": { reachability: 3, impact: 2, complexity: 2 },
      "MISSING_ACCESS_CONTROL": { reachability: 3, impact: 3, complexity: 2 },
      "INFO_LEAK": { reachability: 2, impact: 1, complexity: 1 },
      "LOG_INJECTION": { reachability: 3, impact: 2, complexity: 2 },
      "BUFFER_OVERFLOW": { reachability: 2, impact: 3, complexity: 2 },
      "FORMAT_STRING": { reachability: 3, impact: 2, complexity: 3 },
      "INTEGER_OVERFLOW": { reachability: 2, impact: 2, complexity: 2 },
      "PROCESS_CONTROL": { reachability: 3, impact: 3, complexity: 2 },
      "XPATH_INJECTION": { reachability: 3, impact: 2, complexity: 2 },
      "FILE_UPLOAD": { reachability: 3, impact: 2, complexity: 2 },
      "FILE_READ": { reachability: 3, impact: 2, complexity: 2 },
      "OPEN_REDIRECT": { reachability: 2, impact: 1, complexity: 3 },
      "SESSION_FIXATION": { reachability: 2, impact: 2, complexity: 2 },
      "COOKIE_MANIPULATION": { reachability: 2, impact: 2, complexity: 2 },
      "CREDENTIAL_EXPOSURE": { reachability: 3, impact: 2, complexity: 2 },
      "CSRF": { reachability: 3, impact: 2, complexity: 2 },
      "RACE_CONDITION": { reachability: 2, impact: 2, complexity: 2 },
      "UNCONTROLLED_MEMORY": { reachability: 2, impact: 2, complexity: 2 },
      "IMPROPER_EXCEPTION_HANDLING": { reachability: 2, impact: 1, complexity: 1 },
      "INFINITE_LOOP": { reachability: 2, impact: 1, complexity: 1 },
      "RESOURCE_EXHAUSTION": { reachability: 2, impact: 2, complexity: 2 },
      "WEAK_PASSWORD_POLICY": { reachability: 2, impact: 1, complexity: 1 },
      "PLAINTEXT_TRANSMISSION": { reachability: 3, impact: 2, complexity: 2 },
      "TRUST_BOUNDARY_VIOLATION": { reachability: 3, impact: 2, complexity: 2 },
      "SESSION_TIMEOUT": { reachability: 2, impact: 2, complexity: 2 },
      "DNS_TRUST": { reachability: 3, impact: 2, complexity: 2 },
      "COOKIE_AUTH_BYPASS": { reachability: 3, impact: 2, complexity: 2 },
      "STACK_TRACE_LEAK": { reachability: 2, impact: 1, complexity: 1 },
      "ERROR_MSG_LEAK": { reachability: 2, impact: 1, complexity: 1 },
      "PARAMETER_TAMPERING": { reachability: 3, impact: 2, complexity: 2 },
      "PERSISTENT_COOKIE": { reachability: 2, impact: 1, complexity: 1 },
      "COOKIE_SECURE_MISSING": { reachability: 2, impact: 1, complexity: 1 },
      "UNRESTRICTED_UPLOAD": { reachability: 3, impact: 2, complexity: 2 },
      "SENSITIVE_SERIALIZATION": { reachability: 2, impact: 2, complexity: 2 },
      "SENSITIVE_FIELD": { reachability: 2, impact: 2, complexity: 2 },
      "SESSION_INFO_LEAK": { reachability: 2, impact: 2, complexity: 2 },
      "PASSWORD_DISPLAY": { reachability: 2, impact: 1, complexity: 1 },
      "PERSONAL_INFO_EXPOSURE": { reachability: 2, impact: 2, complexity: 2 },
      "SENSITIVE_OPERATION": { reachability: 3, impact: 3, complexity: 2 },
      "UNINITIALIZED_OBJECT": { reachability: 2, impact: 2, complexity: 2 },
      "THREAD_LOCAL_LEAK": { reachability: 2, impact: 2, complexity: 2 },
      "DOUBLE_FREE": { reachability: 2, impact: 2, complexity: 2 },
      "USE_AFTER_FREE": { reachability: 2, impact: 3, complexity: 2 },
      "TEMP_FILE_EXPOSURE": { reachability: 2, impact: 2, complexity: 2 },
      "MEMORY_LEAK": { reachability: 2, impact: 2, complexity: 2 }
    };

    const config = cvssConfig[vulnType] || { reachability: 2, impact: 2, complexity: 2 };
    
    const severityMultiplier = {
      "严重": 1.0,
      "高危": 0.9,
      "中危": 0.7,
      "低危": 0.5
    };

    const multiplier = severityMultiplier[severity] || 0.7;
    
    const R = config.reachability;
    const I = config.impact;
    const C = config.complexity;
    
    const score = R * 0.40 + I * 0.35 + C * 0.25;
    const cvss = Math.round(score / 3.0 * 10.0 * multiplier * 10) / 10;
    
    const adjustedR = Math.round(R * multiplier);
    const adjustedI = Math.round(I * multiplier);
    const adjustedC = Math.round(C * multiplier);

    return {
      score: Math.round(score * 100) / 100,
      cvss,
      breakdown: `${adjustedR}/${adjustedI}/${adjustedC}`,
      reachability: R,
      impact: I,
      complexity: C,
      reachabilityDesc: this.getReachabilityDesc(R),
      impactDesc: this.getImpactDesc(I),
      complexityDesc: this.getComplexityDesc(C)
    };
  }

  getReachabilityDesc(r) {
    const descs = {
      3: "无需认证，HTTP直接可达",
      2: "需要普通用户认证",
      1: "需要管理员权限或内网访问",
      0: "代码不可达/死代码"
    };
    return descs[r] || "未知";
  }

  getImpactDesc(i) {
    const descs = {
      3: "RCE/任意文件写入/完全数据泄露",
      2: "敏感数据泄露/越权操作",
      1: "有限信息泄露",
      0: "无实际安全影响"
    };
    return descs[i] || "未知";
  }

  getComplexityDesc(c) {
    const descs = {
      3: "单次请求即可利用",
      2: "需要构造特殊payload或多步操作",
      1: "需要特定环境/竞态条件/链式利用",
      0: "有效防护，无法绕过"
    };
    return descs[c] || "未知";
  }

  detectLanguage(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    for (const [lang, extensions] of Object.entries(LANGUAGE_EXTENSIONS)) {
      if (extensions.includes(ext)) {
        return lang;
      }
    }
    return "unknown";
  }

  async scanFile(filePath, projectRoot) {
    const relativePath = path.relative(projectRoot, filePath).replaceAll("\\", "/");
    console.log(`[快速扫描] 正在扫描文件: ${relativePath}`);
    
    const language = this.detectLanguage(filePath);
    if (language === "unknown" || !this.patterns[language]) {
      console.log(`[快速扫描] 跳过文件 (未知语言): ${relativePath}`);
      return [];
    }

    try {
      const content = await fs.readFile(filePath, "utf8");
      const findings = [];
      const lines = content.split("\n");
      console.log(`[快速扫描] 读取文件成功: ${relativePath} (${lines.length} 行)`);

      for (const { pattern, vulnType, cwe, severity } of this.patterns[language]) {
        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
          const line = lines[lineNum];
          if (pattern.test(line)) {
            const codeSnippet = this.extractCodeSnippet(lines, lineNum);
            const vulnId = this.getVulnId(vulnType, severity);
            const cvssDetails = this.calculateCVSSDetailed(vulnType, severity);

            findings.push({
              source: "quick_scan",
              skillId: "gbt-code-audit",
              vulnId,
              title: `发现 ${vulnType} 漏洞`,
              severity: this.normalizeSeverity(severity),
              severityLabel: severity,
              confidence: 0.75,
              location: `${relativePath}:${lineNum + 1}`,
              file: relativePath,
              line: lineNum + 1,
              vulnType,
              cwe,
              language,
              gbtMapping: this.getGbtMapping(vulnType, language),
              cvssScore: cvssDetails.cvss,
              cvssBreakdown: cvssDetails.breakdown,
              cvssScoreRaw: cvssDetails.score,
              reachability: cvssDetails.reachability,
              impact: cvssDetails.impact,
              complexity: cvssDetails.complexity,
              reachabilityDesc: cvssDetails.reachabilityDesc,
              impactDesc: cvssDetails.impactDesc,
              complexityDesc: cvssDetails.complexityDesc,
              evidence: `在 ${relativePath}:${lineNum + 1} 发现 ${vulnType} 相关代码`,
              impact: this.getImpactDescription(vulnType),
              remediation: this.getRemediation(vulnType),
              safeValidation: "建议人工复核代码上下文，确认是否存在实际安全风险",
              codeSnippet,
              status: "误报" // 默认状态为"误报"，等待 LLM 审计判定
            });
            console.log(`[快速扫描] 发现漏洞: ${vulnType} 在 ${relativePath}:${lineNum + 1}`);
          }
        }
      }

      console.log(`[快速扫描] 完成扫描: ${relativePath} (发现 ${findings.length} 个问题)`);
      return findings;
    } catch (error) {
      console.error(`[快速扫描] 扫描文件失败 ${relativePath}:`, error.message);
      return [];
    }
  }

  async scanProject(projectRoot, onProgress) {
    console.log(`[快速扫描] 开始扫描项目: ${projectRoot}`);
    
    const fileList = [];
    await this.walkDirectory(projectRoot, (filePath) => {
      fileList.push(filePath);
    });

    const totalFiles = fileList.length;
    console.log(`[快速扫描] 共发现 ${totalFiles} 个文件`);
    
    const findings = [];
    let processedFiles = 0;
    const concurrencyLimit = 10;
    const batches = [];

    for (let i = 0; i < fileList.length; i += concurrencyLimit) {
      batches.push(fileList.slice(i, i + concurrencyLimit));
    }

    console.log(`[快速扫描] 将文件分成 ${batches.length} 个批次，每批 ${concurrencyLimit} 个文件`);

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      console.log(`[快速扫描] 开始处理第 ${batchIndex + 1}/${batches.length} 批`);
      
      const batchPromises = batch.map(async (filePath) => {
        const fileFindings = await this.scanFile(filePath, projectRoot);
        processedFiles++;

        if (onProgress && processedFiles % 10 === 0) {
          onProgress({
            type: "quick-scan-progress",
            processedFiles,
            totalFiles,
            currentFile: path.relative(projectRoot, filePath)
          });
        }

        return fileFindings;
      });

      const batchResults = await Promise.all(batchPromises);
      const batchFindings = batchResults.flat();
      findings.push(...batchFindings);
      console.log(`[快速扫描] 完成第 ${batchIndex + 1}/${batches.length} 批，发现 ${batchFindings.length} 个问题`);
    }

    const dedupedFindings = this.deduplicateFindings(findings);
    console.log(`[快速扫描] 完成扫描，共发现 ${findings.length} 个问题，去重后 ${dedupedFindings.length} 个问题`);
    return dedupedFindings;
  }

  async walkDirectory(root, callback) {
    const entries = await fs.readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(root, entry.name);
      if (entry.isDirectory()) {
        await this.walkDirectory(fullPath, callback);
      } else if (entry.isFile()) {
        callback(fullPath);
      }
    }
  }

  async countFiles(root) {
    let count = 0;
    await this.walkDirectory(root, () => {
      count++;
    });
    return count;
  }

  extractCodeSnippet(lines, lineNum) {
    const start = Math.max(0, lineNum - 2);
    const end = Math.min(lines.length, lineNum + 3);
    return lines.slice(start, end).join("\n");
  }

  normalizeSeverity(severity) {
    const mapping = {
      "严重": "high",
      "高危": "high", 
      "中危": "medium",
      "低危": "low"
    };
    return mapping[severity] || "medium";
  }

  getGbtMapping(vulnType, language) {
    const typeMapping = this.gbtMapping[vulnType];
    if (!typeMapping) {
      return "GB/T39412-2020 通用基线";
    }
    return typeMapping[language] || typeMapping["default"] || "GB/T39412-2020 通用基线";
  }

  calculateCVSS(vulnType, severity) {
    const baseScores = {
      "COMMAND_INJECTION": 9.8,
      "SQL_INJECTION": 9.8,
      "CODE_INJECTION": 9.8,
      "DESERIALIZATION": 8.8,
      "SSRF": 8.6,
      "PATH_TRAVERSAL": 7.5,
      "XSS": 6.1,
      "HARD_CODE_PASSWORD": 7.5,
      "WEAK_CRYPTO": 7.5,
      "WEAK_HASH": 5.9,
      "PREDICTABLE_RANDOM": 7.5,
      "AUTH_BYPASS": 9.8,
      "INFO_LEAK": 5.3,
      "BUFFER_OVERFLOW": 9.8,
      "FORMAT_STRING": 7.5,
      "PROCESS_CONTROL": 8.6,
      "SESSION_FIXATION": 5.9,
      "COOKIE_MANIPULATION": 5.3,
      "IMPROPER_EXCEPTION_HANDLING": 5.3,
      "INFINITE_LOOP": 5.3
    };

    const severityMultiplier = {
      "严重": 1.0,
      "高危": 0.9,
      "中危": 0.7,
      "低危": 0.5
    };

    const baseScore = baseScores[vulnType] || 5.0;
    const multiplier = severityMultiplier[severity] || 0.7;
    return Math.round(baseScore * multiplier * 10) / 10;
  }

  getImpactDescription(vulnType) {
    const impacts = {
      "COMMAND_INJECTION": "攻击者可通过注入恶意命令在服务器上执行任意系统命令，可能导致服务器被完全控制",
      "SQL_INJECTION": "攻击者可通过注入恶意SQL语句访问、修改或删除数据库中的敏感数据，可能导致数据泄露或篡改",
      "CODE_INJECTION": "攻击者可通过注入恶意代码在应用程序上下文中执行任意代码，可能导致应用程序被完全控制",
      "SPEL_INJECTION": "攻击者可通过注入恶意SpEL表达式执行任意代码，可能导致应用程序被完全控制",
      "SSTI": "攻击者可通过注入恶意模板代码执行任意代码，可能导致应用程序被完全控制",
      "PATH_TRAVERSAL": "攻击者可通过路径遍历访问服务器上的任意文件，可能导致敏感文件泄露或系统文件被篡改",
      "XSS": "攻击者可通过注入恶意脚本在用户浏览器中执行任意JavaScript代码，可能导致用户会话劫持或敏感信息泄露",
      "HARD_CODE_PASSWORD": "硬编码的密码可能被逆向工程获取，攻击者可直接使用这些凭据访问系统",
      "PLAINTEXT_PASSWORD": "明文存储的密码可能被直接获取，攻击者可直接使用这些凭据访问系统",
      "WEAK_CRYPTO": "使用弱加密算法可能被暴力破解或已知攻击方法破解，导致敏感数据泄露",
      "WEAK_HASH": "使用弱哈希算法可能被碰撞攻击或彩虹表攻击破解，导致密码或敏感数据泄露",
      "PREDICTABLE_RANDOM": "使用可预测的随机数生成器可能导致会话令牌、密钥等被预测，攻击者可利用此缺陷进行攻击",
      "WEAK_RANDOM": "使用不充分的随机数生成器可能导致安全令牌被预测，攻击者可利用此缺陷进行攻击",
      "DESERIALIZATION": "恶意构造的反序列化数据可能导致远程代码执行，攻击者可完全控制服务器",
      "SSRF": "攻击者可通过服务器发起任意HTTP请求，可能访问内网服务或泄露敏感信息",
      "XXE": "攻击者可通过恶意XML实体访问服务器文件系统或发起SSRF攻击，可能导致敏感信息泄露",
      "AUTH_BYPASS": "认证绕过可能导致未授权用户访问受保护资源，造成数据泄露或权限提升",
      "REFERER_AUTH_BYPASS": "依赖Referer头进行认证可能导致认证被绕过，攻击者可伪造Referer头访问受保护资源",
      "AUTH_INFO_EXPOSURE": "身份鉴别过程暴露多余信息可能为攻击者提供攻击线索，增加系统被攻击的风险",
      "IDOR": "不安全的直接对象引用可能导致攻击者访问其他用户的数据，造成数据泄露",
      "INFO_LEAK": "敏感信息泄露可能为攻击者提供攻击线索，增加系统被攻击的风险",
      "LOG_INJECTION": "日志注入可能导致日志文件被篡改或注入恶意内容，影响日志审计的准确性",
      "BUFFER_OVERFLOW": "缓冲区溢出可能导致程序崩溃或执行任意代码，攻击者可完全控制系统",
      "FORMAT_STRING": "格式化字符串漏洞可能导致信息泄露或代码执行，攻击者可利用此缺陷进行攻击",
      "PROCESS_CONTROL": "进程控制漏洞可能导致加载恶意库或执行恶意代码，攻击者可完全控制系统",
      "IMPROPER_EXCEPTION_HANDLING": "异常处理不当可能导致敏感信息泄露或系统状态异常",
      "INFINITE_LOOP": "无限循环可能导致服务拒绝攻击，影响系统可用性",
      "SESSION_FIXATION": "会话固定攻击可能导致攻击者劫持用户会话，访问用户账户",
      "COOKIE_MANIPULATION": "Cookie操作不当可能导致会话劫持或敏感信息泄露",
      "XPATH_INJECTION": "XPath注入可能导致攻击者访问或修改XML数据，造成数据泄露或篡改",
      "OPEN_REDIRECT": "开放重定向可能导致攻击者将用户重定向到恶意网站，进行钓鱼攻击",
      "CORS_MISCONFIGURATION": "CORS配置不当可能导致跨域请求被滥用，造成敏感数据泄露",
      "CSRF": "跨站请求伪造可能导致攻击者在用户不知情的情况下执行恶意操作",
      "RACE_CONDITION": "竞态条件可能导致数据不一致或安全检查被绕过，造成权限提升或数据篡改",
      "INTEGER_OVERFLOW": "整数溢出可能导致程序崩溃或安全检查被绕过，攻击者可利用此缺陷进行攻击",
      "UNCONTROLLED_MEMORY": "不受控制的内存分配可能导致内存耗尽或程序崩溃，影响系统可用性",
      "WEAK_PASSWORD_POLICY": "弱密码策略可能导致用户使用弱密码，增加账户被破解的风险",
      "PLAINTEXT_TRANSMISSION": "明文传输可能导致敏感数据在传输过程中被窃取，造成数据泄露"
    };
    return impacts[vulnType] || "可能导致安全风险";
  }

  getRemediation(vulnType) {
    const remediations = {
      "COMMAND_INJECTION": "使用参数化命令执行接口，避免直接拼接用户输入；对用户输入进行严格验证和过滤",
      "SQL_INJECTION": "使用参数化查询或ORM框架，避免直接拼接SQL语句；对用户输入进行严格验证和过滤",
      "CODE_INJECTION": "避免使用eval、exec等动态代码执行函数；对用户输入进行严格验证和过滤",
      "SPEL_INJECTION": "使用SimpleEvaluationContext替代StandardEvaluationContext；对SpEL表达式进行严格验证",
      "SSTI": "避免使用用户输入作为模板内容；对模板引擎进行安全配置",
      "PATH_TRAVERSAL": "对用户输入的文件路径进行规范化处理；使用白名单限制可访问的文件和目录",
      "XSS": "对用户输入进行HTML编码；使用Content Security Policy (CSP)限制脚本执行",
      "HARD_CODE_PASSWORD": "将密码存储在安全的配置文件或环境变量中；使用密钥管理服务存储敏感凭据",
      "PLAINTEXT_PASSWORD": "使用BCryptPasswordEncoder等安全密码编码器；避免使用NoOpPasswordEncoder",
      "WEAK_CRYPTO": "使用强加密算法（如AES-256）；避免使用已知的弱加密算法（如DES、RC4）",
      "WEAK_HASH": "使用强哈希算法（如SHA-256、bcrypt）；避免使用已知的弱哈希算法（如MD5、SHA1）",
      "PREDICTABLE_RANDOM": "使用密码学安全的随机数生成器；避免使用可预测的随机数生成器",
      "WEAK_RANDOM": "使用SecureRandom.getInstanceStrong()获取强随机数生成器",
      "DESERIALIZATION": "对反序列化数据进行严格验证；避免反序列化不受信任的数据",
      "SSRF": "对用户提供的URL进行严格验证和过滤；限制可访问的内网地址范围",
      "XXE": "禁用XML外部实体处理；使用安全的XML解析器配置",
      "AUTH_BYPASS": "实现严格的身份认证机制；避免依赖客户端提供的认证信息",
      "REFERER_AUTH_BYPASS": "避免依赖Referer头进行认证；使用服务器端的会话验证机制",
      "AUTH_INFO_EXPOSURE": "避免在身份鉴别过程中暴露多余信息；对错误消息进行脱敏处理",
      "IDOR": "对用户访问的资源进行权限验证；确保用户只能访问自己的资源",
      "INFO_LEAK": "避免在错误消息中泄露敏感信息；对日志和错误信息进行脱敏处理",
      "LOG_INJECTION": "对日志内容进行严格验证和过滤；避免将用户输入直接写入日志",
      "BUFFER_OVERFLOW": "使用安全的字符串处理函数；对用户输入的长度进行严格限制",
      "FORMAT_STRING": "使用格式化字符串的安全版本；避免将用户输入直接作为格式化字符串",
      "PROCESS_CONTROL": "限制可加载的库和可执行文件；对动态加载的代码进行严格验证",
      "IMPROPER_EXCEPTION_HANDLING": "实现完善的异常处理机制；避免在异常处理中泄露敏感信息",
      "INFINITE_LOOP": "设置循环的最大迭代次数；添加超时机制防止无限循环",
      "SESSION_FIXATION": "在用户登录后重新生成会话令牌；设置合理的会话超时时间",
      "COOKIE_MANIPULATION": "为Cookie设置Secure和HttpOnly标志；对Cookie中的敏感信息进行加密",
      "XPATH_INJECTION": "对XPath查询进行参数化处理；避免直接拼接用户输入到XPath表达式",
      "OPEN_REDIRECT": "对重定向目标URL进行白名单验证；避免使用用户输入作为重定向目标",
      "CORS_MISCONFIGURATION": "严格配置CORS策略；避免使用通配符(*)作为Access-Control-Allow-Origin",
      "CSRF": "实现CSRF令牌验证机制；确保敏感操作需要有效的CSRF令牌",
      "RACE_CONDITION": "使用同步机制保护共享资源；避免在并发环境中使用不安全的操作",
      "INTEGER_OVERFLOW": "对数值运算进行边界检查；使用安全的数值处理方法",
      "UNCONTROLLED_MEMORY": "对内存分配进行限制；避免不受控制的内存分配",
      "WEAK_PASSWORD_POLICY": "实现强密码策略；要求密码长度至少8位且包含大小写字母和数字",
      "PLAINTEXT_TRANSMISSION": "使用HTTPS加密传输敏感数据；避免使用HTTP传输敏感信息"
    };
    return remediations[vulnType] || "建议进行安全加固";
  }

  deduplicateFindings(findings) {
    const seen = new Set();
    const deduped = [];

    for (const finding of findings) {
      const key = `${finding.vulnType}::${finding.location}::${finding.line}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(finding);
      }
    }

    return deduped.sort((a, b) => b.cvssScore - a.cvssScore);
  }
}