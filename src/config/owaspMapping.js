// OWASP Top 10 2021 映射
// 映射关系: vulnType -> [OWASP_ID]

const OWASP_MAPPING = {
  "SQL_INJECTION": ["A03:2021"],
  "COMMAND_INJECTION": ["A03:2021"],
  "CODE_INJECTION": ["A03:2021"],
  "SPEL_INJECTION": ["A03:2021"],
  "SSTI": ["A03:2021"],
  "XSS": ["A03:2021"],
  "XPATH_INJECTION": ["A03:2021"],
  "PATH_TRAVERSAL": ["A01:2021"],
  "SSRF": ["A01:2021"],
  "FILE_UPLOAD": ["A01:2021"],
  "WEAK_CRYPTO": ["A02:2021"],
  "WEAK_HASH": ["A02:2021"],
  "HARD_CODE_PASSWORD": ["A02:2021"],
  "PLAINTEXT_PASSWORD": ["A02:2021"],
  "DESERIALIZATION": ["A08:2021"],
  "AUTH_BYPASS": ["A07:2021"],
  "REFERER_AUTH_BYPASS": ["A07:2021"],
  "IDOR": ["A01:2021"],
  "MISSING_ACCESS_CONTROL": ["A01:2021"],
  "SESSION_FIXATION": ["A07:2021"],
  "CSRF": ["A01:2021"],
  "LOG_INJECTION": ["A02:2021"],
  "INFO_LEAK": ["A05:2021"],
  "OPEN_REDIRECT": ["A01:2021"],
  "CORS_MISCONFIGURATION": ["A05:2021"],
  "WEAK_PASSWORD_POLICY": ["A07:2021"],
  "PLAINTEXT_TRANSMISSION": ["A02:2021"]
};

// OWASP Top 10 2021 中文名称映射
export const OWASP_NAMES = {
  "A01:2021": "失效的访问控制",
  "A02:2021": "加密机制失效",
  "A03:2021": "注入",
  "A04:2021": "不安全的设计",
  "A05:2021": "安全配置错误",
  "A06:2021": "易受攻击和过时的组件",
  "A07:2021": "身份认证与授权失效",
  "A08:2021": "软件和数据完整性失效",
  "A09:2021": "安全日志和监控失败",
  "A10:2021": "服务端请求伪造"
};

export default OWASP_MAPPING;
