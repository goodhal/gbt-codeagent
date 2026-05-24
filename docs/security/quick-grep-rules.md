# Quick Grep Rules / 快速检索规则

Use these rules for triage only. Never treat matches as final proof.
先筛选候选点，再回到 source->transfer->sink 证据链确认。

## Usage

- Preferred command:
  - `rg -n --hidden -S "<pattern>" <target-path>`
- For case-insensitive search:
  - `rg -n --hidden -i "<pattern>" <target-path>`

## 1) SQL Injection / SQL 注入

### Generic
- `(?i)(select|update|delete|insert).*(\+|format\(|f"|%s|\$\{)`
- `(?i)createStatement\(|prepare\(".*\+`

### Java
- `executeQuery\(|executeUpdate\(|createStatement\(`
- `@Query\(".*\$\{.*\}`

### Node/Python/PHP/.NET
- `sequelize\.query\(|knex\.raw\(|\$queryRawUnsafe`
- `cursor\.execute\(f"|cursor\.execute\(.*%`
- `mysqli_query\(|pdo->query\(`
- `FromSqlRaw\(|ExecuteSqlRaw\(`

## 2) Command Injection / 命令执行

### Generic
- `(?i)exec\(|system\(|popen\(|ProcessBuilder\(|Runtime\.getRuntime\(\)\.exec`

### Language hints
- Node: `child_process\.(exec|execSync|spawn|spawnSync)`
- Python: `subprocess\.(run|Popen|call).*shell\s*=\s*True`
- PHP: `shell_exec\(|passthru\(|proc_open\(`
- .NET: `ProcessStartInfo|Process\.Start\(`

## 3) Deserialization / 反序列化

- `ObjectInputStream|readObject\(`
- `BinaryFormatter|LosFormatter|NetDataContractSerializer`
- `pickle\.loads|yaml\.load\(|marshal\.loads`
- `unserialize\(`
- `JSON\.parse\(.*__proto__` (prototype pollution paths)

## 4) XXE / XML Injection

- `DocumentBuilderFactory|SAXParserFactory|XMLInputFactory`
- `setFeature\(.*disallow-doctype-decl`
- `resolveEntity\(|XmlResolver|DtdProcessing`

Flag as risk when secure flags are missing or disabled.

## 5) SSRF / 服务端请求伪造

- `new URL\(|URI\.create\(|HttpClient|RestTemplate|WebClient`
- `requests\.(get|post)|httpx\.|urllib\.request`
- `axios\.|fetch\(|got\(`
- `curl_exec\(|file_get_contents\(.*http`

Look for user-controlled target URL, redirect following, and missing allowlists.

## 6) AuthN/AuthZ Bypass / 认证鉴权绕过

- Routes/controllers missing auth middleware or permission checks
- `@PermitAll|AllowAnonymous|skipAuth|bypassAuth|isAdmin` fragile logic
- Path-based trust decisions with suffix/case/encoding ambiguity

## 7) File Upload/Read/Traversal / 文件上传读取穿越

- Upload handlers: `multipart|IFormFile|multer|move_uploaded_file`
- Path joins: `../|..\\|path\.join|Path\.Combine|normalize\(`
- File read/write APIs fed by request params

Look for executable upload paths, weak extension checks, and traversal bypasses.

## 8) Business Logic Risks / 业务逻辑风险

- Missing ownership/tenant checks on read/update/delete actions
- Price, quantity, role, or status transitions controlled by client input
- Idempotency and replay-sensitive endpoints without nonce/token controls

## Triage to Evidence Conversion

For each candidate, confirm:
1. Source: which input is user-controlled
2. Transfer: how it flows/transforms
3. Sink: which dangerous operation is reached
4. Preconditions: auth role, feature flags, environment, data state
5. Impact: confidentiality/integrity/availability and tenant scope

If any link is missing, mark as `SUSPECTED` or `INFO`.
