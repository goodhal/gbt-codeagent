## Java
### Null Safety
- Method calls on potentially-null return values without null check
- Auto-unboxing of nullable wrapper types
- **Skip**: Optional used, @Nullable annotated + checked, null-guard present

### Thread Safety
Only report shared mutable state in multi-thread context:
- Check-then-act patterns, lazy init without double-check locking
- **Skip**: method-local variables, immutable objects, final fields, single-thread components

### Resource & Performance
- Stream/Connection/Reader not in try-with-resources
- DB query inside loop (N+1)
- **Skip**: try-with-resources, framework-managed resources, known-small data

### Framework
- **Spring**: @Transactional on private methods, missing @PreAuthorize
- **MyBatis**: ${} vs #{} — flag ${} for user-controlled params
- **JPA**: JPQL concatenation instead of parameter binding

---

## TypeScript / JavaScript
### Injection & Execution
- eval() / Function() / setTimeout(string) / setInterval(string) — flag always
- innerHTML / insertAdjacentHTML with user content — XSS
- document.write() — flag always
- **Skip**: textContent, DOMPurify, hardcoded content

### Prototype Pollution
- Object.assign / _.merge / spread into target from user input without __proto__ filtering
- **Skip**: Object.create(null), sanitized against __proto__/constructor

### Async & Error
- Unhandled promise rejections, empty catch blocks
- **Skip**: global unhandledRejection handler, framework error boundary

### Node.js (server-side)
- child_process.exec() with user input — command injection
- fs with user-controlled paths — path traversal
- require() with dynamic paths — code injection
- **Skip**: execFile() with args array, path.resolve() + allowlist

### React
- Component inside component (recreated every render)
- useEffect missing cleanup for subscriptions/event listeners
- Direct DOM manipulation (ref.current.innerHTML = ...)
- **Skip**: useCallback, AbortController cleanup

---

## Python
### Execution & Injection
- eval()/exec()/compile() with user input — critical
- os.system()/subprocess.call(shell=True) — command injection
- pickle.load()/yaml.load() on untrusted data — deserialization
- **Skip**: subprocess.run(args=[]), yaml.safe_load(), json.loads(), ast.literal_eval()

### Path Traversal
- open(user_input), os.path.join(user_input) without sanitization
- **Skip**: pathlib.Path.resolve() checked, UUID-generated filename

### Template Injection
- render_template_string(user_input) in Flask/Jinja2
- Template(user_input).substitute() in Django if user controls template
- **Skip**: template source from file only

### Framework
- Django: DEBUG=True, SECRET_KEY hardcoded, ALLOWED_HOSTS=['*'], @csrf_exempt without alternative
- **Skip**: DEBUG from env, SECRET_KEY from secrets manager

---

## Go
### Error Handling
- Error returned but unchecked (_ assigned)
- panic() in library/handler code
- **Skip**: intentional ignore with comment, defer cleanup

### Concurrency
- Goroutine leak (no cancellation/done channel)
- Data race (shared variable, no sync.Mutex/atomic)
- WaitGroup.Add() inside goroutine
- **Skip**: context.Context cancellation, -race tested, single-goroutine

### Resource
- defer file.Close() in loop (close after loop, not per-iteration)
- HTTP response body not closed
- **Skip**: correct defer pattern, framework-managed

### Security
- template.HTML(userInput) in html/template — XSS
- os/exec.Command("sh", "-c", userInput) — command injection
- math/rand for tokens/session IDs — use crypto/rand
- MD5/SHA1 for password hashing — use bcrypt/argon2
- **Skip**: html/template auto-escaping, exec.Command with args array, crypto/rand
