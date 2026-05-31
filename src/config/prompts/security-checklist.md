## Security Checklist (all languages)

### Injection
- [ ] User input reaches SQL query — is it parameterized? (PreparedStatement / ORM safe methods)
- [ ] User input reaches OS command — is it via args array, not string interpolation?
- [ ] User input in template rendering — is it sandboxed?
- [ ] NoSQL / LDAP / XPath query construction — user input sanitized?
- **Skip if**: parameterized query, ORM safe API, validated whitelist, or framework auto-escaping active.

### Authentication & Authorization
- [ ] Auth endpoints — can auth be bypassed (missing password check, weak token)?
- [ ] Object-level access — is user ID validated against session (not just from request param)?
- [ ] Admin / privileged routes — are role checks present on every endpoint?
- [ ] Session fixation — is session invalidated and regenerated after login? (Java: `session.invalidate()`; JS: `req.session.regenerate()`)
- **Skip if**: framework-enforced auth filter with no exceptions, or endpoint is intentionally public.

### Sensitive Data
- [ ] Hardcoded secrets — password, API key, token, private key in source code.
- [ ] Log statements — do they print secrets, tokens, PII, or full request bodies?
- [ ] Error responses — do they leak stack traces, DB schema, internal paths?
- **Skip if**: values come from env vars / vault / config service (not hardcoded).

### File Operations
- [ ] File paths built from user input — is `../` traversal prevented?
- [ ] File upload — is type verified server-side (MIME + magic bytes), filename sanitized?
- [ ] Upload directory — is it outside web root or protected from direct URL access?
- **Skip if**: paths use UUID generation, or strict allowlist validation on extension + content.

### Deserialization & Parsing
- [ ] Untrusted data deserialized — `pickle`, `unserialize`, `ObjectInputStream`, `jsonpickle`?
- [ ] XML parsing with external entities enabled (XXE)?
- [ ] YAML parsing with `!!python/object` or custom tags enabled?
- **Skip if**: safe parser used (JSON.parse, safe_load, explicit type whitelist).

### Concurrency (server-side only)
- [ ] Shared mutable state — accessed without lock / synchronized / atomic?
- [ ] Check-then-act patterns — race window between check and mutation?
- **Skip if**: method-local variables, read-only access, immutable objects, single-thread context.
