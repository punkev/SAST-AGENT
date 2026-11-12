# Retest Verification Methodology & Checklist

This instruction file defines the systematic verification methodology that `@sast-retest` must apply when determining whether a reported vulnerability has been properly fixed. Every checklist item must be evaluated before assigning a verdict.

---

## 1. Pre-Verification Setup

Before analyzing any issue:

- [ ] Read the issue `.md` file attached in the chat context.
- [ ] Confirm all mandatory fields are present: Issue Name, Description, CWE, Steps to Reproduce, Affected Files, Target Host.
- [ ] Load `.sast-agent/config/ignore-paths.yml` and `.github/instructions/ignore-patterns.instructions.md` — respect all exclusions.
- [ ] Identify the project ecosystem (Java/Spring Boot, Node.js/TypeScript, or Polyglot) from root manifests.

---

## 2. Code Location & Relocation Detection

- [ ] Navigate to the originally reported file and line number(s).
- [ ] If the file exists at the same path, read ±30 lines around the reported location for context.
- [ ] If the file was **renamed or moved**: Search by class/function/route name. Document new location.
- [ ] If the file was **deleted**: Check if the endpoint/route was removed entirely. Search for any replacement.
- [ ] If the **line numbers shifted** (code was added/removed above): Search for the specific vulnerable code pattern within the file.

---

## 3. Vulnerability-Specific Verification Checklists

### 3.1 SQL Injection (CWE-89)

- [ ] Is the raw string concatenation / template literal interpolation into SQL removed?
- [ ] Are ALL query paths now using parameterized statements (`PreparedStatement`, JPA named params `:param`, MyBatis `#{param}`, Prisma tagged templates, Knex `?` bindings)?
- [ ] Check for **dynamic identifiers** (table names, column names, ORDER BY) — are they validated against an allowlist?
- [ ] Check for `${...}` in MyBatis XML/annotations — should be `#{...}`.
- [ ] Are native queries (`@Query(nativeQuery=true)`, `entityManager.createNativeQuery()`) using parameterized bindings?
- [ ] Does the fix cover ALL callers of the vulnerable method, not just the one reported?

### 3.2 Cross-Site Scripting — XSS (CWE-79)

- [ ] Is user input now properly encoded/escaped before rendering in HTML context?
- [ ] Check template engine: Is auto-escaping enabled? Are unescaped directives (`th:utext`, `<%- %>`, `{{{...}}}`, `dangerouslySetInnerHTML`) removed or replaced?
- [ ] Is the Content-Type header set correctly (no `text/html` for API responses)?
- [ ] Are Content Security Policy (CSP) headers applied?
- [ ] Does the fix handle all output contexts (HTML body, attribute, JavaScript, URL)?

### 3.3 Server-Side Template Injection — SSTI (CWE-1336)

- [ ] Is user input no longer passed to template compilation/rendering functions?
- [ ] Are template strings hardcoded or loaded from trusted sources only?
- [ ] Is sandboxing or restricted execution mode enabled on the template engine?
- [ ] Check for indirect SSTI via model attribute names or dynamic template selection.

### 3.4 Server-Side Request Forgery — SSRF (CWE-918)

- [ ] Is user-supplied URL/hostname now validated against an allowlist of permitted destinations?
- [ ] Are private/internal IP ranges blocked (`127.0.0.1`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `169.254.169.254`, `fd00::/8`)?
- [ ] Is URL resolution performed BEFORE the allowlist check (to prevent DNS rebinding)?
- [ ] Are redirects followed safely (re-validated after redirect)?
- [ ] Is the protocol restricted to `http`/`https` only (blocking `file://`, `gopher://`, `dict://`)?

### 3.5 Insecure Deserialization (CWE-502)

- [ ] Is untrusted data no longer deserialized with unsafe deserializers?
- [ ] Are type restrictions / allowlists applied (Jackson `@JsonTypeInfo` with `MINIMAL_CLASS` or allowlisted subtypes)?
- [ ] Is `ObjectMapper.enableDefaultTyping()` removed or replaced with `activateDefaultTyping()` with a safe validator?
- [ ] Are XML parsers configured to disable external entities (XXE)?

### 3.6 Path Traversal / Directory Traversal (CWE-22)

- [ ] Is user input sanitized to remove `../`, `..\\`, URL-encoded traversal sequences?
- [ ] Is the resolved file path validated to be within an expected base directory (canonical path check)?
- [ ] Are Zip Slip protections in place for archive extraction?
- [ ] Is the file stored with a randomized name instead of user-supplied filename?

### 3.7 Remote Code Execution — RCE (CWE-78 / CWE-94)

- [ ] Is user input no longer passed to `Runtime.exec()`, `ProcessBuilder`, `eval()`, `Function()`, `child_process.exec()`?
- [ ] If command execution is necessary, are arguments parameterized (array form) instead of shell-interpolated?
- [ ] Is SpEL / EL expression evaluation restricted from user input?
- [ ] Are JNDI lookups disabled or restricted (`log4j2.formatMsgNoLookups=true`, allowlisted protocols)?

### 3.8 Broken Access Control / IDOR / BOLA (CWE-639)

- [ ] Is authorization enforced at the resource level (not just authentication)?
- [ ] Are object references (IDs) validated against the authenticated user's ownership?
- [ ] Is the fix applied at the correct layer (service/repository, not just controller)?
- [ ] Are indirect references or UUIDs used instead of sequential IDs?

### 3.9 Race Condition / TOCTOU (CWE-367)

- [ ] Is the check-then-act pattern now atomic (pessimistic lock, optimistic concurrency, or atomic DB operation)?
- [ ] Are `SELECT ... FOR UPDATE`, `@Version`, or `UPDATE ... WHERE balance >= amount` patterns in use?
- [ ] Is the fix applied at the database level (not just application-level synchronization)?

### 3.10 Hardcoded Secrets / Credentials (CWE-798)

- [ ] Is the hardcoded secret removed from source code?
- [ ] Is the secret now loaded from environment variables, vault, or externalized config?
- [ ] Has the exposed secret been rotated (new key/token/password generated)?
- [ ] Are test/mock secrets clearly separated and non-functional in production?

### 3.11 File Upload Vulnerabilities (CWE-434)

- [ ] Is file type validation based on magic bytes (not just extension or Content-Type header)?
- [ ] Are uploaded files stored with randomized non-executable names?
- [ ] Are files stored outside the web root or behind a proxy with `Content-Disposition: attachment`?
- [ ] Are file size limits enforced?
- [ ] Is antivirus scanning applied (if applicable)?

### 3.12 ReDoS / Regular Expression Denial of Service (CWE-1333)

- [ ] Is the vulnerable regex replaced with a linear-time alternative?
- [ ] Are regex execution timeouts applied?
- [ ] Is input length limited before regex processing?
- [ ] Have nested quantifiers and catastrophic backtracking patterns been eliminated?

### 3.13 Log Injection / CRLF Injection (CWE-93 / CWE-117)

- [ ] Are newlines (`\r`, `\n`) and control characters stripped from log inputs?
- [ ] Is structured logging (JSON) used instead of string-interpolated log messages?
- [ ] Are log outputs sanitized to prevent log forging?

### 3.14 Weak Cryptography / PRNG (CWE-327 / CWE-338)

- [ ] Is the weak algorithm replaced (e.g., AES-ECB → AES-GCM, MD5 → SHA-256/bcrypt)?
- [ ] Is `SecureRandom` / `crypto.randomBytes()` used instead of `Math.random()` / `java.util.Random`?
- [ ] Are key sizes adequate (AES-256, RSA-2048+)?
- [ ] Are IVs/nonces unique and not hardcoded?

### 3.15 Open Redirect (CWE-601)

- [ ] Is the redirect URL validated against an allowlist of trusted domains?
- [ ] Is the URL parsed and the host component checked (not just prefix matching)?
- [ ] Are protocol-relative URLs (`//evil.com`) blocked?

---

## 4. Universal Fix Quality Checks

After the vulnerability-specific checklist, apply these universal quality gates:

### 4.1 Completeness
- [ ] Does the fix cover ALL code paths that lead to the vulnerable sink, not just the specific one reported?
- [ ] Are there other callers of the vulnerable function/method that remain unpatched?
- [ ] Search the codebase for the same vulnerable pattern in other files (e.g., string concatenation SQL in other repositories/DAOs).

### 4.2 Correctness
- [ ] Is the fix technically sound and aligned with industry best practices?
- [ ] Does the fix use the correct defense mechanism (parameterization over sanitization, allowlists over blocklists)?
- [ ] Is the defense applied at the RIGHT layer (before the sink, not after)?

### 4.3 Bypass Resistance
- [ ] Can the fix be bypassed with encoding tricks (URL encoding, double encoding, Unicode normalization)?
- [ ] Can alternative input vectors reach the same sink (different parameters, HTTP methods, content types)?
- [ ] Does the fix handle edge cases (null input, empty string, maximum length, special characters)?

### 4.4 No Regression
- [ ] Does the fix introduce NEW vulnerabilities?
- [ ] Does overly broad error handling leak sensitive information?
- [ ] Does the fix break functionality in a way that might be rolled back?

### 4.5 Defense in Depth
- [ ] Is the fix applied at a single point of failure, or are multiple layers of defense present?
- [ ] Is input validation combined with output encoding (for XSS)?
- [ ] Is parameterization combined with least-privilege database permissions (for SQLi)?

---

## 5. Verdict Decision Matrix

Use this matrix to translate checklist results into a verdict:

| Scenario | Verdict |
|---|---|
| All checklist items pass. Vulnerable pattern eliminated. No bypass possible. | ✅ **FIXED** |
| Most items pass, but 1+ code paths remain vulnerable or a bypass exists. | ⚠️ **PARTIALLY FIXED** |
| Core vulnerable pattern still present. Fix absent or ineffective. | ❌ **NOT FIXED** |
| Fix appears applied but effectiveness depends on runtime config, external service, or timing. Static analysis cannot confirm. | 🔍 **INCONCLUSIVE** |

