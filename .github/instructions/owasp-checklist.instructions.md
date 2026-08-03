# OWASP Security Checklist

Check every controller endpoint / route handler against these categories.

## OWASP Web Application Top 10 (2021)

### A01: Broken Access Control
- [ ] Missing authentication on sensitive endpoints
- [ ] Missing authorization checks (no `@PreAuthorize`, no middleware, no role check)
- [ ] IDOR / BOLA: User A can access User B's resources by changing an ID parameter
- [ ] Privilege escalation: regular user accessing admin functionality
- [ ] CORS misconfiguration allowing unauthorized origins
- [ ] Directory traversal via file path parameters

### A02: Cryptographic Failures
- [ ] Sensitive data transmitted over HTTP (not HTTPS)
- [ ] Weak hashing algorithms (MD5, SHA1 for passwords)
- [ ] Hardcoded encryption keys or secrets
- [ ] Missing encryption for sensitive data at rest

### A03: Injection
- [ ] SQL injection: string concatenation in SQL/JPQL/HQL/native queries
- [ ] NoSQL injection: user input in MongoDB query operators (`$gt`, `$ne`, `$regex`)
- [ ] OS command injection: user input in `Runtime.exec()`, `ProcessBuilder`, `child_process.exec()`
- [ ] LDAP injection: user input in LDAP queries
- [ ] XSS (reflected): user input echoed in response without encoding
- [ ] XSS (stored): database content rendered without sanitization
- [ ] XSS (DOM): `innerHTML`, `dangerouslySetInnerHTML`, `document.write()` with user data
- [ ] Template injection: user input in server-side templates (Thymeleaf, EJS, Pug)
- [ ] SpEL / EL injection: user input evaluated as expression
- [ ] XPath injection: user input in XPath queries

### A04: Insecure Design
- [ ] Missing rate limiting on authentication endpoints
- [ ] No account lockout after failed login attempts
- [ ] Insecure password reset flow (predictable tokens, no expiry)
- [ ] Missing CAPTCHA on public forms

### A05: Security Misconfiguration
- [ ] Debug mode enabled in production
- [ ] Default credentials present
- [ ] Exposed management endpoints (Spring Actuator, `/debug`, `/health` with sensitive data)
- [ ] Verbose error messages leaking stack traces, file paths, or SQL queries
- [ ] Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS)
- [ ] XXE: unsafe XML parser configuration (external entities enabled)

### A06: Vulnerable Components
- [ ] Known CVEs in dependencies (check version numbers in pom.xml, package.json)
- [ ] Outdated frameworks with known security issues

### A07: Authentication Failures
- [ ] Weak password requirements (no complexity, short minimum length)
- [ ] Missing brute-force protection
- [ ] Session fixation (session ID not regenerated after login)
- [ ] Insecure session cookies (missing `httpOnly`, `secure`, `sameSite`)
- [ ] JWT issues: weak secret, missing expiry, algorithm confusion (`alg: none`), no audience/issuer validation

### A08: Software and Data Integrity Failures
- [ ] Unsafe deserialization: `ObjectInputStream.readObject()`, Jackson `@JsonTypeInfo` with default typing
- [ ] Missing integrity checks on data from external sources

### A09: Logging and Monitoring Failures
- [ ] Sensitive data logged (passwords, tokens, PII)
- [ ] Missing audit logging for security-relevant actions (login, access control decisions)

### A10: SSRF
- [ ] User-controlled URLs passed to HTTP client (`RestTemplate`, `WebClient`, `fetch`, `axios`, `http.request`)
- [ ] URL validation bypass (IP address tricks, DNS rebinding, redirect chains)

## OWASP API Security Top 10 (2023)

### API1: Broken Object-Level Authorization (BOLA)
- [ ] Endpoint accepts object ID and returns data without verifying the caller owns that object
- [ ] Bulk operations that don't check ownership per item

### API2: Broken Authentication
- [ ] Missing authentication on API endpoints
- [ ] Weak token generation or validation
- [ ] Token doesn't expire or has very long expiry

### API3: Broken Object Property Level Authorization
- [ ] API response exposes internal/sensitive fields (password hashes, internal IDs, roles)
- [ ] Mass assignment: request body bound directly to data model without field allowlist

### API4: Unrestricted Resource Consumption
- [ ] No rate limiting on any endpoint
- [ ] No pagination — single request can dump entire dataset
- [ ] File upload with no size limit

### API5: Broken Function-Level Authorization
- [ ] Regular user can access admin API endpoints
- [ ] No role check before executing privileged operations

### API6: Unrestricted Access to Sensitive Business Flows
- [ ] No protection against automated abuse (bot purchasing, mass account creation)

### API7: Server-Side Request Forgery (SSRF)
- [ ] Same as A10 above — user-supplied URLs fetched by server

### API8: Security Misconfiguration
- [ ] Same as A05 — plus API-specific: missing input validation, permissive CORS, exposed API docs in production

### API9: Improper Inventory Management
- [ ] Old or deprecated API versions still accessible
- [ ] Debug/test endpoints exposed in production

### API10: Unsafe Consumption of APIs
- [ ] Trusting data from third-party APIs without validation
- [ ] Following redirects from external APIs blindly
