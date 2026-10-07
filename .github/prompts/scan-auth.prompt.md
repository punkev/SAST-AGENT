# Full Authentication, Token & Access Control Audit

Execute an exhaustive security audit of all authentication mechanisms, JWT/token validations, OAuth2/OIDC flows, session lifecycles, and access control models across the codebase using the `@sast-auth` agent.

## Execution Instructions

1. **Scope**: Inspect all security filters, token handlers, OAuth callbacks, session stores, authorization annotations, and data queries across attached codebases.
2. **Sequential Run Output**:
   - Check `.sast-agent/output/` for existing `Auth Check Run <N>` directories.
   - Increment to the next sequential run directory: `.sast-agent/output/Auth Check Run {N+1}/`.
   - Store findings in `findings.md`, inventory checklist in `scan-progress.md`, structured findings in `findings.json`, and management report in `summary.md`.
3. **Audit Coverage**:
   - JWT algorithm confusion (`alg: none`, HMAC vs RSA), `decode()` without `verify()`, missing `exp`/`nbf`/`iss`/`aud`, weak static secrets, JWKS injection.
   - OAuth2/OIDC missing `state` parameter (Login CSRF), permissive `redirect_uri` regex bypasses, implicit flow in SPAs, missing PKCE on public clients.
   - Session fixation, lack of invalidation on logout/password reset, missing `HttpOnly`/`Secure`/`SameSite` cookie flags.
   - Broken Object-Level Authorization (BOLA/IDOR), missing tenant isolation in queries, missing `@PreAuthorize` role guards, mass assignment privilege escalation.
4. **Mandatory Reporting Requirements**:
   - Clickable file and line link (`file:///` URI format).
   - Real vulnerable code snippet copied verbatim.
   - Secure code fix demonstrating safe token verification, role enforcement, or tenant scoping.
   - Sample Burp Suite HTTP request illustrating the exploit vector.
   - Non-technical plain-English justification of business risk and impact.

Do not modify application source code.
