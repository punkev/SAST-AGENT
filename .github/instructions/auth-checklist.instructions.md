# Authentication, Authorization, Token & Session Security Checklist

Use this checklist to perform an exhaustive, deep-dive static security audit of all authentication mechanisms, token implementations (JWT/PASETO), OAuth2/OIDC flows, session lifecycles, and access control models across the codebase.

---

## 1. JSON Web Token (JWT) & Token Security (CWE-345, CWE-347, CWE-287)

### A. Algorithm Confusion & Signature Verification Bypasses
- [ ] **Acceptance of `alg: none` (CWE-327)**:
  - JWT verification libraries configured to accept unsigned tokens or `"alg": "none"`.
  - Must explicitly enforce cryptographic algorithms (e.g., `algorithms = ["RS256"]` or `algorithms = ["HS256"]`).
- [ ] **Key Confusion / Asymmetric vs Symmetric Confusion**:
  - Verification logic using an RSA/ECDSA public key with HMAC verification (`jwt.verify(token, publicKey, { algorithms: ['HS256'] })`).
  - An attacker signs a token using the server's public key as an HMAC secret key.
  - Must strictly bind the expected algorithm to the key type.
- [ ] **Decoding Without Verification (CWE-345)**:
  - Use of `jwt.decode()` instead of `jwt.verify()` or parsing token payload before verifying signature.
  - Passing untrusted token claims to authorization logic without verifying signature validity first.
- [ ] **JWKS Header Injection (`jku`, `x5u`, `jwk`) (CWE-347)**:
  - Trusting user-supplied `jku` (JSON Web Key Set URL) or `x5u` headers to fetch verification keys from arbitrary attacker servers.
  - Must only fetch JWKS from hardcoded, trusted server-side whitelist domains.

### B. Claim Validation & Expiration
- [ ] **Missing Expiration (`exp`) Validation**:
  - JWT library called with `ignoreExpiration: true` or missing `exp` claim check.
  - Tokens without expiration or tokens with excessively long lifespans (>24 hours) without refresh token rotation.
- [ ] **Missing Audience (`aud`) & Issuer (`iss`) Validation**:
  - Failing to verify that `aud` matches the receiving service and `iss` matches the authentic authorization server.
  - Allows tokens issued for Service A to be reused against Service B.
- [ ] **Missing Not-Before (`nbf`) Handling**:
  - Tokens accepted before their valid active window.

### C. Secret Key Hygiene & Storage
- [ ] **Weak Symmetric Secrets (CWE-798, CWE-326)**:
  - Using HMAC secret keys shorter than 256 bits (32 bytes) or using hardcoded dictionary words (`"secret"`, `"jwt-secret"`).
- [ ] **Insecure Client-Side Storage**:
  - Frontend storing access/refresh tokens in `localStorage` or `sessionStorage` (accessible to any XSS payload).
  - Must store sensitive tokens in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.

---

## 2. OAuth2 & OpenID Connect (OIDC) Implementation (CWE-287, CWE-352, CWE-601)

### A. CSRF & State Parameter Validation
- [ ] **Missing or Predictable `state` Parameter (CWE-352)**:
  - Authorization request sent without an unpredictable, cryptographically random `state` parameter bound to the user's session.
  - Callback endpoint (`/oauth/callback`) does not verify that the returned `state` matches the session state.
  - Enables **Login CSRF**, forcing victim users into attacker accounts.

### B. Redirect URI Validation & Open Redirects
- [ ] **Permissive `redirect_uri` Matching (CWE-601)**:
  - Authorization server or client using prefix matching, wildcard matching (`*.example.com`), or loose regular expressions for `redirect_uri`.
  - Attacker bypasses validation (e.g., `example.com.attacker.com` or `example.com/oauth/callback/../../evil`) to steal authorization codes.
  - Must enforce exact string equality on registered redirect URIs.

### C. Grant Types & PKCE Enforcement
- [ ] **Insecure Implicit Grant in Modern SPAs**:
  - Single Page Applications (SPAs) or mobile apps using the deprecated Implicit Flow (`response_type=token`), returning access tokens directly in URL fragments.
  - Must use **Authorization Code Flow with PKCE** (`Proof Key for Code Exchange`).
- [ ] **Missing PKCE on Public Clients**:
  - SPAs and mobile apps not implementing `code_challenge` (S256) and `code_verifier`, enabling authorization code interception attacks.
- [ ] **Hardcoded Client Secrets in Public Clients**:
  - Embedding `client_secret` in frontend JS bundles, mobile apps, or public desktop clients.

### D. Token Exchange & Scope Escalation
- [ ] **ID Token as Access Token Confusion**:
  - Accepting an OpenID Connect `id_token` as an authorization bearer token to call backend APIs.
- [ ] **Scope / Permission Elevation**:
  - Granting requested scopes without evaluating user authorization policies.

---

## 3. Session Lifecycle & Cookie Security (CWE-384, CWE-613, CWE-1004)

### A. Session Fixation & Rotation
- [ ] **Missing Session Regeneration on Login (CWE-384)**:
  - Retaining pre-authentication session IDs after successful authentication.
  - Must invoke `request.changeSessionId()` (Servlet) or regenerate session ID upon privilege changes.
- [ ] **Missing Logout Invalidation (CWE-613)**:
  - Logout endpoint only clears browser cookies without destroying server-side session state in Redis/database.
  - For stateless JWTs, missing token revocation blacklist (JTI blocklist) upon logout or password reset.

### B. Cookie Security Attributes
- [ ] **Missing `HttpOnly`**:
  - Session cookies accessible to client-side scripts via `document.cookie`.
- [ ] **Missing `Secure` Flag**:
  - Cookies transmitted over unencrypted HTTP connections.
- [ ] **Missing or Insecure `SameSite` Attribute**:
  - Cookies with `SameSite=None` without explicit `Secure` flag, or cookies lacking `SameSite` entirely (leaving them vulnerable to CSRF).
- [ ] **Missing Secure Prefixes**:
  - Sensitive domain-scoped cookies not using `__Host-` or `__Secure-` prefixes to protect against subdomain cookie tossing.

---

## 4. Access Control & Multi-Tenant Isolation (CWE-284, CWE-639, CWE-862)

### A. Broken Object-Level Authorization (BOLA / IDOR)
- [ ] **Missing Tenant / Owner Scope in Data Queries**:
  - Repository methods fetching entities purely by identifier: `findById(id)` without asserting `and organizationId = :currentOrgId` or `and userId = :currentUserId`.
  - Attacker mutates URL parameters (`/api/invoices/1042` ➔ `/api/invoices/1043`) to view or modify unauthorized tenant data.

### B. Missing Function-Level Access Control (Vertical Privilege Escalation)
- [ ] **Unprotected Administrative Endpoints**:
  - Sensitive business routes (`/api/admin/**`, `/api/users/delete`, `/api/billing/**`) lacking `@PreAuthorize("hasRole('ADMIN')")`, `@Secured`, or role guards.
- [ ] **Mass Assignment Privilege Escalation (CWE-915)**:
  - Binding request bodies directly to user account entities containing `role`, `isAdmin`, `isSuperuser`, or `verified` properties.

### C. Multi-Tenant Cache & Context Leaks
- [ ] **Tenant Bleed in Shared Resources**:
  - Caching sensitive user data in Redis without tenant prefixes in cache keys (`cache:user:{id}` instead of `cache:tenant:{orgId}:user:{id}`).
  - Static or ThreadLocal context holders retaining tenant data across pooled worker threads without clearing in `finally` blocks.
