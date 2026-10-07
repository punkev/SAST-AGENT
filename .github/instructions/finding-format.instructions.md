# SAST Finding Format Specification

Every finding in `.sast-agent/output/findings.md` must adhere strictly to the structured markdown format below.

---

## 1. Document Header & Executive Summary

When `findings.md` is created or finalized, it must begin with the Executive Summary:

```markdown
# Static Application Security Testing (SAST) Report

**Generated**: {timestamp}
**Target Project**: {project_name_or_folder}
**Ecosystem**: {Java / Spring Boot | Node.js / Express / NestJS | Polyglot}
**Scan Mode**: Two-Pass Deep Taint & Multi-Surface Analysis

## Executive Summary

| Severity | Count |
|---|---|
| 🔴 **CRITICAL** | {count} |
| 🟠 **HIGH** | {count} |
| 🟡 **MEDIUM** | {count} |
| 🔵 **LOW** | {count} |
| ⚪ **NEEDS-REVIEW** | {count} |
| **Total** | **{total_count}** |

---
```

---

## 2. Standard Individual Finding Format (`FINDING-{NNN}`)

Each standard code vulnerability must follow this template:

```markdown
## FINDING-{NNN}: {Descriptive Title} [{SEVERITY}]

**Severity**: `{CRITICAL | HIGH | MEDIUM | LOW | NEEDS-REVIEW}`
**Exploitability Tier**: `{🔴 Remotely Exploitable (Public) | 🟠 Authenticated / Role-Restricted | 🟡 Internal / Lateral Movement | ⚪ Defense-in-Depth / Conditional}`
**Remediation Effort**: `{Trivial (<30 mins) | Moderate (1–4 hours) | Architectural Refactor (>1 day)}`
**CVSS v3.1**: `{Score}` (`{Vector String, e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}`)
**CWE**: `CWE-{ID}`: {CWE Name}
**Taxonomy / Standard**: `{OWASP Web Top 10 | OWASP API Top 10 | CWE Top 25 | SANS Top 25}`
**File**: [`{basename.ext}:{start}-{end}`](file:///{absolute/path/to/file.ext}#L{start}-L{end}) (Lines {start}-{end})
**Surface Type**: `{REST / MVC Endpoint | WebFlux Route | Message Queue Consumer | Background Scheduler | Template Engine View | File Upload Handler | Security Filter / Interceptor | Configuration}`
**Entry Point**: `{HTTP_METHOD} {route}` OR `{Listener: queue_name}` OR `{View: template_name}` OR `{Handler: upload_or_filter_name}`

### Request Flow (Source to Sink)
1. **Source**: `{Entry point signature / parameter}` in [`{source_file}:{line}`](file:///{path/to/source_file}#L{line})
2. **Transform / Service**: `{method_call()}` in [`{service_file}:{line}`](file:///{path/to/service_file}#L{line})
3. **Sink**: `{sink_call()}` in [`{sink_file}:{line}`](file:///{path/to/sink_file}#L{line}) — **[DANGEROUS SINK]**

### Impact
{Clear, specific explanation of the security risk and attacker capabilities upon exploitation. Avoid generic boilerplate.}

### Vulnerable Code
```{lang}
// {relative/path/to/file.ext} Lines {start}-{end}
{exact_code_from_the_project}
```

### Secure Fix (Git Unified Diff)
```diff
--- a/{relative/path/to/file.ext}
+++ b/{relative/path/to/file.ext}
@@ -{line},{count} +{line},{count} @@
- {vulnerable_lines_to_remove}
+ {remediated_lines_to_add}
```
*{Brief explanation of what the diff changes and why it neutralizes the vulnerability.}*

### Remediation Steps
1. {Actionable step 1}
2. {Actionable step 2}
3. {Actionable step 3}

### Burp Suite / RFC 7230 HTTP PoC *(Mandatory for Critical & High)*
```http
{METHOD} {path_or_route} HTTP/1.1
Host: {target_host_or_localhost}
User-Agent: Mozilla/5.0 (Security Audit)
Authorization: Bearer <VALID_OR_EXPIRED_JWT>
Content-Type: application/json
Content-Length: {length}

{payload_with_exploit_marker}
```

**Expected Server Response / Verification Indicator**:
- **Exploitation Indicator**: {Exact behavior indicating success, e.g., HTTP 200 OK with time delay, reflection in response body, stack trace echo, unauthorized record retrieval}
- **Safe Baseline Response**: {Normal expected HTTP 400 Bad Request or HTTP 403 Forbidden when properly mitigated}

---
```

---

## 3. Composite Exploit Chain Structure (`COMPOSITE-{NNN}`)

Use this format when chaining 2 or 3 indirect, lower-severity, or subtle issues into an escalated composite attack path:

```markdown
## COMPOSITE-{NNN}: {Title} [{ESCALATED SEVERITY}]

**Chained Vulnerabilities**: `FINDING-001` (Info Leak) + `FINDING-004` (Missing Auth Guard) + `FINDING-009` (Mass Assignment)
**Exploitability Tier**: `{🔴 Remotely Exploitable (Public) | 🟠 Authenticated / Role-Restricted | 🟡 Internal / Lateral Movement}`
**Remediation Effort**: `{Moderate (1–4 hours) | Architectural Refactor (>1 day)}`
**Primary Affected File**: [`{basename.ext}:{start}-{end}`](file:///{absolute/path/to/primary_file.ext}#L{start}-L{end})
**Target Endpoint**: `{HTTP_METHOD} {route}`

### Chained Attack Flow
1. **Step 1 (Initial Prerequisite)**: {Attacker leverages Finding 1 (e.g. extracts internal ID format / hash key) from `FileA.java` L12-L24}
2. **Step 2 (Bypass / Access)**: → {Attacker reaches unauthenticated internal endpoint in `FileB.java` L45-L58}
3. **Step 3 (Escalated Exploit)**: → {Attacker triggers mass assignment / state corruption in `FileC.java` L89-L102} — **ESCALATED IMPACT**

### Escalated Impact
{Detailed explanation of how combining these subtle issues yields a Critical/High impact (e.g. Account Takeover, Admin Privilege Escalation, Remote Code Execution).}

### Composite Attack Evidence & Payload
{Step-by-step PoC instructions / HTTP request templates detailing how the chain is executed sequentially.}

### Unified Remediation Strategy
{Comprehensive fix addressing each link in the exploit chain to break the attack path completely.}

---
```

---

## 4. Dedicated Injection Finding Structure (`FINDING-INJ-{NNN}`)

Use this specialized structure for all injection-based vulnerabilities (SQLi, NoSQLi, OS Command Injection, Code Evaluation, SSTI, SpEL/EL, LDAP, XPath/XXE, CRLF/Log Injection, Server-Side XSS, Header Injection, CSV Formula Injection, SSRF). 

**Mandatory Requirements for Every Injection Finding:**
1. Clickable file and line number hyperlink.
2. Vulnerable code snippet directly from the codebase.
3. Secure code fix formatted as a Git Unified Diff (`diff`).
4. Exploitability tier and remediation effort estimates.
5. Sample Burp Suite raw HTTP request **ALWAYS included for EVERY issue reported**.
6. Mermaid dataflow flowchart tracing the path from the untrusted client/input to the target execution engine/sink.
7. Non-technical explanation explaining why the issue happened and the business risk.

```markdown
## FINDING-INJ-{NNN}: {Title} [{SEVERITY}]

**Injection Category**: {SQL Injection | NoSQL Injection | OS Command Injection | Code Evaluation | SSTI | SpEL / EL Injection | LDAP Injection | XPath / XXE | Log Injection (CRLF) | Server-Side XSS | Header Injection | CSV Formula Injection | SSRF}
**Exploitability Tier**: `{🔴 Remotely Exploitable (Public) | 🟠 Authenticated / Role-Restricted | 🟡 Internal / Lateral Movement | ⚪ Defense-in-Depth / Conditional}`
**Remediation Effort**: `{Trivial (<30 mins) | Moderate (1–4 hours) | Architectural Refactor (>1 day)}`
**CWE**: CWE-{ID} ({CWE Name}) | **OWASP**: A03:2021-Injection
**File**: [`{relative/path/to/file.ext}:L{start}-L{end}`](file:///{absolute_path}#L{start}-L{end})
**Endpoint / Component**: `{HTTP_METHOD} {route}` → `{ClassName}.{methodName}()`

### Dataflow Flowchart (Client Input to Execution Sink)
```mermaid
flowchart TD
    A["Front-End User / Client\n(Submits untrusted payload)"] -->|Untrusted input: '{param_name}'| B["Controller / Route Handler\n({ControllerFile}:L{line})"]
    B -->|Transfers unvalidated input| C["Service / Business Layer\n({ServiceFile}:L{line})"]
    C -->|Constructs dynamic command/query/expression| D["Dangerous Sink\n({SinkFile}:L{line})"]
    D -->|Executes instruction directly| E["Target System / Engine / Shell\n({ExecutionEngine})"]
```

### Non-Technical Justification (Why This Occurred & Business Risk)
{Plain-English explanation tailored for non-technical stakeholders (management, product owners, auditors) explaining:
1. Why it happened: How the application combined user-provided text directly into system instructions, database queries, templates, or shell commands instead of treating it as untrusted passive data.
2. The risk: How an attacker can manipulate this command to view unauthorized records, execute arbitrary code, compromise the server, or bypass authentication.}

### Request / Control Flow Trace
1. {Entry point parameter binding with file and line}
2. → {Service layer invocation passing input}
3. → {Dangerous sink executing dynamic command/query with file and line} — **SINK**

### Vulnerable Code
```{language}
{Actual vulnerable code snippet from the codebase}
```

### Secure Fix (Git Unified Diff)
```diff
--- a/{relative/path/to/file.ext}
+++ b/{relative/path/to/file.ext}
@@ -{line},{count} +{line},{count} @@
- {unvalidated_query_or_concatenation}
+ {parameterized_statement_or_allowlist_fix}
```
*{Brief explanation of what the diff changes and why it neutralizes the injection.}*

### Remediation Steps
1. {Step 1: Specific coding change required}
2. {Step 2: Testing or verification required}

### Burp Suite Sample Request (Mandatory for Every Finding)
```http
{RAW_HTTP_METHOD} {path_with_query_or_body} HTTP/1.1
Host: {target_host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: {application/json | application/x-www-form-urlencoded}
Authorization: Bearer {token_placeholder_if_auth_required}

{request_body_with_injection_test_parameter}
```
**Vulnerable Parameter / Header**: `{parameter_name}`
**Expected Behavior**: {What the server responds with, illustrating how input altered command or query execution}

---
```

---

## 5. Dedicated Authentication & Access Control Finding Structure (`FINDING-AUTH-{NNN}`)

Use this specialized structure for all authentication, JWT/token, OAuth2/OIDC, session lifecycle, and Broken Object-Level Authorization (BOLA/IDOR) flaws.

**Mandatory Requirements for Every Auth Finding:**
1. Clickable file and line number hyperlink.
2. Exploitability tier and remediation effort estimate.
3. Impersonation / Privilege Matrix illustrating attacker vs. compromised context.
4. Token / Claims breakdown (for JWT/token flaws).
5. Vulnerable code snippet and Git Unified Diff (`diff`) secure fix.
6. Sample Burp Suite raw HTTP request demonstrating unauthorized access or bypass.

```markdown
## FINDING-AUTH-{NNN}: {Title} [{SEVERITY}]

**Auth Category**: {JWT Algorithm / Signature Bypass | Missing Claim Validation | OAuth2 / OIDC State / CSRF | Session Fixation / Invalidation | BOLA / IDOR | Broken Access Control / Missing Guard | Mass Assignment Privilege Escalation}
**Exploitability Tier**: `{🔴 Remotely Exploitable (Public / Unauthenticated) | 🟠 Authenticated (Low Privilege) | 🟡 Cross-Tenant / Lateral | ⚪ Defense-in-Depth}`
**Remediation Effort**: `{Trivial (<30 mins) | Moderate (1–4 hours) | Architectural Refactor (>1 day)}`
**CWE**: CWE-{ID} ({CWE Name}) | **OWASP**: A01:2021-Broken Access Control OR A07:2021-Identification and Authentication Failures
**File**: [`{relative/path/to/file.ext}:L{start}-L{end}`](file:///{absolute_path}#L{start}-L{end})
**Endpoint / Guard**: `{HTTP_METHOD} {route}` → `{ClassName}.{methodName}()`

### Impersonation & Privilege Matrix
| Dimension | Attacker Baseline | Compromised Target / Escalation |
|---|---|---|
| **Identity / Role** | `{Anonymous | Role: USER}` | `{Target Account | Role: ADMIN}` |
| **Tenant Boundary** | `Tenant A (org_101)` | `Tenant B (org_202)` |
| **Bypass Mechanism** | `{Parameter Tampering / Missing Ownership Check / alg:none / Missing state}` | Full unauthorized data read / write access |

### Token / Claims Breakdown *(Include for JWT / Token findings)*
- **Header**: `{"alg": "none", "typ": "JWT"}` *(Signature verification bypassed)*
- **Payload**: `{"sub": "victim_id", "role": "admin", "exp": 9999999999}`
- **Signature**: `[EMPTY OR UNVALIDATED]`

### Request / Control Flow Trace
1. {Entry point parameter or token extraction with file and line}
2. → {Authorization filter or service method lacking tenancy/role assertion}
3. → {Data mutation or sensitive access without permission check} — **VIOLATION**

### Vulnerable Code
```{language}
{Actual vulnerable code snippet from the codebase}
```

### Secure Fix (Git Unified Diff)
```diff
--- a/{relative/path/to/file.ext}
+++ b/{relative/path/to/file.ext}
@@ -{line},{count} +{line},{count} @@
- {vulnerable_auth_or_query_line}
+ {enforced_tenant_scope_or_token_verification}
```
*{Explanation of the authorization enforcement or token validation added in the diff.}*

### Remediation Steps
1. {Step 1: Enforce role check, tenant filter, or cryptographic signature verification}
2. {Step 2: Add integration tests verifying 403 Forbidden on unauthorized tokens/tenants}

### Burp Suite Sample Request
```http
{METHOD} {route_with_tampered_id} HTTP/1.1
Host: {target_host}
Authorization: Bearer {tampered_or_unprivileged_token}
Content-Type: application/json

{payload}
```
**Exploit Mechanism**: {Explain how the request accesses the target resource without authorization}

---
```

---

## 6. Dedicated Infrastructure as Code & Container Finding Structure (`FINDING-IAC-{NNN}`)

Use this specialized structure for all Dockerfile, Kubernetes, Helm, Terraform, and CI/CD pipeline security findings.

**Mandatory Requirements for Every IaC Finding:**
1. Clickable file and line number hyperlink.
2. Resource Type & Resource Identifier (e.g. Pod name, service, task).
3. Benchmark / Hardening Guide Reference (CIS, NSA/CISA, OWASP CI/CD).
4. Blast Radius / Scope of Impact (container breakout, node compromise, cloud IAM takeover).
5. Vulnerable configuration snippet and Git Unified Diff (`diff`) secure fix.

```markdown
## FINDING-IAC-{NNN}: {Title} [{SEVERITY}]

**Resource Type**: `{Dockerfile | Docker Compose | Kubernetes Pod/Deployment | Helm Template | Terraform Resource | GitHub Actions Workflow}`
**Target Resource**: `{service_name | container_name | resource_block_id}`
**Hardening Standard**: `{CIS Docker Benchmark v1.6 | NSA/CISA Kubernetes Hardening Guide | CIS Kubernetes v1.8 | OWASP Top 10 CI/CD}`
**Exploitability Tier**: `{🔴 Remotely Exploitable | 🟠 Container Escape / Node Compromise | 🟡 Cluster Lateral Movement | ⚪ Defense-in-Depth}`
**Remediation Effort**: `{Trivial (<30 mins) | Moderate (1–4 hours) | Architectural Refactor (>1 day)}`
**CWE**: CWE-{ID} ({CWE Name})
**File**: [`{relative/path/to/manifest.ext}:L{start}-L{end}`](file:///{absolute_path}#L{start}-L{end})

### Blast Radius & Impact Scope
{Plain-English explanation of the security risk: What capabilities does this misconfiguration grant an attacker? (e.g., Root host filesystem write access via hostPath mount, arbitrary code execution in CI/CD pipeline with repository write secrets, unencrypted public S3 bucket allowing data breach).}

### Vulnerable Configuration
```{format}
{Actual vulnerable lines from the Dockerfile, YAML, HCL, or workflow file}
```

### Secure Fix (Git Unified Diff)
```diff
--- a/{relative/path/to/manifest.ext}
+++ b/{relative/path/to/manifest.ext}
@@ -{line},{count} +{line},{count} @@
- {insecure_directive_or_missing_security_context}
+ {hardened_non_root_read_only_or_pinned_directive}
```
*{Explanation of the hardened configuration applied in the diff.}*

### Remediation Steps
1. {Step 1: Specific manifest/Dockerfile modification required}
2. {Step 2: Verification command or container runtime validation}

---
```

---

## 7. Strict Quality Rules & Guidelines

1. **Zero Hallucination / Real Code Only**:
   - Every snippet in `Vulnerable Code` MUST be copied verbatim from files read in the attached workspace.
   - Do NOT use dummy paths like `/path/to/file` or placeholder variables like `userInput`.
2. **Clickable File & Line Markdown Links**:
   - All file references must use standard `[`Basename.ext:L#-#`](file:///absolute/path/to/file.ext#L{start}-L{end})` format so developers can click directly from the report to the offending code in VS Code.
3. **Mandatory Git Unified Diff Format**:
   - Every single `Secure Fix` across all templates MUST use the fenced ````diff ... ```` block showing explicit deletions (`-`) and additions (`+`).
4. **Mandatory Exploitability Tier & Remediation Effort**:
   - Every finding must declare its **Exploitability Tier** (`Remotely Exploitable`, `Authenticated`, `Internal`, `Defense-in-Depth`) and **Remediation Effort** (`Trivial`, `Moderate`, `Architectural Refactor`).
5. **Explicit Source-to-Sink Trace**:
   - Every code finding MUST have a step-by-step trace showing untrusted input entering the application and reaching an unvalidated sink.
   - If a sink cannot be proven reachable from an untrusted entry point, mark it as `[NEEDS-REVIEW]`.
6. **Functional Burp Suite PoCs**:
   - PoCs must use realistic RFC 7230 HTTP syntax with accurate endpoints, methods, headers, and exploit payloads.
   - **For all injection findings (`sast-injection`)**: A Burp Suite sample request is **ALWAYS required** on every finding regardless of severity.
7. **Redaction of Discovered Secrets**:
   - Never print entire hardcoded passwords, tokens, or private keys. Always mask: `AKIA...7FQ2` or `jwt_secret = "s3cr..."`.
8. **No Placeholder Content**:
   - Do NOT use placeholder text like "N/A", "TBD", "Generic sink call".
   - Do NOT omit the Mermaid flowchart or non-technical justification on any injection finding.

---

## 8. Grouping Duplicates

If the same vulnerability pattern appears in multiple files (e.g., SQL injection via string concatenation in 5 different repositories), write ONE finding that lists all affected locations:

```markdown
### Affected Locations
- `UserRepository.java` L45: `"SELECT * FROM users WHERE id = " + id`
- `OrderRepository.java` L23: `"SELECT * FROM orders WHERE user_id = " + userId`
- `ProductRepository.java` L67: `"SELECT * FROM products WHERE name LIKE '%" + name + "%'"`
```
