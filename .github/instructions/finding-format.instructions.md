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
**Scan Mode**: Two-Pass Deep Taint & Surface Analysis

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

## 2. Standard Individual Finding Format

Each standard finding must follow this template:

```markdown
## FINDING-{NNN}: {Descriptive Title} [{SEVERITY}]

**Severity**: `{CRITICAL | HIGH | MEDIUM | LOW | NEEDS-REVIEW}`
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

### Secure Fix
```{lang}
{production_ready_remediated_code_with_comments}
```

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

## 3. Composite Exploit Chain Structure

Use this format when chaining 2 or 3 indirect, lower-severity, or subtle issues into an escalated composite attack path:

```markdown
## COMPOSITE-{NNN}: {Title} [{ESCALATED SEVERITY}]

**Chained Vulnerabilities**: `FINDING-001` (Info Leak) + `FINDING-004` (Missing Auth Guard) + `FINDING-009` (Mass Assignment)
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

## 4. Dedicated SQL Injection Finding Structure (`FINDING-SQL-{NNN}`)

Use this specialized structure for all SQL injection vulnerabilities (Classic, Blind, 2nd-Order, Native Query, PL/SQL, ORM, Dynamic Order By, etc.). 

**Mandatory Requirements for Every SQL Finding:**
1. Clickable file and line number hyperlink.
2. Vulnerable code snippet directly from the codebase.
3. Secure code fix refactored for the specific language/framework.
4. Sample Burp Suite raw HTTP request **ALWAYS included for EVERY issue reported**.
5. Mermaid dataflow flowchart tracing the path from the front-end user to the database engine.
6. Non-technical explanation explaining why the issue happened and the business risk.

```markdown
## FINDING-SQL-{NNN}: {Title} [{SEVERITY}]

**Injection Sub-Type**: {Native Query | Blind (Time/Boolean) | 2nd Order | PL/SQL Stored Procedure | Classic In-Band | Dynamic Clause/Identifier}
**CWE**: CWE-89 (SQL Injection) | **OWASP**: A03:2021-Injection
**File**: [`{relative/path/to/file.ext}:L{start}-L{end}`](file:///{absolute_path}#L{start}-L{end})
**Endpoint / Component**: `{HTTP_METHOD} {route}` → `{ClassName}.{methodName}()`

### Dataflow Flowchart (Front-End User to Database)
```mermaid
flowchart TD
    A["Front-End User / Client\n(Submits HTTP request)"] -->|Untrusted param: '{param_name}'| B["Controller / Route Handler\n({ControllerFile}:L{line})"]
    B -->|Transfers unvalidated input| C["Service / Business Layer\n({ServiceFile}:L{line})"]
    C -->|Concatenates raw input into SQL string| D["Repository / DAO Sink\n({RepositoryFile}:L{line})"]
    D -->|Executes dynamic unparameterized query| E["Database Engine\n({DB_Engine} Execution)"]
```

### Non-Technical Justification (Why This Occurred & Business Risk)
{Plain-English explanation tailored for non-technical stakeholders (management, product owners, auditors) explaining:
1. Why it happened: How the application combined user-provided text directly into database commands instead of treating it as untrusted data.
2. The risk: How an attacker can manipulate this command to view unauthorized records, alter data, or bypass authentication.}

### Request / Control Flow Trace
1. {Entry point parameter binding with file and line}
2. → {Service layer invocation passing input}
3. → {Database sink executing dynamic query with file and line} — **SINK**

### Vulnerable Code
```{language}
{Actual vulnerable code snippet from the codebase}
```

### Secure Code Fix
```{language}
{Corrected implementation using parameterized queries, PreparedStatement, or allowlist}
```

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
**Expected Behavior**: {What the server responds with, illustrating how input altered query structure}

---
```

---

## 5. Strict Quality Rules & Guidelines

1. **Zero Hallucination / Real Code Only**:
   - Every snippet in `Vulnerable Code` MUST be copied verbatim from files read in the attached workspace.
   - Do NOT use dummy paths like `/path/to/file` or placeholder variables like `userInput`.
2. **Clickable File & Line Markdown Links**:
   - All file references must use standard `[`Basename.ext:L#-#`](file:///absolute/path/to/file.ext#L{start}-L{end})` format so developers can click directly from the report to the offending code in VS Code.
3. **Explicit Source-to-Sink Trace**:
   - Every finding MUST have a step-by-step trace showing untrusted input entering the application and reaching an unvalidated sink.
   - If a sink cannot be proven reachable from an untrusted entry point, mark it as `[NEEDS-REVIEW]`.
4. **Functional Burp Suite PoCs**:
   - PoCs must use realistic RFC 7230 HTTP syntax with accurate endpoints, methods, headers, and exploit payloads (e.g. SQLi sleep commands, SSTI expressions, traversal sequences, SSRF targets).
   - **For all SQL findings (`sast-sql`)**: A Burp Suite sample request is **ALWAYS required** on every finding regardless of severity.
5. **Redaction of Discovered Secrets**:
   - Never print entire hardcoded passwords, tokens, or private keys. Always mask: `AKIA...7FQ2` or `jwt_secret = "s3cr..."`.
6. **No Placeholder Content**:
   - Do NOT use placeholder text like "N/A", "TBD", "Generic sink call".
   - Do NOT omit the Mermaid flowchart or non-technical justification on any SQL injection finding.

---

## Grouping Duplicates

If the same vulnerability pattern appears in multiple files (e.g., SQL injection via string concatenation in 5 different repositories), write ONE finding that lists all affected locations:

```markdown
### Affected Locations
- `UserRepository.java` L45: `"SELECT * FROM users WHERE id = " + id`
- `OrderRepository.java` L23: `"SELECT * FROM orders WHERE user_id = " + userId`
- `ProductRepository.java` L67: `"SELECT * FROM products WHERE name LIKE '%" + name + "%'"`
```
