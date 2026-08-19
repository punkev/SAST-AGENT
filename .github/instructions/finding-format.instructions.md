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

## 2. Individual Finding Format

Each finding must follow this standard template:

```markdown
## FINDING-{NNN}: {Descriptive Title} [{SEVERITY}]

**Severity**: `{CRITICAL | HIGH | MEDIUM | LOW | NEEDS-REVIEW}`
**CVSS v3.1**: `{Score}` (`{Vector String, e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}`)
**CWE**: `CWE-{ID}`: {CWE Name}
**OWASP**: `{Web Top 10 Category | API Security Category}`
**File**: [`{basename.ext}:{start}-{end}`](file:///{absolute/path/to/file.ext}#L{start}-L{end}) (Lines {start}-{end})
**Surface Type**: `{REST / MVC Endpoint | WebFlux Route | Message Queue Consumer | Background Scheduler | Template Engine View | Security Filter / Interceptor | Configuration}`
**Entry Point**: `{HTTP_METHOD} {route}` OR `{Listener: queue_name}` OR `{View: template_name}`

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

## 3. Strict Quality Rules

1. **Zero Hallucination / Real Code Only**:
   - Every snippet in `Vulnerable Code` MUST be copied verbatim from files read in the attached workspace.
   - Do NOT use dummy paths like `/path/to/file` or placeholder variables like `userInput`.
2. **Clickable File & Line Markdown Links**:
   - All file references must use standard `[`Basename.ext:L#-#`](file:///absolute/path/to/file.ext#L{start}-L{end})` format so developers can click directly from the report to the offending code in VS Code.
3. **Explicit Source-to-Sink Trace**:
   - Every finding MUST have a step-by-step trace showing untrusted input entering the application and reaching an unvalidated sink.
   - If a sink cannot be proven reachable from an untrusted entry point, mark it as `[NEEDS-REVIEW]`.
4. **Functional Burp Suite PoCs for Actionable Exploitation**:
   - PoCs must use realistic RFC 7230 HTTP syntax with accurate endpoints, methods, headers, and exploit payloads (e.g. SQLi sleep commands, SSTI expressions, traversal sequences, SSRF targets).
5. **Redaction of Discovered Secrets**:
   - Never print entire hardcoded passwords, tokens, or private keys. Always mask: `AKIA...7FQ2` or `jwt_secret = "s3cr..."`.
