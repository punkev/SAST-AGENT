# Prompts for Converting PDF Reports to Retest Issue `.md` Files

Use these prompts with any AI chat agent (ChatGPT, Gemini, Claude, etc.). Upload/attach the PDF vulnerability report alongside the prompt.

---

## Prompt 1: Extract a SINGLE Issue

Copy and paste this prompt into your AI chat, then attach the PDF report:

---

```
I have attached a PDF vulnerability/penetration testing report. Extract ONLY the following issue from it:

**Issue to extract**: [PASTE THE ISSUE NAME OR TITLE HERE]

Format the output as a markdown file using this EXACT structure. Fill in every field from the report — do not leave any field blank. If a field is not explicitly stated in the report, infer it from the context or mark it as "Not specified in report":

---

## Issue 1

### Issue Name
{The exact vulnerability title from the report}

### Vulnerability Type
{e.g., SQL Injection, XSS, SSTI, SSRF, RCE, IDOR, Path Traversal, Race Condition, Hardcoded Secret, Broken Access Control, CSRF, Insecure Deserialization, etc.}

### CWE
{The CWE ID, e.g., CWE-89. If the report doesn't list one, determine the correct CWE based on the vulnerability type.}

### Original Severity
{CRITICAL | HIGH | MEDIUM | LOW — use the severity from the report}

### Issue Description
{Detailed description of the vulnerability. Include: what the flaw is, what component/endpoint is affected, what the security impact is. Pull this directly from the report's description/details section.}

### Steps to Reproduce / Attack Vector
1. {Step 1 from the report — include the exact URL, endpoint, or parameter}
2. {Step 2 — include the payload or action taken}
3. {Step 3 — describe the observed result proving the vulnerability}
{Add more steps as needed based on the report}

### Affected File(s) and Line(s)
- `{path/to/affected/file}` — Lines {start}-{end}
{If the report doesn't specify exact files/lines, list the affected endpoint, component, or module instead, e.g.:}
- Endpoint: `POST /api/v1/users/search`
- Component: `UserController > searchUsers()`

### Target Host
{The target host/URL from the report, e.g., app.example.com:8443 or the IP:port used during testing}

### Original Finding Reference
{The finding ID from the report if one exists, e.g., VULN-001, Finding 3.1, Issue #5, etc.}

### Additional Context
{Any extra context from the report: affected framework/version, screenshots described, related findings, remediation suggestions from the original report, CVSS score if provided, etc.}

---

Output ONLY the markdown content above — no commentary, no explanation, no code fences wrapping the entire output. The output should be ready to save directly as a `.md` file.
```

---

## Prompt 2: Extract ALL Issues (Multiple Issues in One File)

Copy and paste this prompt into your AI chat, then attach the PDF report:

---

```
I have attached a PDF vulnerability/penetration testing report. Extract ALL vulnerabilities/issues from the report and format them into a SINGLE markdown file.

For EACH issue found in the report, create a section using this EXACT structure. Number them sequentially (Issue 1, Issue 2, Issue 3, etc.):

---

## Issue {N}

### Issue Name
{The exact vulnerability title from the report}

### Vulnerability Type
{e.g., SQL Injection, XSS, SSTI, SSRF, RCE, IDOR, Path Traversal, Race Condition, Hardcoded Secret, Broken Access Control, CSRF, Insecure Deserialization, etc.}

### CWE
{The CWE ID, e.g., CWE-89. If the report doesn't list one, determine the correct CWE based on the vulnerability type.}

### Original Severity
{CRITICAL | HIGH | MEDIUM | LOW — use the severity from the report}

### Issue Description
{Detailed description of the vulnerability. Include: what the flaw is, what component/endpoint is affected, what the security impact is. Pull this directly from the report's description/details section.}

### Steps to Reproduce / Attack Vector
1. {Step 1 from the report — include the exact URL, endpoint, or parameter}
2. {Step 2 — include the payload or action taken}
3. {Step 3 — describe the observed result proving the vulnerability}
{Add more steps as needed based on the report}

### Affected File(s) and Line(s)
- `{path/to/affected/file}` — Lines {start}-{end}
{If the report doesn't specify exact files/lines, list the affected endpoint, component, or module instead, e.g.:}
- Endpoint: `POST /api/v1/users/search`
- Component: `UserController > searchUsers()`

### Target Host
{The target host/URL from the report, e.g., app.example.com:8443 or the IP:port used during testing}

### Original Finding Reference
{The finding ID from the report if one exists, e.g., VULN-001, Finding 3.1, Issue #5, etc.}

### Additional Context
{Any extra context from the report: affected framework/version, screenshots described, related findings, remediation suggestions from the original report, CVSS score if provided, etc.}

---

IMPORTANT RULES:
1. Extract EVERY vulnerability from the report — do not skip any, regardless of severity.
2. Separate each issue with a `---` horizontal rule.
3. Number issues sequentially starting from Issue 1.
4. Fill in every field — do not leave any blank. If a field is not in the report, infer it or write "Not specified in report".
5. For CWE: if the report does not list a CWE ID, determine the correct one based on the vulnerability type.
6. For Steps to Reproduce: use the exact endpoints, parameters, and payloads from the report. If the report only provides a description without explicit steps, reconstruct logical steps from the description.
7. For Affected Files: if the report only lists endpoints (not source files), list the endpoints and components instead.
8. Keep the Target Host consistent across all issues (use the primary target from the report).
9. At the TOP of the output, add this summary header:

# Retest Issues — {Application/Project Name from Report}

**Source Report**: {Report title or filename}
**Date of Original Assessment**: {Date from the report}
**Total Issues Extracted**: {count}

| Severity | Count |
|---|---|
| CRITICAL | {count} |
| HIGH | {count} |
| MEDIUM | {count} |
| LOW | {count} |
| **Total** | **{total}** |

---

10. Output ONLY the markdown content — no commentary, no explanation, no code fences wrapping the entire output. The output should be ready to save directly as a `.md` file.
```

---

## Usage Instructions

1. Open your AI chat agent (ChatGPT, Gemini, Claude, etc.)
2. Upload / attach the PDF penetration test report
3. Paste one of the prompts above:
   - **Prompt 1** if you want to retest a specific single issue
   - **Prompt 2** if you want to extract everything for a full retest pass
4. Copy the AI's markdown output
5. Save it as a `.md` file (e.g., `retest-issues.md`)
6. Place the file in your target project workspace or attach it in VS Code Copilot Chat
7. Run `@sast-retest /retest`

