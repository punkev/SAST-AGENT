# Retest Issue Template

Use this template to describe vulnerabilities for retesting with `@sast-retest`. Copy and fill out one section per issue. Multiple issues can be included in a single file.

---

## Issue 1

### Issue Name
{Descriptive title of the vulnerability, e.g., "SQL Injection in User Search Endpoint"}

### Vulnerability Type
{e.g., SQL Injection, XSS, SSTI, SSRF, RCE, IDOR, Path Traversal, Race Condition, Hardcoded Secret, etc.}

### CWE
{e.g., CWE-89}

### Original Severity
{CRITICAL | HIGH | MEDIUM | LOW}

### Issue Description
{Detailed description of the vulnerability. What is the flaw? What component is affected? What is the impact?}

### Steps to Reproduce / Attack Vector
1. {Step 1: e.g., Navigate to POST /api/v1/users/search}
2. {Step 2: e.g., Supply a malicious payload in the "query" parameter}
3. {Step 3: e.g., Observe SQL error in response / unauthorized data returned}

### Affected File(s) and Line(s)
- `{relative/path/to/file.ext}` — Lines {start}-{end}
- `{relative/path/to/another-file.ext}` — Lines {start}-{end}

### Target Host
{The host to use in Burp Suite PoC requests, e.g., app.example.com:8443 or 192.168.1.50:8080}

### Original Finding Reference *(Optional)*
{If this issue came from a previous SAST report, reference the finding ID, e.g., FINDING-003 or FINDING-SQL-002}

### Additional Context *(Optional)*
{Any extra context: framework version, relevant config, related endpoints, known bypass attempts, etc.}

---

<!--
To add more issues, copy everything between the --- separators above and paste below.
Increment the issue number (Issue 2, Issue 3, etc.).
-->

## Issue 2

### Issue Name
{...}

### Vulnerability Type
{...}

### CWE
{...}

### Original Severity
{...}

### Issue Description
{...}

### Steps to Reproduce / Attack Vector
1. {...}
2. {...}
3. {...}

### Affected File(s) and Line(s)
- `{...}` — Lines {start}-{end}

### Target Host
{...}

### Original Finding Reference *(Optional)*
{...}

### Additional Context *(Optional)*
{...}

---

