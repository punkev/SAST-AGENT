# Finding Format Instructions

Every finding must contain exactly or clearly map to:
- **Title / Issue Name**: Descriptive name of the vulnerability.
- **Severity**: Critical, High, Medium, or Low.
- **Confidence**: High, Medium, or Low.
- **CWE/OWASP**: Relevant identifiers.
- **Affected File**: Must be explicitly hyperlinked using an absolute markdown link with line numbers (e.g., `[filename](file:///absolute/path/to/file#L123-L130)`).
- **Line/Function Anchor**: Specific line number and parent function name.
- **Affected Endpoint & Related Endpoints**: Routes affected by the issue.
- **Source & Sink**: The entry point of untrusted input and the vulnerable function where it is processed.
- **Data Flow**: Step-by-step trace showing the path of data from source to sink. This must represent a conceptual Control Flow Graph (CFG) trace, detailing every inter-procedural method call, parameter passing, variable assignment, transformation, and file boundary crossed.
- **Impact**: Detailed description of what an attacker can achieve by exploiting this issue.
- **PoC or Steps to Reproduce (Burp Suite)**: Clear instructions to reproduce the issue using Burp Suite. This MUST include sample/test HTTP requests (with method, headers, and body) formatted in plain text so they can be directly copied and pasted into Burp Suite Repeater/Intruder.
- **Vulnerable Code Snippet**: A fenced code block showing the exact vulnerable code.
- **Safe Implementation**: A fenced code block showing the secure, corrected implementation of the same function/logic.
- **False-Positive Checks & Rationale**: Explanation of why this is verified as a valid finding.
- **Status**: Must be classified as `confirmed`, `needs-review`, `duplicate`, or `false-positive`.

## Duplicate & Multi-File Issues
If a duplicate issue type (e.g., hardcoded credentials, misconfigured security headers, missing CSRF protection) occurs across multiple files:
- It must be grouped and reported as **one** consolidated finding.
- The entry must list and hyperlink all affected files.
- All distinct cases or instances of the issue across those files must be highlighted and explained (for example, showing the distinct redacted secret values or variable names used).

## Mandatory JSONL Schema

When writing findings to `findings.jsonl`, each JSON line MUST use these exact field keys:

```json
{
  "id": "FINDING-001",
  "title": "SQL Injection in User Search Endpoint",
  "severity": "HIGH",
  "confidence": "High",
  "cwe": "CWE-89 / A03:2021-Injection",
  "affected_file": "file:///absolute/path/to/UserController.java#L45-L62",
  "line_anchor": "L45-L62",
  "function_anchor": "searchUsers(String query)",
  "endpoint": "GET /api/users/search?q={input}",
  "source": "req.query.q (HTTP query parameter from client request)",
  "sink": "jdbcTemplate.query(sql) at UserRepository.java:L89",
  "data_flow": "1. Client sends GET /api/users/search?q=<payload>\n2. UserController.searchUsers() receives 'q' via @RequestParam at L45\n3. Passes 'q' to UserService.findUsers(query) at L48\n4. UserService.findUsers() calls UserRepository.searchByName(query) at L23\n5. UserRepository.searchByName() concatenates query into SQL string at L89: \"SELECT * FROM users WHERE name LIKE '%\" + query + \"%'\"\n6. Concatenated SQL passed to jdbcTemplate.query(sql) at L90 — SINK",
  "impact": "An attacker can extract all database records, modify or delete data, and potentially achieve remote code execution via stacked queries or database-specific functions.",
  "why_issue": "Negative verification: No PreparedStatement or parameterized query is used. The query string is directly concatenated. Spring Security is configured but does not sanitize query parameters. No input validation or allowlist exists for the 'q' parameter.",
  "payload": "' UNION SELECT username, password, email, null FROM admin_users --",
  "poc": "GET /api/users/search?q=%27%20UNION%20SELECT%20username%2Cpassword%2Cemail%2Cnull%20FROM%20admin_users%20-- HTTP/1.1\nHost: target.local:8080\nCookie: JSESSIONID=abc123\nAccept: application/json",
  "expected_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{\"name\":\"admin\",\"email\":\"admin@corp.com\",\"role\":\"SUPER_ADMIN\",...}]",
  "evidence": "UserRepository.java L89: String sql = \"SELECT * FROM users WHERE name LIKE '%\" + query + \"%'\";\nNo parameterization. No input filter. Direct concatenation confirmed.",
  "vulnerable_code": "// UserRepository.java L89-L90\nString sql = \"SELECT * FROM users WHERE name LIKE '%\" + query + \"%'\";\nreturn jdbcTemplate.query(sql, new UserRowMapper());",
  "safe_code": "// UserRepository.java L89-L90 (FIXED)\nString sql = \"SELECT * FROM users WHERE name LIKE ?\";\nreturn jdbcTemplate.query(sql, new UserRowMapper(), \"%\" + query + \"%\");",
  "remediation": "1. Replace string concatenation with parameterized query using '?' placeholder.\n2. Use jdbcTemplate.query(sql, mapper, params) overload.\n3. Add input validation: restrict 'q' to alphanumeric + spaces, max 100 chars.\n4. Add integration test verifying parameterized query prevents injection.\n5. Review all other jdbcTemplate usages for the same pattern.",
  "status": "confirmed"
}
```

## Mandatory Evidence Rule

**ALL fields listed above are MANDATORY.** A finding without ALL fields populated with real, specific evidence from the scanned codebase is INVALID.

### Forbidden content (examples of what MUST NOT appear):

| Field | Forbidden placeholder examples |
|---|---|
| `source` | "User HTTP Request Parameter / Input", "N/A" |
| `sink` | "Sensitive Sink API Execution", "N/A" |
| `data_flow` | "Input → Handler → Sink", single-line vague traces |
| `impact` | One-sentence generic statements without specific attacker capabilities |
| `payload` | "' OR '1'='1 --" (when not the actual exploit for this finding) |
| `poc` | "GET /api/v1/endpoint?input=test HTTP/1.1" (generic template) |
| `expected_response` | "HTTP/1.1 200 OK\n{\"status\":\"success\"}" (generic template) |
| `evidence` | "Verified unvalidated sink call", "Line L1 in file: confirmed" |
| `vulnerable_code` | "// Vulnerable Implementation\nsink(inputParam);" |
| `safe_code` | "// Secure Implementation\nString sanitized = sanitize(inputParam);\nsink(sanitized);" |
| `remediation` | "1. Validate input. 2. Use parameterized queries. 3. Test." |
| `why_issue` | "Control bypass verified: inputs reach sink without sanitization" |

### If a field cannot be populated:

If genuine evidence for a mandatory field cannot be determined (e.g., the expected response requires runtime testing), the finding MUST:
1. Set `status` to `needs-review` (not `confirmed`).
2. Include a `missing_fields` array listing the unpopulated field names.
3. Include a `missing_reason` string explaining why the evidence is unavailable.
4. Populate the field with a clear marker: `"[REQUIRES MANUAL VERIFICATION: <reason>]"`.

