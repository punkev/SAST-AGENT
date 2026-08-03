# Finding Format

Every finding in `.sast-agent/output/findings.md` must be a markdown section with this structure:

```markdown
## FINDING-{NNN}: {Title} [{SEVERITY}]

**CWE**: CWE-{id} | **OWASP**: {category}
**File**: `{relative/path/to/file.java}` L{start}-{end}
**Endpoint**: `{HTTP_METHOD} {route}`

### Request Flow
1. {Entry point with file and line}
2. → {Next call with file and line}
3. → {Sink with file and line} — **SINK**

### Impact
{What an attacker can do by exploiting this. Be specific.}

### Vulnerable Code
{Fenced code block with the actual vulnerable code from the codebase}

### Secure Fix
{Fenced code block showing the corrected implementation}

### Remediation
{Numbered steps to fix this specific issue}

### Burp Suite PoC *(Critical and High only)*
{Raw HTTP request in a fenced code block}
**Expected Response**: {What the response reveals}

---
```

## Field Rules

| Field | Required | Notes |
|---|---|---|
| Title | Always | Descriptive name, not generic |
| Severity | Always | CRITICAL, HIGH, MEDIUM, or LOW |
| CWE/OWASP | Always | Specific CWE + OWASP category |
| File + Line | Always | Real path and line numbers from the codebase |
| Endpoint | Always | The HTTP route affected (if applicable) |
| Request Flow | Always | Step-by-step trace with file:line at each step |
| Impact | Always | Specific attacker capabilities |
| Vulnerable Code | Always | Actual code from the codebase, not fabricated |
| Secure Fix | Always | Working corrected code |
| Remediation | Always | Actionable steps |
| Burp PoC | Critical + High only | Copy-pasteable HTTP request |

## What NOT to Do

- Do NOT write a finding without real code evidence from the codebase.
- Do NOT use placeholder text like "N/A", "TBD", "Generic sink call".
- Do NOT fabricate code — every code block must be from an actual file you read.
- Do NOT write one-line impacts like "This is a security issue."
- Do NOT write vague request flows like "Input → Handler → Sink."
- If you cannot fully trace a flow, mark the finding as `[NEEDS-REVIEW]` instead of `[CONFIRMED]`.

## Grouping Duplicates

If the same vulnerability pattern appears in multiple files (e.g., SQL injection via string concatenation in 5 different repositories), write ONE finding that lists all affected locations:

```markdown
### Affected Locations
- `UserRepository.java` L45: `"SELECT * FROM users WHERE id = " + id`
- `OrderRepository.java` L23: `"SELECT * FROM orders WHERE user_id = " + userId`
- `ProductRepository.java` L67: `"SELECT * FROM products WHERE name LIKE '%" + name + "%'"`
```
