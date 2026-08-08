# Finding Format

Every finding in `.sast-agent/output/findings.md` must follow one of the two standard structures below:

---

## 1. Standard Single Finding Structure

```markdown
## FINDING-{NNN}: {Title} [{SEVERITY}]

**CWE**: CWE-{id} | **OWASP**: {category}
**File**: `{relative/path/to/file.java}` L{start}-{end}
**Endpoint / Component**: `{HTTP_METHOD} {route}` or `{ClassName}.{methodName}()`

### Request / Control Flow
1. {Entry point or source with file and line}
2. → {Next inter-procedural call with file and line}
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

---

## 2. Composite Exploit Chain Structure

Use this format when chaining 2 or 3 indirect, lower-severity, or subtle issues into an escalated composite attack path:

```markdown
## COMPOSITE-{NNN}: {Title} [{ESCALATED SEVERITY}]

**Chained Vulnerabilities**: `FINDING-001` (Info Leak) + `FINDING-004` (Missing Auth Guard) + `FINDING-009` (Mass Assignment)
**Primary Affected File**: `{relative/path/to/primary_file.java}` L{start}-{end}
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

## Field Rules

| Field | Required | Notes |
|---|---|---|
| Title | Always | Descriptive name, not generic |
| Severity | Always | CRITICAL, HIGH, MEDIUM, or LOW |
| CWE/OWASP | Always | Specific CWE + OWASP category |
| File + Line | Always | Real path and line numbers from the codebase |
| Endpoint / Component | Always | The HTTP route or component affected |
| Request Flow / Attack Chain | Always | Step-by-step trace with file:line at each step |
| Impact / Escalated Impact | Always | Specific attacker capabilities |
| Vulnerable Code | Single findings | Actual code from the codebase, not fabricated |
| Secure Fix / Unified Remediation | Always | Working corrected code or fix strategy |
| Burp PoC | Critical + High | Copy-pasteable HTTP request |

---

## What NOT to Do

- Do NOT write a finding without real code evidence from the codebase.
- Do NOT use placeholder text like "N/A", "TBD", "Generic sink call".
- Do NOT fabricate code — every code block must be from an actual file you read.
- Do NOT write one-line impacts like "This is a security issue."
- Do NOT write vague request flows like "Input → Handler → Sink."
- If you cannot fully trace a flow, mark the finding as `[NEEDS-REVIEW]` instead of `[CONFIRMED]`.

---

## Grouping Duplicates

If the same vulnerability pattern appears in multiple files (e.g., SQL injection via string concatenation in 5 different repositories), write ONE finding that lists all affected locations:

```markdown
### Affected Locations
- `UserRepository.java` L45: `"SELECT * FROM users WHERE id = " + id`
- `OrderRepository.java` L23: `"SELECT * FROM orders WHERE user_id = " + userId`
- `ProductRepository.java` L67: `"SELECT * FROM products WHERE name LIKE '%" + name + "%'"`
```
