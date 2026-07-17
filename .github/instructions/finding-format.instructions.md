# Finding Format Instructions

Every finding must contain exactly or clearly map to: `Title`, `Severity`, `Confidence`, `CWE/OWASP`, `Affected Endpoint`, `Affected File`, `Line/Function Anchor`, `Source`, `Sink`, `Data Flow`, `Why This Is Exploitable`, `Exploit/Test Request`, `Impact`, `False-Positive Checks`, `Recommended Fix`, `Fixed-Code Example`, `Related Endpoints`, and `Status`.

Use `confirmed`, `needs-review`, `duplicate`, or `false-positive` status. Include minimal evidence references and stable IDs in JSONL. Test requests must be safe, sanitized, and non-destructive. Never print full secrets; show redacted prefixes/suffixes only. Fixed-code examples are illustrative and must not be applied automatically.
