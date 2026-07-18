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

