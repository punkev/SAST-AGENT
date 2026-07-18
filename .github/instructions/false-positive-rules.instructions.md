# False-Positive Rules

Before confirming an issue, check whether input is validated, canonicalized, parameterized, encoded for its context, constrained by an allowlist, or blocked by an effective authorization/security control. Confirm that the code path is reachable in the supported application and not only test/mock/demo/generated/vendor/build code.

## Active Defense & Negative Verification
Before confirming any vulnerability, you must perform a mandatory **Negative Verification** check. You must actively inspect the codebase for active security filters, middleware configurations, ORMs, framework-level controls (e.g., Spring Security configs, CSRF tokens, Helmet configurations), or custom validator functions. You must explicitly document why these controls fail to mitigate the vulnerability and detail how your specific Burp Suite PoC request bypasses or overcomes them.

Do not call a finding safe merely because a sanitizer exists: verify the correct context and that the value is not transformed afterward. Do not call a library safe merely because it is installed: verify configuration and execution path. Do not call a client guard authorization, a public identifier IDOR, or a CORS wildcard exploitable without credential/data context. Classify uncertain evidence as `needs-review`, retain rationale, and link the candidate to its evidence.
