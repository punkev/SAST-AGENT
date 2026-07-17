# False-Positive Rules

Before confirming an issue, check whether input is validated, canonicalized, parameterized, encoded for its context, constrained by an allowlist, or blocked by an effective authorization/security control. Confirm that the code path is reachable in the supported application and not only test/mock/demo/generated/vendor/build code.

Do not call a finding safe merely because a sanitizer exists: verify the correct context and that the value is not transformed afterward. Do not call a library safe merely because it is installed: verify configuration and execution path. Do not call a client guard authorization, a public identifier IDOR, or a CORS wildcard exploitable without credential/data context. Classify uncertain evidence as `needs-review`, retain rationale, and link the candidate to its evidence.
