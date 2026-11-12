# Retest Vulnerability Fix

Verify whether previously reported vulnerabilities have been fixed in the updated source code using `@sast-retest`.

1. **Parse** the attached issue `.md` file to extract all issue names, descriptions, CWEs, steps to reproduce, affected files, and target host.
2. **Locate** the originally reported vulnerable files and line numbers in the current workspace. If files were moved or renamed, search by class/function/route name.
3. **Analyze** the current code at each affected location. Trace the complete source-to-sink data flow in the updated code.
4. **Verify** each fix against the vulnerability-specific checklist in `.github/instructions/retest-methodology.instructions.md`.
5. **Assign Verdict**: `✅ FIXED` | `⚠️ PARTIALLY FIXED` | `❌ NOT FIXED` | `🔍 INCONCLUSIVE` — with detailed justification.
6. **Generate** a Burp Suite / RFC 7230 HTTP PoC request for EVERY issue (verification, bypass, exploitation, or diagnostic) for dynamic evidence gathering.
7. **Write** the full retest report to `.sast-agent/output/retest/retest-{timestamp}.md`.

Do not modify application source code. Base every verdict on actual code analysis — never assume a fix is correct without verifying.

