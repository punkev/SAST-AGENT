---
name: html-report-generator
description: Generate a single, standalone interactive HTML security report merging all SAST findings sorted in decreasing order of severity (Critical -> High -> Medium -> Low).
---

# HTML Report Generator Skill

This skill compiles all SAST findings, state metadata, and evidence into a single, self-contained interactive HTML security audit report (`.sast-agent/reports/index.html`).

## Execution Workflow

Execute via Python runtime:

```bash
python .agents/skills/html-report-generator/scripts/generate_html_report.py
```

If system script execution fails or Python is unavailable, the AI agent itself will directly read `.sast-agent/findings/findings.jsonl`, parse and sort all findings by decreasing severity (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`), and write `.sast-agent/reports/index.html` ensuring every finding renders all required sections.

## Output Requirements

- **File Path:** `.sast-agent/reports/index.html`
- **Ordering:** Strictly decreasing order of severity (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).
- **Consistent Finding Structure:** Every finding card in the report MUST render all 8 mandatory sections in a unified layout:
  1. **Issue Name & Severity**: Title, ID, Severity Badge, CWE/OWASP tags.
  2. **Where Issue Exists**: Hyperlinked file path (`file:///...#L123`), line numbers, function anchor, affected endpoint.
  3. **Payload to Exploit**: Exploit payload string/parameters.
  4. **Test Burp Suite Request**: Copy-pasteable raw HTTP request template.
  5. **Expected Burp Suite Response**: Expected raw HTTP response demonstrating exploitation.
  6. **Evidence & Line-Anchored Link**: Redacted evidence snippet and line-anchored file link.
  7. **Unsafe vs. Safe Code**: Explicit diff/comparison of Unsafe Line of Code vs Safe Line of Code.
  8. **Whole Remediation Plan**: Comprehensive step-by-step remediation guide to prevent/fix the issue.

## Data Quality Validation

The report generator performs **mandatory validation** on every finding:

- **No fake fallbacks:** Missing fields are NEVER filled with generic boilerplate. Instead, they display a visible `⚠️ MISSING — Evidence not provided by scanner` marker styled in red.
- **Completeness scoring:** Each finding is checked against all mandatory evidence fields. Findings with missing or placeholder data are flagged as `INCOMPLETE`.
- **Data Quality Summary banner:** The report header includes a Data Quality Summary showing:
  - Complete findings count vs total
  - Incomplete findings count with percentage
  - File coverage ratio (files visited / files queued)
- **Incomplete badges:** Findings with missing evidence display a prominent `⚠️ INCOMPLETE (N fields)` badge in the card header.
- **Filter by completeness:** An additional filter button allows viewing only incomplete findings.
- **Console warnings:** During generation, the script logs warnings identifying each incomplete finding and its missing fields.

## Key Normalization

The script handles multiple field name variations (e.g., `finding_id`/`id`, `issue_name`/`title`, `burp_poc`/`poc`) through a comprehensive key normalization layer, ensuring findings are parsed correctly regardless of which naming convention the scanner agent used.

