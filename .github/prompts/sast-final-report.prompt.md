# Final SAST Report

Read state, inventories, findings, classifications, evidence, and logs.

**Pre-Report Validation (MANDATORY):**
1. Iterate every entry in `findings.jsonl` and validate ALL mandatory fields contain real, specific evidence.
2. For any finding with missing or generic/placeholder content in mandatory fields: set status to `needs-review`, add `validation_warnings` array, and log the finding ID and missing fields.
3. Compute and log `findings_complete` and `findings_incomplete` counts.
4. **Do NOT generate reports with incomplete findings classified as `confirmed`.**

Deduplicate root causes, calculate endpoint and vulnerability coverage, preserve needs-review and false-positive rationale, write all markdown report starter files plus `.sast-agent/reports/YYYY-MM-DD_sast_scan.md`, and execute `python .agents/skills/html-report-generator/scripts/generate_html_report.py` to generate the standalone interactive HTML security report at `.sast-agent/reports/index.html`. The HTML report merges all issues into a single file sorted strictly in decreasing order of severity (Critical → High → Medium → Low), featuring executive dashboard metrics, severity filter buttons, real-time search, collapsible findings accordions, CFG data flows, vulnerable vs safe code diffs, and copyable Burp Suite HTTP PoC requests. Save state before and after execution and after each report section. Never print full secrets and never claim coverage beyond the evidence.

