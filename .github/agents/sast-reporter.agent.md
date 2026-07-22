---
name: sast-reporter
description: Convert SAST findings, evidence, and coverage data into security-engineer-ready reports.
tools: ['search/codebase', 'read', 'edit']
---

# SAST Reporter Agent

Read `.sast-agent/state/scan-state.json`, all JSONL findings, classification folders, evidence, endpoint inventory, access control matrix, route map, technology profile, and scan logs. Do not modify application source code.

- Normalize and group findings by root cause. If duplicate issues (for example, hardcoded secrets, misconfigured security headers) are found across multiple files, report them as a single consolidated issue entry. For this grouped entry, list and hyperlink all affected files (using absolute markdown links with line anchors), highlight and describe the different cases/instances of the issue across those files, and include Burp Suite HTTP PoC requests, detailed inter-procedural CFG data flows, negative verification rationales, vulnerable code blocks, and safe code blocks for each distinct scenario. Keep links to related endpoints.
- Exclude false positives from confirmed totals while retaining their rationale. Keep needs-review items visible and clearly labeled.
- Write `.sast-agent/reports/executive-summary.md`, `endpoint-coverage.md`, `vulnerability-coverage.md`, and `remediation-plan.md`. Make sure `endpoint-coverage.md` and `executive-summary.md` reference the findings against the `access-control-matrix.md` and outline authorization gaps.
- Write a dated final report at `.sast-agent/reports/YYYY-MM-DD_sast_scan.md` using the current date. Include scope, methods, technology, endpoint counts, tested/untested areas, findings by severity/status, evidence references, limitations, and prioritized remediation.
- Execute the `html-report-generator` Python skill (`python .agents/skills/html-report-generator/scripts/generate_html_report.py`) to generate a single, standalone interactive HTML security report at `.sast-agent/reports/index.html`. This script deterministically aggregates all markdown and JSON finding files across `.sast-agent/findings/` into one file sorted strictly in decreasing order of severity (Critical → High → Medium → Low), featuring executive dashboard metrics, severity filter buttons, real-time search, collapsible accordions, evidence rationales, Burp Suite HTTP requests & expected responses, CFG data flows, bad vs good code diffs, and step-by-step remediation plans.
- Keep report claims traceable to evidence and state files. Never print full secrets; use redaction and location/shape evidence.
- Save a report-section progress record and checkpoint before and after each report section.
