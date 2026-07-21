---
name: html-report-generator
description: Generate a single, standalone interactive HTML security report merging all SAST findings sorted in decreasing order of severity (Critical -> High -> Medium -> Low).
---

# HTML Report Generator Skill

This skill compiles all SAST findings, state metadata, and evidence into a single, self-contained interactive HTML security audit report (`.sast-agent/reports/index.html`).

## Execution Workflow

Try executing via available system runtimes in order:

### 1. Python Execution (Primary)
```bash
python .agents/skills/html-report-generator/scripts/generate_html_report.py
```

### 2. Node.js Execution (Fallback if Python is not installed)
```bash
node .agents/skills/html-report-generator/scripts/generate_html_report.js
```

### 3. Native Agent Generation (Fallback if neither Python nor Node.js are available)
If system script execution fails or runtimes are unavailable, the AI agent itself will directly read `.sast-agent/findings/findings.jsonl`, parse and sort all findings by decreasing severity (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`), and write `.sast-agent/reports/index.html` using the template layout defined in `generate_html_report.js`.

## Output Requirements

- **File Path:** `.sast-agent/reports/index.html`
- **Ordering:** Strictly decreasing order of severity (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).
- **Interactive UI:** Must include executive dashboard metrics, severity filter buttons, real-time search, collapsible accordions, CFG data flows, side-by-side code comparison, and copyable Burp Suite HTTP PoC requests.
