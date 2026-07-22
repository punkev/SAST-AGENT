---
name: html-report-generator
description: Generate a single, standalone interactive HTML security report merging all SAST findings sorted in decreasing order of severity (Critical -> High -> Medium -> Low).
---

# HTML Report Generator Skill

This skill parses and aggregates all SAST findings from `.sast-agent/findings/` (both `findings.jsonl` and all `.md`/`.json` finding files across subfolders) into a single, self-contained interactive HTML report (`.sast-agent/reports/index.html`).

## Execution

Execute the Python report generator script from the workspace root:

```bash
python .agents/skills/html-report-generator/scripts/generate_html_report.py
```

## Features & Guarantees

1. **Deterministic Execution:** Uses pure Python standard library (`sys`, `os`, `json`, `re`, `html`, `datetime`) to parse all JSONL and Markdown findings deterministically.
2. **Comprehensive Markdown Aggregation:** Reads and combines all `.md` and `.json` finding details across `confirmed/`, `needs-review/`, `duplicate/`, and `false-positive/`.
3. **Strict Severity Ordering:** Merges all discovered issues into a single report sorted in decreasing order of severity (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `NEEDS-REVIEW` → `INFO`).
4. **Complete Aspect Cards:** Renders all issue aspects in every finding card:
   - Vulnerability Overview & Description.
   - Evidence & Control Bypass Rationale (Negative Verification).
   - Test PoC / Attack Payload.
   - Burp Suite HTTP Request Template (with copy button).
   - Burp Suite Expected Response.
   - Control Flow Graph (CFG) / Data Flow Trace (Source → Sink).
   - Bad Code vs. Good Code Comparison.
   - Step-by-Step Remediation Strategy.
