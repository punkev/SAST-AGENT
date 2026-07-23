# Repository Copilot Instructions: SAST Agent Framework

This repository provides a custom SAST scanning agent for Java/Spring/Struts, Node/Express, frontend JavaScript/TypeScript, and full-stack web applications.

## Three Scan Modes

### 🔵 Full Scan (First-Time Analysis)

**When to use:** Scanning a source code folder for the **first time**, or when the source code has **changed** since the last scan.

**What it does:** Complete discovery → inventory → deep vulnerability analysis → reports.

**How to run:**
- **Agent:** `.github/agents/sast-scanner.agent.md`
- **Prompt:** `.github/prompts/sast-full-scan.prompt.md`

**Usage:** Attach the source code folder(s) in Copilot chat and invoke the `sast-full-scan` prompt or reference the `sast-scanner` agent.

---

### 🟡 Resume Scan (Continue After Crash/Interruption)

**When to use:** A scan was **interrupted** due to VS Code crash, LLM hang, token exhaustion, or manual cancellation, and you want to **continue from where it left off**.

**What it does:** Reads durable state → diagnoses what happened → repairs corrupted data → resumes from the pending queue → skips completed work.

**How to run:**
- **Agent:** `.github/agents/sast-resume.agent.md`
- **Prompt:** `.github/prompts/sast-resume-scan.prompt.md`

**Usage:** Simply invoke the resume prompt. No need to re-attach source code folders — the agent reads the existing scan queue and state.

---

### 🟢 Rescan (Re-Analyze Same Codebase)

**When to use:** The source code has **already been scanned**, and you want to perform a **fresh vulnerability analysis** without re-doing discovery and inventory. Ideal for:
- Getting a deeper or second-pass analysis
- Re-scanning after a previous run missed vulnerabilities
- Verifying previous findings

**What it does:** Reuses existing inventory → archives previous findings → fresh vulnerability analysis of all files → fresh reports with comparison to prior scan.

**How to run:**
- **Agent:** `.github/agents/sast-rescan.agent.md`
- **Prompt:** `.github/prompts/sast-rescan.prompt.md`

**Usage:** Attach the same source code folder(s) and invoke the `sast-rescan` prompt. The agent will verify prerequisites exist from the prior Full Scan.

> **⚠️ Note:** If the source code has changed since the last Full Scan, use a Full Scan instead. Rescan reuses the existing file inventory and endpoint mappings.

---

## Quick Reference

| Mode | Agent | Prompt | Discovery | Inventory | Analysis | Reports |
|---|---|---|---|---|---|---|
| Full Scan | `sast-scanner` | `sast-full-scan` | ✅ Fresh | ✅ Fresh | ✅ Fresh | ✅ Fresh |
| Resume | `sast-resume` | `sast-resume-scan` | ⏭️ Skip | ⏭️ Skip | 🔄 Continue | ✅ Fresh |
| Rescan | `sast-rescan` | `sast-rescan` | ⏭️ Skip | ⏭️ Reuse | ✅ Fresh | ✅ Fresh |

## Specialized Prompts

For targeted analysis on specific areas:
- `sast-java-web-scan` — Focus on Java/Spring/Struts only
- `sast-node-express-scan` — Focus on Node/Express only
- `sast-frontend-scan` — Focus on frontend JavaScript/TypeScript only
- `sast-endpoint-inventory` — Build endpoint inventory only (no vulnerability analysis)
- `sast-hardcoded-secrets` — Scan for hardcoded secrets and credentials only
- `sast-verify-finding` — Verify a single specific finding
- `sast-final-report` — Generate reports from existing findings

## General Rules

- Use `.sast-agent/` for all scan state, evidence, findings, inventory, logs, and reports. Never use chat history as the only resume state.
- Build and persist endpoint inventory and route-to-handler mappings before deep source-to-sink analysis.
- Record evidence for every finding, redact secrets, and classify each finding as confirmed, needs-review, duplicate, or false-positive.
- Do not modify application source code unless the user explicitly asks for a remediation change. Scanner changes are limited to the SAST framework files.
- Treat configuration as security-relevant; do not blindly ignore config directories.

The framework is designed to be reviewable and optionally commit-able so a scan can be paused, resumed, diffed, and audited.

