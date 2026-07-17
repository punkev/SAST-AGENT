# Repository Copilot Instructions: SAST Agent Framework

This repository uses a custom SAST scanning agent for Java/Spring/Struts, Node/Express, frontend JavaScript/TypeScript, and full-stack web applications.

## Operating instructions

- Use `.github/agents/sast-scanner.agent.md` for a full scan.
- Use `.github/prompts/sast-full-scan.prompt.md` to start discovery, endpoint inventory, analysis, and reporting.
- Use `.github/prompts/sast-resume-scan.prompt.md` to resume an interrupted or failed scan.
- Use `.sast-agent/` for all scan state, evidence, findings, inventory, logs, and reports. Never use chat history as the only resume state.
- Build and persist endpoint inventory and route-to-handler mappings before deep source-to-sink analysis.
- Record evidence for every finding, redact secrets, and classify each finding as confirmed, needs-review, duplicate, or false-positive.
- Do not modify application source code unless the user explicitly asks for a remediation change. Scanner changes are limited to the SAST framework files.
- Treat configuration as security-relevant; do not blindly ignore config directories.

The framework is designed to be reviewable and optionally commit-able so a scan can be paused, resumed, diffed, and audited.
