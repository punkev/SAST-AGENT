# SAST Agent

This repository contains a reusable IDE agent framework for running source-code security reviews on Java/Spring/Struts, Node/Express, frontend, and full-stack web applications.

The agent is designed to work inside an IDE assistant environment such as GitHub Copilot Chat or a compatible agent runner. It does not rely on chat history alone. Instead, it writes durable scan state, endpoint inventory, evidence, findings, and reports under `.sast-agent/` so a scan can be paused, resumed, reviewed, and committed.

## What The Agent Does

The main scanner acts like a security engineer performing a source-code review. Its workflow is endpoint-driven:

1. Reads existing scan state and writes a checkpoint before starting.
2. Detects repository structure, frameworks, source roots, build files, and frontend/backend boundaries.
3. Builds an endpoint inventory before making vulnerability claims.
4. Maps routes to handlers, controllers, middleware, filters, interceptors, and frontend API calls.
5. Models authentication, authorization, data flow, sensitive data, and security boundaries.
6. Traces reachable source-to-sink flows for vulnerability classes such as injection, XSS, CSRF, IDOR/BOLA, SSRF, unsafe uploads, path traversal, weak JWT/session handling, command execution, XXE, deserialization, prototype pollution, and hardcoded secrets.
7. Stores minimal redacted evidence for each candidate finding.
8. Classifies findings as `confirmed`, `needs-review`, `duplicate`, or `false-positive`.
9. Produces reviewable reports under `.sast-agent/reports/`.

The scanner is intentionally conservative: it should not report a vulnerability unless it has evidence, reachability, and a traceable source-to-sink path or security-control gap.

## Repository Layout

- `.github/agents/sast-scanner.agent.md` - main resume-safe SAST scanner.
- `.github/agents/sast-resume.agent.md` - resumes interrupted scans from durable state.
- `.github/agents/sast-reporter.agent.md` - converts findings and evidence into reports.
- `.github/prompts/` - reusable IDE prompts for specific scan modes.
- `.github/instructions/` - shared scanning and finding-format instructions.
- `.sast-agent/config/` - taxonomy, scan scope, source/sink patterns, severity model, and ignore rules.
- `.sast-agent/inventory/` - endpoint, route, technology, auth, dataflow, and sensitive-data maps.
- `.sast-agent/findings/` - structured findings and open finding summaries.
- `.sast-agent/state/` - checkpoints, queues, visited files, visited endpoints, and scan progress.
- `.sast-agent/reports/` - executive summary, coverage reports, remediation plan, and final scan reports.

## IDE Prompts

Use these prompts from `.github/prompts/` while working inside your IDE.

| Prompt | Use It For |
| --- | --- |
| `sast-full-scan.prompt.md` | Runs the complete scanner workflow: discovery, endpoint inventory, route mapping, source-to-sink analysis, finding classification, evidence capture, and reporting. |
| `sast-resume-scan.prompt.md` | Resumes an interrupted scan from `.sast-agent/state/` without depending on prior chat history. |
| `sast-endpoint-inventory.prompt.md` | Builds endpoint inventory and route-to-handler mappings only. Useful before a deeper review or when you want application attack-surface coverage first. |
| `sast-node-express-scan.prompt.md` | Focuses on Node/Express routes, middleware order, controller imports, database queries, JWT, CORS, cookies, templates, filesystem access, redirects, SSRF, prototype pollution, mass assignment, and authorization. |
| `sast-java-web-scan.prompt.md` | Focuses on Java, Spring MVC/Boot, Struts, Servlet/JSP, filters, interceptors, Spring Security, injection, CSRF, JWT/session handling, XXE, deserialization, command execution, uploads, redirects, SSRF, and security headers. |
| `sast-frontend-scan.prompt.md` | Focuses on frontend API calls, forms, route guards, storage token use, DOM XSS, open redirects, client-only authorization assumptions, unsafe rendering, and insecure backend assumptions. |
| `sast-hardcoded-secrets.prompt.md` | Searches source and security-relevant configuration for secrets while storing only redacted evidence and classification details. |
| `sast-verify-finding.prompt.md` | Re-checks one finding by stable ID, validates reachability and controls, updates classification, and records evidence. |
| `sast-final-report.prompt.md` | Generates final reports from state, inventories, findings, evidence, and logs. |

## Typical Usage

Start with a full scan:

```text
Use .github/prompts/sast-full-scan.prompt.md to run a full SAST scan of this repository.
```

Resume later if the scan is interrupted:

```text
Use .github/prompts/sast-resume-scan.prompt.md to continue the scan from durable state.
```

Run a focused framework scan:

```text
Use .github/prompts/sast-node-express-scan.prompt.md to scan the Node/Express attack surface.
```

Verify a specific finding:

```text
Use .github/prompts/sast-verify-finding.prompt.md to verify finding <finding-id>.
```

Generate final reports:

```text
Use .github/prompts/sast-final-report.prompt.md to produce the final SAST report.
```

## Safety Notes

- The scanner should not modify application source code.
- Scan artifacts belong under `.sast-agent/`.
- Secrets must be redacted in evidence, findings, and reports.
- Endpoint inventory and handler mapping should come before deep vulnerability claims.
- Findings should be traceable to evidence and classified consistently.
- Local logs and raw evidence snippets are ignored by default through `.gitignore`.
