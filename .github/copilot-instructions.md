# SAST Multi-Agent Framework — Copilot Instructions

This repository defines a specialized Static Application Security Testing (SAST) multi-agent framework designed for GitHub Copilot in VS Code. It audits Java/Spring and JavaScript/Node.js/TypeScript applications for critical vulnerabilities across HTTP endpoints, message queues, schedulers, template engines (SSTI), security middleware, and hardcoded secrets.

---

## 1. Quick Start: How to Scan

1. Open VS Code with this repository or open GitHub Copilot Chat.
2. **Attach your target project source code folder** to the chat.
3. Run one of the slash prompts or invoke an agent:

| Prompt | Agent Invoked | Purpose |
|---|---|---|
| `/scan` | `@sast-orchestrator` | **(Recommended)** Auto-detects language, enforces ignore rules, indexes surfaces, runs code taint & secrets scan |
| `/scan-java` | `@sast-java` | Direct Two-Pass Java/Spring scan (REST, Kafka, RabbitMQ, SQS, Thymeleaf/JSP SSTI) |
| `/scan-js` | `@sast-js` | Direct Two-Pass Node.js/TS scan (Express, NestJS, Next.js, BullMQ, EJS/Pug SSTI) |
| `/scan-secrets` | `@sast-secrets` | Dedicated hardcoded secrets scan across all folders (with separate production vs. test sections) |
| `/resume-scan` | `@sast-resume` | Continues an interrupted scan from `.sast-agent/output/scan-progress.md` |
| `/rescan` | `@sast-resume` | Re-analyzes all indexed entry points with fresh eyes and archives previous report |

---

## 2. Specialized Multi-Agent Roles

| Agent | File | Specialty |
|---|---|---|
| `@sast-orchestrator` | `.github/agents/sast-orchestrator.agent.md` | Pre-scan ignore enforcement, ecosystem detection, surface indexing, dispatching |
| `@sast-java` | `.github/agents/sast-java.agent.md` | Two-pass Java taint engine (REST, queues, SpEL, JNDI, deserialization, SSRF, SQLi) |
| `@sast-js` | `.github/agents/sast-js.agent.md` | Two-pass Node/TS taint engine (routes, workers, prototype pollution, NoSQLi, eval, SSRF) |
| `@sast-secrets` | `.github/agents/sast-secrets.agent.md` | Deep hardcoded credential & token discovery with dual-section (Prod vs. Test) reporting |
| `@sast-verifier` | `.github/agents/sast-verifier.agent.md` | False-positive elimination, CVSS v3.1 scoring, Burp PoC generation, markdown report writing |
| `@sast-resume` | `.github/agents/sast-resume.agent.md` | Resume & rescan state coordinator |

---

## 3. Core Scanning Rules & Mandates

- **Strict Scope Exclusion**: Load `.sast-agent/config/ignore-paths.yml` and `.github/instructions/ignore-patterns.instructions.md`. Never read media, fonts, documents, or build artifacts into context.
- **Secrets in Test Files**: `@sast-secrets` scans all folders including tests, but isolates test findings into a dedicated section in `.sast-agent/output/secrets-findings.md`.
- **No Code Modifications**: Agents NEVER modify application source code. All output is written to `.sast-agent/output/`.
- **Zero Hallucination / Real Code**: Every finding must reference real file paths, line numbers, and verbatim code blocks.
- **Burp PoCs for High/Crit**: Critical and High severity code findings must provide copy-pasteable Burp Suite HTTP requests.
