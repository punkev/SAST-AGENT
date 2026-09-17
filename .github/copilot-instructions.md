# SAST Multi-Agent Framework — Copilot Instructions

This repository defines a specialized Static Application Security Testing (SAST) multi-agent framework designed for GitHub Copilot in VS Code. It audits Java/Spring and JavaScript/Node.js/TypeScript applications for critical vulnerabilities across HTTP endpoints, message queues, schedulers, template engines (SSTI), file upload handlers, security middleware, ReDoS/resource starvation, race conditions, log injection, weak crypto/PRNG, hardcoded secrets, and exhaustive SQL/persistence layer injections.

---

## 1. Quick Start: How to Scan

1. Open VS Code with this repository or open GitHub Copilot Chat.
2. **Attach your target project source code folder(s)** to the chat.
3. Run one of the slash prompts or invoke an agent:

| Prompt | Agent Invoked | Purpose |
|---|---|---|
| `/scan` | `@sast-orchestrator` | **(Recommended)** Auto-detects language, enforces ignore rules, indexes surfaces, runs code taint & secrets scan |
| `/scan-sql` | `@sast-sql` | Full audit of controllers, services, repositories, and procedures for all SQLi types |
| `/scan-java` | `@sast-java` | Direct Two-Pass Java/Spring scan (REST, Kafka/RabbitMQ/SQS, SSTI, ReDoS, Race Conditions, Uploads, Taint) |
| `/scan-js` | `@sast-js` | Direct Two-Pass Node.js/TS scan (Express/NestJS/Next.js, BullMQ, SSTI, Prototype Pollution, ReDoS, Taint) |
| `/scan-secrets` | `@sast-secrets` | Dedicated hardcoded secrets scan across all folders (with separate production vs. test sections) |
| `/resume-scan` | `@sast-resume` | Continues an interrupted scan from `.sast-agent/output/scan-progress.md` |
| `/rescan` | `@sast-resume` | Re-analyzes all indexed entry points with fresh eyes and archives previous report |

---

## 2. Specialized Multi-Agent Roles

| Agent | File | Specialty |
|---|---|---|
| `@sast-orchestrator` | `.github/agents/sast-orchestrator.agent.md` | Pre-scan ignore enforcement, ecosystem detection, surface indexing, dispatching |
| `@sast-sql` | `.github/agents/sast-sql.agent.md` | Deep SQL, PL/SQL, Native Query, Blind & 2nd Order SQLi scanner with sequential run tracking (`SQL Check Run <N>`) |
| `@sast-java` | `.github/agents/sast-java.agent.md` | Two-pass Java taint engine (REST, queues, SpEL, JNDI, deserialization, SSRF, SQLi, ReDoS, Race Conditions, Uploads) |
| `@sast-js` | `.github/agents/sast-js.agent.md` | Two-pass Node/TS taint engine (routes, workers, prototype pollution, NoSQLi, eval, SSRF, ReDoS, Event Loop Starvation) |
| `@sast-secrets` | `.github/agents/sast-secrets.agent.md` | Deep hardcoded credential & token discovery with dual-section (Prod vs. Test) reporting |
| `@sast-verifier` | `.github/agents/sast-verifier.agent.md` | False-positive elimination, CVSS v3.1 scoring, Burp PoC generation, markdown report writing |
| `@sast-resume` | `.github/agents/sast-resume.agent.md` | Resume & rescan state coordinator |

---

## 3. Scan Output & Run Directories

All scan outputs are written to `.sast-agent/output/` (gitignored):
- **General & Orchestrated Scans**:
  - `findings.md`: Final verified markdown vulnerability report.
  - `secrets-findings.md`: Dedicated credentials report (Production vs. Test sections).
  - `scan-progress.md`: Live attack surface inventory & batch progress checklist.
- **SQL Injection Scans (`@sast-sql`)**:
  - Automatically versioned into sequential directories: `.sast-agent/output/SQL Check Run 1/`, `SQL Check Run 2/`, etc.
  - Each run directory contains `findings.md`, `scan-progress.md`, `summary.md`, and `findings.json`.

---

## 4. Core Scanning Rules & Mandates

- **Strict Scope Exclusion**: Load `.sast-agent/config/ignore-paths.yml` and `.github/instructions/ignore-patterns.instructions.md`. Never read media, fonts, documents, or build artifacts into context.
- **Secrets in Test Files**: `@sast-secrets` scans all folders including tests, but isolates test findings into a dedicated section in `.sast-agent/output/secrets-findings.md`.
- **No Code Modifications**: Agents NEVER modify application source code. All output is written to `.sast-agent/output/`.
- **Zero Hallucination / Real Code**: Every finding must reference real file paths, line numbers, and verbatim code blocks.
- **Burp PoCs for High/Crit**: Critical and High severity general code findings must provide copy-pasteable Burp Suite HTTP requests.
- **Mandatory Evidences for SQL Scans (`@sast-sql`)**:
  - Sample Burp Suite raw HTTP request is **MANDATORY for EACH and EVERY finding reported** (regardless of severity).
  - Mermaid dataflow flowchart (Front-End User ➔ Controller ➔ Service ➔ Repository ➔ DB) is **MANDATORY**.
  - Non-technical plain-English justification (why it occurred and business risk) is **MANDATORY**.
