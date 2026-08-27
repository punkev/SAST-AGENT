# Enterprise SAST Multi-Agent Framework for VS Code Copilot

A specialized, multi-agent Static Application Security Testing (SAST) framework engineered for GitHub Copilot in Visual Studio Code. It performs deep, two-pass taint and data-flow analysis across Java/Spring and JavaScript/Node.js/TypeScript codebases, alongside a dedicated credentials and secret discovery engine.

---

## Key Capabilities

- **Automatic Ecosystem Detection**: Identifies Java/JVM vs. Node.js/TypeScript vs. Polyglot workspaces, build tools (Maven, Gradle, npm, pnpm, yarn), and frameworks (Spring Boot, Quarkus, NestJS, Express, Next.js).
- **Master Pre-Scan Ignore Matrix**: Automatically excludes all media, documents, fonts, binaries, and build caches before reading files into LLM context.
- **Dedicated Hardcoded Secrets Engine (`@sast-secrets`)**: Comprehensive detection of API keys, tokens, base64-encoded credentials, private keys, database passwords, and cloud keys across all folders, with clean separation between **Production Secrets** and **Test/Mock Secrets**.
- **Expanded Attack Surface Coverage**: Audits REST/HTTP controllers, WebFlux reactive routes, **Message Queues** (Kafka, RabbitMQ, SQS, BullMQ), **Background Schedulers**, **Template Engines (SSTI)** (Thymeleaf, JSP, EJS, Pug, Handlebars), **File Upload Handlers**, and **Security Middleware**.
- **Comprehensive Vulnerability Taxonomy Beyond OWASP Top 10**:
  - **OWASP Web & API Top 10**: SQLi, NoSQLi, Command Injection, SSTI, Deserialization (Jackson, SnakeYAML, native), Broken Object-Level Auth (BOLA/IDOR), SSRF, Path Traversal / Zip Slip, XSS.
  - **CWE Top 25 & SANS Top 25 Extensions**:
    - **Resource Exhaustion & ReDoS (CWE-1333, CWE-400, CWE-834)**: Catastrophic regex backtracking, unbounded stream buffering, Node.js event-loop starvation.
    - **Concurrency & Race Conditions (CWE-362, CWE-367, CWE-366)**: Spring singleton bean mutable state pollution, Check-Then-Act TOCTOU double-spend flaws without database locks.
    - **Insecure File Upload & Temp Files (CWE-434, CWE-436, CWE-377)**: MIME spoofing, SVG script execution, world-readable temp files.
    - **Log Injection & Information Exposure (CWE-117, CWE-532, CWE-209)**: CRLF log forging in SLF4J/Winston, sensitive data in logs, verbose stack traces in HTTP responses.
    - **SSL/TLS Validation & Insecure Transport (CWE-295, CWE-319, CWE-1385)**: All-trusting `TrustManager`, `rejectUnauthorized: false`, Cross-Site WebSocket Hijacking (CSWSH).
    - **Weak Randomness & Session Lifecycle (CWE-330, CWE-384, CWE-613, CWE-1004)**: `java.util.Random`/`Math.random()` in security tokens/OTPs, session fixation, missing cookie flags (`HttpOnly`, `Secure`, `SameSite`).
    - **Open URL Redirection & HTTP Response Splitting (CWE-601, CWE-113, CWE-644)**: Unvalidated redirects, header injection, cache deception.
- **Two-Pass Taint Engine**: 
  - **Pass 1**: Surface & Sink Discovery (indexes entry points and locates dangerous sink signatures).
  - **Pass 2**: Deep Bidirectional Taint Analysis (traces sources forward to sinks and dangerous sinks backward to entry points).
- **False-Positive Elimination & Triage**: Dedicated `@sast-verifier` agent cross-examines candidate findings against framework mitigations, parameter binding, concurrency locks, and DTO validators.
- **Actionable Reporting & Exploitation PoCs**: Markdown report with CVSS v3.1 vectors, CWE classification, bidirectional source-to-sink traces, production-ready fix diffs, and copy-pasteable Burp Suite PoCs for Critical and High severity findings.

---

## Architecture Overview

```
                               ┌──────────────────────────────────────────────┐
                               │            GitHub Copilot Chat               │
                               │  (User attaches source code folder & /scan)  │
                               └──────────────────────┬───────────────────────┘
                                                      │
                                                      ▼
                               ┌──────────────────────────────────────────────┐
                               │             @sast-orchestrator               │
                               │  - Step 0: Enforce Master Ignore Matrix      │
                               │  - Step 1: Detect Language & Framework Stack │
                               │  - Step 2: Initialize Attack Surface & State │
                               │  - Step 3: Dispatch to Specialized Agents    │
                               └──────┬───────────────┬───────────────┬───────┘
                                      │               │               │
                     Java / JVM Stack │               │ Secrets Scan  │ Node / JS / TS Stack
                                      ▼               ▼               ▼
           ┌─────────────────────────────┐ ┌─────────────────────┐ ┌─────────────────────────────┐
           │         @sast-java          │ │    @sast-secrets    │ │          @sast-js           │
           │  Pass 1: Sinks & Sources    │ │  Audits all folders │ │  Pass 1: Sinks & Sources    │
           │    - REST / JAX-RS / WebFlux│ │  including tests:   │ │    - Express / NestJS / Next│
           │    - Kafka / RabbitMQ / SQS │ │  - Section 1: Prod  │ │    - BullMQ / KafkaJS       │
           │    - Thymeleaf / JSP SSTI   │ │  - Section 2: Test  │ │    - EJS / Pug SSTI         │
           │  Pass 2: Bidirectional Taint│ │  Outputs to         │ │  Pass 2: Bidirectional Taint│
           │    - Source -> Service -> DB│ │  secrets-findings.md│ │    - Route -> Service -> DB │
           └──────────────┬──────────────┘ └─────────────────────┘ └──────────────┬──────────────┘
                          │                                                       │
                          └───────────────────────────┬───────────────────────────┘
                                                      │ Candidate Findings
                                                      ▼
                               ┌──────────────────────────────────────────────┐
                               │               @sast-verifier                 │
                               │  - Validate Data Flow & Eliminate FPs        │
                               │  - Verify Framework Sanitizers & Validations │
                               │  - Assign CWE, OWASP & CVSS v3.1 Vector      │
                               │  - Generate Burp Suite PoC (Crit / High)     │
                               │  - Write / Append to output/findings.md      │
                               └──────────────────────────────────────────────┘
```

---

## How to Use

1. Open this repository in VS Code (or have its instructions loaded).
2. Open **GitHub Copilot Chat**.
3. **Attach your target project's root folder**.
4. Run a command or invoke a specialized agent:

### Available Prompts

| Command | Prompt File | Description |
|---|---|---|
| `/scan` | `.github/prompts/scan.prompt.md` | **(Recommended)** Runs full automated scan with language auto-detection, surface indexing, taint flow, and secrets discovery |
| `/scan-secrets` | `.github/prompts/scan-secrets.prompt.md` | Dedicated hardcoded secrets and credentials scan across all folders (with separate production vs. test sections) |
| `/scan-java` | `.github/prompts/scan-java.prompt.md` | Targeted Two-Pass Java / Spring Boot scan |
| `/scan-js` | `.github/prompts/scan-js.prompt.md` | Targeted Two-Pass Node.js / TypeScript scan |
| `/resume-scan` | `.github/prompts/resume-scan.prompt.md` | Resumes an interrupted scan from the last checkpoint in `scan-progress.md` |
| `/rescan` | `.github/prompts/rescan.prompt.md` | Re-evaluates all indexed surfaces with fresh analysis and archives existing report |

---

## Repository Structure

```
SAST-AGENT/
├── .github/
│   ├── copilot-instructions.md              # Master Copilot chat config & orchestration rules
│   ├── agents/
│   │   ├── sast-orchestrator.agent.md       # Ecosystem detector & orchestrator agent
│   │   ├── sast-java.agent.md               # Two-pass Java/Spring scanner agent
│   │   ├── sast-js.agent.md                 # Two-pass Node.js/TypeScript scanner agent
│   │   ├── sast-secrets.agent.md            # Hardcoded secrets scanner (Prod vs. Test)
│   │   ├── sast-verifier.agent.md           # Verification, FP elimination & PoC agent
│   │   └── sast-resume.agent.md             # Resume / rescan coordinator agent
│   ├── instructions/
│   │   ├── ignore-patterns.instructions.md  # Strict pre-scan exclusion rules
│   │   ├── secret-detection.instructions.md # Secret regexes, signatures & heuristics
│   │   ├── finding-format.instructions.md   # Report schema, CVSS v3.1 & Burp PoC rules
│   │   └── owasp-checklist.instructions.md  # Comprehensive OWASP 2021 & API 2023 checklist
│   └── prompts/
│       ├── scan.prompt.md                   # Full automated scan prompt
│       ├── scan-secrets.prompt.md           # Dedicated secrets scan prompt
│       ├── scan-java.prompt.md              # Targeted Java scan prompt
│       ├── scan-js.prompt.md                # Targeted Node.js scan prompt
│       ├── resume-scan.prompt.md            # Resume interrupted scan prompt
│       └── rescan.prompt.md                 # Rescan codebase prompt
├── .vscode/
│   └── settings.json                        # Copilot instruction registrations
├── .sast-agent/
│   ├── config/
│   │   └── ignore-paths.yml                 # Master pre-scan ignore matrix
│   └── output/                              # (Generated during scans - gitignored)
│       ├── scan-progress.md                 # Live surface inventory & batch progress checklist
│       ├── findings.md                      # Final verified markdown vulnerability report
│       └── secrets-findings.md              # Dedicated dual-section secrets report
├── .gitignore
└── README.md
```

---

## Output Reports

During a scan, two distinct reports are produced under `.sast-agent/output/`:

1. `findings.md`: Full architectural and code-level vulnerability report (SQLi, SSTI, RCE, SSRF, Deserialization, Broken Auth, BOLA) with CVSS v3.1 scores, verified source-to-sink call traces, secure fix diffs, and Burp Suite PoCs.
2. `secrets-findings.md`: Dedicated credentials report separated into:
   - **Section 1: Production & Configuration Secrets (High Risk)**: Discovered in production code, `.env`, or configuration files.
   - **Section 2: Test Files & Fixtures Secrets (Credential Leak Risk)**: Discovered in test folders, mocks, or sample fixtures with analysis on whether the secret is a mock value or an exposed live credential.

---

## License

MIT
