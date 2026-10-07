# Enterprise SAST Multi-Agent Framework for VS Code Copilot

A specialized, multi-agent Static Application Security Testing (SAST) framework engineered for GitHub Copilot in Visual Studio Code. It performs deep, two-pass taint and data-flow analysis across Java/Spring and JavaScript/Node.js/TypeScript codebases, alongside a dedicated credentials engine, an exhaustive injection-based scanner, an identity/access control auditor, and an Infrastructure-as-Code (IaC) & container security analyzer.

---

## Key Capabilities

- **Automatic Ecosystem Detection**: Identifies Java/JVM vs. Node.js/TypeScript vs. Polyglot workspaces, build tools (Maven, Gradle, npm, pnpm, yarn), and frameworks (Spring Boot, Quarkus, NestJS, Express, Next.js).
- **Master Pre-Scan Ignore Matrix**: Automatically excludes all media, documents, fonts, binaries, and build caches before reading files into LLM context.
- **Dedicated Hardcoded Secrets Engine (`@sast-secrets`)**: Comprehensive detection of API keys, tokens, base64-encoded credentials, private keys, database passwords, and cloud keys across all folders, with clean separation between **Production Secrets** and **Test/Mock Secrets**.
- **Dedicated Injection Vulnerability Scanner (`@sast-injection`)**: Audits single or multiple attached folders for **ALL injection-based vulnerabilities and input-handling flaws** (SQLi, NoSQLi, OS Command Injection, Code Evaluation, SSTI, SpEL/EL, LDAP, XPath/XXE, CRLF/Log Injection, Header Injection, CSV Formula Injection, SSRF), organizing findings into sequential `Injection Check Run <N>` folders with mandatory Burp Suite requests and non-technical Mermaid flowcharts.
- **Dedicated Authentication & Access Control Auditor (`@sast-auth`)**: Deep-dive analysis of JWT algorithms (`alg: none`, HMAC vs RSA), expiration/claims validation, OAuth2/OIDC flows (missing `state` parameter, redirect URI matching, PKCE), session lifecycles, and Broken Object-Level Authorization (BOLA/IDOR).
- **Dedicated Infrastructure as Code & Container Scanner (`@sast-iac`)**: Static analysis of Dockerfiles (root execution, image pinning, sensitive build args), Kubernetes manifests (privileged pods, hostPath, capabilities, resource limits), Terraform/cloud templates, and GitHub Actions CI/CD workflows (script injection, untrusted PR triggers).
- **Expanded Attack Surface Coverage**: Audits REST/HTTP controllers, WebFlux reactive routes, **Message Queues** (Kafka, RabbitMQ, SQS, BullMQ), **Background Schedulers**, **Template Engines (SSTI)** (Thymeleaf, JSP, EJS, Pug, Handlebars), **GraphQL APIs**, **gRPC/WebSocket services**, **File Upload Handlers**, and **Security Middleware**.
- **Comprehensive 24-Category Vulnerability Taxonomy Beyond OWASP Top 10**:
  - **OWASP Web & API Top 10**: SQLi, NoSQLi, Command Injection, SSTI, Deserialization (Jackson, SnakeYAML, native), Broken Object-Level Auth (BOLA/IDOR), SSRF, Path Traversal / Zip Slip, XSS, Security Misconfigurations.
  - **Advanced Modern Web Application Security**:
    - **Cross-Site Request Forgery (CSRF) & Web Messaging (CWE-352, CWE-346)**: Disabled CSRF filters on session apps, missing tokens on state mutations, unvalidated `postMessage` origins, permissive CORS with credentials.
    - **Clickjacking & UI Redressing (CWE-1021)**: Missing `frame-ancestors` CSP or `X-Frame-Options` on interactive pages.
    - **GraphQL API Vulnerabilities (CWE-400, CWE-200, CWE-862)**: Introspection exposed in production, unbounded query depth DoS, batching attack brute-force bypass, missing field-level authorization.
    - **gRPC & WebSocket Flaws (CWE-1385, CWE-319)**: Plaintext gRPC channels, missing interceptor auth, Cross-Site WebSocket Hijacking (CSWSH), unauthenticated message frames.
    - **Business Logic & Workflow Flaws (CWE-840, CWE-398)**: Price/quantity tampering, voucher/coupon double-spend race conditions, workflow step forced browsing, missing rate limiting.
    - **Insecure File Downloads & Reflected File Download (RFD) (CWE-22, CWE-20)**: Arbitrary file download via path traversal, executable `.bat`/`.sh` downloads.
    - **Advanced Cryptography & Uninitialized Memory (CWE-326, CWE-908)**: AES-GCM nonce reuse, static IVs, Bleichenbacher PKCS#1 v1.5 padding oracle, Node.js `Buffer.allocUnsafe()` memory leaks.
    - **Production Artifact & Metadata Leaks (CWE-200, CWE-215)**: Exposed source maps (`.map`), public `.git`/`.env` files, server version banners.
    - **Resource Exhaustion & ReDoS (CWE-1333, CWE-400, CWE-834)**: Catastrophic regex backtracking, unbounded stream buffering, Node.js event-loop starvation.
    - **Concurrency & Race Conditions (CWE-362, CWE-367, CWE-366)**: Spring singleton bean mutable state pollution, Check-Then-Act TOCTOU double-spend flaws without database locks.
    - **Insecure File Upload & Temp Files (CWE-434, CWE-436, CWE-377)**: MIME spoofing, SVG script execution, world-readable temp files.
    - **Log Injection & Information Exposure (CWE-117, CWE-532, CWE-209)**: CRLF log forging in SLF4J/Winston, sensitive data in logs, verbose stack traces.
    - **SSL/TLS Validation & Insecure Transport (CWE-295, CWE-319, CWE-1385)**: All-trusting `TrustManager`, `rejectUnauthorized: false`.
    - **Weak Randomness & Session Lifecycle (CWE-330, CWE-384, CWE-613, CWE-1004)**: `java.util.Random`/`Math.random()` in tokens/OTPs, session fixation, missing cookie security flags.
    - **Open URL Redirection & HTTP Response Splitting (CWE-601, CWE-113, CWE-644)**: Unvalidated redirects, header injection, cache deception.
- **Two-Pass Taint Engine**: 
  - **Pass 1**: Surface & Sink Discovery (indexes entry points and locates dangerous sink signatures).
  - **Pass 2**: Deep Bidirectional Taint Analysis (traces sources forward to sinks and dangerous sinks backward to entry points).
- **False-Positive Elimination & Triage**: Dedicated `@sast-verifier` agent cross-examines candidate findings against framework mitigations, parameter binding, concurrency locks, and DTO validators.
- **Actionable Reporting & Exploitation PoCs**: Markdown report with CVSS v3.1 vectors, CWE classification, bidirectional source-to-sink traces, production-ready fix diffs, copy-pasteable Burp Suite PoCs, and Mermaid dataflow flowcharts.

---

## Architecture Overview

```
                               ┌──────────────────────────────────────────────┐
                               │            GitHub Copilot Chat               │
                               │  (User attaches source code folder & prompt) │
                               └──────────────────────┬───────────────────────┘
                                                      │
                                                      ▼
                               ┌──────────────────────────────────────────────┐
                               │             @sast-orchestrator               │
                               │  - Step 0: Enforce Master Ignore Matrix      │
                               │  - Step 1: Detect Language & Framework Stack │
                               │  - Step 2: Initialize Attack Surface & State │
                               │  - Step 3: Dispatch to Specialized Agents    │
                               └──────┬───────┬───────┬───────┬───────┬───────┘
                                      │       │       │       │       │
              Java / JVM Code Taint   │       │       │       │       │ Node / JS / TS Code Taint
                                      ▼       │       │       │       ▼
            ┌─────────────────────────────┐   │       │       │ ┌─────────────────────────────┐
            │         @sast-java          │   │       │       │ │          @sast-js           │
            │  Pass 1: Sinks & Sources    │   │       │       │ │  Pass 1: Sinks & Sources    │
            │  Pass 2: Bidirectional Taint│   │       │       │ │  Pass 2: Bidirectional Taint│
            └──────────────┬──────────────┘   │       │       │ └──────────────┬──────────────┘
                           │                  │       │       │                │
                           ├──────────────────┼───────┼───────┼────────────────┤
                           │                  │       │       │                │
                           ▼                  ▼       ▼       ▼                ▼
            ┌──────────────────────┐ ┌───────────────┐ ┌─────────────┐ ┌────────────────────┐
            │   @sast-injection    │ │  @sast-auth   │ │  @sast-iac  │ │   @sast-secrets    │
            │  - SQL, NoSQL, Cmd   │ │  - JWT, OAuth │ │  - Docker   │ │  - Prod Credentials │
            │  - SSTI, Code, SpEL  │ │  - OIDC, BOLA │ │  - K8s/Helm │ │  - Test / Mock Keys  │
            │  - LDAP, XPath, SSRF │ │  - Sessions   │ │  - Terraform│ │  - Dual-Section Rep │
            │  Output: Inj Run <N> │ │ Output:Auth<N>│ │ Output:IaC<N│ │ Output:secrets.md   │
            └──────────────┬───────┘ └───────┬───────┘ └──────┬──────┘ └────────────────────┘
                           │                 │                │
                           └─────────────────┼────────────────┘
                                             │ Candidate Findings
                                             ▼
                               ┌──────────────────────────────────────────────┐
                               │               @sast-verifier                 │
                               │  - Validate Data Flow & Eliminate FPs        │
                               │  - Verify Framework Sanitizers & Validations │
                               │  - Assign CWE, OWASP & CVSS v3.1 Vector      │
                               │  - Generate Burp Suite PoC                   │
                               │  - Write / Append to output/findings.md      │
                               └──────────────────────────────────────────────┘
```

---

## How to Use

### ⚡ Fast-Mode Pre-Scan Acceleration (Recommended)
Before running prompts in Copilot Chat, you can run the zero-dependency fast pre-scanner in your terminal. It indexes entry points and candidate sinks in **under 1 second**, saving **70%+ LLM token overhead** and speeding up the scan by **5x–10x**:

```cmd
.\scripts\pre-scan.cmd
```
*Or in PowerShell directly (bypassing ExecutionPolicy restrictions):*
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\pre-scan.ps1
```
*(Or specify a folder: `.\scripts\pre-scan.cmd -TargetPath "C:\path\to\target"`)*

### 🔍 Running Copilot Chat Scans
1. Open this repository in VS Code (or have its instructions loaded).
2. Open **GitHub Copilot Chat**.
3. **Attach your target project folder(s)** (single or multiple attached folders).
4. Run a command or invoke a specialized agent:

### Available Prompts

| Command | Prompt File | Description |
|---|---|---|
| `/scan` | `.github/prompts/scan.prompt.md` | **(Recommended)** Runs full automated scan with language auto-detection, surface indexing, taint flow, and secrets discovery |
| `/scan-injection` | `.github/prompts/scan-injection.prompt.md` | Exhaustive audit of all injection-based flaws (SQLi, NoSQLi, Command, SSTI, Code, SpEL/EL, LDAP, XPath/XXE, CRLF, SSRF). Saves to `Injection Check Run <N>` |
| `/scan-auth` | `.github/prompts/scan-auth.prompt.md` | Dedicated audit of authentication, JWT/tokens, OAuth2/OIDC, sessions, and BOLA/IDOR. Saves to `Auth Check Run <N>` |
| `/scan-iac` | `.github/prompts/scan-iac.prompt.md` | Dedicated audit of Dockerfiles, Kubernetes manifests, Helm charts, Terraform, and CI/CD pipelines. Saves to `IaC Check Run <N>` |
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
│   │   ├── sast-injection.agent.md          # Dedicated injection scanner agent (Injection Check Run <N>)
│   │   ├── sast-auth.agent.md               # Dedicated auth, token & BOLA/IDOR agent (Auth Check Run <N>)
│   │   ├── sast-iac.agent.md                # Dedicated IaC & container security agent (IaC Check Run <N>)
│   │   ├── sast-java.agent.md               # Two-pass Java/Spring scanner agent
│   │   ├── sast-js.agent.md                 # Two-pass Node.js/TypeScript scanner agent
│   │   ├── sast-secrets.agent.md            # Hardcoded secrets scanner (Prod vs. Test)
│   │   ├── sast-verifier.agent.md           # Verification, FP elimination & PoC agent
│   │   └── sast-resume.agent.md             # Resume / rescan coordinator agent
│   ├── instructions/
│   │   ├── ignore-patterns.instructions.md  # Strict pre-scan exclusion rules
│   │   ├── secret-detection.instructions.md # Secret regexes, signatures & heuristics
│   │   ├── finding-format.instructions.md   # Report schema, CVSS v3.1, injection format & Burp PoC rules
│   │   ├── owasp-checklist.instructions.md  # 24-category comprehensive OWASP & web security checklist
│   │   ├── injection-checklist.instructions.md # Exhaustive injection vulnerabilities checklist
│   │   ├── auth-checklist.instructions.md   # Authentication, JWT, OAuth2/OIDC & session checklist
│   │   └── iac-checklist.instructions.md    # Docker, Kubernetes, Terraform & CI/CD checklist
│   └── prompts/
│       ├── scan.prompt.md                   # Full automated scan prompt
│       ├── scan-injection.prompt.md         # Full injection vulnerabilities audit prompt
│       ├── scan-auth.prompt.md              # Authentication & access control audit prompt
│       ├── scan-iac.prompt.md               # IaC & container security audit prompt
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
│       ├── Injection Check Run 1/           # Sequentially created for injection vulnerability scans
│       ├── Auth Check Run 1/                # Sequentially created for authentication audits
│       ├── IaC Check Run 1/                 # Sequentially created for IaC & container scans
│       ├── scan-progress.md                 # General scan live surface inventory
│       ├── findings.md                      # General scan verified vulnerability report
│       └── secrets-findings.md              # Dedicated dual-section secrets report
├── .gitignore
└── README.md
```

---

## Output Reports

During a scan, output is organized dynamically under `.sast-agent/output/`:

1. **General Scans**:
   - `findings.md`: Full architectural and code-level vulnerability report with CVSS v3.1 scores, verified source-to-sink call traces, secure fix diffs, and Burp Suite PoCs.
   - `secrets-findings.md`: Dedicated credentials report separated into Production vs. Test sections.
   - `scan-progress.md`: Real-time inventory checklist tracking progress.

2. **Specialized Scan Runs**:
   - **Injection Scans (`@sast-injection`)**: `.sast-agent/output/Injection Check Run <N>/`
   - **Auth & Access Control Scans (`@sast-auth`)**: `.sast-agent/output/Auth Check Run <N>/`
   - **IaC & Container Scans (`@sast-iac`)**: `.sast-agent/output/IaC Check Run <N>/`
   - Each run directory contains `findings.md`, `scan-progress.md`, `summary.md`, and `findings.json`.

---

## Finding Format & Evidence Standards

Every finding provides complete, traceable evidence with specialized schemas tailored to the audit type:

| Field | General Scans (`FINDING-{NNN}`) | Injection Scans (`FINDING-INJ-{NNN}`) | Auth Scans (`FINDING-AUTH-{NNN}`) | IaC Scans (`FINDING-IAC-{NNN}`) |
|---|---|---|---|---|
| **Title + Severity + CWE** | Required | Required | Required | Required |
| **Exploitability Tier** | Required | Required | Required | Required |
| **Remediation Effort** | Required | Required | Required | Required |
| **File + Line Link (`file:///`)** | **Required** | **Required** | **Required** | **Required** |
| **Vulnerable Snippet** | Real Source Code | Real Source Code | Real Source Code | Real Manifest / YAML |
| **Secure Fix Format** | **Git Unified Diff (`diff`)** | **Git Unified Diff (`diff`)** | **Git Unified Diff (`diff`)** | **Git Unified Diff (`diff`)** |
| **Mermaid Dataflow Chart** | Optional | **MANDATORY** | Optional | N/A |
| **Impersonation Matrix** | Optional | N/A | **MANDATORY** | N/A |
| **Blast Radius / Impact** | Text | Plain-English Justification | Plain-English Justification | **Scope of Compromise** |
| **Hardening Benchmark** | OWASP / CWE | OWASP Top 10 | OWASP Top 10 | **CIS / NSA Benchmark** |
| **Burp Suite Raw HTTP PoC** | Critical + High | **MANDATORY (Every Finding)** | **MANDATORY** | N/A |

---

## License

MIT
