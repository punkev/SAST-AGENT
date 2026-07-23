# SAST Agent Framework

This repository contains a professional, resume-safe **Static Application Security Testing (SAST) Agent Framework** designed for running source-code security reviews on Java/Spring/Struts, Node/Express, frontend JavaScript/TypeScript, and full-stack web applications inside **GitHub Copilot Chat** (optimized for **GPT-5.3 Codex** and **GPT-5.5** models).

Unlike basic LLM chat prompts that rely on ephemeral chat history, this agent operates using a **Smart Hybrid Architecture**: it enumerates 100% of repository files, organizes them into prioritized risk tiers, audits code in module batches, performs negative-verification checks, constructs inter-procedural Control Flow Graphs (CFGs), and writes durable scan state, evidence, and reports under `.sast-agent/`.

---

## Key Features

1. **100% Repository File Coverage**: Every file and folder (except configured ignore paths) is indexed into `scan-queue.jsonl` and audited. No non-endpoint utility or background script is skipped.
2. **Smart Hybrid Architecture**:
   - 🔴 **Tier 1 (High Priority - Deep Analysis)**: Route handlers, endpoints, auth filters, config files (`.env`, `application.yml`, `web.xml`), high-entropy secrets, and dangerous sinks (`exec`, `eval`, `query`, `innerHTML`, `XMLInputFactory`, deserializers).
   - 🟡 **Tier 2 (Medium Priority - Dataflow Audit)**: Service layers, DAO/repositories, custom validators, session managers, data models.
   - 🟢 **Tier 3 (Low Priority - Fast Pattern Pass)**: Pure utility formatters, constants, boilerplate DTOs/getters/setters, static assets.
3. **Module-Based Batching**: Audits code in prioritized chunks to prevent context saturation and LLM token fatigue.
4. **Active Defense (Negative Verification)**: Inspects existing controls (primitive type parsing, ORM parameterization, security filters) to disprove false positives before confirming findings.
5. **Deterministic HTML Report Generator**: Uses an integrated Python/Node skill (`.agents/skills/html-report-generator/`) to compile findings into a standalone interactive HTML report (`.sast-agent/reports/index.html`) sorted in strict decreasing severity order (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).

---

## Repository Directory & File Breakdown

### 📁 `.github/` — Agent Definitions, Instructions & Prompts
This directory configures how GitHub Copilot Chat interacts with the SAST framework.

- 📄 [`copilot-instructions.md`](file:///.github/copilot-instructions.md): System-level operating instructions for GitHub Copilot Chat when loaded in this repository.
- 📁 **`agents/`** — Custom Subagent Workflow Definitions:
  - 📄 [`sast-scanner.agent.md`](file:///.github/agents/sast-scanner.agent.md): Main resume-safe SAST scanner agent executing Smart Hybrid Tiering, whole-file cross-referencing, multi-file CFG tracing, and evidence capture.
  - 📄 [`sast-resume.agent.md`](file:///.github/agents/sast-resume.agent.md): Specialized agent for resuming interrupted scans from state checkpoints without depending on prior chat memory.
  - 📄 [`sast-reporter.agent.md`](file:///.github/agents/sast-reporter.agent.md): Reporter agent that converts raw findings into markdown summaries and invokes the HTML report skill.
- 📁 **`instructions/`** — Shared Rule Sets & Analysis Standards:
  - 📄 [`sast-core.instructions.md`](file:///.github/instructions/sast-core.instructions.md): Core SAST scanning methodology, Smart Hybrid Tiering rules, and negative verification constraints.
  - 📄 [`finding-format.instructions.md`](file:///.github/instructions/finding-format.instructions.md): Finding template enforcing absolute hyperlinked file anchors, step-by-step CFGs, copyable Burp Suite HTTP PoC requests, and vulnerable/safe code blocks.
  - 📄 [`false-positive-rules.instructions.md`](file:///.github/instructions/false-positive-rules.instructions.md): Criteria for marking candidates as false positives (primitive parsing, framework ORMs, dead code).
  - 📄 [`state-management.instructions.md`](file:///.github/instructions/state-management.instructions.md): Instructions for handling durable JSONL state, atomic checkpoints, and queue tracking.
  - 📄 [`endpoint-extraction.instructions.md`](file:///.github/instructions/endpoint-extraction.instructions.md): Rules for discovering backend HTTP routes and frontend API calls.
  - 📄 [`java-spring-struts.instructions.md`](file:///.github/instructions/java-spring-struts.instructions.md): Specific scanning guidelines for Java, Spring MVC/Boot, Struts, and Servlet/JSP applications.
  - 📄 [`node-express.instructions.md`](file:///.github/instructions/node-express.instructions.md): Guidelines for Node.js, Express middleware order, Mongo/SQL queries, JWTs, and prototype pollution.
  - 📄 [`frontend-web.instructions.md`](file:///.github/instructions/frontend-web.instructions.md): Guidelines for DOM XSS, route guards, token handling, and frontend API consumption.
- 📁 **`prompts/`** — Executable IDE Prompt Workflows:
  - 📄 [`sast-full-scan.prompt.md`](file:///.github/prompts/sast-full-scan.prompt.md): Prompt to run a 100% full-repository comprehensive SAST scan.
  - 📄 [`sast-resume-scan.prompt.md`](file:///.github/prompts/sast-resume-scan.prompt.md): Prompt to resume an interrupted scan from `.sast-agent/state/`.
  - 📄 [`sast-endpoint-inventory.prompt.md`](file:///.github/prompts/sast-endpoint-inventory.prompt.md): Prompt to build endpoint inventories and Access Control Matrices only.
  - 📄 [`sast-java-web-scan.prompt.md`](file:///.github/prompts/sast-java-web-scan.prompt.md): Prompt focused on Java, Spring, and Struts security analysis.
  - 📄 [`sast-node-express-scan.prompt.md`](file:///.github/prompts/sast-node-express-scan.prompt.md): Prompt focused on Node.js and Express backend security.
  - 📄 [`sast-frontend-scan.prompt.md`](file:///.github/prompts/sast-frontend-scan.prompt.md): Prompt focused on frontend client security (DOM XSS, API security, token handling).
  - 📄 [`sast-hardcoded-secrets.prompt.md`](file:///.github/prompts/sast-hardcoded-secrets.prompt.md): Prompt for scanning source code and config files (`.env`, `application.yml`, `web.xml`) for high-entropy secrets.
  - 📄 [`sast-verify-finding.prompt.md`](file:///.github/prompts/sast-verify-finding.prompt.md): Prompt to re-audit a single candidate finding by ID.
  - 📄 [`sast-final-report.prompt.md`](file:///.github/prompts/sast-final-report.prompt.md): Prompt to generate final markdown reports and trigger the HTML report skill.

---

### 📁 `.agents/` — Custom Skills & Tools
Contains modular extension skills registered with the agent runtime.

- 📁 **`skills/html-report-generator/`**:
  - 📄 [`SKILL.md`](file:///.agents/skills/html-report-generator/SKILL.md): Skill specification detailing interactive HTML report generation with 3-tier fallback execution (Python → Node.js → Native LLM).
  - 📁 **`scripts/`**:
    - 📄 [`generate_html_report.py`](file:///.agents/skills/html-report-generator/scripts/generate_html_report.py): Pure Python script (zero dependencies) parsing JSONL findings and generating `.sast-agent/reports/index.html` sorted by severity.
    - 📄 [`generate_html_report.js`](file:///.agents/skills/html-report-generator/scripts/generate_html_report.js): Node.js fallback script performing identical deterministic HTML generation.

---

### 📁 `.sast-agent/` — Configuration & Master Templates
Contains default rulesets and serves as the template base for scanned target applications.

- 📁 **`config/`**:
  - 📄 [`vulnerability-taxonomy.yml`](file:///.sast-agent/config/vulnerability-taxonomy.yml): Vulnerability classification taxonomy with CWE and OWASP mappings.
  - 📄 [`sources-and-sinks.yml`](file:///.sast-agent/config/sources-and-sinks.yml): Pattern dictionary of untrusted input sources, dangerous sinks, and transformations.
  - 📄 [`scan-scope.yml`](file:///.sast-agent/config/scan-scope.yml): Scope configuration defining source roots, file extensions, and phase order.
  - 📄 [`severity-model.yml`](file:///.sast-agent/config/severity-model.yml): Severity classification rules (Critical, High, Medium, Low).
  - 📄 [`ignore-paths.yml`](file:///.sast-agent/config/ignore-paths.yml): Path exclusions for low-value or vendor files.
- 📁 **`findings/`**:
  - 📄 `findings.jsonl`: Durable JSON stream storing all candidate and verified findings.
  - 📄 `open-findings.md`: Catalog of open findings.
- 📁 **`inventory/`**:
  - 📄 `endpoint-inventory.md`: Inventory of discovered HTTP endpoints.
  - 📄 `access-control-matrix.md`: Role-based access control matrix.
  - 📄 `route-to-handler-map.md`: Route-to-controller mapping.
  - 📄 `repo-profile.md`: Repository structure profile.
  - 📄 `technology-detection.md`: Detected frameworks and languages.
  - 📄 `authn-authz-model.md`: Authentication/authorization architecture summary.
  - 📄 `dataflow-map.md`: High-level data propagation map.
  - 📄 `sensitive-data-map.md`: Locations of sensitive data and credentials.
  - 📄 `frontend-api-calls.md`: Inventory of frontend API endpoints.
- 📁 **`reports/`**:
  - 📄 `executive-summary.md`: High-level executive security report.
  - 📄 `endpoint-coverage.md`: Endpoint coverage audit.
  - 📄 `vulnerability-coverage.md`: Taxonomy coverage audit.
  - 📄 `remediation-plan.md`: Prioritized remediation guide.
- 📁 **`state/`**:
  - 📄 `scan-state.json`: Global scan progress and metrics.
  - 📄 `scan-queue.jsonl`: Queue of files to scan.
  - 📄 `visited-files.jsonl`: Audit log of scanned files.
  - 📄 `visited-endpoints.jsonl`: Audit log of scanned endpoints.
  - 📁 **`checkpoints/`**:
    - 📄 `latest.json`: Snapshot for crash recovery and resume.

---

### 📁 `.vscode/` — IDE Workspace Configuration
- 📄 [`settings.json`](file:///.vscode/settings.json): Editor settings configuring Copilot Chat context indexing rules.

---

## Usage Instructions

### 1. How to Use Prompts in Copilot Chat
Prompts in `.github/prompts/` are pre-configured instructions for specific scan tasks. You can invoke them in Copilot Chat by referencing the prompt file path:

```text
Use .github/prompts/sast-full-scan.prompt.md to run a full SAST scan of this repository.
```

### 2. How to Use Agents in Copilot Chat
Agent definitions in `.github/agents/` define specialized agent personas and tool workflows. You can invoke an agent by referencing its agent file:

```text
Use .github/agents/sast-scanner.agent.md to perform a security scan on the open codebase.
```

### 3. How to Use an Agent with a Prompt
For optimal results, combine an agent persona with a specific prompt workflow:

```text
Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-full-scan.prompt.md to execute a full comprehensive scan.
```

---

## Typical Scanning Workflows

### Scenario A: Running a Full 100% Repository Scan
To scan every file, route, utility, and configuration file in your target application:
```text
Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-full-scan.prompt.md to run a full SAST scan.
```

### Scenario B: Resuming an Interrupted Scan
If a scan is interrupted or paused, resume from the last saved state checkpoint without re-scanning completed files:
```text
Use .github/agents/sast-resume.agent.md with .github/prompts/sast-resume-scan.prompt.md to continue scanning.
```

### Scenario C: Scanning for Hardcoded Secrets & Credentials
To perform a targeted scan of source code and configuration files (`.env`, `application.yml`, `web.xml`) for API keys and secrets:
```text
Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-hardcoded-secrets.prompt.md to scan for hardcoded secrets.
```

### Scenario D: Focused Framework Scans
- **Node.js / Express**:
  ```text
  Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-node-express-scan.prompt.md to scan the backend.
  ```
- **Java / Spring / Struts**:
  ```text
  Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-java-web-scan.prompt.md to scan Java components.
  ```
- **Frontend (React / Angular / Vue)**:
  ```text
  Use .github/agents/sast-scanner.agent.md with .github/prompts/sast-frontend-scan.prompt.md to scan frontend code.
  ```

### Scenario E: Generating Reports & Interactive HTML Dashboard
To compile markdown reports and generate the standalone interactive HTML report (`.sast-agent/reports/index.html`):
```text
Use .github/agents/sast-reporter.agent.md with .github/prompts/sast-final-report.prompt.md to generate final scan reports.
```

---

## Safety and Security Guidelines

- **No Code Mutation**: The scanner performs read-only analysis and will not modify application source code unless explicitly requested to apply a remediation patch.
- **Secret Redaction**: Credentials and API keys detected in findings are automatically redacted (e.g., `AKIA...7FQ2`).
- **Durable Local State**: All scan state, inventories, and reports are saved locally under `.sast-agent/`.
