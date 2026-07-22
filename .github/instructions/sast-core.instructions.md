# Core SAST Instructions

## Method

Use a **Smart Hybrid Architecture** to achieve complete repository coverage without token fatigue or format degradation:
1. **Smart Triage Priority Tiering**: Enumerate 100% of files in `scan-queue.jsonl` (excluding `ignore-paths.yml`). Categorize files into **Tier 1 (High Priority Deep Analysis)** for endpoints, auth filters, config files, high-entropy secrets, and dangerous sinks; **Tier 2 (Medium Priority Dataflow Audit)** for services, DAO/repositories, and validators; and **Tier 3 (Low Priority Fast Pattern Pass)** for static formatters, DTOs, and assets.
2. **Module-Based Batching & Instant Saving**: Process queued files in prioritized batches (Tier 1 → Tier 2 → Tier 3). Immediately record verified findings to `.sast-agent/findings/findings.jsonl` after each batch to preserve context and prevent missing findings.
3. **Deterministic Report Generation**: Delegate HTML report creation to the `html-report-generator` Python skill (`python .agents/skills/html-report-generator/scripts/generate_html_report.py`) to ensure 100% consistent formatting, error-free UI accordions, complete aspect cards, and strict severity ordering (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).

## Sources and sinks

Sources include request paths, query/form parameters, JSON bodies, headers, cookies, uploaded files, message queues, environment/config values, database results, browser URL/DOM/storage, and inter-service responses. Sinks include SQL/JPQL/native queries, Mongo/LDAP/XPath expressions, commands, filesystem paths, XML parsers, templates/HTML, redirects, SSRF clients, deserializers, JWT verification, and authorization decisions.

## Rules

- Read `.sast-agent/config` and ignore only configured low-value paths.
- Treat production configuration, security filters, dependency manifests, and deployment descriptors as in scope.
- Distinguish authentication from authorization and server enforcement from client-only controls.
- Perform explicit **Negative Verification**: inspect strict type-safety checks (e.g., primitive type parsing, schema validation, enum bounds) and automated ORM parameterization (e.g., JPA/Hibernate bindings, Prisma, parameterized drivers) to ensure existing controls do not mitigate the issue before confirming a finding.
- Save state for each file, endpoint, controller, route, verified finding, and report section.
- Keep evidence concise, line-anchored, and secret-redacted.

## Output

Use the required endpoint and finding templates specified in `finding-format.instructions.md`. All findings must feature hyperlinked file paths, explicit impact statements, Burp Suite HTTP PoC requests, detailed step-by-step CFG data flows, and vulnerable/safe code blocks. Group duplicate issues occurring across multiple files into a single consolidated finding. Generate `access-control-matrix.md` under inventory. Update inventories, JSONL records, classification folders, `open-findings.md`, and reports. Record coverage gaps and unverified candidates explicitly.
