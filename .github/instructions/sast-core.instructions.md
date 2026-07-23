# Core SAST Instructions

## Method

Use a **Smart Hybrid Architecture** to achieve complete repository coverage without token fatigue or format degradation:
1. **Smart Triage Priority Tiering**: Enumerate 100% of files in `scan-queue.jsonl` (excluding `ignore-paths.yml`). Categorize files into **Tier 1 (High Priority Deep Analysis)** for endpoints, auth filters, config files, high-entropy secrets, and dangerous sinks; **Tier 2 (Medium Priority Dataflow Audit)** for services, DAO/repositories, and validators; and **Tier 3 (Low Priority Fast Pattern Pass)** for static formatters, DTOs, and assets.
2. **Module-Based Batching & Instant Saving**: Process queued files in prioritized batches (Tier 1 → Tier 2 → Tier 3). Immediately record verified findings to `.sast-agent/findings/findings.jsonl` after each batch to preserve context and prevent missing findings.
3. **Deterministic Report Generation**: Delegate HTML report creation to the `html-report-generator` skill (`generate_html_report.py`) to ensure 100% consistent formatting, error-free UI accordions, and strict severity ordering (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).

## Sources and sinks

Sources include request paths, query/form parameters, JSON bodies, headers, cookies, uploaded files, message queues, environment/config values, database results, browser URL/DOM/storage, and inter-service responses. Sinks include SQL/JPQL/native queries, Mongo/LDAP/XPath expressions, commands, filesystem paths, XML parsers, templates/HTML, redirects, SSRF clients, deserializers, JWT verification, and authorization decisions.

## Rules

- Read `.sast-agent/config` and ignore only configured low-value paths.
- Treat production configuration, security filters, dependency manifests, and deployment descriptors as in scope.
- Distinguish authentication from authorization and server enforcement from client-only controls.
- Perform explicit **Negative Verification**: inspect strict type-safety checks (e.g., primitive type parsing, schema validation, enum bounds) and automated ORM parameterization (e.g., JPA/Hibernate bindings, Prisma, parameterized drivers) to ensure existing controls do not mitigate the issue before confirming a finding.
- Save state for each file, endpoint, controller, route, verified finding, and report section.
- Keep evidence concise, line-anchored, and secret-redacted.

## Finding Integrity Rule (MANDATORY)

A finding MUST NOT be written to `findings.jsonl` with status `confirmed` unless ALL of the following fields contain real, specific, non-placeholder data extracted from the actual scanned codebase:

- `title`, `severity`, `confidence`, `cwe`
- `affected_file` (absolute path), `line_anchor`, `function_anchor`, `endpoint`
- `source`, `sink`, `data_flow` (step-by-step inter-procedural CFG trace)
- `impact` (specific attacker capabilities for this finding)
- `payload` (specific exploit payload for this vulnerability instance)
- `poc` (complete Burp Suite HTTP request with real method, path, headers, body)
- `expected_response` (realistic expected HTTP response showing exploitation)
- `evidence` (redacted code snippet with line references)
- `vulnerable_code` (exact code from the codebase), `safe_code` (corrected version)
- `remediation` (specific step-by-step fix for this finding)
- `why_issue` (rationale including what controls were checked and why they fail)

If ANY mandatory field cannot be populated with real evidence, the finding MUST be classified as `needs-review` with `missing_fields` and `missing_reason` populated. **Generic boilerplate, template strings, or fabricated evidence is STRICTLY FORBIDDEN and constitutes a scan integrity violation.**

## Coverage Completeness Rule (MANDATORY)

Before transitioning to the reporting phase, the agent MUST:
1. Cross-reference every entry in `scan-queue.jsonl` against `visited-files.jsonl`.
2. Compute `coverage_ratio = files_visited / files_queued`.
3. If `coverage_ratio < 1.0`: either scan the remaining files OR document each unvisited file in `.sast-agent/reports/coverage-gaps.md` with a reason.
4. Update `scan-state.json` with `files_queued`, `files_visited`, `files_skipped`, `coverage_ratio`, `endpoints_discovered`, `endpoints_analyzed`, and `endpoint_coverage_ratio`.
5. **The scan CANNOT be marked as `completed` if unvisited files exist without documented justification.**

## Output

Use the required endpoint and finding templates specified in `finding-format.instructions.md`. All findings must feature hyperlinked file paths, explicit impact statements, Burp Suite HTTP PoC requests, detailed step-by-step CFG data flows, and vulnerable/safe code blocks. Group duplicate issues occurring across multiple files into a single consolidated finding. Generate `access-control-matrix.md` under inventory. The final scan report must contain a formal **Scan Metadata** header logging the Git commit hash/ref, run timestamps, and a reference link to the state checkpoint file. The remediation plan must categorize fixes by effort-to-impact quadrants. Update inventories, JSONL records, classification folders, `open-findings.md`, and reports. Record coverage gaps and unverified candidates explicitly.
