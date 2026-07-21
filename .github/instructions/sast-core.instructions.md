# Core SAST Instructions

## Method

Use endpoint-driven source-to-sink analysis. Start with repository discovery, including a rapid **Semantic Pre-Triage Scan** of dangerous code patterns to prioritize targets. Build an endpoint inventory mapping paths to user roles, generating a role-based **Access Control Matrix**. Resolve route-to-handler mappings, model dataflow, and construct inter-procedural **Control Flow Graphs (CFGs)** before testing sinks. Search patterns are triage only; a confirmed finding needs a reachable source, relevant transformations, sink, impact, verified evidence, and an **Active Defense (Negative Verification)** check proving existing controls are bypassed.

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
