# Core SAST Instructions

## Method

Use endpoint-driven source-to-sink analysis. Start with repository and technology discovery, then inventory endpoints and route-to-handler mappings, then model authentication/authorization and dataflow before testing sinks. Search patterns are triage only; a confirmed finding needs a reachable source, relevant transformations, sink, impact, and evidence.

## Sources and sinks

Sources include request paths, query/form parameters, JSON bodies, headers, cookies, uploaded files, message queues, environment/config values, database results, browser URL/DOM/storage, and inter-service responses. Sinks include SQL/JPQL/native queries, Mongo/LDAP/XPath expressions, commands, filesystem paths, XML parsers, templates/HTML, redirects, SSRF clients, deserializers, JWT verification, and authorization decisions.

## Rules

- Read `.sast-agent/config` and ignore only configured low-value paths.
- Treat production configuration, security filters, dependency manifests, and deployment descriptors as in scope.
- Distinguish authentication from authorization and server enforcement from client-only controls.
- Save state for each file, endpoint, controller, route, verified finding, and report section.
- Keep evidence concise, line-anchored, and secret-redacted.

## Output

Use the required endpoint and finding templates. Update inventories, JSONL records, classification folders, `open-findings.md`, and reports. Record coverage gaps and unverified candidates explicitly.
