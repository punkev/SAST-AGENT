# Run Full SAST Scan

Execute an end-to-end security audit on the attached source code folders using the `@sast-orchestrator` agent.

1. **Step 0**: Read `.sast-agent/config/ignore-paths.yml` and strictly ignore all media, document, font, binary, test, and build cache files.
2. **Step 1**: Automatically detect the project language (Java/JVM vs. Node.js/TypeScript vs. Polyglot) and framework ecosystem.
3. **Step 2**: Index the full attack surface (REST/HTTP, Message Queues, Schedulers, Template SSTI, Configs) in `.sast-agent/output/scan-progress.md`.
4. **Step 3**: Execute Pass 1 (Sink & Surface Discovery) and Pass 2 (Bidirectional Taint Analysis) using `@sast-java` or `@sast-js`.
5. **Step 4**: Verify findings, eliminate false positives, score with CVSS v3.1, and construct Burp PoCs via `@sast-verifier`.
6. **Step 5**: Save all confirmed findings to `.sast-agent/output/findings.md`.

Do not modify application source code. Never invent unverified vulnerabilities.
