# Run Full SAST Scan

Execute an end-to-end security audit on the attached source code folders using the `@sast-orchestrator` agent.

1. **Step 0 (Pre-Flight & Fast Index Check)**:
   - Check if `.sast-agent/output/pre-scan-index.json` or `.sast-agent/output/scan-progress.md` was generated via `.\scripts\pre-scan.cmd` or `.\scripts\pre-scan.ps1`.
   - If present: Load the pre-computed entry points and candidate sinks directly to bypass directory traversal and save tokens.
   - If absent: Read `.sast-agent/config/ignore-paths.yml` and strictly exclude media, binary, doc, and cache files.
2. **Step 1**: Detect the project language (Java/JVM vs. Node.js/TypeScript vs. Polyglot) and framework ecosystem.
3. **Step 2**: If not already pre-populated from fast index, catalog the attack surface (REST/HTTP, Message Queues, Schedulers, SSTI, Configs) in `.sast-agent/output/scan-progress.md`.
4. **Step 3**: Execute Pass 1 (Sink & Surface Discovery) and Pass 2 (Bidirectional Taint Analysis) using `@sast-java` or `@sast-js`.
5. **Step 4**: Verify findings, eliminate false positives, score with CVSS v3.1, and construct Burp PoCs via `@sast-verifier`.
6. **Step 5**: Save all confirmed findings to `.sast-agent/output/findings.md`.

Do not modify application source code. Never invent unverified vulnerabilities.
