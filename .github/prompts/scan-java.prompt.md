# Scan Java Project

Run the `sast-java` agent on the attached Java/Spring source code folders.

1. Find all `@Controller` / `@RestController` classes and list their endpoints.
2. Scan controllers in batches of 3, tracing the full request flow: Controller → Service → Repository → DB.
3. Check every endpoint against the OWASP Web Top 10 + API Top 10 checklist.
4. Save findings to `.sast-agent/output/findings.md` after every batch.
5. After all controllers, scan config files for misconfigurations and hardcoded secrets.

Do not modify application source code. Do not invent vulnerabilities.
