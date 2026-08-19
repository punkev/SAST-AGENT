# Scan Java Project

Execute a targeted Java / Spring SAST scan on the attached source code using `@sast-java` and `@sast-verifier`.

1. Read `.sast-agent/config/ignore-paths.yml` and ignore all media, test suites (`src/test/**`), and build directories (`target/**`, `build/**`).
2. **Pass 1**: Index all REST endpoints (`@Controller`, `@RestController`), Message Queue listeners (`@KafkaListener`, `@RabbitListener`, `@SqsListener`), Schedulers (`@Scheduled`), and Template Views (Thymeleaf/JSP).
3. **Pass 2**: Perform deep bidirectional taint analysis (Source -> Service -> DAO -> Sink and Sink -> Caller) in batches of 3-4 items.
4. Route candidate findings through `@sast-verifier` to eliminate false positives, compute CVSS v3.1 scores, generate Burp PoCs for Critical/High findings, and write to `.sast-agent/output/findings.md`.
5. Audit configuration files (`application.yml`, `SecurityConfig.java`, `pom.xml`, `build.gradle`).

Do not modify application source code. All findings must reference real code evidence.
