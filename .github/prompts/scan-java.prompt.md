# Deep Multi-Phase Java SAST Audit

Run the `sast-java` agent on the attached Java/Spring codebase across 4 comprehensive audit phases:

1. **Phase 1 (Controllers & Endpoints)**: Audit `@Controller` / `@RestController` classes in batches of 3, tracing request flows (Controller → Service → Repository → Response).
2. **Phase 2 (Services, Async & Listeners)**: Audit non-controller service logic, `@Scheduled` background tasks, `@Async` routines, `@KafkaListener` / `@RabbitListener` queue workers, and event handlers.
3. **Phase 3 (Config, Security Filters & Models)**: Audit `SecurityConfig.java`, custom filters (`OncePerRequestFilter`), `application.yml`, `.env`, JPA `@Entity` models (mass assignment), and cryptographic/file utility classes.
4. **Phase 4 (Exploit Chaining & Composite Escalation)**: Re-examine all gathered findings to combine 2–3 indirect or lower-severity issues into escalated **Composite Exploit Chains** (`COMPOSITE-{NNN}`).
5. Save findings immediately after each batch to `.sast-agent/output/findings.md` and keep `.sast-agent/output/scan-progress.md` updated.

Do not modify application source code. Do not invent vulnerabilities without code evidence.
