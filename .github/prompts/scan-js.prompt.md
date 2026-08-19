# Scan Node.js / TypeScript Project

Execute a targeted Node.js / JavaScript / TypeScript SAST scan on the attached source code using `@sast-js` and `@sast-verifier`.

1. Read `.sast-agent/config/ignore-paths.yml` and ignore all media, test suites (`**/test/**`, `**/*.spec.*`), and build directories (`node_modules/**`, `dist/**`, `.next/**`).
2. **Pass 1**: Index all route handlers (Express, NestJS, Fastify, Next.js API/Server Actions), Message Queue consumers (BullMQ, KafkaJS), and Template views (EJS, Pug, Handlebars).
3. **Pass 2**: Perform deep bidirectional taint analysis (Request Sources -> Middleware -> Services -> Sinks and Sink -> Handler) in batches of 3-5 items.
4. Route candidate findings through `@sast-verifier` to eliminate false positives, compute CVSS v3.1 scores, generate Burp PoCs for Critical/High findings, and write to `.sast-agent/output/findings.md`.
5. Audit configuration files (`package.json`, `.env`, Helmet/CORS middleware, JWT settings).

Do not modify application source code. All findings must reference real code evidence.
