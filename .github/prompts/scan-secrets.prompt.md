# Scan Hardcoded Secrets & Credentials

Run the `@sast-secrets` agent to perform a dedicated credentials and secret discovery audit on the attached codebase.

1. **Scope**: Scan all production source files, configuration files (`application*.yml`, `package.json`, `pom.xml`, `.env*`, scripts), AND all test files / directories (`src/test/**`, `**/tests/**`, `**/__tests__/**`, `**/mocks/**`, `**/fixtures/**`).
2. **Exclusions**: Ignore media files, documents, fonts, compiled binaries, and vendor caches (`node_modules`, `target`, `dist`, `.git`).
3. **Detection**: Search for AWS/GCP/Azure keys, GitHub/GitLab tokens, Slack/Discord webhooks, Stripe/Twilio keys, JWT tokens, base64-encoded basic auth, private keys, database connection strings, and hardcoded passwords.
4. **Dual-Section Reporting**: Write findings to `.sast-agent/output/secrets-findings.md` separated into:
   - **Section 1**: Production & Configuration Secrets (High Risk)
   - **Section 2**: Test Files & Fixtures Secrets (Credential Leak Risk)
5. **Masking**: Mask all sensitive tokens in the report (e.g., `sk_live_51...abc`).

Do not modify application source code.
