# Scan JavaScript Project

Run the `sast-js` agent on the attached JavaScript/TypeScript source code folders.

1. Identify the project type (Express backend, Next.js, React frontend, etc.).
2. Find all route handlers / API endpoints.
3. Scan routes in batches of 3-5, tracing the full request flow: Route → Middleware → Business Logic → DB.
4. Check every route against the OWASP Web Top 10 + API Top 10 checklist.
5. Save findings to `.sast-agent/output/findings.md` after every batch.
6. Check for frontend-specific issues (DOM XSS, token exposure, client-side auth bypass) if applicable.
7. Scan config and dependencies for misconfigurations, hardcoded secrets, and known CVEs.

Do not modify application source code. Do not invent vulnerabilities.
