# Resume Interrupted SAST Scan

Resume an interrupted scan from `.sast-agent/output/scan-progress.md` using the `@sast-resume` agent.

1. Inspect `.sast-agent/output/scan-progress.md` and locate the first uncompleted item (`- [ ]`).
2. Resume Pass 1 or Pass 2 scanning using `@sast-java` or `@sast-js` in batches.
3. Route findings through `@sast-verifier` and append to `findings.md`.
4. Update `scan-progress.md` status upon completion.
