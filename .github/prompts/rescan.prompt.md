# Rescan Project

Run the `sast-resume` agent in **rescan mode** on the attached source code.

Reuse the existing controller/route list from `.sast-agent/output/scan-progress.md` but perform a fresh vulnerability analysis:
1. Reset all progress checkboxes to unchecked.
2. Archive previous findings (rename `findings.md` to `findings-{date}.md`).
3. Scan all controllers/routes again from scratch with fresh eyes.

Use this when:
- The previous scan missed vulnerabilities
- You want a second-pass analysis
- You want to verify previous findings

If the source code has changed, run a full scan instead (use `scan-java` or `scan-js`).
