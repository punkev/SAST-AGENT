---
name: sast-resume
description: Resume an interrupted SAST scan (Java or JS) from the last checkpoint in scan-progress.md.
tools: ['search/codebase', 'read', 'edit']
---

# Resume SAST Scan

Resume an interrupted scan from where it left off. Works for both Java and JS scans.

**Do NOT modify application source code.** Only update files under `.sast-agent/output/`.

## How to Resume

1. **Read `.sast-agent/output/scan-progress.md`.**
   - If this file doesn't exist, tell the user: "No scan in progress. Run a full scan first using `scan-java` or `scan-js`."
   - If this file exists, read it to determine what's done and what's pending.

2. **Find the first unchecked item** — the first `- [ ]` line in the Controllers or Route Handlers section.

3. **Determine scan type** from the file:
   - If it lists "Controllers" with Java-style names → this is a Java scan. Follow `sast-java` agent instructions.
   - If it lists "Route Handlers" with JS-style names → this is a JS scan. Follow `sast-js` agent instructions.

4. **Continue scanning from the first unchecked item**, processing in batches:
   - Java: 3 controllers per batch
   - JS: 3-5 route handlers per batch

5. **Append new findings** to `.sast-agent/output/findings.md` (do not overwrite existing findings).

6. **Mark completed items** as `[x]` in `scan-progress.md` after each batch.

7. When all items are checked, run the config/secrets pass if it hasn't been done, then update the final summary.

## Rescan Mode

If the user says "rescan" or "scan again":
1. Read the existing `scan-progress.md` to get the controller/route list (don't re-discover).
2. Reset all `[x]` back to `[ ]`.
3. Clear `findings.md` (or archive by renaming to `findings-{timestamp}.md`).
4. Start scanning from the beginning using the existing list.

## Rules

- Follow the same finding format, evidence rules, and OWASP checklist as the original scan agent.
- Do NOT duplicate findings — check `findings.md` for existing entries before writing.
- Save after every batch.
