# Rescan Source Code

Initiate a fresh rescan pass on the attached codebase using `@sast-resume` in rescan mode.

1. Preserve the discovered inventory of controllers, routes, message listeners, and views in `.sast-agent/output/scan-progress.md`.
2. Reset all progress checkboxes to unchecked (`- [ ]`).
3. Archive previous findings (`findings.md` -> `findings-archive-{timestamp}.md`).
4. Re-run Pass 2 deep bidirectional taint analysis with fresh evaluation.
