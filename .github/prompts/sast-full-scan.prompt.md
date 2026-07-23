# Full SAST Scan (First-Time Complete Analysis)

Run the `sast-scanner` workflow for this repository. This is a **first-time complete scan** that performs full discovery, inventory, and deep vulnerability analysis.

1. Before execution, read all durable state files. Set `scan_mode` to `"full"` in `scan-state.json`. Write a start checkpoint.
2. Discover repository scope and technologies. Enumerate **100% of files and folders** across the repository (excluding only configured ignore paths) and populate `scan-queue.jsonl`.
3. Inventory Java/Spring/Struts, Node/Express, and frontend endpoints and save `.sast-agent/inventory/endpoint-inventory.md` and `.sast-agent/inventory/route-to-handler-map.md`.
4. Build authn/authz, dataflow, sensitive-data, and frontend API inventories.
5. Scan **every single file in the queue** using the Deep Dive Multi-Pass Analysis strategy:
   - **Pass 1**: Individual file deep analysis in small batches (3-5 files). Read ENTIRE file contents for Tier 1/2 files. Simultaneously load related modules for cross-file context. Save findings after EVERY batch.
   - **Pass 2**: Cross-file dataflow correlation. Trace multi-file source-to-sink paths. Identify authorization gaps across endpoint chains.
   - **Every finding written to `findings.jsonl` MUST contain ALL mandatory fields with real, file-specific evidence — no generic placeholders or boilerplate.**
6. **COVERAGE VERIFICATION GATE:** Cross-reference `scan-queue.jsonl` against `visited-files.jsonl`. If any files remain unvisited, scan them NOW or document gaps in `.sast-agent/reports/coverage-gaps.md`. Update `scan-state.json` with coverage metrics. **Do NOT proceed until all files are accounted for.**
7. **FINDING VALIDATION GATE:** Iterate all entries in `findings.jsonl` and validate that every mandatory field contains real evidence. Downgrade incomplete findings to `needs-review`. Log validation results. **Do NOT proceed to report generation with incomplete findings classified as `confirmed`.**
8. Generate all reports, including the dated final report. Execute the `html-report-generator` skill.
9. Update state before and after execution and after every meaningful unit of work. If interrupted, leave a valid checkpoint and pending queue so a Resume Scan can continue.

Do not modify application source code. Do not report unsupported suspicions as vulnerabilities. Do not write findings with placeholder or generic evidence in any field.

> **If this scan is interrupted**, use the `sast-resume-scan` prompt to continue from where it left off.
> **To re-analyze the same codebase later**, use the `sast-rescan` prompt to skip discovery and run fresh analysis.
