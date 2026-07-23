# Rescan SAST (Fresh Analysis, Skip Discovery)

Run the `sast-rescan` agent on the attached source code folders.

This mode **reuses existing inventory and discovery data** from a prior Full Scan and performs a **fresh vulnerability analysis** from scratch. Use this when:
- The source code has already been scanned at least once
- You want a deeper or second-pass analysis without redoing recon
- The previous scan missed vulnerabilities or had incomplete findings
- You want fresh findings on the same codebase

## What happens

1. The agent validates that prerequisite inventory files exist from a prior Full Scan (if not, it will tell you to run a Full Scan first).
2. Previous findings are **archived** (not deleted) for later comparison.
3. Scan progress is reset — all files will be re-analyzed from scratch.
4. The full vulnerability analysis runs: source-to-sink tracing, CFG construction, negative verification, evidence collection.
5. Coverage and evidence quality gates are enforced before report generation.
6. Fresh reports are generated, including a comparison against the previous scan's findings.

## Prerequisites

A prior Full Scan must have completed (or at least finished the discovery/inventory phases). The following files must exist:
- `.sast-agent/inventory/endpoint-inventory.md`
- `.sast-agent/inventory/route-to-handler-map.md`
- `.sast-agent/state/scan-queue.jsonl`

If the source code has changed since the last Full Scan, use a **Full Scan** instead to re-discover the repository structure.

Do not modify application source code. Do not write findings with placeholder or generic evidence.
