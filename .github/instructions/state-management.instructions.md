# State Management Instructions

Durable state is authoritative. Before work, read `scan-state.json`, `checkpoints/latest.json`, `scan-queue.jsonl`, `visited-files.jsonl`, and `visited-endpoints.jsonl`. Never infer progress only from chat history.

For every meaningful unit, write or append a record with scan ID, timestamp, phase, stable file/endpoint ID, status, and note. Mark work completed only after its artifact is saved. Keep pending/failed work in the queue. Refresh `latest.json` and counters after each unit and at phase boundaries. Use stable IDs based on normalized path plus method/route or file/function anchor so resume does not duplicate work.

If a record is malformed, preserve it, log the repair, reconstruct from the latest valid checkpoint and inventories, and write a fresh checkpoint before continuing. State updates must not contain full secrets.

## JSONL Integrity Validation

All `.jsonl` files (`scan-queue.jsonl`, `visited-files.jsonl`, `visited-endpoints.jsonl`, `findings.jsonl`) are append-only logs that may be corrupted if a crash occurred during a write operation.

**On every scan start (full, resume, or rescan), validate JSONL integrity:**

1. Read each `.jsonl` file line by line.
2. Attempt to parse each line as JSON.
3. If a line fails to parse:
   - It was likely truncated by a mid-write crash.
   - Log the corrupted line content and error to `.sast-agent/logs/corrupted-records.log`.
   - Remove the corrupted line from the working file.
   - Report the repair count.
4. After validation, rewrite the file with only valid lines.
5. If the last line of `visited-files.jsonl` matches `current_file` in `scan-state.json`, the file was being processed when the crash occurred. Re-queue it for analysis.

## Scan Mode Tracking

The `scan_mode` field in `scan-state.json` MUST be set at the start of every scan:

| Mode | Value | Set By | Meaning |
|---|---|---|---|
| Full Scan | `"full"` | `sast-scanner` agent | First-time complete discovery + analysis |
| Resume | `"resume"` | `sast-resume` agent | Continuing interrupted scan |
| Rescan | `"rescan"` | `sast-rescan` agent | Fresh analysis reusing existing inventory |

**Mode transition rules:**
- A Full Scan always starts fresh with `scan_mode: "full"`.
- A Resume preserves the existing `scan_mode` (it continues whatever was running). If `scan_mode` is null, set to `"resume"` with a warning.
- A Rescan sets `scan_mode: "rescan"` and archives previous findings.
- Every mode transition MUST be recorded in `scan_mode_history` array with `{mode, timestamp, scan_id}`.

## Crash Recovery Protocol

When the Resume agent starts, it MUST follow this protocol:

1. **Detect crash type** by examining state:
   - `status: "in_progress"` + `current_file` set = crash during file analysis
   - `status: "in_progress"` + `current_phase: "reporting"` = crash during report generation
   - `status: "not_started"` + `scan_id` set = crash during initialization
   - Missing or empty state files = catastrophic crash or first run

2. **Record crash context** in `last_crash_context`:
   ```json
   {
     "phase": "source-to-sink-scan",
     "file": "src/controllers/UserController.java",
     "endpoint": "GET /api/users",
     "timestamp": "2024-01-15T10:30:00Z",
     "reason": "Inferred: LLM context exhaustion (last checkpoint 45min ago)"
   }
   ```

3. **Increment `resume_count`** and append to `scan_mode_history`.

4. **Write a fresh checkpoint** before resuming any work.

## Coverage Audit Rule (MANDATORY)

Before ANY phase transition to the reporting phase, the agent MUST perform a coverage audit:

1. **File Coverage**: Read every entry in `scan-queue.jsonl` and check against `visited-files.jsonl`. Compute `file_coverage_ratio = files_visited / files_queued`.
2. **Endpoint Coverage**: Read every entry in `endpoint-inventory.md` and check against `visited-endpoints.jsonl`. Compute `endpoint_coverage_ratio = endpoints_analyzed / endpoints_discovered`.
3. **Finding Completeness**: Read every entry in `findings.jsonl` and validate all mandatory fields. Compute `finding_completeness_ratio = complete_findings / total_findings`.
4. **Record in scan-state.json**: Write `files_queued`, `files_visited`, `files_skipped`, `file_coverage_ratio`, `endpoints_discovered`, `endpoints_analyzed`, `endpoint_coverage_ratio`, `findings_total`, `findings_complete`, `findings_incomplete`, and `finding_completeness_ratio`.
5. **Gate**: If `file_coverage_ratio < 1.0`, the agent MUST either scan the remaining files or document each gap in `.sast-agent/reports/coverage-gaps.md`. If `finding_completeness_ratio < 1.0`, the agent MUST fix incomplete findings or downgrade them to `needs-review`.
6. **Only after the coverage audit passes** may the agent proceed to report generation.

