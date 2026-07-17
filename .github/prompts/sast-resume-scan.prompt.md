# Resume SAST Scan

Run the `sast-resume` agent. Read `scan-state.json`, `checkpoints/latest.json`, `scan-queue.jsonl`, `visited-files.jsonl`, and `visited-endpoints.jsonl`; validate or repair them, write a fresh checkpoint before resuming, skip completed work, and continue the pending queue. Log the resume and update state before and after execution and after every meaningful unit of work. Do not modify application source code.
