# State Management Instructions

Durable state is authoritative. Before work, read `scan-state.json`, `checkpoints/latest.json`, `scan-queue.jsonl`, `visited-files.jsonl`, and `visited-endpoints.jsonl`. Never infer progress only from chat history.

For every meaningful unit, write or append a record with scan ID, timestamp, phase, stable file/endpoint ID, status, and note. Mark work completed only after its artifact is saved. Keep pending/failed work in the queue. Refresh `latest.json` and counters after each unit and at phase boundaries. Use stable IDs based on normalized path plus method/route or file/function anchor so resume does not duplicate work.

If a record is malformed, preserve it, log the repair, reconstruct from the latest valid checkpoint and inventories, and write a fresh checkpoint before continuing. State updates must not contain full secrets.
