# Verify One SAST Finding

Read durable state first and identify the requested finding by stable ID. Trace the source through transformations and controls to the sink, confirm endpoint-to-handler mapping and reachability, inspect relevant tests/configuration, and record minimal redacted evidence. Apply false-positive checks, classify as confirmed, needs-review, duplicate, or false-positive, update `findings.jsonl` and the appropriate folder, then write a checkpoint before and after execution. Do not modify application source code.
