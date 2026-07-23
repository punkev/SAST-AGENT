# Resume SAST Scan

Run the `sast-resume` agent to continue an interrupted scan.

## When to Use

Use this prompt when a previous Full Scan or Rescan was **interrupted** and you want to continue from where it left off. Common scenarios:
- VS Code crashed or the window was closed mid-scan
- The LLM model hung or timed out
- The scan ran out of context/tokens
- You manually cancelled the scan
- The network disconnected

## What Happens

1. The agent reads all durable state files (scan-state, checkpoints, queues, visited records, findings).
2. **Crash diagnostics**: Validates all JSONL files for integrity, repairs any corrupted entries from mid-write crashes, and reports what happened.
3. **Recovery summary**: Prints a clear summary of completed vs pending work before resuming.
4. **Resumes from pending queue**: Skips all completed files/endpoints and continues analyzing only the remaining work.
5. Applies the same coverage and evidence quality gates before generating reports.

## Important Notes

- **No need to re-attach source code** — the agent reads the existing scan queue and state.
- If all state files are missing, the agent will inform you that a **Full Scan** is required instead.
- The agent automatically uses smaller batch sizes if the previous crash was likely due to token exhaustion.

Do not modify application source code. Do not write findings with placeholder or generic evidence.
