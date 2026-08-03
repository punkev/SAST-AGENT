# Resume Scan

Run the `sast-resume` agent to continue an interrupted scan.

Read `.sast-agent/output/scan-progress.md`, find the first unchecked item, and continue scanning from there. Append new findings to the existing `findings.md`.

Use this when:
- VS Code crashed or the chat session ended mid-scan
- The LLM timed out or ran out of context
- You manually stopped a scan and want to continue later
