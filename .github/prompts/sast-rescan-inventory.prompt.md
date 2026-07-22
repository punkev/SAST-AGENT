# SAST Fast Inventory-Reusing Rescan

Execute a fast, token-efficient vulnerability re-scan using the pre-built inventories and queue under `.sast-agent/`.

1. Read `.sast-agent/state/scan-state.json`, `.sast-agent/inventory/` (`endpoint-inventory.md`, `route-to-handler-map.md`, `repo-profile.md`, `access-control-matrix.md`), and `.sast-agent/state/scan-queue.jsonl`.
2. **SKIP Discovery & Inventory Phases**: Do not waste tokens or time re-detecting technologies, mapping routes, or rebuilding endpoint inventories. Reuse all existing `.sast-agent/inventory/` files.
3. **Vulnerability Audit Pass**: Immediately audit queued source files across Smart Triage Priority Tiers (Tier 1 → Tier 2 → Tier 3) for missed vulnerabilities, logic flaws, high-entropy secrets, and insecure configurations.
4. Record verified findings to `.sast-agent/findings/findings.jsonl`.
5. Execute the `html-report-generator` skill (`python .agents/skills/html-report-generator/scripts/generate_html_report.py` or `node .agents/skills/html-report-generator/scripts/generate_html_report.js`) to refresh `.sast-agent/reports/index.html`.
