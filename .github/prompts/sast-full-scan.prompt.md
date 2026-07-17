# Full SAST Scan

Run the `sast-scanner` workflow for this repository.

1. Before execution, read all durable state files and write a start checkpoint.
2. Discover repository scope and technologies.
3. Inventory Java/Spring/Struts, Node/Express, and frontend endpoints and save `.sast-agent/inventory/endpoint-inventory.md` and `.sast-agent/inventory/route-to-handler-map.md` using the required entry format.
4. Build authn/authz, dataflow, sensitive-data, and frontend API inventories.
5. Scan reachable source-to-sink flows across the configured taxonomy, verify candidates, classify findings, redact secrets, and write evidence.
6. Generate all reports, including the dated final report.
7. Update state before and after execution and after every meaningful unit of work. If interrupted, leave a valid checkpoint and pending queue.

Do not modify application source code. Do not report unsupported suspicions as vulnerabilities.
