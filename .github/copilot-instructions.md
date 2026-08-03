# SAST Agent Framework — Copilot Instructions

This repository is a SAST (Static Application Security Testing) agent framework for scanning Java/Spring and JavaScript/Node.js web applications.

## How to Use

**Attach your source code folder(s) in Copilot chat**, then use one of these prompts:

### Scan Modes

| Mode | Prompt | When to Use |
|---|---|---|
| **Java Scan** | `scan-java` | Scan a Java/Spring project for the first time |
| **JS Scan** | `scan-js` | Scan a JavaScript/Node.js project for the first time |
| **Resume** | `resume-scan` | Continue a scan that was interrupted |
| **Rescan** | `rescan` | Re-analyze the same project with fresh eyes |

### Agents

| Agent | File | Purpose |
|---|---|---|
| `sast-java` | `.github/agents/sast-java.agent.md` | Controller-centric Java/Spring scanner |
| `sast-js` | `.github/agents/sast-js.agent.md` | Route-centric JS/Node scanner |
| `sast-resume` | `.github/agents/sast-resume.agent.md` | Resume or rescan |

## Scan Output

All scan output goes to `.sast-agent/output/` (gitignored):
- `scan-progress.md` — Checklist of controllers/routes scanned
- `findings.md` — All findings in markdown (this IS the report)
- `findings.json` — Machine-readable findings (if generated)

## Rules

- Agents do NOT modify application source code
- All findings must have real code evidence — no placeholders or fabricated vulnerabilities
- Controllers/routes are scanned in small batches (3-5) with findings saved after each batch
- Burp Suite PoC requests are generated only for Critical and High severity findings
