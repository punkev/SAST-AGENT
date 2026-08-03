# SAST Agent Framework

A lightweight SAST (Static Application Security Testing) agent for GitHub Copilot Chat that scans Java/Spring and JavaScript/Node.js web applications for security vulnerabilities.

## How It Works

1. Open VS Code with this repo
2. Open GitHub Copilot Chat
3. Attach your source code folder(s)
4. Run a scan prompt (e.g., `/scan-java` or `/scan-js`)

The agent traces **controller/route request flows end-to-end** — from HTTP entry point through service layers to database sinks — checking against OWASP Web Top 10 and API Top 10.

## Scan Modes

| Mode | Prompt | Description |
|---|---|---|
| **Java Scan** | `scan-java` | Scans Java/Spring projects. Finds all `@Controller`/`@RestController` classes, traces their endpoint flows, checks OWASP. |
| **JS Scan** | `scan-js` | Scans Node.js/Express, Next.js, React, Angular projects. Finds all route handlers, traces flows, checks OWASP. |
| **Resume** | `resume-scan` | Continues an interrupted scan from the last checkpoint. |
| **Rescan** | `rescan` | Re-analyzes the same project without re-doing discovery. |

## Project Structure

```
SAST-AGENT/
├── .github/
│   ├── copilot-instructions.md              # Master Copilot config
│   ├── agents/
│   │   ├── sast-java.agent.md               # Java/Spring scanner agent
│   │   ├── sast-js.agent.md                 # JS/Node scanner agent
│   │   └── sast-resume.agent.md             # Resume/rescan agent
│   ├── instructions/
│   │   ├── finding-format.instructions.md   # How findings are structured
│   │   └── owasp-checklist.instructions.md  # OWASP Top 10 + API Top 10
│   └── prompts/
│       ├── scan-java.prompt.md              # "Scan this Java project"
│       ├── scan-js.prompt.md                # "Scan this JS project"
│       ├── resume-scan.prompt.md            # "Continue interrupted scan"
│       └── rescan.prompt.md                 # "Rescan same project"
├── .vscode/
│   └── settings.json                        # Copilot settings
├── .sast-agent/
│   └── config/
│       └── ignore-paths.yml                 # Paths to skip during scanning
├── .gitignore
└── README.md
```

### Runtime Output (gitignored)

During a scan, the agent creates:

```
.sast-agent/output/
├── scan-progress.md     # Checklist of controllers/routes (tracks progress)
├── findings.md          # All vulnerability findings (THE report)
└── findings.json        # Machine-readable findings (optional)
```

## What Gets Checked

The agents check against **OWASP Web Application Top 10 (2021)** and **OWASP API Security Top 10 (2023)**:

- **Injection**: SQL, NoSQL, OS command, template, SpEL, XPath, LDAP
- **Broken Access Control**: Missing auth, IDOR/BOLA, privilege escalation, CORS
- **XSS**: Reflected, stored, DOM-based
- **SSRF**: User-controlled URLs in server-side HTTP clients
- **Broken Authentication**: Weak JWT, session issues, brute-force
- **Security Misconfiguration**: Debug mode, exposed endpoints, missing headers, XXE
- **Mass Assignment**: Direct model binding without field allowlists
- **Sensitive Data Exposure**: Passwords in responses, tokens in URLs, secrets in code
- **Deserialization**: Unsafe `ObjectInputStream`, Jackson default typing

## Finding Format

Each finding includes:

| Field | Required For |
|---|---|
| Title + Severity + CWE/OWASP | All findings |
| File path + line numbers | All findings |
| Endpoint (HTTP route) | All findings |
| Request flow (source → sink trace) | All findings |
| Impact description | All findings |
| Vulnerable code block | All findings |
| Secure fix code block | All findings |
| Remediation steps | All findings |
| Burp Suite PoC HTTP request | Critical + High only |

## Design Philosophy

- **Controller-centric**: Scan routes/controllers first, not every file. This is where vulnerabilities live.
- **Small batches**: 3 controllers per batch. Save after each batch. Prevents context exhaustion.
- **Markdown state**: Progress tracked in a simple markdown checklist. LLMs read/write markdown naturally.
- **Lean instructions**: Agent files are focused. Less instruction overhead = more context for actual analysis.
- **No fabrication**: Every finding must reference real code. No generic placeholders allowed.

## Configuration

### Ignore Paths

Edit `.sast-agent/config/ignore-paths.yml` to customize which paths are skipped:

```yaml
ignore:
  - '**/test/**'
  - '**/node_modules/**'
  - '**/target/**'
  - '**/build/**'
  - '**/dist/**'
```

## License

MIT
