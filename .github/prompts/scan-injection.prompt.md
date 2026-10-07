# Full Injection Vulnerabilities Audit Across All Layers & Modules

Execute a comprehensive Injection Vulnerability security audit on all attached codebases/folders using the `sast-injection` agent.

## Execution Instructions

1. **Multi-Folder Scope**: Analyze all attached folders, modules, and subdirectories (controllers, routes, services, repositories, DAOs, ORM mappers, dynamic query builders, process executors, template engines, and logging pipelines).
2. **Sequential Run Output**:
   - Check `.sast-agent/output/` for existing `Injection Check Run <N>` directories.
   - Increment to the next sequential run directory: `.sast-agent/output/Injection Check Run {N+1}/`.
   - Store all findings in `findings.md`, live progress in `scan-progress.md`, structured export in `findings.json`, and the executive report in `summary.md`.
3. **Exhaustive Injection Taxonomy**:
   - **SQL Injection (SQLi)**: Classic In-Band, Native Queries, Blind (Boolean/Time), Second-Order, PL/SQL, Structural (`ORDER BY`, dynamic tables), ORM/MyBatis `${param}`.
   - **NoSQL Injection (NoSQLi)**: MongoDB operator injection (`$gt`, `$ne`, `$where`, `$regex`), unvalidated query objects, Spring Data Mongo `BasicQuery`.
   - **OS Command Injection (CWE-78)**: `Runtime.exec`, `ProcessBuilder`, `child_process.exec`, `spawn` with shell:true, argument injection.
   - **Code Injection (CWE-94)**: `eval()`, `new Function()`, `vm.runInContext()`, `ScriptEngine.eval()`.
   - **Server-Side Template Injection (SSTI) (CWE-1336)**: Thymeleaf (`__${...}__`, unescaped fragments), Velocity, FreeMarker, JSP EL, EJS (`<%- %>`), Pug, Handlebars.
   - **Expression Language (EL) & OGNL Injection (CWE-917)**: Spring SpEL (`parseExpression()`), OGNL, MVEL, Bean Validation custom templates.
   - **LDAP Injection (CWE-90)**: `DirContext.search`, `ldapjs` filters with unescaped attributes.
   - **XML / XPath / XXE Injection (CWE-643, CWE-611)**: `XPath.evaluate()`, unparsed entity injection.
   - **Log Injection / CRLF (CWE-117, CWE-93)**: Log forging in Logback/SLF4J/Winston, HTTP response splitting.
   - **HTML / Script Injection (Server-side XSS) (CWE-79)**: Dynamic unescaped server rendering.
   - **Header & Host Header Injection (CWE-113, CWE-644)**: Unsanitized HTTP headers.
   - **CSV / Formula Injection (CWE-1236)**: Dynamic spreadsheet exports with formula prefixes.
   - **SSRF / URL Protocol Injection (CWE-918)**: User-controlled URL schemes and targets in HTTP clients.
4. **Mandatory Reporting Requirements for EVERY Discovered Issue**:
   - Hyperlink to the affected file with exact line numbers (`file:///` scheme).
   - Real vulnerable code snippet directly from the codebase.
   - Secure code fix demonstrating safe remediation.
   - **Sample Burp Suite raw HTTP request ALWAYS included for EVERY issue reported**.
   - **Mermaid flowchart of data travel from the front-end user to the target sink/engine**.
   - **Non-technical justification** explaining why the vulnerability occurred and the business risk for non-technical stakeholders.

Do not modify application source code. Do not invent findings without real code evidence.
