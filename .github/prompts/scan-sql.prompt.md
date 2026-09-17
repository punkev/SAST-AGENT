# Full SQL Injection Audit Across All Layers & Modules

Execute a comprehensive SQL Injection security audit on all attached codebases/folders using the `sast-sql` agent.

## Execution Instructions

1. **Multi-Folder Scope**: Analyze all attached folders, modules, and subdirectories (controllers, routes, services, repositories, DAOs, ORM mappers, dynamic query builders, and database stored procedures).
2. **Sequential Run Output**:
   - Check `.sast-agent/output/` for existing `SQL Check Run <N>` directories.
   - Increment to the next sequential run directory: `.sast-agent/output/SQL Check Run {N+1}/`.
   - Store all findings in `findings.md`, progress in `scan-progress.md`, structured data in `findings.json`, and the executive report in `summary.md`.
3. **Exhaustive SQL Injection Taxonomy**:
   - Classic In-Band SQLi (string concatenation, UNION-based, error-based).
   - Native Query Injections (`createNativeQuery`, `@Query(..., nativeQuery=true)`, raw JDBC, raw ORM queries).
   - Blind SQL Injection (Boolean-based conditional responses, Time-based sleep/delay execution).
   - Second-Order / Stored SQL Injection (tainted data retrieved from database/queues and executed in subsequent queries).
   - PL/SQL & Stored Procedure / Function Injections (`EXECUTE IMMEDIATE`, dynamic PL/pgSQL, `sp_executesql`).
   - Dynamic Structural Injections (`ORDER BY`, `GROUP BY`, column/table name interpolation, `LIMIT`/`OFFSET`).
   - ORM / Mapper Injections (MyBatis `${param}`, Hibernate JPQL/HQL, Sequelize/TypeORM/Prisma unsafe raw queries).
4. **Mandatory Reporting Requirements for EVERY Discovered Issue**:
   - Hyperlink to the affected file with exact line numbers.
   - Real vulnerable code snippet from the codebase.
   - Secure code fix demonstrating safe remediation.
   - **Sample Burp Suite raw HTTP request ALWAYS included for EVERY issue reported**.
   - **Mermaid flowchart of data travel from the front-end user to the database engine**.
   - **Non-technical justification** explaining why the vulnerability occurred and the business risk for non-technical stakeholders.

Do not modify application source code. Do not invent findings without real code evidence.
