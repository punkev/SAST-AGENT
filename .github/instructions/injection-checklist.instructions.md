# Injection Vulnerabilities SAST Audit Checklist

Use this checklist to perform an exhaustive, end-to-end security audit across controllers, routes, service layers, data mappers, process builders, template engines, and logging pipelines for **all injection-based vulnerabilities**.

---

## 1. Injection Taxonomy & Vulnerability Patterns

### A. SQL & Persistence Layer Injections (CWE-89)
- [ ] **Classic In-Band SQL Injection**:
  - Direct string concatenation in queries (`"SELECT * FROM users WHERE username = '" + username + "'"`).
  - Use of `String.format()`, f-strings, template literals (`` `SELECT * FROM ${table} WHERE id = ${id}` ``), `printf`, or `%s`.
  - Iterative `StringBuilder` or `StringBuffer` in loops or dynamic queries without parameter binding.
  - UNION-based and Error-based query injection patterns.
- [ ] **Native Query Injections & Framework Sinks**:
  - Spring Data / JPA: `@Query(value = "SELECT ... " + :input, nativeQuery = true)`, `entityManager.createNativeQuery(...)`, `jdbcTemplate.query(...)`.
  - JPQL & HQL: Concatenation in `entityManager.createQuery(...)` or Hibernate `session.createQuery(...)`.
  - Node.js ORMs: `sequelize.query(...)`, `connection.query(...)`, `repository.query(...)`, Prisma `prisma.$queryRawUnsafe(...)`, Knex `knex.raw(...)`.
  - Python / Django / SQLAlchemy: `cursor.execute("..." + var)`, `Model.objects.raw()`, `.extra(where=[...])`, `text("..." + var)`.
  - C# / .NET: `FromSqlRaw("..." + input)` without parameterized format placeholders, Dapper raw strings.
- [ ] **MyBatis / iBatis Sinks**:
  - `${param}` direct string substitution instead of `#{param}` parameterized binding in `*Mapper.xml` or `@Select`/`@Update`.
  - Dynamic `LIKE` queries (`LIKE '%${search}%'`) instead of `CONCAT('%', #{search}, '%')`.
- [ ] **PL/SQL & Stored Procedure Injections**:
  - Dynamic SQL in Oracle PL/SQL (`EXECUTE IMMEDIATE '...' || input`), PostgreSQL PL/pgSQL (`EXECUTE`), SQL Server (`sp_executesql`).
  - Concatenation in application procedure calls (`CallableStatement`).
- [ ] **Blind & Inferential SQL Injection**:
  - Boolean-based: Condition manipulation (`AND 1=1` vs `AND 1=2`) causing differential HTTP responses or record counts.
  - Time-based: Injected delays (`SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`).
- [ ] **Second-Order / Stored SQL Injection**:
  - Untrusted data stored in database columns or message queues retrieved and executed in downstream unparameterized queries.
- [ ] **Dynamic Structural Injections**:
  - Non-parameterizable clauses: `ORDER BY` and `GROUP BY` column names or directions (`ASC`/`DESC`).
  - Dynamic table, schema, or column names without server-side allowlists.
  - Dynamic `LIMIT` and `OFFSET` without strict integer casting.

### B. NoSQL Injection (CWE-943)
- [ ] **MongoDB Query Selector & Operator Injection**:
  - Express/Node.js body/query directly passed to Mongoose/Mongo: `db.users.find({ username: req.body.username })` where payload is `{"$ne": null}` or `{"$gt": ""}`.
  - Spring Data Mongo: `BasicQuery` built with string concatenation or unsanitized JSON.
- [ ] **JavaScript Evaluation in NoSQL**:
  - Unsafe use of `$where`, `mapReduce`, or `$accumulator` accepting user strings.
- [ ] **CouchDB / Cassandra CQL Injection**:
  - Dynamic CQL string formatting in Cassandra drivers.

### C. OS Command Injection (CWE-78)
- [ ] **Java Process Sinks**:
  - `Runtime.getRuntime().exec(cmd)` with string concatenation.
  - `ProcessBuilder` with commands passed through shell wrapper (`sh -c` or `cmd.exe /c`).
- [ ] **Node.js Child Process Sinks**:
  - `child_process.exec(cmd)` and `child_process.execSync(cmd)`.
  - `child_process.spawn(cmd, args, { shell: true })`.
- [ ] **Python Process Sinks**:
  - `os.system(cmd)`, `os.popen(cmd)`.
  - `subprocess.Popen(cmd, shell=True)` or `subprocess.run(..., shell=True)`.
- [ ] **Command Chaining & Metacharacters**:
  - Injections exploiting `;`, `&`, `&&`, `|`, `||`, `$()`, backticks, newlines, and flag/argument injection.

### D. Code Injection & Dynamic Evaluation (CWE-94)
- [ ] **JavaScript Dynamic Evaluation**:
  - `eval()`, `new Function(code)`, `vm.runInContext()`, `vm.runInNewContext()`.
  - Passing strings to `setTimeout("..." + code, ms)` or `setInterval(...)`.
- [ ] **Java Script Engine**:
  - `ScriptEngineManager` / Nashorn / Rhino / GraalVM JS: `engine.eval(userInput)`.
- [ ] **Python Dynamic Evaluation**:
  - `eval(userInput)`, `exec(userInput)`.

### E. Server-Side Template Injection (SSTI) (CWE-1336)
- [ ] **Java Template Engines**:
  - Thymeleaf: Unescaped view names or expression preprocessing `__${...}__` in controller return strings.
  - Velocity / FreeMarker / Pebble: Dynamic template string rendering from user input.
  - JSP EL: Dynamic evaluation of `${...}` expressions from untrusted variables.
- [ ] **Node.js Template Engines**:
  - EJS: Unescaped raw output `<%- userInput %>` or rendering dynamic template strings.
  - Pug: Unescaped interpolation `!{userInput}`.
  - Handlebars: Unescaped triple-brace `{{{userInput}}}` in sensitive HTML/script contexts.
  - Nunjucks / Twig.js dynamic template compilation.

### F. Expression Language (EL) & OGNL Injection (CWE-917)
- [ ] **Spring Expression Language (SpEL)**:
  - Dynamic string passed to `SpelExpressionParser.parseExpression(userInput).getValue()`.
  - Spring Cloud Config or OAuth2 endpoints evaluating SpEL expressions.
- [ ] **OGNL / MVEL Injection**:
  - OGNL dynamic expression evaluation (Struts / MyBatis dynamic tags).
  - MVEL `MVEL.eval(userInput)`.
- [ ] **Bean Validation EL Injection**:
  - Custom constraint validators calling `context.buildConstraintViolationWithTemplate(userInput)` which interpolates SpEL/EL expressions by default.

### G. LDAP Injection (CWE-90)
- [ ] **Java JNDI / LDAP**:
  - Concatenating user inputs into LDAP filter strings in `DirContext.search("(&(uid=" + user + ")...)")`.
- [ ] **Node.js LDAP**:
  - Unsanitized inputs in `ldapjs` search filters.

### H. XML, XPath & XXE Injection (CWE-643, CWE-611)
- [ ] **XPath Injection**:
  - Dynamic queries in `XPath.evaluate("//user[name='" + input + "']")`.
- [ ] **XML External Entity (XXE)**:
  - XML parsers (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`) parsing user XML without disabling `http://apache.org/xml/features/disallow-doctype-decl` and external entities.

### I. Log Injection & Log Forging / CRLF (CWE-117, CWE-93)
- [ ] **Log Forging**:
  - Logging unescaped user inputs containing `\r` and `\n` to forge audit log entries or inject fake security events.
- [ ] **HTTP Response Splitting / Header Injection**:
  - Inserting `\r\n` into response headers via user-controlled cookies, redirects (`Location`), or custom headers (`Set-Cookie`).

### J. HTML / Script Injection (Server-Side Reflected / Stored XSS) (CWE-79)
- [ ] **Server-Side HTML Injection**:
  - Unescaped user text rendered directly into server-generated HTML responses or API error pages.

### K. CSV / Formula Injection (CWE-1236)
- [ ] User-controllable data exported to CSV / Excel sheets starting with formula indicators (`=`, `+`, `-`, `@`, `|`) without prepending a single quote `'` or sanitizing.

### L. SSRF / URL Protocol Injection (CWE-918)
- [ ] Untrusted inputs concatenated into outbound HTTP client targets (`RestTemplate`, `WebClient`, `axios`, `fetch`) allowing internal service access or cloud metadata exfiltration (`http://169.254.169.254`).

---

## 2. End-to-End Taint Tracing Workflow

For every endpoint or handler, systematically trace taint propagation:

```
[Untrusted Entry Point: HTTP Request / Message Queue / File Upload / Webhook]
       │
       ▼ (Extracts: params, headers, body, query, JSON properties)
[Controller / Route Handler Layer]
       │
       ▼ (Passes variables to service/business logic methods)
[Service / Business Layer]
       │
       ▼ (Assembles command, query, template, LDAP filter, or log string)
[Dangerous Injection Sink]
       │
       ▼ (Executes instruction directly in subsystem)
[Database / OS Shell / Interpreter / Template Engine / LDAP / Log File]
```

1. **Source Identification**: Locate untrusted user inputs (HTTP endpoints, WebSocket messages, message broker queues, file uploads).
2. **Transformations & Sanitization**: Inspect all string manipulation, encoding, validation regexes, or casting between source and sink.
3. **Sink Verification**: Inspect the exact method call delivering the dynamic command/query to the underlying execution engine.
4. **Identify False Positives**:
   - Parameterized statements / prepared bindings used.
   - Strict server-side allowlists / enum lookups enforced.
   - Strict parsing/casting (`Integer.parseInt()`, `UUID.fromString()`) prior to interpolation.
   - Context-aware auto-escaping properly active.

---

## 3. Secure Remediation Best Practices

For every identified vulnerability, recommend the appropriate defensive pattern:

1. **Parameterization & Prepared Statements**:
   - Always bind variables as data parameters rather than concatenating them into executable syntax.
2. **Strict Server-Side Allowlists**:
   - When parameterization is syntactically impossible (identifiers, table/column names, `ORDER BY`, shell commands), use an explicit allowlist or enum mapping.
3. **Contextual Encoding & Escaping**:
   - Encode data appropriately for the interpreter (HTML encoding, LDAP filter escaping, CRLF stripping).
4. **Safe APIs & Structured Execution**:
   - Use `ProcessBuilder` with separate argument arrays (no shell invocation).
   - Use safe ORM methods and avoid raw query execution.
   - Disable external entity resolution in XML parsers.
5. **Least Privilege**:
   - Restrict database permissions, disable administrative procedures, and execute processes under low-privilege service accounts.
