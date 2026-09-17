# SQL & Persistence Layer Injection Audit Checklist

Use this checklist to perform an exhaustive, end-to-end security audit of all controllers, routes, service layers, repositories, ORM mappers, dynamic query builders, and database stored procedures across single or multiple attached project folders.

---

## 1. SQL Injection Taxonomy & Vulnerability Patterns

### A. Classic In-Band SQL Injection (String Concatenation & Formatting)
- [ ] **Direct String Concatenation**: SQL queries constructed using string addition (`"SELECT * FROM users WHERE username = '" + username + "'"`).
- [ ] **String Formatting & Interpolation**: Use of `String.format()`, f-strings, template literals (`` `SELECT * FROM ${table} WHERE id = ${id}` ``), `printf`, or `%s` specifiers in SQL strings.
- [ ] **StringBuilder / StringBuffer**: Iterative concatenation in loops or conditional query builders without parameter binding.
- [ ] **UNION-Based Injections**: User input reflected in queries allowing `UNION SELECT` to extract arbitrary table data.
- [ ] **Error-Based Injections**: Unhandled SQL exceptions returning database error banners, query syntax details, or error-based extraction payloads.

### B. Native Query Injections & Framework Sinks
- [ ] **Java / Spring JPA Native Queries**:
  - `@Query(value = "SELECT ... " + :input, nativeQuery = true)` with string concatenation.
  - `entityManager.createNativeQuery("SELECT ... " + userInput)`.
  - `jdbcTemplate.query("SELECT ... " + userInput, ...)`, `jdbcTemplate.execute(...)`, `namedParameterJdbcTemplate`.
  - Hibernate session: `session.createSQLQuery(...)` or `session.createNativeQuery(...)`.
- [ ] **Java Persistence Query Language (JPQL) & HQL Injection**:
  - String concatenation in `entityManager.createQuery("FROM User WHERE name = '" + name + "'")`.
  - Dynamic JPQL path traversal, entity property injection, or HQL function abuse.
- [ ] **Node.js / TypeScript ORMs & Drivers**:
  - Raw SQL queries in Sequelize: `sequelize.query("SELECT * FROM ... " + input)`.
  - Raw SQL in TypeORM: `connection.query(...)`, `repository.query("... " + input)`, `createQueryBuilder().where("name = " + input)`.
  - Raw SQL in Prisma: `prisma.$queryRawUnsafe(...)` instead of `prisma.$queryRaw`.
  - Knex.js raw queries: `knex.raw("... " + input)`.
  - Direct database driver queries: `pg.query(...)`, `mysql.query(...)`, `sqlite3.all(...)` with concatenated strings.
- [ ] **Python (Django / SQLAlchemy / Flask)**:
  - Django `raw("... " + input)` or `.extra(where=["... " + input])`.
  - SQLAlchemy `text("... " + input)` executed directly without parameter dicts.
- [ ] **C# / .NET (Entity Framework / Dapper)**:
  - EF Core `FromSqlRaw("... " + input)` without format placeholders (`FromSqlInterpolated`).
  - Dapper raw string executions without anonymous parameter objects.
- [ ] **Go (database/sql / GORM)**:
  - `db.Exec(fmt.Sprintf("...", input))` or `db.Raw(fmt.Sprintf("...", input))`.
  - GORM `Where("name = " + input)` instead of `Where("name = ?", input)`.
- [ ] **PHP (PDO / mysqli)**:
  - `$pdo->query("SELECT ... " . $input)` instead of `$pdo->prepare()`.
  - `$mysqli->query("SELECT ... " . $input)`.

### C. MyBatis / iBatis Sinks
- [ ] **`${parameter}` Substitution vs `#{parameter}`**:
  - Inspection of XML mapper files (`*Mapper.xml`) and `@Select` / `@Update` annotations.
  - Misuse of `${var}` (direct text replacement) instead of `#{var}` (parameterized placeholder) in `WHERE`, `IN`, `ORDER BY`, or `LIKE` clauses.
  - Unsafe `LIKE` handling: `LIKE '%${search}%'` instead of `LIKE CONCAT('%', #{search}, '%')`.

### D. PL/SQL, PL/pgSQL & Stored Procedure/Function Injections
- [ ] **Dynamic SQL in Oracle PL/SQL**:
  - Dynamic queries constructed in `EXECUTE IMMEDIATE 'SELECT ... ' || p_input`.
  - Unsafe `DBMS_SQL` dynamic cursor operations.
  - Procedure parameters passed unescaped to database utility packages.
- [ ] **Dynamic SQL in PostgreSQL (PL/pgSQL)**:
  - `EXECUTE 'SELECT ... ' || quote_ident(or raw input)` without proper `format('%I', ...)` identifier escaping or `USING` parameter clauses.
- [ ] **Dynamic SQL in Microsoft SQL Server (T-SQL)**:
  - `EXEC('SELECT ... ' + @input)` or dynamic calls to `sp_executesql` concatenating parameters into the SQL string instead of passing them in the parameter definition list.
- [ ] **Stored Procedure Invocation from App Code**:
  - Application code concatenating user input directly into procedure invocation calls: e.g. `CallableStatement cstmt = conn.prepareCall("{call proc('" + input + "')}");`.

### E. Blind & Inferential SQL Injection (Boolean & Time-Based)
- [ ] **Boolean-Based Blind**:
  - Queries where input alters conditional branch logic (`AND 1=1` vs `AND 1=2`), leading to observable differences in HTTP response codes, response body content, JSON message states, or record pagination.
- [ ] **Time-Based Blind / Heavy Query Injection**:
  - Sinks where output is discarded (e.g., logging queries, background analytics, asynchronous updates, token validation), but injected delays (`SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`, or CPU-heavy regular expressions) alter server response latency.

### F. Second-Order / Stored SQL Injection
- [ ] **Database-to-Query Propagation**:
  - Unsanitized input stored in a database column (e.g., user profile name, user agent, address, organization title) that is later read and used in an unparameterized SQL statement in a secondary routine, admin dashboard, batch reporting task, or background worker.
- [ ] **Queue / Event-to-Query Propagation**:
  - Data received via message brokers (Kafka, RabbitMQ, SQS) originating from user input, inserted into dynamic queries downstream without parameter binding.

### G. Dynamic Structural Injection (Identifiers, Clauses & Aggregates)
- [ ] **`ORDER BY` & `GROUP BY` Injection**:
  - Parameterized queries (`?` or `:param`) do not parameterize table names, column names, or sort orders in ANSI SQL.
  - Application accepting `sortBy`, `sortDirection`, or `groupBy` from HTTP query parameters and directly interpolating them into SQL: `"ORDER BY " + sortField + " " + sortDir`.
- [ ] **Dynamic Table / Schema Name Injection**:
  - Multi-tenant applications dynamically switching table names or schemas via string concatenation based on tenant IDs or user headers.
- [ ] **Dynamic Column Selection**:
  - APIs accepting dynamic projections (`fields=id,name,email`) concatenating fields directly into the `SELECT ...` clause without allowlist validation.
- [ ] **Dynamic `IN (...)` Clause Construction**:
  - Manually joining array elements with commas into a string concatenated into an `IN (...)` clause instead of binding individual query parameters.
- [ ] **Pagination (`LIMIT` / `OFFSET`) Injection**:
  - Concatenating page size or offset parameters without casting to strict integers.

### H. Multi-Statement & Stacked Query Injections
- [ ] Drivers or database engines configured with multi-query execution enabled (e.g., MySQL `allowMultiQueries=true`, PostgreSQL, SQL Server), allowing an attacker to terminate the first query with a semicolon `;` and execute arbitrary subsequent statements (`DROP`, `INSERT`, `UPDATE`, administrative procedures).

---

## 2. End-to-End Taint Tracing Workflow

For every endpoint or handler, systematically trace taint propagation:

```
[HTTP Entry / Message Consumer]
       │
       ▼ (Extracts: @RequestParam, @PathVariable, @RequestBody, DTO, Query Params, Headers)
[Controller / Router Layer]
       │
       ▼ (Passes variables to service methods)
[Service / Business Layer]
       │
       ▼ (Assembles business data, constructs filter/query DTOs)
[Repository / DAO / ORM Layer]
       │
       ▼ (Builds query string: Native Query, JPQL, MyBatis XML, Raw SQL)
[Database Driver / Engine Sink]
```

1. **Source Identification**: Locate where user-controlled inputs enter (HTTP controllers, WebSocket messages, GraphQL queries, message queue listeners, file uploads).
2. **Transformations & Sanitization**: Inspect all string manipulation, encoding, validation regexes, or ORM method invocations between source and sink.
3. **Sink Verification**: Inspect the exact method call that delivers the SQL string to the database connection.
4. **Identify False Positives**:
   - Verify if a prepared statement is actually used (`PreparedStatement`, parametrized query with `?` or `:name`).
   - Verify if an allowlist is enforced before string interpolation (e.g., `Set<String> ALLOWED_COLUMNS = Set.of("id", "name", "date")`).
   - Verify if integer parsing (`Integer.parseInt()`) occurs prior to interpolation.

---

## 3. Secure Remediation Best Practices

For every identified vulnerability, recommend the appropriate defensive pattern:

1. **Strict Parameterization (Prepared Statements)**:
   - Java: Use named parameters in Spring Data (`@Query("SELECT u FROM User u WHERE u.username = :username")`) or `PreparedStatement`.
   - Node.js: Use replacement arrays or objects (`sequelize.query('SELECT * FROM users WHERE id = ?', { replacements: [id] })`).
   - Python: Pass parameter tuples (`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`).
2. **Allowlist Mapping for Identifiers & Clauses**:
   - When parameterization is not supported by SQL syntax (table names, column names, `ORDER BY`, `ASC`/`DESC`), enforce a strict server-side allowlist / enum map.
3. **ORM Built-In Safe Query APIs**:
   - Use CriteriaBuilder, QueryDSL, or type-safe ORM query builder methods instead of raw string queries.
4. **Stored Procedure Security**:
   - Use parameter binding (`USING` clause in PostgreSQL/PL/pgSQL, parameter arrays in `sp_executesql`).
5. **Least Privilege Database Accounts**:
   - Configure web application database connections with minimal required privileges (prevent schema alteration, stored procedure creation, file access).
