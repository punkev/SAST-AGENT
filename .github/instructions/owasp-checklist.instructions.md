# Comprehensive OWASP & CWE Vulnerability Checklist

Use this checklist during **Pass 1 (Sink & Source Discovery)** and **Pass 2 (Bidirectional Taint Analysis)** across Java/Spring and Node.js/TypeScript codebases.

---

## 1. Injection Vulnerabilities (CWE-89, CWE-94, CWE-78, CWE-918, CWE-1336)

### SQL / JPQL / HQL / MyBatis Injection (CWE-89)
- **Java**:
  - String concatenation or formatted strings in `JdbcTemplate.query()`, `Statement.executeQuery()`, `EntityManager.createNativeQuery()`, `EntityManager.createQuery()`.
  - Hibernate/JPA queries with unparameterized `SELECT ... WHERE field = ' + userInput`.
  - Dynamic `ORDER BY` or `GROUP BY` clauses with user-controlled input (prepared statements cannot parameterize column names).
  - **MyBatis Injection**: Using `${param}` (raw string substitution) instead of `#{param}` (prepared statement parameter) in XML mappers or `@Select` / `@Update` annotations.
  - **Spring Data SpEL Injection**: User input evaluated inside `@Query("... ?#{[0]} ...")`.
- **Node.js**:
  - String concatenation in raw SQL queries: `db.query("SELECT * FROM users WHERE name = '" + req.body.name + "'")`.
  - Unsafe Sequelize/TypeORM/Knex raw expressions: `sequelize.literal()`, `knex.raw()`, `prisma.$queryRawUnsafe()`.

### NoSQL Injection (CWE-943)
- **Node.js / MongoDB**:
  - Passing unvalidated objects directly into query operators: `db.collection.find({ user: req.body.username, pass: req.body.password })` where `req.body.password = { "$ne": null }`.
  - Use of `$where`, `mapReduce`, or `$accumulator` with user-supplied JavaScript strings.

### Server-Side Template Injection — SSTI (CWE-1336)
- **Java**:
  - **Thymeleaf Fragment Injection**: Returning user-controlled strings directly as view names in Spring MVC without `@ResponseBody`.
  - Unescaped rendering in Thymeleaf using `th:utext` or JSP `<%= ... %>`.
  - Freemarker / Velocity template loading from untrusted strings or parameters.
  - SpEL evaluation: `SpelExpressionParser.parseExpression(userInput).getValue()`.
- **Node.js**:
  - EJS: rendering unsanitized strings with `ejs.render(userInput, data)` instead of precompiled templates.
  - Pug / Handlebars / Nunjucks: compiling user-controlled template strings directly (`pug.compile(userInput)`).

### Command & Code Injection (CWE-78, CWE-94)
- **Java**:
  - `Runtime.getRuntime().exec(userInput)` or `new ProcessBuilder(userInput)`.
  - **JNDI Injection**: `InitialContext.lookup(userInput)` with untrusted LDAP/RMI/DNS URLs.
  - OGNL / MVEL evaluation of untrusted strings.
- **Node.js**:
  - `child_process.exec(userInput)`, `child_process.execSync(userInput)`, `child_process.spawn(userInput, { shell: true })`.
  - `eval(userInput)`, `new Function(userInput)()`, `vm.runInThisContext(userInput)`, `vm2` (known sandbox escapes).

---

## 2. Asynchronous & Message Queue Vulnerabilities (CWE-502, CWE-20)

### Kafka / RabbitMQ / SQS Consumer Injection & Deserialization
- **Java**:
  - `@KafkaListener`, `@RabbitListener`, `@JmsListener`, `@SqsListener` receiving untrusted payload strings without validation and passing directly into SQL/exec/XML sinks.
  - Using Java native serialization or polymorphic JSON deserialization on message queue payloads.
- **Node.js**:
  - BullMQ, KafkaJS, or `amqplib` workers parsing unvalidated message payloads and performing file system writes, child process calls, or raw database queries.

---

## 3. Deserialization & Software Integrity Failures (CWE-502)

- **Java**:
  - Native deserialization: `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`.
  - **Jackson Polymorphic Deserialization**: `@JsonTypeInfo(use = Id.CLASS)`, `@JsonTypeInfo(use = Id.MINIMAL_CLASS)`, `ObjectMapper.enableDefaultTyping()`, or `objectMapper.activateDefaultTyping()`.
  - **SnakeYAML RCE Gadgets**: `new Yaml().load(untrustedString)` without `SafeConstructor`.
  - **XML Parsers (XXE - CWE-611)**: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` without explicitly calling `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- **Node.js**:
  - `node-serialize.unserialize()`, `serialize-javascript`, or unsafe YAML parsers (`js-yaml.load()` on untrusted input).

---

## 4. Prototype Pollution & Object Manipulation (CWE-1321)

- **Node.js**:
  - Recursive object merge/extend on user input: `_.merge({}, req.body)`, `Object.assign({}, req.body)`.
  - Custom deep-clone or property assignment utility functions that do not sanitize `__proto__`, `constructor`, `prototype`.
  - Fastify / Express request body parsers without prototype pollution guards.

---

## 5. Broken Access Control & BOLA / IDOR (CWE-284, CWE-639, CWE-862)

- **Missing Endpoint Authorization**:
  - Java Spring: Endpoints lacking `@PreAuthorize("hasRole(...)")`, `@Secured`, or unprotected in `SecurityFilterChain`.
  - Node.js: Express/NestJS routes lacking auth guards / middleware on state-changing endpoints (`POST`, `PUT`, `DELETE`).
- **IDOR / Broken Object-Level Authorization (BOLA)**:
  - Endpoints receiving an ID parameter (`/api/documents/{id}`, `req.params.id`) and fetching/modifying the entity without asserting tenant/user ownership (`WHERE id = :id AND user_id = :currentUserId`).
- **URL Normalization & Filter Bypasses**:
  - Spring Security vs Interceptor inconsistencies: Matrix variable injection (`/admin;foo/users`), URL casing tricks on Windows, trailing slashes.
- **Mass Assignment (CWE-915)**:
  - Spring: `@RequestBody` or `@ModelAttribute` binding directly to JPA entity classes with sensitive fields (e.g., `role`, `isAdmin`, `balance`).
  - Node.js: `User.create(req.body)` or `User.update(req.body)` without strict schema filtering or DTOs.

---

## 6. Server-Side Request Forgery — SSRF (CWE-918)

- **Java**:
  - User-controlled URLs passed to `RestTemplate`, `WebClient`, `HttpURLConnection`, `HttpClient`, `URL.openStream()`, Apache `HttpClient`.
  - Bypasses of naive blacklists (handling `169.254.169.254`, `127.0.0.1`, `0.0.0.0`, `localhost`, `[::1]`, DNS rebinding).
- **Node.js**:
  - User-controlled URLs passed to `fetch`, `axios.get(req.body.url)`, `got()`, `request()`, `needle()`.

---

## 7. Path Traversal & Zip Slip (CWE-22, CWE-29)

- **Java**:
  - **Multipart File Upload Traversal**: Using `MultipartFile.getOriginalFilename()` directly without `new File(filename).getName()` or `Path.getFileName()`.
  - **Zip Slip**: Extracting entries from `ZipInputStream` using `entry.getName()` without asserting `destinationFile.getCanonicalPath().startsWith(targetDir.getCanonicalPath())`.
- **Node.js**:
  - `fs.readFile(path.join(__dirname, req.query.file))`, `res.sendFile(req.query.path)`.
  - Unsanitized archive extraction (`unzipper`, `tar`, `adm-zip`).

---

## 8. Cross-Site Scripting — XSS (CWE-79)

- **Java**:
  - Spring MVC controllers returning unescaped user data in Thymeleaf `th:utext` or JSP `<%= ... %>`.
- **Node.js**:
  - Frontend: `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, `document.write()`.
  - Backend: `res.send("<h1>Hello " + req.query.name + "</h1>")`.

---

## 9. Security Misconfiguration & Cryptographic Failures (CWE-16, CWE-327, CWE-798)

- **Java Cryptography Defaults**:
  - Calling `Cipher.getInstance("AES")` without specifying mode (defaults to insecure **`AES/ECB/PKCS5Padding`** in Java).
  - Using static IVs (`new IvParameterSpec(new byte[16])`) or weak RNGs (`java.util.Random`) for tokens.
  - MD5 / SHA-1 used for password hashing (must use BCrypt, Argon2, PBKDF2).
- **Spring Actuator & DevTools Exposure**:
  - `management.endpoints.web.exposure.include=*` exposing `/actuator/heapdump`, `/actuator/env`, `/actuator/mappings`, `/actuator/threaddump`.
  - DevTools active in production classpath or remote debug enabled.
- **Node.js Security Misconfiguration**:
  - Permissive CORS (`Access-Control-Allow-Origin: *` with credentials enabled or reflecting `req.headers.origin`).
  - Disabled CSRF on session-authenticated applications.
  - Missing security headers (`Helmet`, `Strict-Transport-Security`, `Content-Security-Policy`).
