# Comprehensive OWASP, CWE Top 25 & Advanced SAST Vulnerability Checklist

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

---

## 10. Resource Exhaustion, ReDoS & Denial of Service (CWE-400, CWE-1333, CWE-776, CWE-409, CWE-834)

### Regular Expression Denial of Service — ReDoS (CWE-1333)
- **Java**:
  - `Pattern.compile(userInput)` with untrusted dynamic regexes.
  - Applying regular expressions with nested quantifiers (e.g., `(a+)+$`, `(a|aa)+$`, `([a-zA-Z0-9]+)*$`) on untrusted long input strings without execution timeouts.
- **Node.js**:
  - Dynamic `new RegExp(req.query.pattern)` or regex matching on user input using vulnerable backtracking expressions.
  - Vulnerable third-party validation patterns in `validator.js`, `moment`, or custom parsing functions.

### Unbounded Stream & Memory Starvation (CWE-400, CWE-834)
- **Java**:
  - Reading unbounded streams: `InputStream.readAllBytes()`, `ByteArrayOutputStream` on client input without explicit byte limits or chunking.
  - Missing upload size limits (`spring.servlet.multipart.max-file-size` / `spring.servlet.multipart.max-request-size` disabled or set to `-1`).
- **Node.js**:
  - Unbounded stream buffering (`req.pipe()`, `concat-stream`, `busboy` / `multer` without `limits: { fileSize: ... }`).
  - **Event-Loop Starvation (CWE-834)**: Synchronous compute operations on the main event loop handling large user payloads (`JSON.parse` of huge strings, synchronous crypto `crypto.pbkdf2Sync` in request handlers, synchronous file I/O `fs.readFileSync` on user routes).

### Decompression Bombs & XML Expansion (CWE-409, CWE-776)
- **Java / Node.js**:
  - **Zip Bombs**: Uncompressed byte threshold missing in archive extraction (allowing small payloads to extract gigabytes of zeroes).
  - **XML Billion Laughs**: Parsing untrusted XML without entity expansion limits (`EntityExpansionLimit`).

---

## 11. Concurrency, Race Conditions & State Pollution (CWE-362, CWE-367, CWE-366)

### Spring Singleton Bean State Pollution (CWE-362, CWE-366)
- **Java**:
  - Mutable instance fields in Spring singleton beans (`@Controller`, `@RestController`, `@Service`, `@Component`) storing request-specific state (e.g. `private String currentUserId;`, `private User currentUser;`).
  - Concurrent requests overwrite singleton instance state, causing data leakage and cross-tenant privilege escalation.

### Check-Then-Act Concurrency Flaws / Double-Spend (CWE-367)
- **Java & Node.js**:
  - Checking account balances, coupon usage, gift card redemption, or inventory stock in code, followed by a separate update query without database locking:
    ```
    // Vulnerable Check-Then-Act
    if (user.getBalance() >= amount) {
        user.setBalance(user.getBalance() - amount);
        userRepository.save(user);
    }
    ```
  - Missing pessimistic locking (`SELECT ... FOR UPDATE` / `@Lock(LockModeType.PESSIMISTIC_WRITE)`), optimistic locking (`@Version`), or atomic database updates (`UPDATE users SET balance = balance - :amount WHERE id = :id AND balance >= :amount`).
  - File existence checks followed by file creation/writing (`fs.existsSync` -> `fs.writeFileSync`) without atomic file descriptors.

---

## 12. Insecure File Upload & Temporary File Handling (CWE-434, CWE-436, CWE-377, CWE-378)

### Unrestricted File Upload & Extension Bypass (CWE-434, CWE-436)
- **Java & Node.js**:
  - Uploading executable scripts (JSP, HTML, SVG with `<script>` tags, `.phtml`, `.phar`, `.shtml`) to web-accessible directories or public S3 buckets.
  - Relying exclusively on client-supplied `Content-Type` headers or file extensions without verifying magic bytes (`Apache Tika`, `file-type`).
  - Blacklist-based extension filtering (bypassed via `.jspx`, `.pht`, double extensions `.jpg.php`, or case manipulation).

### Insecure Temporary File Creation (CWE-377, CWE-378)
- **Java**:
  - `File.createTempFile("prefix", ".tmp")` creates world-readable files on Unix-based operating systems in `/tmp`. Must use `Files.createTempFile()` with explicit POSIX permissions `PosixFilePermissions.asFileAttribute(EnumSet.of(OWNER_READ, OWNER_WRITE))`.
- **Node.js**:
  - Writing temporary files in `/tmp` without strict file modes (`mode: 0o600`).

---

## 13. Log Injection, Sensitive Data Exposure & Error Handling (CWE-117, CWE-532, CWE-209)

### Log Injection / Log Forging (CRLF Injection - CWE-117)
- **Java & Node.js**:
  - Writing unescaped user inputs directly to logs: `logger.info("Failed login for user: " + username)`.
  - Attackers inject `\r\n` (CRLF) characters to forge fraudulent log entries, mask intrusion traces, or inject malicious escape codes into log viewing terminals.

### Sensitive Information in Logs (CWE-532)
- **Java & Node.js**:
  - Logging passwords, credit card numbers, Social Security numbers, session tokens, JWTs, or API keys in debug/info logs: `logger.debug("Request payload: " + requestBody)`.

### Verbose Error Message Information Disclosure (CWE-209)
- **Java & Node.js**:
  - `@ExceptionHandler` methods or Express error middleware echoing raw exception messages (`e.getMessage()`), stack traces, raw SQL queries, or internal file paths to client HTTP responses.

---

## 14. SSL/TLS Validation, Insecure Transport & WebSockets (CWE-295, CWE-319, CWE-1385)

### Improper SSL/TLS Certificate Validation (CWE-295)
- **Java**:
  - Implementing custom `X509TrustManager` with empty `checkServerTrusted()` and `checkClientTrusted()` methods (trusting all certificates).
  - Setting `HostnameVerifier` to return `true` unconditionally (`NoopHostnameVerifier`).
- **Node.js**:
  - Setting `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` or passing `rejectUnauthorized: false` in `https.Agent`, `axios`, `got`, or `fetch` options.

### Insecure Internal Transport (CWE-319)
- **Java & Node.js**:
  - Transmitting sensitive authentication tokens or credentials over plaintext HTTP or unencrypted internal socket connections.
  - Plaintext database or Redis cache connections (`useSSL=false`, `redis://` instead of `rediss://`) transmitting session data across untrusted networks.

### Cross-Site WebSocket Hijacking — CSWSH (CWE-1385)
- **Java & Node.js**:
  - WebSocket handshakes relying on session cookies without validating the `Origin` header or requiring a one-time anti-CSRF token.

---

## 15. Weak Randomness, Session Lifecycle & Cookie Security (CWE-330, CWE-338, CWE-384, CWE-613, CWE-1004, CWE-614)

### Cryptographically Weak Randomness (CWE-330, CWE-338)
- **Java**:
  - Using `java.util.Random` or `ThreadLocalRandom` to generate security-sensitive values (password reset tokens, MFA OTP codes, API keys, session identifiers). Must use `java.security.SecureRandom`.
- **Node.js**:
  - Using `Math.random()` to generate tokens, OTPs, or cryptographic keys. Must use `crypto.randomBytes()` or `crypto.randomInt()`.

### Session Fixation & Insufficient Invalidation (CWE-384, CWE-613)
- **Java & Node.js**:
  - Failing to invalidate the existing session and assign a new session ID upon successful user login (`request.changeSessionId()` or Spring Security `sessionManagement().sessionFixation().migrateSession()`).
  - Stateless JWT implementations with no revocation blacklist / JTI tracking on logout or password change.

### Missing Cookie Security Flags & Insecure Prefixes (CWE-1004, CWE-614)
- **Java & Node.js**:
  - Setting session or authentication cookies without `HttpOnly`, `Secure`, and `SameSite=Lax` or `SameSite=Strict`.
  - Omitting secure cookie prefixes (`__Host-` or `__Secure-`) for sensitive domain-wide cookies.

---

## 16. Open Redirect & HTTP Response Splitting (CWE-601, CWE-113, CWE-644)

### Open URL Redirection (CWE-601)
- **Java**:
  - Passing untrusted user parameters directly to `response.sendRedirect(returnUrl)` or Spring MVC `new RedirectView(returnUrl)` / `return "redirect:" + returnUrl;` without strict domain allowlisting.
- **Node.js**:
  - Passing unvalidated query parameters to `res.redirect(req.query.target)` or Next.js `redirect(url)`.

### HTTP Response Splitting & Header Injection (CWE-113)
- **Java & Node.js**:
  - Writing user input containing unescaped `\r\n` into HTTP response headers (`response.setHeader("X-Custom", userInput)`, `res.set("X-User", req.query.name)`).

### Web Cache Deception & Cache Poisoning (CWE-644)
- **Java & Node.js**:
  - Static caching rules combined with dynamic endpoints where unkeyed headers (e.g. `X-Forwarded-Host`, `X-Original-URL`) are reflected in cached responses.

---

## 17. Cross-Site Request Forgery (CSRF) & Web Messaging (CWE-352, CWE-346)

### Cross-Site Request Forgery (CSRF - CWE-352)
- **Java**:
  - Spring Security with `.csrf().disable()` on session-authenticated web applications.
  - State-changing actions (`POST`, `PUT`, `DELETE`, `PATCH`) triggered via `GET` handlers (`@GetMapping("/user/delete")`).
  - Missing anti-CSRF token verification (`CsrfTokenRepository`) on form submits or AJAX calls using session cookies.
- **Node.js**:
  - Express session apps lacking `csurf` or double-submit cookie CSRF middleware on state-changing endpoints.
  - SameSite cookie gaps: session cookies configured without `SameSite=Lax` or `SameSite=Strict`.

### Insecure Cross-Document Messaging (postMessage - CWE-346)
- **Node.js / Frontend**:
  - Listening to messages without origin validation: `window.addEventListener('message', (e) => { eval(e.data); })` without asserting `e.origin === 'https://trusted.domain'`.
  - Sending sensitive tokens via `postMessage` with wildcard target origin: `window.postMessage(token, '*')`.

### Permissive CORS with Credentials (CWE-942)
- **Java & Node.js**:
  - Dynamically echoing the client `Origin` header into `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true`.
  - Trusting the `null` origin (`Origin: null`), which can be generated by sandboxed `<iframe>` elements or local file schemes.

---

## 18. Clickjacking & UI Redressing (CWE-1021)

- **Java & Node.js**:
  - Interactive, authenticated web pages missing frame protection headers.
  - Missing `Content-Security-Policy: frame-ancestors 'self'` or `X-Frame-Options: DENY` / `SAMEORIGIN`.
  - Allows attackers to embed the application inside a transparent `<iframe>` to trick users into executing unintended actions.

---

## 19. GraphQL API Vulnerabilities (CWE-400, CWE-200, CWE-862)

- **Java (Spring GraphQL / GraphQL Java) & Node.js (Apollo Server / Yoga)**:
  - **Introspection Enabled in Production (CWE-200)**: GraphQL introspection query (`__schema`, `__type`) accessible to unauthenticated public users, exposing entire schema, queries, mutations, and internal types.
  - **Unbounded Query Depth / Circular DoS (CWE-400)**: Missing query depth limiting or query complexity analysis, allowing nested recursive queries (`user { friends { friends { friends ... } } }`) that exhaust server CPU and memory.
  - **Batching Attack Brute-Force Bypass**: Accepting multiple operations in a single HTTP request (array of GraphQL queries), allowing attackers to test thousands of credentials/OTPs in a single HTTP request, bypassing IP-based rate limiters.
  - **Missing Field-Level Authorization (CWE-862)**: Relying only on root-level endpoint security while individual GraphQL fields or mutations lack `@PreAuthorize` or resolver permission checks.
  - **Field Suggestion Information Leakage**: Leaving field suggestion error messages enabled in production, which reveals internal field names upon syntax typos.

---

## 20. gRPC, Protocol Buffers & WebSocket Security (CWE-1385, CWE-319, CWE-287)

- **Java (gRPC-Java) & Node.js (@grpc/grpc-js)**:
  - **Plaintext gRPC Transport**: Using `InsecureServerCredentials.create()` or `ManagedChannelBuilder.usePlaintext()` transmitting protobuf payloads unencrypted across networks.
  - **Missing Interceptor Authorization**: gRPC service methods without server interceptors validating authentication tokens / metadata credentials.
- **Java (Spring WebSocket) & Node.js (ws / Socket.io)**:
  - **Cross-Site WebSocket Hijacking (CSWSH - CWE-1385)**: WebSocket handshake relying on session cookies without validating the `Origin` header.
  - **Missing Message Frame Authentication**: Authorizing only the initial handshake while subsequent individual WebSocket message frames lack identity/authorization checks.

---

## 21. Business Logic, Parameter Tampering & Workflow Flaws (CWE-840, CWE-398)

- **Java & Node.js**:
  - **Price / Quantity Parameter Tampering**: Accepting order prices, totals, or negative item quantities directly from client payloads without server-side catalog price lookup.
  - **Workflow Step Bypassing (Forced Browsing)**: Allowing direct access to downstream order/transaction completion endpoints without verifying that prerequisite steps (payment verification, identity check) succeeded.
  - **Voucher / Promo Code Double-Spend Race Conditions**: Checking voucher usage status in code without database-level row locking (`SELECT ... FOR UPDATE`), allowing concurrent HTTP requests to redeem a single-use coupon multiple times.
  - **Missing Rate Limiting on High-Impact Endpoints**: Authentication, password reset, OTP submission, voucher validation, and SMS/email triggers lacking rate limiting, enabling brute-force and resource flooding.

---

## 22. Insecure File Downloads & Reflected File Download (RFD) (CWE-22, CWE-20)

- **Java & Node.js**:
  - **Arbitrary File Download via Path Traversal**: Endpoints taking a filename or path parameter (`/api/download?file=...`) and serving file contents using `FileInputStream` or `res.download()` without verifying that the resolved canonical path remains within the designated base directory.
  - **Reflected File Download (RFD)**: Endpoints echoing user input in responses served with `Content-Disposition: attachment; filename=...` without restricting extensions, allowing malicious executable scripts (`.bat`, `.sh`, `.cmd`) to be downloaded from trusted domains.

---

## 23. Advanced Cryptography Pitfalls & Uninitialized Memory (CWE-326, CWE-908, CWE-327)

- **Java**:
  - **GCM Nonce / IV Reuse**: Reusing Initialization Vectors (IVs) with AES-GCM mode, destroying confidentiality and integrity.
  - **Static / Hardcoded IVs**: Initializing `IvParameterSpec` with fixed byte arrays (`new byte[]{1,2,3...}`).
  - **Bleichenbacher PKCS#1 v1.5 Padding Oracle**: Using `RSA/ECB/PKCS1Padding` instead of `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
  - **Signature Verification Exceptions Caught Unsafely**: Catching `SignatureException` and continuing execution or returning true.
- **Node.js**:
  - **Uninitialized Memory Allocation (CWE-908)**: Using `Buffer.allocUnsafe(size)` or deprecated `new Buffer(size)` to allocate memory buffers without zero-filling, leaking sensitive heap memory fragments to HTTP responses.

---

## 24. Information Disclosure via Production Artifacts & Metadata (CWE-200, CWE-215)

- **Java & Node.js**:
  - **Source Maps in Production**: Bundled `.map` files (e.g. `main.js.map`) deployed to public web root, exposing complete unminified TypeScript/Java source code and internal comments.
  - **Exposed VCS & Configuration Metadata**: Static web root serving `.git/`, `.env`, `docker-compose.yml`, or internal configuration files.
  - **Server Version Banners**: Leaking precise framework and server versions in HTTP response headers (`Server: Apache/2.4.41`, `X-Powered-By: Express`).


