# Java, Spring, Struts Instructions

## Discover

Find `@Controller`, `@RestController`, class/method `@RequestMapping`, `@GetMapping`, `@PostMapping`, `@PutMapping`, `@PatchMapping`, `@DeleteMapping`, `@PathVariable`, `@RequestParam`, `@RequestBody`, `web.xml`, Servlet mappings, Struts XML action mappings, Struts annotations, JSP form actions, filters, interceptors, and Spring Security configuration.

## Sources

Inspect `HttpServletRequest`, path/query/form parameters, headers, cookies, multipart files, `@PathVariable`, `@RequestParam`, `@RequestBody`, `@ModelAttribute`, session attributes, and deserialized request objects. Track values through DTOs, validators, service methods, repositories, template models, and exception handlers.

## Sinks and checks

Check concatenated native SQL/JPQL, unsafe Criteria construction, LDAP/XPath, `Runtime.exec`/`ProcessBuilder`, file APIs, redirects, `RestTemplate`/WebClient/URL clients, XML parsers, Java deserialization, JSP EL/scriptlets, template rendering, and object binding. Inspect Spring Security matcher order, CSRF, CORS, session cookies, password reset, JWT issuer/audience/signature/algorithm validation, role checks, Struts interceptors, and exposed actions.

## False positives and output

Verify parameterization, allowlists, canonicalization, parser hardening, authorization checks, server-side enforcement, and reachable production configuration. A safe wrapper is not proof unless the value reaches the sink through it. Map every issue to a handler and save redacted, line-anchored evidence in the required finding format.
