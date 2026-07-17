# Endpoint Extraction Instructions

Extract endpoints before deep scanning and preserve one entry per method/path/handler combination.

## Java and Struts

Combine class-level and method-level mappings. Detect Spring annotations, Servlet/web.xml mappings, Struts XML actions and annotations, JSP form actions, filters, interceptors, and Spring Security matchers. Record path variables, parameters, body types, controller method, and effective middleware/security chain.

## Node and frontend

Resolve Express mounts (`app.use`), router prefixes, route methods, middleware order, controller imports, and fallback handlers. Record frontend calls and forms separately, including method, URL construction, caller, auth token behavior, and inferred backend mapping.

## Required entry

Use `Endpoint`, `HTTP Method`, `Path`, `Framework`, `Controller/Route File`, `Handler Function`, `Auth Required`, `Authorization Check Found`, `Input Sources`, `Sensitive Actions`, `Downstream Calls`, `Database/File/Command/Template Sinks`, `Potential Vulnerability Areas`, `Trace Status`, and `Manual Review Notes`. Save progress immediately after each endpoint and route mapping.
