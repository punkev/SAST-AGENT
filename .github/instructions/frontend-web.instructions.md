# Frontend Web Instructions

## Discover

Inventory `fetch`, axios, `XMLHttpRequest`, Angular `HttpClient`, React/Vue API services, form `action` values, hardcoded backend URLs, route guards, interceptors, and local/session storage or cookie token use.

## Analyze

Trace URL, query, response, and DOM data into `innerHTML`, `outerHTML`, `insertAdjacentHTML`, dangerous framework HTML bindings, eval-like APIs, redirects, URL constructors, and template renderers. Check whether tokens are exposed to JavaScript, whether cookies use secure flags, whether CSRF protections are assumed rather than enforced, and whether client-only guards are incorrectly treated as authorization.

## False positives and output

Framework escaping is a control only when the relevant rendering context is escaped. A route guard is not server authorization. A public API base URL is not automatically a secret. Map API calls to backend endpoints when possible, record assumptions, redact tokens, and write inventory/finding evidence with stable anchors.
