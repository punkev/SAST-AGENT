# Node and Express Instructions

## Discover

Find `express()`, `express.Router()`, `app.get/post/put/patch/delete/use`, `router.*`, route modules, controller imports, middleware chains, error handlers, template engines, and server configuration. Track mounted prefixes so inventory paths are complete.

## Sources

Inspect `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`, uploaded files, WebSocket/message inputs, environment/config values, and frontend-controlled URLs. Track values through destructuring, object spreads, validators, serializers, async calls, and middleware.

## Sinks and checks

Check SQL and Mongo query objects/operators, filesystem paths, `child_process` APIs, template rendering, `res.redirect`, outbound HTTP clients, XML parsers, JWT verification, cookie/session settings, CORS, `helmet`, prototype mutation, mass assignment, and middleware ordering. Confirm authentication and per-resource/per-function authorization in the actual mounted route.

## False positives and output

Account for schema validation, query builders, escaping, safe template context, URL allowlists, fixed command argument arrays, and middleware that is actually mounted before the handler. A package presence alone does not prove protection. Save handler mappings, redacted evidence, finding classifications, and progress records.
