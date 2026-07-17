# Endpoint Inventory

Status: Not started

The scanner must replace the status and append one complete entry for every discovered backend and frontend endpoint. Combine class/router prefixes with method paths, record middleware/security context, and keep unresolved routes marked for review.

## Required entry template

Endpoint: `EP-<stable-id>`
HTTP Method: `GET|POST|PUT|PATCH|DELETE|...`
Path: `<effective path or unresolved path>`
Framework: `<Spring|Servlet|Struts|Express|Frontend|...>`
Controller/Route File: `<relative path>`
Handler Function: `<class.method or function>`
Auth Required: `<yes|no|unknown; mechanism>`
Authorization Check Found: `<yes|no|unknown; anchor>`
Input Sources: `<params/body/headers/cookies/files/browser source>`
Sensitive Actions: `<data read/write/admin/auth/file/command/etc.>`
Downstream Calls: `<services and functions>`
Database/File/Command/Template Sinks: `<sinks or none>`
Potential Vulnerability Areas: `<taxonomy IDs>`
Trace Status: `<not-started|partial|complete|blocked>`
Manual Review Notes: `<assumptions, gaps, and evidence refs>`

## Coverage counters

- Discovered endpoints: 0
- Mapped handlers: 0
- Fully traced: 0
- Blocked/unresolved: 0
