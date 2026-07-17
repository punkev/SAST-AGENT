# Repository Profile

Status: Not started

The scanner writes a durable profile here during discovery. Record repository purpose, source roots, application boundaries, build/package manifests, deployment/runtime assumptions, public entry points, frontend/backend relationships, and files excluded by `.sast-agent/config/ignore-paths.yml`.

## Expected sections

- Scan ID and discovery timestamp
- Repository/module tree
- Backend modules and deployment units
- Frontend modules and build outputs
- Configuration and dependency manifests reviewed
- External services, databases, queues, file stores, and identity providers
- Scope exclusions and coverage limitations
