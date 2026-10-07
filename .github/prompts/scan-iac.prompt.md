# Full Infrastructure as Code (IaC) & Container Security Audit

Execute a comprehensive static security audit of all Dockerfiles, Kubernetes manifests, Helm charts, Terraform configurations, and CI/CD pipelines across the repository using the `@sast-iac` agent.

## Execution Instructions

1. **Scope**: Inspect all `Dockerfile*`, `docker-compose*.yml`, Kubernetes manifests (`*.yaml`), Helm templates, Terraform (`*.tf`), and GitHub Actions (`.github/workflows/*.yml`).
2. **Sequential Run Output**:
   - Check `.sast-agent/output/` for existing `IaC Check Run <N>` directories.
   - Increment to the next sequential run directory: `.sast-agent/output/IaC Check Run {N+1}/`.
   - Store findings in `findings.md`, inventory checklist in `scan-progress.md`, structured findings in `findings.json`, and management report in `summary.md`.
3. **Audit Coverage**:
   - Docker root user, unpinned base images, sensitive `ENV`/`ARG` build variables, missing health checks.
   - Kubernetes privileged containers (`privileged: true`), `allowPrivilegeEscalation`, root users, missing CPU/RAM limits, hostPath mounts, default token auto-mounting.
   - Terraform public storage buckets (`public-read`), unencrypted S3/EBS/RDS, security groups open to `0.0.0.0/0`.
   - GitHub Actions script injection (`${{ github.event... }}` in `run:`), dangerous `pull_request_target`, unpinned action hashes.
4. **Mandatory Reporting Requirements**:
   - Clickable file and line link (`file:///` URI format).
   - Real vulnerable configuration snippet copied verbatim.
   - Production-ready safe remediated configuration diff.
   - Non-technical explanation of risk and potential blast radius.

Do not modify application source code or infrastructure manifests.
