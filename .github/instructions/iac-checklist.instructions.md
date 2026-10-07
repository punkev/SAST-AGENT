# Infrastructure as Code (IaC) & Container Security Checklist

Use this checklist to perform an exhaustive static security audit of all container images, orchestration manifests, infrastructure templates, and CI/CD pipelines across the workspace.

---

## 1. Container & Dockerfile Security (CWE-250, CWE-732)

### A. Root User Execution & Privilege Escalation
- [ ] **Missing Non-Root User**:
  - Container does not declare a non-root `USER` directive (runs by default as `root` UID 0).
  - Remediation: Specify `USER 10001:10001` or create and switch to a dedicated service user (`RUN adduser -D appuser && USER appuser`).
- [ ] **Sudo & Setuid Binaries**:
  - Unnecessary inclusion of `sudo`, `su`, or binaries with SUID/SGID bits set (`chmod u+s`).

### B. Base Image Integrity & Package Pinning
- [ ] **Unpinned Base Images**:
  - Use of `FROM node:latest`, `FROM openjdk:latest`, or untagged images.
  - Must pin immutable image digests (e.g., `FROM node:20-alpine@sha256:...`) or strict semantic tags.
- [ ] **Bloated / Insecure Base Images**:
  - Full OS distributions used in production instead of Minimal / Distroless / Alpine images.
- [ ] **Missing Package Update & Cache Hygiene**:
  - Package manager caches left inside image layers (`apt-get clean && rm -rf /var/lib/apt/lists/*` omitted).

### C. Sensitive Data & Secret Leakage in Build Stages
- [ ] **Hardcoded Secrets in Dockerfile**:
  - `ENV` or `ARG` directives containing database passwords, private keys, or API tokens (`ARG AWS_SECRET_KEY=...`).
  - `ENV` values persist in image metadata and are visible via `docker inspect` or `docker history`.
  - Remediation: Use BuildKit secrets mount (`RUN --mount=type=secret,id=mysecret ...`).
- [ ] **Sensitive Files in Build Context**:
  - Missing `.dockerignore` file allowing `.git/`, `.env`, private keys, local build caches, or configuration files to be copied into the container image.

### D. File Permissions & Health Checks
- [ ] **Insecure File Ownership**:
  - `COPY` or `ADD` commands copying files without `--chown=appuser:appuser`, leaving them owned by root.
- [ ] **Use of `ADD` with Remote URLs**:
  - Using `ADD` with external URLs (vulnerable to MITM or unverified downloads). Must use `curl`/`wget` with hash verification.
- [ ] **Missing Container Health Checks**:
  - Production containers missing `HEALTHCHECK` instructions, preventing orchestrators from detecting hung processes.

---

## 2. Kubernetes Manifests & Helm Charts (CWE-250, CWE-284)

### A. Pod Security Context & Privileges
- [ ] **Privileged Containers (`privileged: true`)**:
  - Grants container full capabilities of the host system kernel. Must be strictly `privileged: false`.
- [ ] **Allow Privilege Escalation (`allowPrivilegeEscalation: true`)**:
  - Allows child processes to gain more privileges than the parent process. Must set `allowPrivilegeEscalation: false`.
- [ ] **Root User in Pod**:
  - Missing `securityContext.runAsNonRoot: true` and `securityContext.runAsUser: >10000`.
- [ ] **Read-Only Root Filesystem**:
  - Root filesystem writable (`readOnlyRootFilesystem: false` or omitted). Must set `readOnlyRootFilesystem: true` with writable `/tmp` mounted via `emptyDir`.
- [ ] **Linux Capabilities**:
  - Dangerous capabilities retained (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`).
  - Must drop all capabilities and add only required:
    ```yaml
    capabilities:
      drop: ["ALL"]
    ```

### B. Host Resource Exposure
- [ ] **Host Namespace Sharing**:
  - `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` sharing host kernel namespaces.
- [ ] **Dangerous Host Path Mounts (`hostPath`)**:
  - Mounting sensitive host directories into pods (`/var/run/docker.sock`, `/etc`, `/root`, `/proc`, `/sys`).

### C. Resource Quotas & Denial of Service
- [ ] **Missing CPU & Memory Limits**:
  - Containers lacking `resources.limits.cpu` and `resources.limits.memory`, enabling pod runaway consumption and node starvation (DoS).

### D. Service Account & Network Policies
- [ ] **Default Service Account Token Auto-Mounting**:
  - Pods not needing Kubernetes API access with `automountServiceAccountToken: true` (or default).
  - Must set `automountServiceAccountToken: false`.
- [ ] **Missing Network Policies**:
  - Namespaces with default allow-all ingress/egress network traffic allowing lateral movement between compromised pods.

---

## 3. Terraform & Cloud Infrastructure Templates (CWE-284, CWE-319, CWE-326)

### A. Cloud Storage (AWS S3, GCP Cloud Storage, Azure Blob)
- [ ] **Public Bucket Policies & ACLs**:
  - S3 bucket ACL set to `public-read` or `public-read-write`.
  - Missing `aws_s3_bucket_public_access_block` enforcing `block_public_acls = true`, `block_public_policy = true`.
- [ ] **Unencrypted Storage**:
  - S3 bucket missing server-side encryption configuration (`aws_s3_bucket_server_side_encryption_configuration`).
  - Cloud disks / EBS volumes created with `encrypted = false`.
- [ ] **Missing Access Logging & Versioning**:
  - Cloud storage buckets lacking access logging and object versioning.

### B. Network & Security Groups
- [ ] **Overly Permissive Ingress Rules**:
  - Security groups allowing ingress from `0.0.0.0/0` or `::/0` on sensitive management ports (SSH port 22, RDP port 3389, Database ports 3306, 5432, 27017, Redis 6379, Elasticsearch 9200).
- [ ] **Unencrypted In-Transit Traffic**:
  - Load balancers (ALB/NLB) accepting plaintext HTTP port 80 without automatic HTTP-to-HTTPS redirect.

### C. Database & Data Store Instances (RDS, DocumentDB, DynamoDB)
- [ ] **Publicly Accessible Databases**:
  - `publicly_accessible = true` on RDS instances.
- [ ] **Missing At-Rest Database Encryption**:
  - `storage_encrypted = false` on RDS / Cloud SQL instances.
- [ ] **Missing Automated Backups & Deletion Protection**:
  - Production databases with `deletion_protection = false` or `backup_retention_period = 0`.

---

## 4. CI/CD Pipeline Security (GitHub Actions & GitLab CI) (CWE-78, CWE-284)

### A. Script Injection via Untrusted Contexts
- [ ] **Direct Context Interpolation in `run:` Steps**:
  - Using `${{ github.event.issue.title }}`, `${{ github.event.pull_request.head.ref }}`, or `${{ github.event.comment.body }}` directly inside inline shell scripts.
  - Remediation: Pass untrusted contexts through environment variables:
    ```yaml
    env:
      ISSUE_TITLE: ${{ github.event.issue.title }}
    run: |
      echo "$ISSUE_TITLE"
    ```

### B. Dangerous Workflow Triggers
- [ ] **`pull_request_target` with Untrusted Code Checkout**:
  - Workflows triggered by `pull_request_target` checking out the pull request head commit (`ref: ${{ github.event.pull_request.head.sha }}`) and running build/test commands.
  - Allows external PR authors to execute arbitrary code with repository write tokens and secret access.

### C. Action Pinning & Secret Hygiene
- [ ] **Unpinned Third-Party Actions**:
  - Using mutable branch tags (e.g. `uses: actions/checkout@v4` or `@main`) instead of full commit SHA pins (`uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`).
- [ ] **Overprivileged Default `GITHUB_TOKEN`**:
  - Workflows without explicit top-level `permissions:` block defaulting to read-write access across contents, packages, and pull requests.
  - Must define minimal permissions:
    ```yaml
    permissions:
      contents: read
    ```
