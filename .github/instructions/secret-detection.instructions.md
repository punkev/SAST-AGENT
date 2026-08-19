# Secret Detection Heuristics & Signature Matrix

This instruction document defines the signatures, patterns, and validation heuristics for the `@sast-secrets` agent to discover hardcoded credentials across source files, configs, and test suites.

---

## 1. High-Confidence Signature Patterns

### Cloud & Infrastructure Credentials
- **AWS Access Key ID**: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`
- **AWS Secret Access Key**: `(?i)aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]`
- **Google Cloud API Key**: `AIza[0-9A-Za-z\\-_]{35}`
- **Google OAuth / Service Account**: `"type": "service_account"`, `"private_key": "-----BEGIN PRIVATE KEY...`
- **Azure Tenant / Client Secret**: `(?i)(azure|client_secret|tenant_id)(.{0,20})?['"][0-9a-fA-F-]{36}['"]`

### API & SaaS Platform Tokens
- **GitHub Personal Access Token (Classic)**: `ghp_[0-9a-zA-Z]{36}`
- **GitHub Fine-Grained Token**: `github_pat_[0-9a-zA-Z_]{82}`
- **GitHub OAuth Access Token**: `gho_[0-9a-zA-Z]{36}`
- **GitLab Personal Access Token**: `glpat-[0-9a-zA-Z\\-_]{20,}`
- **Slack Bot Token**: `xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`
- **Slack User Token**: `xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`
- **Slack Webhook URL**: `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+`
- **Stripe Live Secret Key**: `sk_live_[0-9a-zA-Z]{24,34}`
- **Stripe Live Restricted Key**: `rk_live_[0-9a-zA-Z]{24,34}`
- **Twilio Account SID & Auth Token**: `AC[a-f0-9]{32}`, `(?i)twilio(.{0,20})?['"][a-f0-9]{32}['"]`
- **SendGrid API Key**: `SG\.[a-zA-Z0-9_\-\.]{66}`
- **OpenAI API Key**: `sk-[a-zA-Z0-9]{48}`, `sk-proj-[a-zA-Z0-9_\-]{80,}`

### Cryptographic Keys & Certificates
- **RSA / EC / OpenSSH Private Keys**:
  - `-----BEGIN RSA PRIVATE KEY-----`
  - `-----BEGIN OPENSSH PRIVATE KEY-----`
  - `-----BEGIN PRIVATE KEY-----`
  - `-----BEGIN EC PRIVATE KEY-----`
  - `-----BEGIN PGP PRIVATE KEY BLOCK-----`

### Authentication Tokens & JWTs
- **JSON Web Tokens (JWT)**: `eyJh[a-zA-Z0-9_\-]+\.eyJh[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`
- **Basic Auth / Base64 Encoded Credentials**:
  - `Basic [a-zA-Z0-9+/=]{16,}` (Decode base64 and check for `username:password` pattern)
  - String literals containing `Authorization: Basic ...` or `Authorization: Bearer ...`

### Database & Generic Credentials
- **Database Connection Strings**:
  - `postgres(ql)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+\/[a-zA-Z0-9_]+`
  - `mongodb(\+srv)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+`
  - `mysql:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+\/[a-zA-Z0-9_]+`
  - `redis:\/\/[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+`
- **Generic Password / Secret Assignments**:
  - `(?i)(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key)\s*[:=]\s*["'][^"'\s]{8,}["']`

---

## 2. Base64 & Encoded Token Decoding Heuristics

When encountering suspicious base64 strings:
1. Check if the string matches base64 pattern: `^[A-Za-z0-9+/]+={0,2}$` with length divisible by 4.
2. Attempt decoding to ASCII text.
3. If decoded output matches `username:password`, JSON structure with private keys, or known token prefixes, report as an encoded hardcoded credential.

---

## 3. False-Positive Filtering & Placeholder Suppression

Do **NOT** report synthetic dummy placeholders such as:
- `password = "password"`, `password = "123456"`, `password = "admin"`
- `apiKey = "YOUR_API_KEY"`, `apiKey = "INSERT_API_KEY_HERE"`, `apiKey = "xxxxxxxxxxxx"`
- `JWT_SECRET = "CHANGE_ME"`, `token = "test_token_123"`
- Environment variable lookups: `process.env.DB_PASSWORD`, `System.getenv("API_KEY")`, `@Value("${api.key}")`

---

## 4. Main Codebase vs. Test Files Separation

- **Main / Production Findings**: Discovered in `src/main/**`, `lib/**`, `app/**`, `routes/**`, `config/**`, `.env*`, `application.yml`, etc. These represent direct credential exposure risks.
- **Test Suite Findings**: Discovered in `src/test/**`, `**/test/**`, `**/__tests__/**`, `**/mocks/**`, `**/fixtures/**`, `*Test.java`, `*.spec.ts`. These represent potential leak risks or real credentials accidentally used in test fixtures.
