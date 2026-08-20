# Comprehensive Secret Detection Heuristics & Signature Matrix

This instruction document defines the complete detection signatures, regular expressions, cryptographic key heuristics, and decoding algorithms for the `@sast-secrets` agent to discover hardcoded credentials across source files, configs, properties, scripts, and test suites.

---

## 1. Cryptographic Keys & Symmetric Encryption Secrets (HIGH PRIORITY)

### Java Symmetric Encryption Keys & Specs
- **`SecretKeySpec` Instantations**:
  - `new SecretKeySpec\s*\(\s*["'][^"'\s]{8,}["']\.getBytes\(\)\s*,\s*["'](AES|DES|DESede|Blowfish|RC4|ChaCha20|HmacSHA256|HmacSHA512|HmacSHA1|HmacMD5)["']\s*\)`
  - `new SecretKeySpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{[^}]+\}\s*,\s*["'][A-Za-z0-9_-]+["']\s*\)`
  - `new SecretKeySpec\s*\(\s*(Base64\.getDecoder\(\)\.decode|Hex\.decodeHex|DatatypeConverter\.parseBase64Binary|Base64\.decodeBase64)\s*\(\s*["'][A-Za-z0-9+/=_-]{16,}["']\s*\)\s*,\s*["'][A-Za-z0-9_-]+["']\s*\)`
- **Key Derivation (PBE / PBKDF2 / Salt)**:
  - `new PBEKeySpec\s*\(\s*["'][^"'\s]{6,}["']\.toCharArray\(\)` or `new PBEKeySpec\s*\(\s*new\s+char\s*\[\s*\]\s*\{[^}]+\}`
  - Static Salts: `byte\s*\[\s*\]\s*(salt|SALT)\s*=\s*(new\s+byte\s*\[\s*\]\s*\{[^}]+\}|["'][^"'\s]{8,}["']\.getBytes\(\))`
- **Static Initialization Vectors (IVs) & Nonces**:
  - `new IvParameterSpec\s*\(\s*["'][^"'\s]{8,}["']\.getBytes\(\)\s*\)`
  - `new IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{[^}]+\}\s*\)`
  - `new GCMParameterSpec\s*\(\s*[0-9]+\s*,\s*["'][^"'\s]{8,}["']\.getBytes\(\)\s*\)`
- **Keystore & Truststore Passwords**:
  - `\.load\s*\(\s*[^,]+,\s*["'][^"'\s]{4,}["']\.toCharArray\(\)\s*\)`
  - Properties: `javax\.net\.ssl\.(keyStorePassword|trustStorePassword)\s*=\s*["']?[^"'\s]+["']?`
  - Spring: `server\.ssl\.(key-store-password|trust-store-password|key-password)\s*[:=]\s*["']?[^"'\s]+["']?`

### Node.js / JavaScript / TypeScript Symmetric Keys
- **Node `crypto` Module**:
  - `crypto\.createCipheriv\s*\(\s*['"][^'"]+['"]\s*,\s*(Buffer\.from\(['"][a-fA-F0-9+/=]{16,}['"]|['"][^'"]{16,32}['"])\s*,`
  - `crypto\.createDecipheriv\s*\(\s*['"][^'"]+['"]\s*,\s*(Buffer\.from\(['"][a-fA-F0-9+/=]{16,}['"]|['"][^'"]{16,32}['"])\s*,`
  - `crypto\.createHmac\s*\(\s*['"][a-zA-Z0-9_-]+['"]\s*,\s*['"][^'"]{8,}['"]\s*\)`
- **CryptoJS & Web Crypto API**:
  - `CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit|Blowfish)\.(encrypt|decrypt)\s*\([^,]+,\s*['"][^'"]{8,}['"]`
  - `CryptoJS\.Hmac(SHA256|SHA512|SHA1|MD5)\s*\([^,]+,\s*['"][^'"]{8,}['"]`
  - `crypto\.subtle\.importKey\s*\(\s*['"]raw['"]\s*,\s*new\s+TextEncoder\(\)\.encode\(\s*['"][^'"]{8,}['"]\s*\)`

### Raw Hex & Base64 Key Assignments (Cross-Language)
- **Hex Encoded Keys (128-bit, 192-bit, 256-bit, 512-bit)**:
  - `(?i)(aes_key|secret_key|crypto_key|encryption_key|symmetric_key|hmac_key|master_key|cipher_key)\s*[:=]\s*["']([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})["']`
- **Base64 Encoded Keys (16, 24, 32, 64 bytes)**:
  - `(?i)(aes_key|secret_key|crypto_key|encryption_key|symmetric_key|hmac_key|master_key|cipher_key)\s*[:=]\s*["']([A-Za-z0-9+/]{22}==|[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)["']`
- **Byte Array Initializer Literals**:
  - `(byte\s*\[\s*\]|Buffer\.from\(\[)\s*(0x[0-9a-fA-F]{1,2}\s*,\s*){7,}0x[0-9a-fA-F]{1,2}`

---

## 2. Asymmetric Private Keys & Certificates

- **PEM & OpenSSH Private Keys**:
  - `-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`
  - `-----BEGIN PGP PRIVATE KEY BLOCK-----`
  - `-----BEGIN CERTIFICATE-----` (when paired with private key data)
- **PKCS#8 / PKCS#12 / DER Hex/Base64 Blobs**:
  - `KeyFactory\.getInstance\([^)]+\)\.generatePrivate\(new\s+PKCS8EncodedKeySpec\((Base64\.decode|Hex\.decode)\(["'][^"']+["']\)\)\)`

---

## 3. Webhook & Message Signing Secrets

- **Stripe Webhook Secret**: `whsec_[0-9a-zA-Z]{32,}`
- **GitHub Webhook Secret**: `(?i)(github_webhook|webhook_secret|hub_signature)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']`
- **Shopify Shared Secret**: `shpss_[0-9a-fA-F]{32}`
- **Slack Signing Secret**: `(?i)(slack_signing_secret|signing_secret)\s*[:=]\s*["'][0-9a-fA-F]{32}["']`
- **Razorpay Key Secret**: `(?i)(razorpay_secret|key_secret)\s*[:=]\s*["'][0-9a-zA-Z]{24}["']`

---

## 4. Cloud, Infrastructure & SaaS Credentials

### Cloud Platform Credentials
- **AWS Access Key ID & Secret Key**:
  - `(AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}`
  - `(?i)aws_secret_access_key\s*[:=]\s*["'][0-9a-zA-Z\/+]{40}["']`
- **Google Cloud API Key & Service Accounts**:
  - `AIza[0-9A-Za-z\\-_]{35}`
  - `"type":\s*"service_account"`, `"private_key_id":\s*"[0-9a-f]{40}"`
- **Azure Tenant / Client Secrets**:
  - `(?i)(azure|client_secret|tenant_id)\s*[:=]\s*["'][0-9a-fA-F-]{36}["']`
- **Kubernetes & Terraform Tokens**:
  - `(?i)k8s_token\s*[:=]\s*["']eyJh[a-zA-Z0-9_\-\.]+["']`

### API & SaaS Platform Tokens
- **GitHub Personal Access Tokens**: `ghp_[0-9a-zA-Z]{36}`, `github_pat_[0-9a-zA-Z_]{82}`, `gho_[0-9a-zA-Z]{36}`
- **GitLab Personal Access Token**: `glpat-[0-9a-zA-Z\\-_]{20,}`
- **Slack Tokens**: `xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`, `xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`
- **Slack Webhook URL**: `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+`
- **Stripe API Keys**: `sk_live_[0-9a-zA-Z]{24,34}`, `rk_live_[0-9a-zA-Z]{24,34}`
- **Twilio Credentials**: `AC[a-f0-9]{32}`, `(?i)twilio(.{0,20})?['"][a-f0-9]{32}['"]`
- **SendGrid API Key**: `SG\.[a-zA-Z0-9_\-\.]{66}`
- **OpenAI API Key**: `sk-[a-zA-Z0-9]{48}`, `sk-proj-[a-zA-Z0-9_\-]{80,}`

---

## 5. Authentication, Tokens, JWT & Session Secrets

- **JWT Signing Keys**:
  - `Jwts\.parser\(\)\.setSigningKey\(\s*["'][^"'\s]{8,}["'](\.getBytes\(\))?\s*\)`
  - `jwt\.sign\([^,]+,\s*['"][^'"]{8,}['"]\s*\)`
  - `jwt\.verify\([^,]+,\s*['"][^'"]{8,}['"]\s*\)`
- **JSON Web Tokens (Raw JWT String Literals)**:
  - `eyJh[a-zA-Z0-9_\-]+\.eyJh[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`
- **Basic Auth / Base64 Encoded Strings**:
  - `Basic\s+[a-zA-Z0-9+/=]{16,}` (Decoded to verify `user:password`)
  - `Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{16,}`
- **Session & Cookie Signing Secrets**:
  - `express-session`: `secret:\s*['"][^'"]{8,}['"]`
  - `cookie-parser`: `cookieParser\(['"][^'"]{8,}['"]\)`

---

## 6. Database, Message Broker & Generic Passwords

- **Database Connection URIs**:
  - `postgres(ql)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+\/[a-zA-Z0-9_]+`
  - `mongodb(\+srv)?:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+`
  - `mysql:\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+\/[a-zA-Z0-9_]+`
  - `redis:\/\/[^@\s]+@[a-zA-Z0-9_\.\-]+:[0-9]+`
  - `jdbc:(mysql|postgresql|oracle|sqlserver|db2):\/\/[^;]+;password=[^;]+`
- **Kafka & Broker SASL JAAS Configurations**:
  - `org\.apache\.kafka\.common\.security\.(plain|scram)\.PlainLoginModule\s+required\s+username=["'][^"']+["']\s+password=["'][^"']+["']`
- **Generic Password / Credential Properties**:
  - `(?i)(password|passwd|pwd|db_pass|db_password|admin_pass|root_password)\s*[:=]\s*["'][^"'\s]{6,}["']`

---

## 7. Shannon Entropy & False-Positive Filtering

When assessing candidate strings:
1. **Shannon Entropy**: High-entropy strings (> 3.5 for base64, > 3.0 for hex) with length >= 16 characters are strong indicators of generated cryptographic keys or tokens.
2. **Exclude Obvious Placeholders**:
   - `password = "password"`, `password = "123456"`, `password = "admin"`
   - `apiKey = "YOUR_API_KEY"`, `apiKey = "INSERT_API_KEY_HERE"`, `apiKey = "xxxxxxxxxxxx"`
   - `JWT_SECRET = "CHANGE_ME"`, `token = "test_token_123"`
   - Dynamic environment lookups: `process.env.*`, `System.getenv(*)`, `@Value("${...}")`
