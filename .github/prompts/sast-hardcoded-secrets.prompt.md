# Hardcoded Secrets Scan

Read state and checkpoint first. Search source and security-relevant configuration for API keys, bearer tokens, passwords, private keys, database/cloud credentials, JWT secrets, and OAuth client secrets. Distinguish test fixtures and placeholders using the false-positive rules, but do not expose full values. Record only redacted evidence, location, secret type, reachability/deployment context, and classification. Update state before and after execution and after every verified candidate. Do not modify application source code.
