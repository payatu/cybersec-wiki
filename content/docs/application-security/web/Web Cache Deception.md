---
title: Web Cache Deception
---

# Web Cache Deception

**Web Cache Deception** is an attack where a malicious actor tricks a web cache into storing sensitive user-specific content (e.g., account details, billing info) in a publicly accessible cached page.

It exploits the misconfiguration of caching systems when paired with poor cache key design on web servers and CDNs.

---

## Fundamentals

| Component | Role |
| --- | --- |
| **Caching Proxy/CDN** | Stores content to reduce backend load and improve performance |
| **Web Server** | Delivers user-specific content but may misinterpret cacheable paths |
| **Attacker** | Crafts deceptive URLs to force cache storage of user-sensitive data |

---

## **How Web Cache Deception Works**

1. **Attacker lures victim** to visit a malicious link (e.g., **`https://example.com/profile/nonexistent.css`**).
2. **Server processes** the request as **`/profile`** (due to path confusion or misconfiguration).
3. **Caching server stores** the response (thinking it's a static file).
4. **Another user requests** the same URL and gets the cached sensitive data.

---

## Attack Surface

Look for cacheable endpoints that return user-specific or dynamic content, such as:

- Account/Profile pages
- Dashboard pages
- Order history and invoices
- Shopping carts
- Billing information
- API endpoints returning user data
- JavaScript files containing embedded user information
- Export/Download functionality
- Password reset pages
- Search pages with personalized results
- CDN-backed static routes
- Reverse proxies (Cloudflare, Akamai, Fastly, Varnish, Nginx)

---

## Exploitation Techniques

### 1. Static Extension Abuse

Append cacheable extensions to dynamic resources.

```
/profile.css
/account.js
/dashboard.jpg
```

---

### 2. Path Confusion

Exploit differences between the cache and origin server when parsing URLs.

```
/account.php/anything.css
/profile/..;/style.css
/account%2Ftest.css
```

---

### 3. Delimiter Abuse

Use delimiters interpreted differently by the cache and backend.

```
/account;.css
/account;.js
/account?.css
```

---

### 4. Encoded Path Traversal

Attempt alternate URL encodings.

```
/account%2Fsecret.css
/account%252fsecret.css
```

---

### 5. Query Normalization Abuse

Some caches ignore query parameters.

```
/account.css?random=123
/account.css?cachebuster=1
```

---

### 6. Header Manipulation

Test headers that may affect routing or cache behavior.

```
X-Forwarded-Host
X-Forwarded-Proto
X-Rewrite-URL
X-Original-URL
Forwarded
```

---

### 7. Cache Rule Confusion

Test requests using different methods.

```
GET
HEAD
OPTIONS
```

Some CDNs cache GET responses but normalize HEAD requests differently.

---

## Common Scenarios

### 1. Cacheable Extension Added to Sensitive Path

**Condition:** Web cache stores `/account.js` or `/account.html`, but backend serves sensitive data based on session cookies.

**Payload:**

```
https://victim.com/account/secret.js
https://victim.com/profile/secret.html
```

**Result:** Cache stores sensitive user data; next user hitting same URL sees it.

---

### 2. Authenticated Content Served via Cacheable Route

**Condition:** Authenticated pages (like `/account`) are served with no-cache header, but URL with fake extensions trick cache.

**Example Flow:**

1. Attacker visits `/account;secret.css` (browser ignores `;secret.css`)
2. Cache stores the response
3. Anyone accessing same URL gets attacker’s content

---

### 3. User-Specific Data Cached Without Session Separation

**Condition:** Cache key is based only on URL, not on headers like `Cookie`, `Authorization`, or session tokens.

**Result:** Response for authenticated user gets served to anonymous visitors.

---

### 4. CDN ignores Query Strings, or They Are Normalized

**Payload:**

```
/account.css?ignoreme
/account%2F.css
/account.php/..;/index.html
//account/test
```

**Cache Key Bypass:** Query string removed/ignored in caching key.

---

### 5. Caching JavaScript with Embedded Sensitive Data

**If:** User data is embedded in JavaScript as `var email = "user@domain.com";`

**Payload:**

```
/account.js
```

If cached, all users can see other users' data by loading the cached JavaScript.

---

### 6. Prefixes/Suffixes That Fool the Cache

- Using suffixes like `.jpg`, `.css`, `.html`, etc.
- Path manipulation: `/account.php/anything.jpg`

---

---

## **Bypassing Cache Protections**

### **A. Bypassing `Vary: Cookie`**

If the cache keys on **`Cookie`**, try:

- Removing cookies
- Using fake session IDs
- Manipulating **`Vary`** headers

### **B. Bypassing `Cache-Control: private`**

Some CDNs ignore **`private`** directives. Test with:

text

```
GET /account HTTP/1.1
Host: example.com
X-Forwarded-For: 1.2.3.4
```

### **C. Exploiting Cache Hierarchies**

Some setups have multiple cache layers (e.g., Cloudflare → Origin Cache). Poisoning one layer may affect others.

### D. **Bypassing Cache Deception Armor**

Cloudflare Deception Armor could be bypassed by using `.avif` extension making Cache deception attack possible on vulnerable origin servers.

Reference: [https://hackerone.com/reports/1391635](https://hackerone.com/reports/1391635)

---

## Detection Techniques

### Manual Detection

- Identify authenticated pages returning sensitive information.
- Append static extensions to dynamic endpoints.
- Compare authenticated and unauthenticated responses.
- Check cache-related headers:
    - `Cache-Control`
    - `Age`
    - `ETag`
    - `Expires`
    - `X-Cache`
    - `CF-Cache-Status`
    - `Via`
- Verify whether another browser or user receives identical cached content.

### Automated Detection

- Burp Suite Repeater
- Param Miner
- Web Cache Vulnerability Scanner
- Nuclei cache templates
- Custom scripts using curl

---

## Test Cases

| Scenario | Payload | Expected Result |
| --- | --- | --- |
| Static extension | `/profile.css` | Sensitive response cached |
| Fake JavaScript | `/account.js` | User-specific JS cached |
| Fake image | `/dashboard.jpg` | Cached authenticated content |
| Encoded path | `/account%2Ftest.css` | Cache/origin mismatch |
| Path confusion | `/account.php/test.css` | Dynamic content cached |
| Query normalization | `/account.css?x=1` | Same cached response |
| Semicolon path | `/account;.css` | Cache confusion |
| Alternate session | Incognito request | Cached victim data returned |

**Tips:**

- Use static resource extensions like `.css`, `.js`, `.jpg` to trick cache
- Try variations with slashes, dots, semicolons
- Percent-encode components: `%2F`, `%3B`

---

## Indicators of a Vulnerable System

- Presence of CDN or reverse proxy (Akamai, Cloudflare, Varnish, etc.)
- Inconsistent cache headers across similar routes
- Cache control headers like `Cache-Control: public` with user-specific content
- Lack of session-awareness in caching mechanism
- Missing `Vary: Cookie` or `Vary: Authorization`
- Presence of `CF-Cache-Status: HIT`
- Increasing `Age` header values

---

## Impact

Successful exploitation of Web Cache Deception may lead to:

- Disclosure of authenticated user data
- Exposure of personally identifiable information (PII)
- Leakage of account details, invoices, or billing information
- Session-specific JavaScript disclosure
- Exposure of API responses intended for authenticated users
- Information disclosure across different users
- Increased risk of account takeover when sensitive tokens are cached

---

## Mitigation Strategies

| Level | Mitigation |
| --- | --- |
| 🔹 CDN/Cache | - Do not cache URLs containing cookies or authorization headers- Use `Vary: Cookie, Authorization` headers- Enforce strict cache key rules |
| 🔸 Application | - Do not embed sensitive data in pages likely to be cached- Serve authenticated content from clearly uncacheable paths |
| 🔻 Headers | - Set `Cache-Control: no-store, private` for authenticated pages- Use `X-Accel-Expires: 0` or `Pragma: no-cache` where applicable |
| ⚙️ DevOps | - Monitor cache hits/misses with logging- Regularly test cache behavior on production replicas |

---

## Tools & Techniques

| Tool | Purpose |
| --- | --- |
| Burp Suite | Modify requests, analyze cache headers |
| curl/wget | Reproduce caching behavior with headers |
| browser dev tools | Track caching via network tab |
| CDN configuration panel | Review caching rules, behavior |
| Param Miner | Discover cache key discrepancies |
| Web Cache Vulnerability Scanner | Detect cache poisoning/deception |

---

## Good to Read:

[https://hackerone.com/reports/631589](https://hackerone.com/reports/631589)

[https://hackerone.com/reports/397508](https://hackerone.com/reports/397508)

[https://hackerone.com/reports/394016](https://hackerone.com/reports/394016)

## References

[https://portswigger.net/web-security/web-cache-deception](https://portswigger.net/web-security/web-cache-deception)

[https://swisskyrepo.github.io/PayloadsAllTheThings/Web%20Cache%20Deception/#caching-custom-javascript](https://swisskyrepo.github.io/PayloadsAllTheThings/Web%20Cache%20Deception/#caching-custom-javascript)

[https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)

[https://book.hacktricks.wiki/en/pentesting-web/cache-deception/index.html](https://book.hacktricks.wiki/en/pentesting-web/cache-deception/index.html)

[https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf)

[https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20%281%29.pdf](https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20%281%29.pdf)

[https://www.usenix.org/system/files/sec22-mirheidari.pdf](https://www.usenix.org/system/files/sec22-mirheidari.pdf)