---
title: Web Cache Poisoning
---

# Web Cache Poisoning

## What is Web Cache Poisoning?

It’s when an attacker **injects a malicious response** into the cache, which is then **served to unsuspecting users**. If the cache stores and delivers that response without verifying it properly, you’ve got a poisonable cache.

## Fundamentals

Web cache poisoning occurs when a response is cached using one set of request attributes (cache key), while the response content is influenced by other attacker-controlled inputs that are not included in that key.

### Cache Poisoning Flow

1. Attacker sends a request containing a manipulated header, cookie, query parameter, or path.
2. The backend uses that input when generating the response.
3. The caching layer stores the response under a cache key.
4. The malicious response is served to subsequent users requesting the same cached resource.

### Cache Key vs Unkeyed Input

| Component | Meaning |
| --- | --- |
| Cache Key | The values used by the cache to identify a unique response (e.g., path, host, method, selected headers). |
| Unkeyed Input | A value that changes the response but is not included in the cache key. |
| Poisoned Response | The cached response containing attacker-controlled content. |
| Cache Hit | The poisoned response is served to other users. |

### Typical Requirement

A successful web cache poisoning attack generally requires:

- The response is cacheable.
- User-controlled input influences the response.
- That input is not part of the cache key.
- The poisoned response is served to other users.

### How It Works

1. The attacker finds a way to inject malicious input (e.g., headers, query strings).
2. The backend reflects that input into the response.
3. The caching layer stores that response.
4. Other users receive the poisoned response without ever seeing the attacker's original request.

For example, if a reverse proxy (like Varnish, Cloudflare, Akamai) caches responses **without considering attacker-controlled headers or query params**, that’s a prime opportunity.

---

## Attack Surface

Look for cacheable endpoints where request input affects the response:

- Home pages and landing pages
- Login and logout pages
- Password reset flows
- Search results
- Redirect endpoints
- Static asset URLs (JS, CSS, images)
- CDN-backed content
- API endpoints with public caching
- Error pages
- Localization and language selection
- A/B testing or feature flag responses
- User-agent specific responses

### High-Risk Inputs

- Host header
- X-Forwarded-Host
- X-Forwarded-Proto
- X-Original-URL
- X-Rewrite-URL
- Referer
- Origin
- Cookies
- Query parameters
- Path segments
- Accept-Language
- User-Agent

---

## Common Scenarios & Real-World Examples

### 1. Converting Reflected XSS into Stored XSS via X-Forwarded Headers

```
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Host: attacker.com
```

- Backend reflects this header in HTML (e.g., `<base href>`, redirect URLs).
- CDN caches it for everyone. Boom, stored XSS.

### 2. Open Redirect via Cached Location Header

```
GET /login HTTP/1.1
X-Forwarded-Host: evil.com
```

- Location header becomes: `Location: https://evil.com/dashboard`
- Redirect is cached.

### **3. Cache Key Normalization Issues**

- Some caches normalize keys inconsistently.
- **Examples:**
    - Case sensitivity (**`/page`** vs **`/Page`**)
    - URL encoding (**`%41`** vs **`A`**)
    - Trailing slashes (**`/path`** vs **`/path/`**)

### **4. Query Parameter Poisoning**

- If query parameters are unkeyed but reflected:
    
    ```
    GET /?utm_source=evil HTTP/1.1
    Host: example.com
    ```
    
    - If **`utm_source`** is unkeyed but embedded in a script, it can poison the cache.

### **5. Cookie Poisoning**

- If cookies influence the response but are not part of the cache key:
    
    http
    
    ```
    GET / HTTP/1.1Host: example.comCookie: lang=en; malicious_payload=alert(1)
    ```
    

### **6. DOM-Based Cache Poisoning**

- If JavaScript dynamically generates cache keys, attackers can manipulate DOM inputs.

---

## Exploitation Techniques

### Header-Based Poisoning

Manipulate headers that are reflected into the response but not included in the cache key.

```
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com
```

### Query Parameter Poisoning

Use parameters that change the response but are ignored by the cache key.

```
GET /?utm_source=evil HTTP/1.1
Host: victim.com
```

### Cookie-Based Poisoning

Inject values through cookies when the response changes but the cookie is not part of the cache key.

```
GET / HTTP/1.1
Host: victim.com
Cookie: theme=dark; payload=evil
```

### Redirect Poisoning

Influence the Location header and cache the malicious redirect.

```
GET /login HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com
```

### Stored XSS via Cache

Inject a payload that is reflected into HTML or JavaScript, then cached for other users.

```
GET /?q=</script><script>alert(1)</script> HTTP/1.1
Host: victim.com
```

---

## Advanced Attack Scenarios

### Split Cache Key Poisoning

The backend and cache disagree on which request components define a unique response.

### Cache Deception

A dynamic response is cached as if it were a static resource.

### Normalization Mismatch

The cache and backend normalize paths differently.

Examples:

- /page vs /Page
- /path vs /path/
- %2F vs /
- %2e%2e/ vs ../

### Parameter Cloaking

Duplicate parameters are interpreted differently by the cache and backend.

```
GET /?id=1&id=2 HTTP/1.1
```

### Host Header Poisoning

The backend generates absolute URLs using attacker-controlled host information.

### CDN Edge vs Origin Mismatch

The CDN caches a response differently from the origin server.

---

## Payloads

- Common Headers to Play With

```
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Forwarded-Scheme: javascript:
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

- Useful Query Params

```
?cb=1234
?debug=true
?param=</script><script>alert(1)</script>
```

Try duplicate query parameters (`?id=1&id=2`), junk params (`?unused=value`), and weird encodings (`%00`, `%2F`, `%2e`).

---

## Test Cases

| Scenario | Test | Expected Indicator |
| --- | --- | --- |
| Header reflection | Add X-Forwarded-Host | Reflected in response |
| Query reflection | Add random parameter | Reflected in response |
| Cache hit | Repeat request | X-Cache: HIT |
| Parameter order | Swap parameter order | Same cached response |
| Path case | /Page vs /page | Same cached response |
| Trailing slash | /path vs /path/ | Same cached response |
| Duplicate parameter | id=1&id=2 | Different backend behavior |
| Cookie influence | Add custom cookie | Response changes |
| Redirect poisoning | Modify host header | Cached redirect |
| Stored XSS | Inject reflected payload | Payload served to others |

---

## Detection Techniques

### Manual Detection

- Check Cache-Control headers.
- Check X-Cache, CF-Cache-Status, Age, or similar headers.
- Identify reflected input in the response.
- Repeat requests to confirm caching.
- Compare responses with and without attacker-controlled input.
- Test parameter order, case sensitivity, encoding, and trailing slashes.
- Test duplicate parameters.
- Test unkeyed headers.

### Automated Detection

- Burp Suite Param Miner
- Burp Web Cache Poisoning Scanner
- Nuclei cache poisoning templates
- OWASP ZAP
- autopoisoner
- Custom scripts for repeated request comparison

---

## Bypasses & Tricks

### 1. Path Normalization

- `/..;/admin` may resolve to `/admin` but look different to the cache.

### 2. Double Encoding

- `%252e%252e/` → `%2e%2e/` → `../`

### 3. Null Bytes

- `%00` or `%00%00` to truncate or confuse backends.

### 4. Header Case Manipulation

- `x-forwarded-host`, `X-Forwarded-Host`, `X-FoRwArDeD-HoSt`

### 5. Smuggling via CRLF (less common now)

```
X-Test: injected\r\nSet-Cookie: admin=true
```

---

## Impact

Successful web cache poisoning may lead to:

- Stored XSS affecting many users
- Open redirect attacks
- Session theft
- Credential theft
- Account takeover
- Delivery of malicious JavaScript
- Defacement of cached pages
- Phishing through trusted domains
- CDN-wide impact
- Denial of service
- Cache deception
- Information disclosure

---

## Defense & Best Practices

### Application Layer

- Don’t reflect `Host`, `X-Forwarded-*` headers unless necessary.
- Sanitize inputs used in redirects, templates, and JSON.
- Add `Vary:` headers properly for all inputs affecting output.
- Example:
    
    ```
    Cache-Control: no-store
    Vary: X-Forwarded-Host
    ```
    

### Cache/Proxy Layer

- Whitelist which headers affect routing.
- Normalize and strip unknown or unnecessary headers.
- Use `no-store`, `private`, `no-cache` for dynamic content.
- Avoid wildcard caching rules.

### Security Config

- Disable caching for unauthenticated/dynamic pages.
- Log and monitor suspicious cache keys and hit/miss ratios.

---

## References

[https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)

[https://owasp.org/www-community/attacks/Cache_Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)

[https://www.vaadata.com/blog/web-cache-poisoning-attacks-and-security-best-practices/](https://www.vaadata.com/blog/web-cache-poisoning-attacks-and-security-best-practices/)

[https://www.cobalt.io/blog/hacking-web-cache-deep-dive-in-web-cache-poisoning-attacks](https://www.cobalt.io/blog/hacking-web-cache-deep-dive-in-web-cache-poisoning-attacks)

[https://owasp.org/www-community/attacks/Cache_Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)

[https://www.jianjunchen.com/p/web-cache-posioning.CCS24.pdf](https://www.jianjunchen.com/p/web-cache-posioning.CCS24.pdf) (Research Paper)

[https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)

[https://infosecwriteups.com/web-cache-poisoning-wwwwwh-ee2b47d6bacc](https://infosecwriteups.com/web-cache-poisoning-wwwwwh-ee2b47d6bacc)

[https://hackerone.com/reports/1424094](https://hackerone.com/reports/1424094)

[https://hackerone.com/reports/394016](https://hackerone.com/reports/394016)

[https://hackerone.com/reports/1424094](https://hackerone.com/reports/1424094)