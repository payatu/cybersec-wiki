---
title: Insecure Direct Object Reference (IDOR)
---

# Insecure Direct Object Reference (IDOR)

## **1. Fundamentals of IDOR**

**Insecure Direct Object Reference (IDOR)** is a vulnerability that occurs when an application exposes a direct reference to an internal object (like a database key, filename, or identifier) without proper authorization checks. Attackers can manipulate these references to access, modify, or delete unauthorized data.

**Classic Example:**

You're logged in and see:

```
https://bank.com/profile?id=123
```

Change `123` to `124` → **resources belonging to other users become accessible.**.

Here, **`123`** is a **direct object reference** - likely a user ID, account number, or database primary key - that the application uses to fetch and return the corresponding profile. The issue is that the server fails to verify whether the logged-in user actually owns or is authorized to access the resource associated with ID `123`. 

Changing it to `124` exploits this missing access control, instantly revealing another user's profile. 

**Real Impact:** Unauthorized data access, data modification, data deletion, privilege escalation, account takeover, business logic abuse, and unauthorized transactions.

**Four main types:**

1. **URL Tampering** – Changing IDs in the URL
2. **Body Manipulation** – Modifying POST/PUT request bodies
3. **Cookie ID Manipulation** – Editing session/user cookies
4. **Header/Parameter ID Manipulation** – Modifying IDs passed in custom headers or query parameters
5. **File / Resource ID Manipulation – Accessing unauthorized files by modifying file identifiers**

Some applications expose file identifiers, document IDs, invoice numbers, or storage object keys in requests. If proper authorization checks are missing, attackers can modify these identifiers to access files belonging to other users.

Example:

```
GET https://example.com/api/download?fileId=45821
```

If the application only checks whether the file exists but **does not verify ownership**, an attacker can change the ID:

```
GET https://example.com/api/download?fileId=45822
```

This may allow access to another user's documents, invoices, medical reports, or private uploads.

## **Attack Surfaces**

### **1. URL Parameter Testing**

- **Basic increment/decrement:** `id=123` → `id=124`
- **Different formats:**
    - Decimal: `287789`, `287790`
    - Hexadecimal: `0x4642d`, `0x4642e`
    - Unix timestamps: `1695574808`, `1695575098`
    - Base64: `MTIz` → `MTI0`
- **Names/emails as IDs:** `john.doe`, `john.doe@mail.com`, base64 encoded
- **UUID-based IDs:** Predictability depends on version and implementation; UUID v1 (e.g., `95f6e264-bb00-11ec-8833-00155d01ef00`) may be partially predictable due to timestamp/node patterns, while UUID v4 (e.g., `3b9f1c2a-7d5e-4c8a-9f3d-91a6d2f4c8b1`) is random and harder to enumerate, but still requires proper authorization checks
- **MongoDB Object IDs:** `5ae9b90a2c144b9def01ec37` (timestamp-based structure, may be partially predictable)

### **2. POST Body Testing**

- **Change user_id in JSON/XML:**
    
    ```
    {"user_id": 123} → {"user_id": 124}
    ```
    
- **Array wrapping trick:** `{"id": 19}` → `{"id": [19]}`
- **Mass assignment:** Add unauthorized fields like `role: "admin"`

### **3. Cookie Manipulation**

- **Simple cookies:** `user_id=123` → `user_id=124`
- **Base64 encoded:** `eyJ1c2VyX2lkIjoxMjN9` → decode → modify → re-encode
- **Session tokens:** JWT with embedded user_id

### **4. HTTP Header Testing**

- **Custom headers:** `X-User-ID: 123`
- **Authorization headers:** `Bearer eyJ...` (JWT manipulation)
- **Referer/Origin header manipulation:** Bypass checks by changing these

### **5. File Access Testing**

- **Documents:** `/download?file=doc_123.pdf`
- **Images:** `/images/user/123/avatar.jpg`
- **Backups:** `/backups/user_123.zip`

### **6. API Endpoint Testing**

- **REST patterns:** `GET /api/users/123`, `PUT /api/users/124`
- **Nested resources:** `/api/companies/1/employees/123`
- **GraphQL:** `query { user(id: "123") { email } }`

---

## **Bypassing defenses (using encoding and obfuscation)**

### **1. Hashed/Encoded IDs**

- **MD5:** `md5("123") = 202cb962ac59075b964b07152d234b70`
- **SHA1/SHA2:** Generate your own hashes
- **Base64:** `echo "124" | base64` → `MTI0Cg==`
- **URL-safe Base64:** `dXNlcjoxMjM=` → `dXNlcjoxMjQ=`

### **2. Parameter Pollution**

```
GET /api/profile?user_id=123&user_id=124
```

Or in JSON:

```
{"user_id": 123, "user_id": 124, "email": "attacker@evil.com"}
```

### **3. Content-Type Switching**

- JSON → XML → Form-Data
- Example: `Content-Type: application/xml` with `<user_id>124</user_id>`

### **4. HTTP Method Switching**

- `GET` → `POST` → `PUT` → `DELETE` → `HEAD`
- Some endpoints check auth differently per method

### **5. Wildcard Attacks**

```
GET /api/users/*
GET /api/users/%
GET /api/users/_
GET /api/users/.*
GET /api/users?ids=*
```

### **6. Boolean Parameter Bypass**

Found `"public": false` in response? Try `?public=true` in request

### **7. Alternate Data Representation**

- Decimal → Hex: `/user/1001` → `/user/0x3E9`
- Different encoding schemes

---

## **Advance Attack Scenarios**

### **1. Blind IDOR**

- **No direct response?** Check for:
    - Email notifications to victim
    - Webhook callbacks
    - Time delays (longer response = processing real data)
    - State changes (friend requests, profile updates)

### **2. Race Conditions**

- Send multiple concurrent requests with different IDs
- Use **Turbo Intruder** to bypass validation windows
- Example: Changing order_id mid-checkout process

### **3. Hidden Endpoint Discovery**

- **Search JS files** for API endpoints
- Pattern: `/api/v2/integration/install/{id}`
- **Brute-force:** `/api/v1/user`, `/api/v2/user`, `/api/user`, `/users`

### **4. Account Takeover via Email Change**

From reports:

1. Change your email to victim's via POST
2. Intercept "verify email" response
3. Change `"verified": false` → `"verified": true`
4. Access victim's billing info, subscription history

### **5. No Content ≠ No Bug**

Got `204 No Content` when changing ID?

- Switch `POST` → `GET`
- Might get full PII back

### **6. Auth Header Contains ID**

```
Authorization: ODIxMjIyODY6ODIxMjIyODY=
```

Base64 decode → `82122286:82122286`

Change to victim's ID → re-encode → account takeover

### **7. Support Ticket Takeover**

Ticket: `/Issue/9085/855f5bb19e7b...` (hashed)

But comment endpoint: `POST /comment {"ticket_id": 9085}`

Change to `9084` → comment on other tickets

---

## **Framework specific scenarios:**

### **GraphQL IDOR**

```
query { user(id: "123") { privateData } }
```

Batch queries: `[{"query": "user(id: \"123\")"}, {"query": "user(id: \"124\")"}]`

### **REST API IDOR**

- Pagination: `/api/users?page=1&size=100` → change size
- Filters: `/api/orders?user_id=123` → `user_id=124`

### **SOAP/XML API**

```
<userId>123</userId> → <userId>124</userId>
```

---

## **Detection Techniques (using Manual and Automated Techniques)**

### **Manual Testing:**

- **Identify all object references:** URLs, headers, cookies, body
- **Change values systematically:** +1, -1, different formats
- **Check responses:** Data leakage, errors, status codes
- **Look for indirect effects:** Emails, notifications, exports

### **Automated Tools:**

**Burp Suite:**

1. **Intruder:** Number fuzzing (1-10000)
2. **Autorize:** Auto-replay with different sessions
3. **AuthMatrix:** Role-based testing
4. **Param Miner:** Find hidden parameters
5. **InQL:** GraphQL testing

**FFUF:**

```
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -mc 200
ffuf -u https://target.com/api/user -X POST -d '{"user_id":"FUZZ"}' -w ids.txt
```

**Custom Python Script:**

```
import requests
for uid in range(1,1000):
    r = requests.get(f"https://target.com/api/user/{uid}")
    if r.status_code == 200 and "email" in r.text:
        print(f"Found:{uid}")
```

---

## **Impact**

- **Unauthorized data access:** PII, messages, financial info
- **Data manipulation:** Edit profiles, billing, orders
- **Account takeover:** Change email/password
- **Privilege escalation:** Grant admin roles
- **Financial fraud:** Redirect payments, issue refunds
- **Reputation damage:** Leak business/customer data

**Real examples from reports:**

- View other users' order information
- Delete other users' messages
- Access private integrations by changing boolean flags
- Take over accounts via email manipulation
- Access billing information and payment history

---

## **Prevention Techniques**

- **Use indirect references** – Avoid exposing real database identifiers; use mapping layers or reference tokens instead
- **Enforce centralized authorization checks** – Implement a single, consistent authorization layer to validate access across all endpoints and services
- **Apply tenant scoping** – Ensure every request is restricted to the correct tenant/context to prevent cross-tenant data access
- **Implement RBAC/ABAC enforcement** – Define and enforce Role-Based Access Control or Attribute-Based Access Control for fine-grained permissions
- **Validate server-side ownership** – Always verify object ownership on the server before allowing read/write/delete operations
- **Use random or non-guessable identifiers** – Prefer UUIDv4 or similarly unpredictable IDs instead of sequential identifiers
- **Validate all inputs strictly** – Enforce proper format, type, and scope validation for all user-controlled parameters
- **Never trust client-side controls** – Treat all client-side restrictions as untrusted and enforce security rules on the server
- **Log and monitor access patterns** – Track object access attempts and alert on abnormal or cross-boundary access behavior
- **Use framework-level security guards** – Leverage built-in controls such as `@PreAuthorize`, `@PostAuthorize`, or equivalent middleware to enforce authorization consistently

---

## **Tools**

| **Tool** | **What It's For** |
| --- | --- |
| **Autorize(Burp Suite Extension)** | Auto authorization testing |
| **AuthMatrix(Burp Suite Extension)** | Role-based access testing |
| **InQL** | GraphQL IDOR testing |

---

## Good To Read

[IDOR in the Wild: A Comprehensive Analysis of 250 Real-World Vulnerabilities - IDOR Case Study | The Bug Hunter](https://www.thebughunter.blog/case-studies/idor-analysis)

[Top 235 IDOR Bug Bounty Reports](https://readmedium.com/top-235-idor-bug-bounty-reports-e00c8061fe28)

[https://infosecwriteups.com/10-hunting-for-idors-the-most-underrated-vulnerability-9567ebf97585](https://infosecwriteups.com/10-hunting-for-idors-the-most-underrated-vulnerability-9567ebf97585)

---

## **References**

- [Insecure Direct Object Reference Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [WSTG - Latest | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [swisskyrepo/PayloadsAllTheThings: A list of useful payloads and bypass for Web Application Security and Pentest/CTF](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [IDOR - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/idor.html)
- [McHire Chatbot Platform: Default Credentials and IDOR Expose 64M Applicants’ PII](https://ian.sh/mcdonalds)
- [https://infosecwriteups.com/idor-insecure-direct-object-references-my-first-p1-in-bugbounty-fb01f50e25df](https://infosecwriteups.com/idor-insecure-direct-object-references-my-first-p1-in-bugbounty-fb01f50e25df)