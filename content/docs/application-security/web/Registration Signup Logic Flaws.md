---
title: Registration / Signup Logic Flaws
---

# Registration / Signup Logic Flaws

Registration logic flaws occur when the application’s business logic is improperly implemented, allowing attackers to bypass authentication, manipulate account creation, or escalate privileges during the registration process.

---

## Understanding Registration Logic

- **Standard Registration Flow**
    
    ```jsx
    1. User submits credentials/details
    2. Server validates input and uniqueness (Email/Username)
    3. Server generates verification (Email / OTP / Token)
    4. User submits verification code/token
    5. Server activates account and creates session
    ```
    
- Each stage must enforce strict validation and state consistency
- Registration often interacts with authentication, session management, and user identity systems

---

## Attack Surfaces

- Registration Form
- Email / OTP Verification Flow
- OAuth / SSO Registration
- Multi-step Registration Flows
- API-based Registration Endpoints
- Hidden / Legacy Signup Routes

---

## Exploitation Techniques

- **Duplicate Registration (Account Overwrite)**
    
    ```jsx
    POST /signup
    Host: target.com
    { "email": "victim@example.com", "password": "attacker_password" }
    ```
    
    If the application does not properly enforce uniqueness, it may overwrite an existing account.
    
    **Test variations in email handling:**
    
    - Case variation:
        - `VICTIM@gmail.com`
        - `victim@gmail.com`
    - Sub-addressing:
        - `victim+1@gmail.com`
    - Dot trick (Gmail-specific):
        - `v.i.c.t.i.m@gmail.com`
    - Special characters / encoding:
        - `victim@gmail.com%00`
        - `%09`, `%20`
    - Trailing characters:
        - `test@test.com`
    - Multiple `@` parsing edge cases:
        - `victim@gmail.com@attacker.com`
        - `victim@attacker.com@gmail.com`
    - Unicode / normalization:
        - Homoglyphs
        - Soft hyphen (`\u00AD`)

---

- **Email / Username Enumeration**
    
    Attackers identify valid users by observing differences in responses.
    
    - “`User already exists`” vs generic error
    - Timing differences

---

- **Denial of Service via Large Input Fields**
    
    Submit excessively large payloads in Registration Form fields:
    
    - `username`
    - `password`
    - `email`
    
    If not handled, this can lead to server errors or resource exhaustion.
    

---

- **Missing Rate Limiting on Signup**
    
    Automated requests can be sent:
    
    - Mass account creation
    - Resource exhaustion

---

- **Stored XSS in Registration Fields**
    
    ```jsx
    <script>alert(1)</script>
    "><img src=x onerror=alert(1)>
    ```
    
    If input is not sanitized, malicious scripts are stored and executed later.
    

---

- **Weak Password Policies**
    
    Applications may allow:
    
    - `123456`
    - `password`
    
    Weak policies increase risk of brute-force and credential attacks.
    

---

## Bypassing Defenses

- **Email Verification Bypass**
    
    Modify verification logic:
    
    ```jsx
    { "verified": true }
    ```
    
    Or skip verification step entirely if endpoints are not properly protected.
    

---

- **Multi-Step Registration Flow Bypass**
    
    Directly access activation endpoint:
    
    ```jsx
    POST /activate-account
    ```
    
    Without completing previous steps
    

---

- **HTTP Parameter Pollution (HPP)**
    
    ```jsx
    {
      "email": "victim@example.com",
      "email": "attacker@example.com"
    }
    ```
    
    Confuses backend parsing and bypasses validation.
    

---

- **Mass Assignment / Hidden Parameter Injection**
    
    ```jsx
    {
      "email": "attacker@test.com",
      "role": "admin"
    }
    ```
    
    If backend binds all parameters blindly, attacker can escalate privileges.
    

---

- **Server-Side Validation Bypass**
    - Disable client-side controls
    - Modify API requests directly

---

## Advanced Attack Scenarios

1. **Weak or Predictable Verification Tokens**
    - Sequential tokens
    - Reusable tokens
    
    Attackers can guess or reuse tokens to activate accounts.
    

---

1. **OTP Brute Force During Signup**
    
    If OTP attempts are not limited:
    
    - Brute-force verification codes

---

1. **OAuth / SSO Account Takeover**
    
    Improper account linking may allow:
    
    - Register/login using victim’s email via OAuth

---

1. **Hidden / Legacy Registration Endpoints**
    
    ```jsx
    /api/register
    /v1/signup
    ```
    
    These endpoints may lack proper validation or security controls.
    

---

1. **Pre-Account Takeover (Signup & OAuth Linking Issues)**
Attackers may register accounts using a victim’s email before the legitimate user signs up. Improper OAuth account linking can later allow attackers to take control of the victim’s account.

---

1. **Race Conditions in Signup / Verification Flows**
Concurrent requests during signup or verification (OTP/token) may allow attackers to bypass validation, create multiple accounts, or activate accounts without proper verification.

---

1. **Verification Token Issues**
    - Token reuse
    - Cross-account token usage
    Weak or improperly validated tokens may allow attackers to verify or activate accounts they do not own.

---

1. **Business Logic Abuse**
    - Referral abuse (self-referral, multi-account abuse)
    - Free trial abuse (re-registering to gain benefits repeatedly)
    Improper validation of business rules may allow attackers to exploit signup incentives.

---

1. **Hidden / Extra Parameter Handling in API-Based Signup Flows**
Improper handling of additional or hidden parameters in API requests may allow attackers to manipulate account creation (e.g., assigning roles or bypassing restrictions).

---

## Detection Techniques

### Manual Detection Techniques

Test inputs:

- Existing emails
- Random/invalid emails
- Special characters

Example payloads:

`email=victim@example.com`

`email=attacker@test.com`

Indicators of Vulnerability:

- Duplicate accounts allowed
- Verification can be skipped
- Different responses for valid/invalid users
- Unexpected parameters accepted

---

### Automated Detection Techniques

**Burp Suite**

- Intruder: Automate signup requests
- Param Miner: Discover hidden parameters

---

## Impacts

- Account takeover
- Authentication bypass
- Privilege escalation
- Spam account creation
- Stored XSS exploitation
- Resource exhaustion

---

## **Quick Testing Checklist**

- **Rate Limiting**
    - Is rate limiting applied on signup and verification endpoints?
    - Can mass account creation or OTP brute-force be performed?
- **Verification Token Security**
    - Are verification tokens properly generated and validated?
    - Is expiration enforced?
    - Can tokens be reused or replayed?
- **Verification Flow**
    - Are tokens single-use and bound to the correct user?
    - Can tokens be reused or used across accounts?
    - Can verification be bypassed or skipped?
- **OAuth / SSO**
    - Is account linking secure?
    - Is the `state` parameter properly validated?
    - Can an account be created or linked without proper verification?
- **Race Conditions**
    - Can signup or verification flows be abused via concurrent requests?
    - Can multiple OTPs or tokens be validated simultaneously?
- **Business Logic Abuse**
    - Can signup benefits (referrals, free trials) be abused?
    - Can multiple accounts be created to exploit incentives?
    - Are hidden or extra parameters accepted in API-based signup flows?

---

## Tools

- Burp Suite (Repeater, Intruder)
- ffuf
- wfuzz

---

## Mitigation & Preventions

- Enforce uniqueness at database level
- Validate inputs on server side
- Implement strong password policies
- Enforce email/OTP verification strictly
- Apply rate limiting on signup and OTP
- Prevent mass assignment vulnerabilities
- Secure OAuth account linking

---

## Good to Read

[https://hackerone.com/reports/64946](https://hackerone.com/reports/64946)

[https://hackerone.com/reports/245538](https://hackerone.com/reports/245538)

[https://sm4rty.medium.com/hunting-for-bugs-in-sign-up-register-feature-2021-c47035481212](https://sm4rty.medium.com/hunting-for-bugs-in-sign-up-register-feature-2021-c47035481212)

---

## References

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process)

[https://blog.1nf1n1ty.team/hacktricks/pentesting-web/registration-vulnerabilities](https://blog.1nf1n1ty.team/hacktricks/pentesting-web/registration-vulnerabilities)

[https://osintteam.blog/register-signup-vulnerabilities-step-by-step-guide-for-bug-hunters-86239ee4cc95](https://osintteam.blog/register-signup-vulnerabilities-step-by-step-guide-for-bug-hunters-86239ee4cc95)

[https://n3t-hunt3r.gitbook.io/pentest-book/web-application-pentesting/registration-vulnerabilities](https://n3t-hunt3r.gitbook.io/pentest-book/web-application-pentesting/registration-vulnerabilities)

[https://hacktricks.wiki/en/pentesting-web/registration-vulnerabilities.html](https://hacktricks.wiki/en/pentesting-web/registration-vulnerabilities.html)