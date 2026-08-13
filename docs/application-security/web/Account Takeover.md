---
title: Account Takeover
---

# Account Takeover (ATO)

## Introduction

Account Takeover (ATO) vulnerabilities occur when an attacker gains unauthorized access to a user account by exploiting weaknesses in authentication, session management, password recovery, or identity federation mechanisms.

ATO is typically not a single vulnerability but a **chain of authentication and logic flaws** that result in full account compromise.

---

# Fundamentals of Account Takeover

## Core Concept

Account takeover occurs when the **authentication or identity verification process is bypassed, broken, or abused**, allowing an attacker to impersonate a legitimate user.

---

## Authentication Lifecycle

```
Registration → Authentication → Session Creation → Session Usage → Session Termination
```

ATO occurs when any stage is:

- Weakly implemented
- Inconsistently enforced
- Not invalidated properly

---

## Authentication Models

### 1. Password-Based Authentication

- Username + password
- Most commonly attacked via credential reuse or brute force

### 2. Session-Based Authentication

- Cookie/session ID maintained server-side
- Vulnerable to hijacking and fixation

### 3. Token-Based Authentication (JWT/API)

- Stateless authentication using signed tokens
- Vulnerable to weak signing, replay, or missing validation

### 4. Federated Authentication (OAuth / SSO)

- Delegated identity (Google, GitHub, Microsoft)
- Vulnerable to misconfigured redirects and account linking issues

### 5. Password Recovery Systems

- Email / SMS / OTP based reset flows
- Most critical ATO vector in real-world attacks

---

## Trust Boundaries in ATO

Authentication systems assume:

- Credentials prove identity
- Tokens are unforgeable
- Sessions belong to one user
- OAuth providers are fully trusted
- Reset flows are one-time and secure

Breaking these assumptions leads to ATO.

---

## Attack Surface

- Login endpoints
- Registration flows
- Password reset / forgot password
- Session cookies / JWT tokens
- OAuth / SSO callback endpoints
- API authentication endpoints
- MFA / OTP verification flows
- Account linking / social login
- Mobile authentication APIs

---

# Types of Account Takeover Attacks

## 1. Credential-Based Attacks

- Credential Stuffing: Reuse of leaked username/password pairs from breaches
- Password Spraying: Common passwords used across many accounts to avoid lockouts
- Brute Force (Low and High Entropy): Systematic password guessing attacks

---

## 2. Session-Based Attacks

- Session Hijacking: Stealing session cookies via XSS, MITM, or malware
- Session Fixation: Forcing victim to use attacker-controlled session ID
- Session Replay: Reusing valid session tokens due to lack of invalidation
- Session Prediction: Guessing weak or predictable session identifiers

---

## 3. Password Reset Attacks

- Predictable reset tokens
- Token reuse
- Missing expiration
- Broken identity verification
- Reset link manipulation
- Host header / email injection abuse

---

## 4. OAuth / SSO Attacks

- Improper account linking
- Missing state parameter validation
- Open redirect in callback URL
- Token leakage via redirect URI
- Identity confusion (same email different provider)

---

## 5. JWT / API Authentication Attacks

- Weak or missing signature verification
- Algorithm confusion (none/HS/RS attacks)
- Token replay
- Missing expiration (`exp`)
- JWT tampering
- Refresh token abuse

---

## 6. MFA Bypass Attacks

- MFA not enforced on all endpoints
- MFA bypass via password reset
- Backup code abuse
- Step-skipping logic flaws
- SMS/OTP interception

---

## 7. Registration / Account Linking Issues

- Duplicate account creation using same email
- OAuth account takeover via pre-registration
- Email verification bypass
- Account takeover via social login mismatch

---

## Exploitation Techniques

### Credential Stuffing

```
POST /login
{
  "username": "victim",
  "password": "password123"
}
```

- Use breached credential lists
- Rotate IPs to avoid blocking

---

### Password Spraying

```
Password: Password1
Target: multiple users
```

- Avoid lockout triggers
- Test common passwords across many accounts

---

### Session Hijacking

```
document.cookie
```

- Steal session via XSS / MITM
- Replay session token in browser or API client

---

### Session Fixation

```
Set-Cookie: session=attacker_session
```

- Victim logs in using attacker-controlled session ID

---

### Password Reset Abuse

```
https://target.com/reset?token=12345
```

Test for:

- Predictable tokens
- Token reuse
- Missing expiration
- Email injection in reset flow

---

### OAuth Misconfiguration

- Missing state validation
- Account linking bypass
- Redirect URI manipulation

---

### Token Replay / JWT Abuse

- Reuse of valid tokens
- Missing expiration validation
- Tampered payload without signature verification

---

## Bypassing Defenses

### Rate Limiting Issues

- No throttling on login/reset endpoints

### MFA Flaws

- MFA only applied after login
- MFA bypass via alternate flows

### Token Reuse

- Reset/session tokens remain valid after use

---

# Advanced Attack Scenarios

## Chained Account Takeover

Example chain:

- Weak password policy
- No rate limiting
- Weak reset tokens

→ Full account compromise

---

## OAuth Account Takeover

- Victim logs in using OAuth
- Attacker links OAuth identity first
- Victim account gets overridden

---

## Session Fixation + Login Flow Abuse

- Attacker sets session ID
- Victim logs in
- Session becomes authenticated attacker session

---

## Pre-Account Takeover (Registration Abuse)

- Email not verified
- Duplicate account creation allowed
- OAuth mismatch exploited

---

## Race Condition Attacks

- OTP reuse via parallel requests
- Password reset token race exploitation

---

## MFA Bypass Edge Cases

- MFA not required for API endpoints
- MFA skipped in reset flows
- Backup codes reused

---

# Detection Techniques

## Manual Testing

- Test weak credentials
- Analyze login response behavior
- Test password reset flow
- Validate session lifecycle
- Check token reuse
- Observe MFA enforcement consistency

---

## Automated Testing

### Burp Suite

- Intruder → credential stuffing
- Sequencer → token randomness analysis
- Repeater → manual flow testing

---

# Impact

- Full account takeover
- Data theft and leakage
- Financial fraud
- Privilege escalation
- API abuse
- Persistent unauthorized access
- Regulatory violations (GDPR, PCI-DSS)

---

# Quick Testing Checklist

## Rate Limiting

- Can login/reset be brute-forced?
- Is credential stuffing possible?

## MFA

- Is MFA enforced consistently?
- Can MFA be bypassed via alternate flows?

## Session Security

- Is session rotated after login?
- Are cookies secure (HttpOnly, Secure, SameSite)?
- Is logout invalidating sessions?

## Password Reset

- Are tokens random and single-use?
- Do reset links expire?

## OAuth / SSO

- Is state parameter validated?
- Is account linking secure?
- Is email verification enforced?

## JWT / API Auth

- Are tokens properly signed?
- Is expiration enforced?
- Can tokens be replayed?

## Race Conditions

- Can OTP/reset be reused concurrently?

---

# Tools

- Burp Suite (Repeater, Intruder, Sequencer)
- ffuf
- wfuzz
- Nuclei
- jwt_tool
- curl / Postman
- Hydra (credential testing)

---

# Mitigation & Prevention

- Strong password policies
- Rate limiting and IP throttling
- MFA enforcement across all endpoints
- Secure session management (rotation + invalidation)
- Strong reset token generation (single-use, expiring)
- Proper OAuth state validation
- JWT signature validation + expiration enforcement
- Account linking verification (email binding control)
- Monitoring for anomalous login attempts

---

# Good To Read (Real-World Reports)

- [https://hackerone.com/reports/2293343](https://hackerone.com/reports/2293343)
- [https://hackerone.com/reports/317476](https://hackerone.com/reports/317476)
- [https://hackerone.com/reports/745324](https://hackerone.com/reports/745324)
- [https://hackerone.com/reports/314808](https://hackerone.com/reports/314808)
- [https://hackerone.com/reports/534450](https://hackerone.com/reports/534450)

---

# References

- [https://owasp.org/www-community/attacks/Session_Prediction](https://owasp.org/www-community/attacks/Session_Prediction)
- [https://owasp.org/www-community/Authentication_Cheat_Sheet](https://owasp.org/www-community/Authentication_Cheat_Sheet)
- [https://www.vaadata.com/blog/account-takeover-techniques-and-security-best-practices/](https://www.vaadata.com/blog/account-takeover-techniques-and-security-best-practices/)
- [https://www.bluevoyant.com/knowledge-center/account-takeover-5-types-of-attacks-4-protective-measures](https://www.bluevoyant.com/knowledge-center/account-takeover-5-types-of-attacks-4-protective-measures)
- [https://medium.com/@bughunt789/the-hidden-flaw-exploiting-password-resets-for-account-takeover-39508956982b](https://medium.com/@bughunt789/the-hidden-flaw-exploiting-password-resets-for-account-takeover-39508956982b)
- [https://medium.com/@security.tecno/hacking-your-first-oauth-on-the-web-application-account-takeover-using-redirect-and-state-5e857c7b1d43](https://medium.com/@security.tecno/hacking-your-first-oauth-on-the-web-application-account-takeover-using-redirect-and-state-5e857c7b1d43)
- [https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPACCOUNTTAKEOVER.md](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPACCOUNTTAKEOVER.md)