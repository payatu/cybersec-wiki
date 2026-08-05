---
title: Multi-Factor Authentication (MFA) Bypass
---

# Multi-Factor Authentication (MFA) Bypass

MFA Bypass occurs when an attacker circumvents the secondary authentication factor (OTP, TOTP, push approval, email/SMS verification) due to flaws in implementation, session handling, or API/UI inconsistencies. These issues allow attackers to complete authentication using only primary credentials or by abusing logic gaps in the verification flow.

---

## Fundamentals of MFA Flow

A secure MFA implementation follows a strict, server-controlled sequence:

1. User submits primary credentials (username/password)
2. Server validates credentials and marks session as **partially authenticated**
3. Server triggers second factor (OTP / push / TOTP)
4. User submits second factor
5. Server validates second factor and upgrades session to **fully authenticated**

### Key Security Principle

- MFA must act as a **hard gate**
- No sensitive action should be accessible until MFA is fully verified
- Session must explicitly track authentication stage

---

## MFA Types (Important for Testing)

### TOTP (Authenticator Apps)

- Time-based 6-digit codes (Google Authenticator, Authy)
- Risk: brute force, replay, clock skew abuse

### SMS / Email OTP

- OTP delivered via SMS/email
- Risk: SIM swap, email compromise, interception

### Push-Based MFA

- “Approve/Deny” notification (Duo, Microsoft Authenticator)
- Risk: MFA fatigue attacks, lack of context prompts

### Backup Codes

- Static recovery codes
- Risk: leakage, reuse, insecure storage

### Device-Based MFA (“Remember this device”)

- Trusted device cookies / fingerprinting
- Risk: cookie theft, device spoofing, reuse across sessions

---

## MFA Attack Surface

- **Login Flow Redirection:** Forcing the browser to skip the `/mfa-verify` page and go straight to `/dashboard`.
- **API Endpoints:** Direct interaction with REST/GraphQL endpoints that might not enforce MFA as strictly as the Web UI.
- **Account Recovery:** "I lost my phone" flows that revert to weaker security (e.g., security questions).
- **Remember Me Features:** Exploiting long-lived "Trusted Device" cookies to impersonate a verified machine.
- **OAuth/SSO:** Bypassing MFA by logging in via a third-party provider (Google/GitHub) that isn't configured to require MFA for your app.
- **Mobile App Deep Links:** MFA callback URIs handled by mobile apps that don't validate the calling context.
- **Password Reset Flow:** Resetting a password sometimes re-issues a session without re-triggering MFA.
- **Multiple Enrolled Factors:** Endpoints for managing/adding a second device or factor, which may not require re-verification of the *existing* factor.

---

## Common MFA Bypass Classes

### 1. Broken Authentication Flow (Step Skipping)

- Application allows direct access to authenticated pages after password step only
- MFA step is cosmetic or frontend-only

---

### 2. Missing Session State Upgrade

- Session is not marked as “MFA verified”
- Password authentication grants full access prematurely

```
POST /login
→ session=authenticated
(no MFA requirement enforced)
```

### 3. API vs UI Enforcement Mismatch

- UI enforces MFA
- API endpoints allow direct access

```
GET /api/user/profile
Cookie: session=login_only
```

---

### 4. MFA Not Bound to Session/User

- OTP validated but not linked to correct session
- OTP reuse across sessions possible

---

### 5. Missing MFA on Sensitive Actions (Step-Up Failure)

- MFA enforced only at login
- Sensitive actions not protected

Examples:

- password change
- email update
- fund transfer

---

### 6. OAuth / SSO MFA Bypass

- Identity provider login bypasses MFA requirement
- No step-up authentication after OAuth callback

```
/oauth/callback?code=xyz
→ session issued without MFA verification
```

---

### 7. Push Notification Fatigue Attack

- Repeated push prompts overwhelm user
- User approves due to annoyance or confusion

---

### 8. Trusted Device Abuse

- “Remember this device” cookie reused
- Device trust not invalidated after logout/password change

---

## Exploitation Techniques

### 1. OTP Brute Force

- No rate limiting on `/verify-otp`
- 0000–9999 tested via Intruder

**Indicator:**

- Valid OTP returns `200 OK` or session upgrade

---

### 2. Response Manipulation

- Client trusts server response instead of enforcing logic

```
HTTP/1.1 401 Unauthorized
{"success": false}
```

→ Modified to:

```
HTTP/1.1 200 OK
{"success": true}
```

---

### 3. Empty or Null OTP Handling

- Backend incorrectly accepts missing parameters

```
{"otp":""}
{"otp":null}
```

---

### 4. OTP Reuse / Race Condition

- OTP not invalidated after use

```
engine.queue(target.req,"123456")# reused OTP in parallel requests
```

---

### 5. Direct Navigation / Step Skipping

- Access restricted page after password login only

```
/login → /dashboard (no MFA completed)
```

---

### 6. Parameter Tampering

```
POST /verify-mfa
mfa_enabled=false
```

→ MFA bypass due to logic trust in client input

---

## Advance Attack Scenarios

- **MFA Fatigue / Push Bombing:** Repeatedly trigger push notifications (via automated login attempts) at odd hours until the victim taps "Approve" just to stop the noise. Notably used in real-world breaches (e.g., Uber 2022).
- **Adversary-in-the-Middle (AiTM) Phishing:** Deploy a reverse-proxy phishing page that relays the victim's credentials and OTP to the real site in real time, capturing the resulting authenticated session cookie — bypassing MFA regardless of its strength.
- **Backup Code Enumeration:** If backup/recovery codes are short, sequential, or reused across resets, brute-force or predict them.
- **Concurrent Session Racing:** Initiate MFA on two devices/sessions simultaneously where the validation check-then-invalidate isn't atomic, allowing both to succeed.
- **JWT/Token Claim Tampering:** If MFA status is stored in a client-modifiable JWT (e.g., `"amr": ["otp"]` or `"mfa": true`) and the signature isn't properly verified (`alg: none`, weak secret, key confusion), forge a "post-MFA" token directly.
- **Downgrade via Multi-Method Support:** If a user has both WebAuthn and SMS enrolled, force the flow to offer/accept the weaker SMS/email OTP path instead of the strong factor.
- **CSRF on MFA Disable/Enrollment:** Trick an already-authenticated victim into a request that disables their MFA or registers the attacker's device as a trusted second factor.
- **Cross-Device/Cross-Session Token Leakage:** OTP or session validation tokens leaked via Referer headers, logs, or third-party analytics scripts embedded on the MFA page.

---

## Framework-Specific Scenarios

- **Auth0 / Okta:** Misconfigured "Adaptive MFA" rules that skip MFA based on spoofable signals (IP reputation, device fingerprint headers that can be forged client-side).
- **AWS Cognito:** Custom Lambda triggers (`Define Auth Challenge`, `Verify Auth Challenge Response`) with flawed logic that can return a success response regardless of the actual challenge answer.
- **Firebase Authentication:** Multi-factor session info (`mfaPendingCredential`) leakage or reuse if not properly scoped/expired.
- **Keycloak:** Misconfigured authentication flow "requirements" (e.g., OTP set to `ALTERNATIVE` instead of `REQUIRED`), allowing the flow to succeed without the second factor.
- **Django (django-otp / django-two-factor-auth):** Session variable (`otp_device_id`) manipulation if not tied server-side to a verified state; testing for the same via cookie/session tampering.
- **Spring Security (spring-security-mfa extensions):** Custom `AuthenticationProvider` chains where a partial-authentication token is mistakenly granted full `GrantedAuthority` before the second factor step completes.

---

## Test Cases

| Scenario | Action | Expected Behavior |
| --- | --- | --- |
| Direct access | Open `/dashboard` after login | Should require MFA |
| API bypass | Call API before OTP | Should deny access |
| Empty OTP | Submit blank OTP | Should reject request |
| Replay OTP | Reuse old OTP | Should fail |
| Parameter tampering | mfa=false | Should not bypass |
| Session reuse | Same session before/after MFA | Should be invalid |

---

## Detection Techniques

### Manual Testing

- Compare session before and after MFA
- Check if session upgrades after OTP
- Attempt API access before MFA completion
- Test OTP brute force without lockout
- Validate logout invalidates MFA state
- Check trusted device bypass behavior

---

### MFA State Validation Check

```
Before MFA → auth_state = password_only
After MFA  → auth_state = fully_authenticated
```

If unchanged → MFA is not enforced server-side

---

### API Enumeration

```
GET /api/user
GET /api/admin
```

If accessible before MFA → broken enforcement

---

## Impact

- Full account takeover even when MFA is implemented, if it can be bypassed through logic flaws or API/UI inconsistencies
- Unauthorized access to sensitive user data, including personal information, financial records, and internal application data
- Ability to perform privileged actions such as changing passwords, updating email addresses, or modifying account settings without proper verification
- Financial fraud through unauthorized transactions or bypassing additional verification layers on payment flows
- Violation of regulatory and compliance requirements such as PCI-DSS, HIPAA, GDPR due to ineffective authentication controls
- Large-scale compromise in cases where MFA bypass affects APIs, SSO flows, or shared authentication infrastructure
- Persistent unauthorized access when sessions remain valid through trusted device abuse or improper session invalidation
- Breakdown of security assumptions, where MFA gives a false sense of protection while the underlying system remains exploitable

---

## Prevention & Mitigation

- Enforce MFA strictly on the server side as a mandatory authentication checkpoint before granting full session access
- Maintain clear authentication states such as `PASSWORD_VERIFIED` and `MFA_VERIFIED` to prevent premature access escalation
- Regenerate session identifiers immediately after successful MFA validation to prevent session fixation issues
- Bind MFA validation tightly to the specific session, user account, and device context to avoid reuse or cross-session abuse
- Apply strict rate limiting and lockout mechanisms on OTP verification endpoints to prevent brute force attempts
- Ensure OTPs are invalidated immediately after a single use (one-time consumption enforcement)
- Require step-up authentication for sensitive operations like password change, fund transfer, or account recovery
- Prevent any MFA bypass through direct API calls by enforcing consistent backend validation across UI and API layers
- Enforce proper MFA validation claims in OAuth and SSO flows before issuing authenticated sessions
- Include contextual information (device, location, IP, login history) in push-based MFA prompts to reduce approval-based abuse

---

## Good To Read

- [OWASP MFA Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-4/)
- [Two factor Authentication Enforcement Bypass](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwivw_Xrr4uTAxV3SGwGHfAYC0kQFnoECBgQAQ&url=https%3A%2F%2Fhackerone.com%2Freports%2F1050244&usg=AOvVaw0ssgr43sabDpPKgDSnuhBI&opi=89978449)
- ["email" MFA mode allows bypassing MFA from victim's device when the device trust is not expired](https://hackerone.com/reports/665722)
- [Two-factor authentication bypass lead to information disclosure](https://hackerone.com/reports/2486086)

---

## References

- [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)
- [https://cheatsheetseries.owasp.org/cheatsheets/](https://cheatsheetseries.owasp.org/cheatsheets/)
- [https://portswigger.net/web-security/authentication/multi-factor](https://portswigger.net/web-security/authentication/multi-factor)
- [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)

[Updated MFA Bypass Cheatsheet](https://app.notion.com/p/Updated-MFA-Bypass-Cheatsheet-39547a46cb0380239175cc137751747f?pvs=21)