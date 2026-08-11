---
title: Third party service integration issues
---

# Third party service integration issues

---

## **Description**

Third-party service integration issues arise when web applications incorporate external services (e.g., payment gateways, analytics/CDNs, social login providers, APIs, scripts, or libraries). These integrations expand the attack surface by introducing untrusted code, data flows, and trust boundaries. Without proper controls, they enable supply chain attacks, data leakage, injection flaws, and authentication bypasses - often because developers treat third-party components as inherently safe.

Almost every app depends on outside services: a CDN for JS libraries, a "Login with Google" button, a payment gateway, a Slack/Stripe webhook, an npm package. Each of these is a door into the app that the app's own team doesn't fully control.

**The core problem**: developers trust these doors more than they should. They validate what a user types very carefully, but they often skip validation on data or code that comes back from a third party, on the assumption that partners and vendors are automatically safe. They aren't. If a vendor's CDN gets hacked, or a partner API can be manipulated, or an OAuth login flow has a loose check somewhere - that trust gap becomes your entry point.

**Maps to**: OWASP API10:2023 (Unsafe Consumption of APIs), A08:2021 (Software & Data Integrity Failures) overlap, CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

---

## Understanding Third-Party Integrations

### Trust Boundaries

Every third-party integration introduces a new trust boundary. Even if the external service itself is legitimate, the application must treat every response, callback, script, or authentication token as untrusted until it is validated.

Typical trust relationships include:

- Browser ↔ Third-party JavaScript
- Application ↔ External APIs
- Identity Provider ↔ OAuth/OIDC Client
- Payment Gateway ↔ Webhook Endpoint
- CI/CD ↔ Dependency Registries (npm, PyPI, Maven)

A compromise at any point can directly affect the application.

---

### Common Third-Party Components

- CDN-hosted JavaScript
- Analytics platforms
- Payment gateways
- OAuth/OIDC providers
- SAML Identity Providers
- Maps & Geolocation APIs
- SMS / Email providers
- Webhooks
- Chat widgets
- Advertisement scripts
- Feature flag providers
- Package managers (npm, pip, Maven)

---

## Attack Surface

- Client-side script/tag inclusion: `<script src="cdn.vendor.com/...">`, tag managers (GTM), iframes, dynamic imports
- OAuth/OIDC/SAML login flows and redirect handlers
- Server-side calls to external APIs (address validation, payment, geocoding, enrichment services)
- Webhook receivers (Stripe, GitHub, Slack, Twilio callbacks)
- npm/pip/Maven dependencies and their transitive chain
- Source maps and bundled JS shipping secrets
- Third-party plugin ecosystems (WordPress, Shopify apps, browser extensions)

### Common Third-Party Integration Weaknesses

- Missing validation of third-party responses
- Trusting webhook payloads without signature verification
- Wildcard OAuth redirect URIs
- Missing OAuth state validation
- Third-party JavaScript without SRI
- Exposed API keys in frontend bundles
- Loading outdated third-party libraries
- Package dependency confusion
- Dependency hijacking
- Expired CDN or vendor domains
- Blind trust of partner APIs
- Over-privileged API keys
- Missing certificate validation
- Weak TLS configuration when calling external APIs

## Exploitation Techniques

### **1. Unsafe Consumption of Third-Party APIs (OWASP API10:2023)**

**Why this happens:** the app's developers wrote strict validation for anything the *user* types directly into a form. But data that arrives *indirectly* - through an address-lookup service, a partner API, a webhook - often skips that same validation, because the developer assumes "this came from our trusted partner, not a random user." If you, the attacker, can control what that partner service returns (e.g. you submit your own address to an autocomplete field, or you control a webhook payload), you've smuggled attacker input in through a channel nobody is filtering.

**Where to look:** any field sourced from a third-party integration that gets rendered, queried, or used in a redirect without re-validation - KYC/identity verification responses, marketplace product feeds, partner-submitted webhook data.

### **2. Third-Party JavaScript / Script Inclusion Issues**

**Why this happens**: when a browser loads <script src="[https://cdn.vendor.com/lib.js](https://cdn.vendor.com/lib.js)">, that script runs with the same trust and permissions as the target site itself. If anyone other than the target can control what that script contains, they effectively have stored XSS on the target - without ever touching the target's own servers.

**Why this is dangerous**: the browser has no way of knowing the script came from a different company. It executes it as if the target site wrote it. So the security of the whole page becomes dependent on the security of a CDN or vendor the target doesn't control.

> **Find every script that isn't hosted on the target's own domain**
> 

Anything pointing outside `target.com` is worth checking further.

```jsx
curl -s https://target.com/ | grep -oP '<script[^>]+src="[^"]+"'
```

> **Check whether each script has Sub Resource Integrity (SRI)**
> 

SRI is a hash the browser checks before running the script - if the CDN's content doesn't match the hash, the browser refuses to run it. No SRI means no such safety net.

```jsx
curl -s https://target.com/ | grep -E '<script[^>]+src=' | grep -v 'integrity='
```

> **Check if the domain behind the script is still owned by anyone legitimate.**
> 

If a domain referenced in a `<script src>` has expired or is about to, anyone  can register it and serve their own JavaScript from it - which the target site will then load and run automatically. This is exactly what happened with Polyfill.io in 2024, affecting 380,000+ sites.

```jsx
whois cdn-vendor-domain.com
```

### **3. OAuth 2.0 / Federated Authentication Misconfigurations**

This is the highest-impact category here. The entire security of this flow depends on one guarantee: **the authorization code can only ever be delivered back to a URL the target site actually owns and controls.** Everything below is about breaking that guarantee. The goal here is simple: get the identity provider to send the authorization code to a URL *you* control instead of the real app. If you succeed, you get a valid login code for the victim's account.

```jsx
# This is what a normal, legitimate request looks like:
https://target.com/oauth/authorize?client_id=X&redirect_uri=https://target.com/callback&response_type=code

# Different variations to try here to get the authrorization code
redirect_uri=https://target.com.attacker.com/callback
redirect_uri=https://attacker.com/target.com/callback
redirect_uri=https://target.com@attacker.com/callback
redirect_uri=https://target.com/callback/../../evil.com
redirect_uri=https://target.com/%2e%2e/evil.com
redirect_uri=https://target.com/callback%2f..%2f..%2fevil.com
redirect_uri=https://target.com/legit-open-redirect?url=https://attacker.com
redirect_uri=https://attacker.target.com/callback
```

**Putting it together - how to actually test this in Burp, step by step:**

1. Log in through the normal OAuth flow once with Burp's proxy running, so you capture the real `/authorize` and `/callback` requests. Send both to Repeater.
2. In Repeater, take the `/authorize` request and swap in each `redirect_uri` payload from above, one at a time. Resend.
3. Look at the response. It should be a redirect (3xx status code). Check the `Location` header it returns - did the identity provider actually agree to send the code to your modified URI, or did it reject the request?

### **4. Exposed Secrets & Misconfigured Integration Endpoints**

**Why this happens:** anything shipped to the browser as JavaScript can be read by anyone - there's no such thing as a "hidden" secret in client-side code. Developers sometimes forget this and hardcode an API key meant for a third-party service (payment processor, cloud storage, email provider) directly into the frontend bundle, assuming minification makes it unreadable. It doesn't - it just makes it harder to read, not impossible.

> **Search for the keys inside the JS file**
> 

```jsx
grep -EoP '(AKIA[0-9A-Z]{16})' bundle.js                        # AWS access key
grep -EoP '(sk_live_[0-9a-zA-Z]{24,})' bundle.js                # Stripe secret key
grep -EoP '(AIza[0-9A-Za-z\-_]{35})' bundle.js                  # Google API key
grep -EoP '(xox[baprs]-[0-9a-zA-Z-]{10,})' bundle.js            # Slack token
grep -EoP '(ghp_[0-9a-zA-Z]{36})' bundle.js                     # GitHub PAT
```

> **Automate the search instead of relying only on manual grep patterns using Trufflehog tool**
> 

```jsx
trufflehog url https://target.com --json | jq 'select(.Verified==true)'
trufflehog github --repo=https://github.com/target-org/target-repo
```

### 5. Webhook Validation Failures

**What a webhook is:** instead of your app constantly asking Stripe "did the payment go through yet?", Stripe just sends your app a POST request the moment it happens - "hey, this payment succeeded." Your app's webhook endpoint receives that and updates its own database accordingly (marks the order as paid, upgrades the user's plan, etc.).

**The problem:** that endpoint is just a normal URL. If the app doesn't verify that the request genuinely came from Stripe (and not from anyone else who knows the URL), then anyone can POST a fake "payment succeeded" message directly, without ever paying.

> **Test whether a signature is required at all**
> 

If this returns a 200 OK and no signature header was required, the endpoint is forgeable - you can fake "payment succeeded," "subscription upgraded," or any other event the app trusts blindly.

```jsx
curl -X POST https://target.com/webhooks/stripe \
  -H "Content-Type: application/json" \
  -d '{"type":"charge.succeeded","data":{"object":{"amount":0,"metadata":{"user_id":"victim_id"}}}}'
```

> **Test signature replay**
> 

Even with a valid signature, if the app doesn't also check a timestamp or a one-time nonce, a signature that was valid once stays valid forever. Capture a real, legitimately-signed webhook payload (from your own test transaction) and resend it later. If the app re-processes it - for example, applying the same "subscription upgraded" event a second time - that's a replay vulnerability.

```jsx
curl -X POST https://target.com/webhooks/stripe \
  -H "Stripe-Signature: t=OLD_TIMESTAMP,v1=CAPTURED_SIG" \
  -d @captured_payload.json
```

## **Impact**

**Account takeover** - OAuth redirect_uri/state flaws are the most direct path to full ATO in this category

**Payment/session skimming at scale** - compromised CDN JS = Magecart-style card/session theft across every page load (Polyfill.io: 380,000+ sites)

**Forged business events** - unsigned webhooks let attackers fake "payment succeeded," "subscription upgraded," "KYC verified" without paying/completing the real flow

**Secrets → infrastructure compromise** - a single leaked key in a JS bundle can cascade into cloud account compromise if the key has broader IAM permissions than intended

**Regulatory exposure** - PCI-DSS (payment data via compromised third-party script), GDPR (PII sent to/leaked via third-party integration)

## **Prevention Techniques**

- **SRI on every external script/style:** `integrity="sha384-<hash>"` + `crossorigin="anonymous"`
- **Strict CSP:** explicit `script-src` allowlist, no wildcards, `object-src 'none'`, `frame-ancestors 'none'`
- **OAuth: enforce `state` + PKCE on every flow**, exact-match `redirect_uri` validation (no wildcard subdomains, no path-prefix matching)
- **Webhook signatures verified with constant-time comparison**, timestamp/nonce to block replay, IP allowlisting where the provider publishes static ranges
- **No secrets in client bundles:**  proxy third-party API calls server-side; rotate any key found exposed
- **Pin dependency and CDN versions:** no `@latest`, no floating CDN paths
- **Monitor domain/subdomain expiry** for anything referenced in production DNS or script tags
- **Treat third-party API responses as untrusted input:** same validation/encoding rules as user input, applied at time of consumption, not just at time of ingestion

## **Tools**

- **Burp Suite:** Intercept & modify requests
- **Retire.js:** Detect vulnerable JS libs
- **TruffleHog / Gitleaks**: Secret scanning in JS bundles, source maps, and repos
- **wpscan**: WordPress plugin/theme vulnerability + enumeration
- **jwt_toolIf:** If OAuth issues JWTs - alg confusion, signature stripping tests

## **Good to Read:**

- [https://www.intigriti.com/blog/business-insights/how-to-scope-third-party-assets](https://www.intigriti.com/blog/business-insights/how-to-scope-third-party-assets)
- https://medium.com/@omarahmed_13016/leaking-pii-at-scale-how-third-parties-can-unintentionally-put-your-data-at-risk-6101fcb3d5e0
- [https://mokhansec.medium.com/the-p2-bug-you-could-miss-without-reading-the-documentation-b0eacc3b7587](https://mokhansec.medium.com/the-p2-bug-you-could-miss-without-reading-the-documentation-b0eacc3b7587)
- [https://medium.com/@ahmedelmorsy312/weakness-of-integration-bce1520ba672](https://medium.com/@ahmedelmorsy312/weakness-of-integration-bce1520ba672)

## **References**

- OWASP Third Party JavaScript Management Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
- OWASP API Security Top 10 (2023) – Unsafe Consumption of APIs: [https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- PortSwigger – OAuth 2.0 authentication vulnerabilities: [https://portswigger.net/web-security/oauth](https://portswigger.net/web-security/oauth)