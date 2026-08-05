---
title: Subdomain Takeover
---

# Subdomain Takeover

Subdomain Takeover is a web application security vulnerability that occurs when a subdomain points to a third-party service (e.g., GitHub Pages, Heroku, AWS S3) that has been removed or deleted. An attacker can claim the abandoned resource on that service and effectively "take over" the subdomain, leading to phishing, session hijacking, OAuth token theft, and reputational damage.

## Fundamentals of Subdomain Takeover

### Types of Takeovers :

**1. CNAME-Based Subdomain Takeover**

- Subdomain has a CNAME record pointing to a third-party service (e.g., `sub.victim.com` → `custom.gohire.io`)
- The third-party resource (bucket, page, app) was deleted
- Attacker registers the same resource name on that service → owns the subdomain

**2. A / AAAA Record Takeover**

- Less common; involves orphaned IPs or load balancers
- Applicable when records point to decommissioned infrastructure

**3. NS (Nameserver) Record Takeover**

- If one NS record of a domain points to a decommissioned nameserver
- Attacker gains control over that NS server → can redirect a portion of traffic
- Higher risk if attacker sets high TTL, prolonging the attack

**4. MX Record Takeover**

- MX records point to an unclaimed or deleted mail service
- Attacker can receive or send emails from the legitimate subdomain
- Enhances phishing efficacy (emails appear to come from victim domain)

**5. Domain Takeover (Not Subdomain)**

- Entire domain (`domain.tld`) has been abandoned and is up for re-registration
- Attacker registers the domain if cheap enough
- Risk increases if the domain receives sensitive data via GET params or Referer header

**6. Wildcard DNS Exploitation**

- Wildcard CNAME (e.g., `.example.com` → `something.github.io`) routes all unknown subdomains
- Attacker creates a GitHub Page matching the wildcard target
- Can generate arbitrary subdomains for the victim domain

### Base Concepts

- **Dangling DNS Record:** A DNS record (CNAME, A, etc.) that points to a resource that no longer exists or has been released
- **Claiming:** Registering the same resource name on the third-party service to "claim" the subdomain
- **Ownership Verification:** Secure services (e.g., Okta) require DNS TXT record verification before allowing custom domains—these are typically not vulnerable

## Important Points

- Subdomain takeover happens because DNS records get messy—forgotten CNAMEs, decommissioned services, or outdated entries
- Microsoft found **670+ vulnerable subdomains** in a single audit
- Around **21%** of DNS records lead to unresolved content; **63%** of those return 404
- Attackers exploit the fact that many services allow adding a custom domain *without* verifying ownership via DNS
- Vulnerable services (GitHub Pages, Heroku, S3, Netlify, etc.) only require a CNAME pointing to them—no TXT verification
- Secure services (Okta, Statuspage) use domain ownership challenges (e.g., random TXT record) before allowing custom domains

## Attack Surfaces

- **Subdomains pointing to:**
    - GitHub Pages, Bitbucket, GitLab Pages
    - AWS S3, Elastic Beanstalk, CloudFront
    - Heroku, Netlify, Vercel
    - Shopify, Zendesk, Intercom
    - [ReadMe.io](http://readme.io/), Help Scout, Help Juice
    - Ngrok, [Surge.sh](http://surge.sh/), Fastly
    - Microsoft Azure ([cloudapp.net](http://cloudapp.net/), [azurewebsites.net](http://azurewebsites.net/), [blob.core.windows.net](http://blob.core.windows.net/))
    - GoHire, ReadMe, Ghost, Pantheon, etc.
- **Forgot Password / Email verification** flows that use subdomain links
- **OAuth redirect URIs** that whitelist `.example.com`
- **CSP `script-src`** or other directives allowing subdomains
- **CORS** policies trusting subdomains
- **Cookie scoping** (e.g., `domain=.example.com`) making cookies accessible to any subdomain

## Exploitation and Bypassing Defenses

### Step 1: Enumerate Subdomains

**Passive Enumeration** (no direct interaction with target):

- Certificate Transparency logs, search engines, VirusTotal
- Tools: **Amass**, **Sublist3r**, **Subfinder**, **Chaos (ProjectDiscovery)**

**Active Enumeration** (direct DNS probing):

- Brute-force subdomains using wordlists
- Tools: **MassDNS**, **puredns**, **dnsgen**

```bash
# Sublist3r
python sublist3r.py -d example.com -o subdomains.txt

# Amass (passive + active)
amass enum -passive -d example.com -o subdomains.txt
```

### Step 2: Identify Dangling CNAMEs

- For each subdomain, resolve CNAME and check if target host exists
- If CNAME points to a third-party (e.g., `s3.amazonaws.com`, `github.io`) and that resource returns 404 / "not found" → potential takeover

### Step 3: Fingerprint and Claim

- Match HTTP response against known error signatures (see [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz))
- Register the resource on the third-party service (S3 bucket, GitHub Page, Heroku app) with the same name as the CNAME target
- Serve PoC content on a hidden path (e.g., `/random-string.html` with HTML comment)

### Bypassing Ownership Verification

- Some services have weak or no verification—adding a CNAME is enough
- For services with TXT verification, subdomain takeover is **not** possible unless there is a bypass
- Check [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) for per-service status (Vulnerable / Edge case / Not vulnerable)

### Wildcard CNAME Bypass

- If `.example.com` CNAME points to `something.github.io`
- Create a GitHub Page for `something` → all non-existent subdomains resolve to attacker content
- Example: [NITECTF 2022 CTF write-up](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api)

## Advanced Attack Scenarios

### 1. Cookie Theft and Session Hijacking

- If cookies are scoped to `domain=.example.com`, any subdomain can read them (unless HttpOnly)
- From `evil.example.com` (taken over), attacker loads `https://example.com` in iframe or sends requests → browser sends cookies
- Steal session cookies and replay for account takeover

### 2. CORS Bypass

- Main app may allow `Access-Control-Allow-Origin: https://*.example.com`
- After takeover, attacker’s page at `taken-over.example.com` sends requests to main domain
- Response includes sensitive data (e.g., API responses, user info) → exfiltration

```
GET /api/user HTTP/1.1
Host: example.com
Origin: <https://vulnerable.example.com>
```

If server responds with `Access-Control-Allow-Origin: <https://vulnerable.example.com`> and attacker controls that subdomain → data stolen

### 3. OAuth Token Theft via Redirect URI

- OAuth whitelist: `.example.com`
- Attacker uses `redirect_uri=https://taken-over.example.com/callback`
- Victim authenticates → OAuth provider redirects with `code` or `access_token`
- Attacker captures token → account takeover

### 4. CSP Bypass

- CSP: `script-src 'self' vulnerable.example.com`
- Attacker hosts malicious script on taken-over subdomain
- Page loads script from `https://vulnerable.example.com/evil.js` → XSS, keylogging, etc.

### 5. CSRF with Same-Site Cookies

- Modern browsers use SameSite; subdomains are still "same site"
- From taken-over subdomain, attacker sends POST to main domain
- Cookies sent automatically (unless SameSite=Strict and cross-site)
- Enables CSRF if no other protections (e.g., anti-CSRF tokens) exist

### 6. Phishing with Legitimate Domain

- Subdomain under victim’s domain + valid SSL (Let’s Encrypt)
- Phishing emails/links look legitimate → higher success
- Harder for spam filters to block

### 7. Email Abuse (MX Takeover)

- MX points to defunct mail service
- Attacker claims it → receives password reset, 2FA codes, support tickets
- Can send emails from `@sub.victim.com`

### 8. Second-Order Subdomain Takeover

- Subdomain used internally (admin panels, APIs) and not public
- Takeover still allows internal abuse if that subdomain is trusted

---

## Service-Specific Scenarios

| Service | Status | Fingerprint / Indicator |
| --- | --- | --- |
| **AWS S3** | Vulnerable | `The specified bucket does not exist` |
| **GitHub Pages** | Edge case | `There isn't a GitHub Pages site here.` |
| **Heroku** | Edge case | `No such app` |
| **Netlify** | Edge case | `Not Found - Request ID:` |
| **Vercel** | Edge case | `DEPLOYMENT_NOT_FOUND` |
| [**ReadMe.io**](http://readme.io/) | Vulnerable | `The creators of this project are still working...` |
| **GoHire** | Vulnerable | `You may have followed an invalid link, or the job has been archived` |
| **Azure** (multiple) | Vulnerable | `NXDOMAIN` on various `*.azure*.net` |
| **Bitbucket** | Vulnerable | `Repository not found` |
| [**Surge.sh**](http://surge.sh/) | Vulnerable | `project not found` |
| **Pantheon** | Vulnerable | `404 error unknown site!` |
| **Help Scout** | Vulnerable | `No settings were found for this company:` |
| **Ngrok** | Vulnerable | `Tunnel *.ngrok.io not found` |
| **Shopify** | Edge case | `Sorry, this shop is currently unavailable.` |
| **Fastly** | Not vulnerable | `Fastly error: unknown domain:` |
| **CloudFront** | Not vulnerable | Domain verification in place |
| **Okta** | Not vulnerable | TXT-based domain ownership verification |

Full list: [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

### Example: AWS S3 Takeover

```bash
# Create bucket with same name as CNAME target
aws s3 mb s3://vulnerable-sub.example.com

# Enable static website hosting
aws s3 website s3://vulnerable-sub.example.com --index-document index.html

# Host PoC
echo "<!-- PoC by username -->" > index.html
aws s3 cp index.html s3://vulnerable-sub.example.com/
```

### Test Cases Quick Reference

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| CNAME to S3 | Create bucket with CNAME target name | Subdomain serves attacker content |
| CNAME to GitHub Pages | Add CNAME file with subdomain in GitHub repo | Subdomain serves attacker page |
| CNAME to Heroku | Create Heroku app with same subdomain | Subdomain points to attacker app |
| Wildcard CNAME | Create resource matching wildcard target | Arbitrary subdomains resolve to attacker |
| OAuth redirect | Use taken-over subdomain in `redirect_uri` | OAuth token sent to attacker |
| Cookie scope | Load main domain from subdomain | Cookies (if not HttpOnly) readable by attacker |
| CORS misconfig | Send request from subdomain to main API | Sensitive data returned if subdomain in Allow-Origin |
| MX takeover | Claim abandoned mail service | Receive/send emails from victim domain |
|  |  |  |

## Detection Techniques

### Manual Detection

1. **DNS Reconnaissance**
    - Enumerate subdomains (Amass, Sublist3r, etc.)
    - Resolve CNAME for each subdomain
    - Identify records pointing to third-party domains (S3, Heroku, GitHub, etc.)
2. **Inspect DNS records**
Run: **dig sub.target.com**
- Observe result like :

```
sub.target.com CNAME target.herokuapp.com
```

1. **HTTP Fingerprinting**
    - Visit each subdomain
    - Compare response body/headers to known error signatures
    - Check for 404, "not found", "bucket does not exist", etc.
2. **Dangling CNAME Check**
    - CNAME points to `xyz.github.io` but GitHub returns "no site here" → likely vulnerable
    - CNAME points to `bucket.s3.amazonaws.com` but bucket deleted → vulnerable
3. **Historical / Passive DNS**
    - Use SecurityTrails, RiskIQ, Censys, Shodan, VirusTotal
    - Old CNAMEs may reveal previously used services

### Automated Detection

1. **Subzy**
Subdomain takeover tool which works based on matching response fingerprints from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md)
- `./subzy run --target test.google.com`
- `./subzy run --targets list.txt`
1. **Nuclei (Takeover Templates)aa**
YAML templates to match takeover signatures
- `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- echo "https://sub.example.com" | nuclei -tags takeover
1. **Subjack** 
Concurrent scans with built-in fingerprints
- `go get github.com/haccer/subjack`
- `subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl`
1.  **tko-subs**
Dangling CNAMEs, NXDOMAIN, NS; optional takeover
- `go get github.com/anshumanbh/tko-subs`
- `tko-subs -domains=domains.txt -data=providers-data.csv -output=output.csv`
1. **SubOver**
50+ fingerprints, fast Go scanner
- `go get github.com/Ice3man543/SubOver`
- `./SubOver -l subdomains.txt -https`
1. **dnsReaper**
 50+ signatures, cloud/DNS integration, CSV/JSON
- `docker pull punksecurity/dnsreaper` or pip
- `docker run punksecurity/dnsreaper single --domain sub.example.com`
1. **Subdominator**
Fingerprint-based takeover scanner
- `sudo snap install subdominator`
- `subdominator -l subdomains.txt -o takeovers.txt`
1. **BBot**
Recon with baddns takeover module
- `pipx install bbot`
- `bbot -t example.com -p kitchen-sink` or `-m baddns`
1. **Cariddi**
Crawling + takeover checks during reconnaissance
- `go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest`
- `echo "https://example.com" | cariddi -intensive`

## Impact

- **Phishing:** Host content on trusted subdomain + valid SSL → higher success
- **Session hijacking:** Read cookies scoped to parent domain from subdomain
- **OAuth token theft:** Redirect tokens to attacker-controlled subdomain
- **CORS bypass:** Exfiltrate sensitive data from main application
- **CSP bypass:** Execute malicious scripts in app context
- **CSRF:** Send authenticated requests from "same site" subdomain
- **Email abuse:** Receive/send emails from victim domain (MX takeover)
- **Reputational damage:** Defacement, malware hosting
- **Account takeover:** Combined with OAuth, cookies, or password reset flows

## Prevention Techniques

- **Remove unused DNS records** before decommissioning services.
- **Claim or reclaim** resources (re-create bucket/page) if subdomain is still needed.
- **Use domain ownership verification** (TXT record challenge) before allowing custom domains.
- **DNS lifecycle:** Make DNS removal the first step in decommissioning; creation the last step in deployment.
- **Avoid wildcard CNAMEs** to third-party services when possible.
- **Regular DNS audits** with automated scanners (Nuclei, Subjack, etc.).
- **Real-time monitoring** for DNS changes and dangling records.
- **Asset inventory:** Track all subdomains and linked third-party services.
- **Least privilege:** Limit who can create/modify DNS and cloud resources.

## Tools

| Tool | Purpose |
| --- | --- |
| [Subjack](https://github.com/haccer/subjack) | Fast takeover detection with fingerprint list |
| [tko-subs](https://github.com/anshumanbh/tko-subs) | Subdomain takeover checker |
| [SubOver](https://github.com/Ice3man543/SubOver) | Takeover detection |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Use `-tags takeover` for takeover templates |
| [Subzy](https://github.com/PentestPad/subzy) | Subdomain takeover verification |
| [dnsReaper](https://github.com/punk-security/dnsReaper) | Dangling DNS / takeover scanning |
| [Subdominator](https://github.com/Stratus-Security/Subdominator) | Subdomain enumeration + takeover |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Subdomain enumeration |
| [Amass](https://github.com/OWASP/Amass) | Passive/active subdomain enumeration |
| [BBot](https://github.com/blacklanternsecurity/bbot) | Recon + takeover checks |
| [Cariddi](https://github.com/edoardottt/cariddi) | Crawling with takeover checks |
| [Aquatone](https://github.com/michenriksen/aquatone) | Visual recon, orphaned page detection |

## Good to Read

- [Top 25 Subdomain Takeover Bug Bounty Reports](https://readmedium.com/top-25-subdomain-takeover-bug-bounty-reports-f6e386ba4413)
- [HackerOne: Subdomain Takeover Reports](https://hackerone.com/reports/661751) (and similar reports)
- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) — Community list of vulnerable services
- [0xpatrik - Subdomain Takeover](https://0xpatrik.com/subdomain-takeover/)
- [HackerOne Blog - Guide to Subdomain Takeovers](https://www.hackerone.com/blog/guide-subdomain-takeovers-20)

## References

- [https://0xpatrik.com/subdomain-takeover/](https://0xpatrik.com/subdomain-takeover/)
- [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [https://www.hackerone.com/blog/guide-subdomain-takeovers-20](https://www.hackerone.com/blog/guide-subdomain-takeovers-20)
- [https://www.stratussecurity.com/post/subdomain-takeover-guide](https://www.stratussecurity.com/post/subdomain-takeover-guide)
- [https://hackerone.com/reports/661751](https://hackerone.com/reports/661751)
- [https://hackerone.com/reports/276269](https://hackerone.com/reports/276269)
- [https://hackerone.com/reports/219205](https://hackerone.com/reports/219205)
- [https://hackerone.com/reports/383564](https://hackerone.com/reports/383564)
- [https://hackerone.com/reports/154425](https://hackerone.com/reports/154425)
- [https://hackerone.com/reports/335330](https://hackerone.com/reports/335330)
- [https://hackerone.com/reports/149679](https://hackerone.com/reports/149679)
- [https://hackerone.com/reports/570651](https://hackerone.com/reports/570651)
- [https://readmedium.com/top-25-subdomain-takeover-bug-bounty-reports-f6e386ba4413](https://readmedium.com/top-25-subdomain-takeover-bug-bounty-reports-f6e386ba4413)
- [https://book.hacktricks.xyz/pentesting-web/subdomain-takeover](https://book.hacktricks.xyz/pentesting-web/subdomain-takeover)
- [https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api) (Wildcard CNAME example)

---