---
title: Checklist
---

## Reconnaisance (Information Gathering)
- Information Gathering (via tool like CFF Explorer)
- Identify architecture - Two-tier or Three-tier 
- Is the App - Internet or Intranet based (via tool like Wireshark)
- Identify - Proxy-aware or Proxy-Unaware
- Identify technologies used on Client-Side
- Identify technologies used on Server-Side
- Identify the Proccess ID
- Identify application entry points
- Identify user roles
- Identify Network Communication - Ports and Protocols in use 
- Port Scanning (via tool like Nmap)
- Check for webapp associated with the thick client
- Check whether thick client app redirects to a web application

## Injection
- OS Command Injection
- SQL Injection
- NoSQL Injection
- External XML Entity (XXE)
- XSS (Cross Site Scripting)
- HTML Injection
- XPath Injection
- LDAP Injection
- Host Header Injection
- CSV Injection
- (HTTP) Parameter Pollution
- Server-Side Template Injection (SSTI)

## Broken Authentication and Session Management
- Vulnerable Authentication Flow
    - via Response Manipulation
    - via SQL/NoSQL Injection
    - Via Null (Absence of) Password
    - Use of Default Credentials 
    - Use of Hardcoded Credentials
    - Via Memory Manipulation
    - Via Registry Manipulation
- Username Enumeration
- Weak Lock Out Mechanism
- Flawed Brute-Force Protection
- Vulnerable Remember Password
- Weak Password Policy
- Flawed User Registration Process
- OAuth/OpenID
- SSO
- MFA
- Session based weaknesses

## Sensitive Data Exposure
- Improper cryptographic key management
- Presence of sensitive data in log files
- Presence of sensitive data in local files 
- Presence of sensitive data in registry
- Presence of sensitive data in config files
- Presence of hard-coded sensitive data in source code
- Presence of sensitive data in memory
- Sensitive Data Persists in Memory after Formal Logout

## Improper Cryptography Usage
- Missing encryption
- Use of Weak cryptographic Keys
- Weak Cryptography (encryption) algorithm implemented (in Authentication)
- Use of old/less-secure Hashing algorithms
- Use of Hash values without Salting 
- Insufficient randomness for cryptographic functions/keys

## Improper Authorization (Broken Access Control)
- Privilege Escalation
    - Via enabling hidden functionalities
    - Via enabling objects (eg. text fields, buttons)
    - Via disabling objects (eg. text fields, buttons)
    - Via Parameter manipulation
    - Weak file/folder permission per user role
    - Read/Write access of the registry 
    - Read/Write access of the configuration files
    - Read/Write access of the log files 
    - Via Memory Manipulation
    - Via Registry Manipulation
- Horizontal Privilege Escalation
- Vertical Privilege Escalation
- Analyze setuid/setgid permission
- Forced Browsing
- Insecure Direct Object References (IDOR) 
- URL/Open Redirection
- Path/Directory Traversal
- Read/Write permission for App Directory or Files
- Tampering cookies/sesssions
- JWT Based Attacks

## Security Misconfiguration
- Improper Error Handling (verbose messages)
- Absent/weakly configured security headers
- Cross-Origin Resource Sharing (CORS) Misconfiguration
- Server Banner Information Disclosure
- HTTP Request Smuggling
- Check for unquoted service paths
- Unnecessarily exposed features (ports, services, pages, accounts, or privileges).
- CAPTCHA
- Unicode Normalization
- Path normalization issues
- Unrestricted File Upload

## Insecure Communication
- Sensitive data transmitted in plain text (eg. Database Queries)
- Usage of plaintext communication protocols (eg. FTP, TELNET, HTTP, MQTT, WS)
- SSL Vulnerabilities  
    - Weak SSL/DTLS cipher
    - Weak SSL/DTSL protocol
    - SSL cipher expired/about to expire
    - Self signed certificate
    - Certificate signed with a weak hashing algorithm
- Insecure implementation of certificate validation
- HTTPS not enabled
- HTTPS not enforced
- Analyze and/or bypass firewall rules

## Poor Code Quality
- Verify StrongNaming (signing an assembly with a key)
- Check for missing Code-Signing and Verification checks (for File Integrity)
- Reverse Engineering 
    - Decompile the application
    - Rebuild the application
    - Patch the application
    - Bypass licence/validation check
- Race Condition
- Lack Of Binary Protections
- Check for HighEntropyVA
- Is ASLR (Address Space Layout Randomization) enabled
- Is DEP (Data Execution Prevention) enabled
- Is SafeSEH (Safe Structured Exception Handlers) enabled
- Is CFG (Control Flow Guard) enabled
- Lack of Code Obfuscation
- DLL Injection
- DLL proxying
- Buffer Overflow
    - Stack Buffer Overflow
    - Heap Buffer Overflow

## Using Components with known vulnerabilities
- Using Component with Known Vulnerabilities 
- Using unmaintained/obsolete libraries 

## Insufficient logging and monitoring
- Logs (containing sensitive data) publiclly available
- Log Injection/Forging
- Logging Sensitive information
- Lack of logging important information
- Side Channel Data Leaks

## Miscellaneous
- Application Debuggable 
- Analyze the Dump File
- Business Logic (Application Specific)
    - Bypassing license/extending lifetime of trial software via register manipulation
    - Payment Manipulation
- String based analysis
- Server-Side attacks
    - SSRF
    - Local File Inclusion (LFI)
    - Remote File Inclusion (RFI)
    - Denial Of Service attack (DOS)