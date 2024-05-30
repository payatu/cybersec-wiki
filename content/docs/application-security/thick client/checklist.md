---
title: Checklist
---

# Checklist

## Reconnaisance (Information Gathering)
- Information Gathering (via tool like CFF Explorer) (https://www.hackingarticles.in/thick-client-penetration-testing-information-gathering/)
- Identify architecture - Two-tier or Three-tier (https://medium.com/@GacheruEvans/2-tier-vs-3-tier-architecture-26db56fe7e9c)
- Is the App - Internet or Intranet based (via tool like Wireshark) (https://powell-software.com/resources/blog/difference-between-intranet-and-internet/)
- Identify - Proxy-aware or Proxy-Unaware (https://www.browserstack.com/docs/app-live/troubleshooting/proxy-aware)
- Identify technologies used on Client-Side 
- Identify technologies used on Server-Side
- Identify the Proccess ID (https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/finding-the-process-id, https://www.geeksforgeeks.org/get-process-id-of-linux-foreground-and-background-processes/)
- Identify application entry points
- Identify user roles
- Identify Network Communication - Ports and Protocols in use 
- Port Scanning (via tool like Nmap) (https://www.freecodecamp.org/news/what-is-nmap-and-how-to-use-it-a-tutorial-for-the-greatest-scanning-tool-of-all-time/)
- Check for webapp associated with the thick client
- Check whether thick client app redirects to a web application

## Injection
- [OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [External XML Entity (XXE)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [XSS (Cross Site Scripting)](https://owasp.org/www-community/attacks/xss/)
- [HTML Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)
- [XPath Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection)
- [LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
- [Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [(HTTP) Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [Server-Side Template Injection (SSTI)](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)

## Broken Authentication and Session Management
- Vulnerable Authentication Flow
    - via Response Manipulation (https://medium.com/@MAALP/authentication-bypass-using-response-manipulation-6c33eb1257ac)
    - via SQL/NoSQL Injection (https://portswigger.net/support/using-sql-injection-to-bypass-authentication)
    - Via Null (Absence of) Password (https://owasp.org/www-community/vulnerabilities/Empty_String_Password)
    - Use of Default Credentials  (https://rohit443.medium.com/using-default-credential-to-admin-account-takeover-677e782ff2f2)
    - Use of Hardcoded Credentials (https://infosecwriteups.com/go-code-review-1-hard-coded-credentials-are-security-sensitive-4317a8431eaa)
    - Via Memory Manipulation (https://abhigowdaa.medium.com/sensitive-information-in-hexdump-bb6a6306532c)
    - Via Registry Manipulation (https://abhigowdaa.medium.com/passwords-in-registry-entry-30e69fb6524f)
- Username Enumeration (https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)
- Weak Lock Out Mechanism (https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- Flawed Brute-Force Protection (https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)
- Vulnerable Remember Password (https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password)
- Weak Password Policy (https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy)
- Flawed User Registration Process (https://sm4rty.medium.com/hunting-for-bugs-in-sign-up-register-feature-2021-c47035481212)
- OAuth/OpenID (https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
- SSO (https://medium.com/@batuhanaydinn/bug-bounty-hunter-understanding-saml-vulnerabilities-xsw-attacks-8c43c601d2d1)
- MFA (https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- Session based weaknesses (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

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