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
- Identify Network Communication - Ports and Protocols in use (https://www.hackingarticles.in/thick-client-penetration-testing-information-gathering/)
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
- Improper cryptographic key management (https://cqr.company/web-vulnerabilities/cryptographic-key-management-issues/)
- Presence of sensitive data in log files (https://stackify.com/linux-logs/, https://www.solarwinds.com/resources/it-glossary/windows-event-log)
- Presence of sensitive data in local files  (https://www.darkrelay.com/post/thick-client-penetration-testing#:~:text=Testing%20for%20Information%20Leakage)
- Presence of sensitive data in registry (https://www.netspi.com/blog/technical-blog/thick-application-pentesting/introduction-to-hacking-thick-clients-part-3/)
- Presence of sensitive data in config files (https://payatu.com/blog/thick-client-penetration-testing/#:~:text=Buffer%20Overflow-,Hardcoded,-Sensitive%20Information%20In)
- Presence of hard-coded sensitive data in source code (https://www.cyberark.com/resources/threat-research-blog/thick-client-penetration-testing-methodology#:~:text=an%20obfuscation%20process.-,Binary%20Analysis,-After%20we%20have))
- Presence of sensitive data in memory (https://www.netspi.com/blog/technical-blog/thick-application-pentesting/introduction-to-hacking-thick-clients-part-6-the-memory/)
- Sensitive Data Persists in Memory after Formal Logout

## Improper Cryptography Usage
- Missing encryption (https://cwe.mitre.org/data/definitions/311)
- Use of Weak cryptographic Keys (https://www.thesslstore.com/blog/cryptographic-keys-101-what-they-are-how-they-secure-data/)
- Weak Cryptography (encryption) algorithm implemented (in Authentication) (https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+use+insecure+or+weak+cryptographic+algorithms)
- Use of old/less-secure Hashing algorithms (https://cwe.mitre.org/data/definitions/328.html)
- Use of Hash values without Salting (https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/)
- Insufficient randomness for cryptographic functions/keys (https://www.netdata.cloud/blog/understanding-entropy-the-key-to-secure-cryptography-and-randomness/)

## Improper Authorization (Broken Access Control)
- Privilege Escalation (https://delinea.com/blog/windows-privilege-escalation)
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
- Analyze setuid/setgid permission (https://www.cbtnuggets.com/blog/technology/system-admin/linux-file-permissions-understanding-setuid-setgid-and-the-sticky-bit)
- Forced Browsing (https://owasp.org/www-community/attacks/Forced_browsing)
- Insecure Direct Object References (IDOR) (https://portswigger.net/web-security/access-control/idor)
- URL/Open Redirection (https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- Path/Directory Traversal (https://owasp.org/www-community/attacks/Path_Traversal)
- Read/Write permission for App Directory or Files
- Tampering cookies/sesssions (https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies)
- JWT Based Attacks (https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)

## Security Misconfiguration
- Improper Error Handling (verbose messages)
- Absent/weakly configured security headers (https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- Cross-Origin Resource Sharing (CORS) Misconfiguration (https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- Server Banner Information Disclosure (https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- HTTP Request Smuggling (https://portswigger.net/web-security/request-smuggling)
- Check for unquoted service paths (https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/UnquotedServicePath.md)
- Unnecessarily exposed features (ports, services, pages, accounts, or privileges).
- CAPTCHA
- Unicode Normalization (https://book.hacktricks.xyz/pentesting-web/unicode-injection/unicode-normalization)
- Path normalization issues
- Unrestricted File Upload (https://book.hacktricks.xyz/pentesting-web/file-upload)

## Insecure Communication
- Sensitive data transmitted in plain text (eg. Database Queries) (https://docs.guardrails.io/docs/vulnerability-classes/insecure-network-communication/cleartext-transmission)
- Usage of plaintext communication protocols (eg. FTP, TELNET, HTTP, MQTT, WS) (https://www.pcisecuritystandards.org/glossary/insecure-protocol-service-port/)
- SSL Vulnerabilities  (https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
    - Weak SSL/DTLS cipher (https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection)
    - Weak SSL/DTSL protocol
    - SSL cipher expired/about to expire
    - Self signed certificate
    - Certificate signed with a weak hashing algorithm
- Insecure implementation of certificate validation
- HTTPS not enabled
- HTTPS not enforced
- Analyze and/or bypass firewall rules

## Poor Code Quality
- Verify StrongNaming (signing an assembly with a key) (https://learn.microsoft.com/en-us/dotnet/standard/assembly/strong-named)
- Check for missing Code-Signing and Verification checks (for File Integrity) (https://en.wikipedia.org/wiki/Code_signing)
- Reverse Engineering (https://rahulmondal666.medium.com/learning-thick-client-vapt-with-me-part-3-patching-the-application-by-reverse-engineering-e231ca6bfa34)
    - Decompile the application
    - Rebuild the application
    - Patch the application
    - Bypass licence/validation check
- Race Condition (https://book.hacktricks.xyz/pentesting-web/race-condition)
- Lack Of Binary Protections (https://blog.securelayer7.net/static-analysismemory-forensics-reverse-engineering-thick-client-penetration-testing-part-4/)
    - Check for HighEntropyVA (https://learn.microsoft.com/en-us/cpp/build/reference/highentropyva?view=msvc-170)
    - Is ASLR (Address Space Layout Randomization) enabled (https://blog.securelayer7.net/static-analysismemory-forensics-reverse-engineering-thick-client-penetration-testing-part-4/)
    - Is DEP (Data Execution Prevention) enabled
    - Is SafeSEH (Safe Structured Exception Handlers) enabled
    - Is CFG (Control Flow Guard) enabled
- Lack of Code Obfuscation (https://payatu.com/blog/thick-client-penetration-testing/#Lack_of_code_obfuscation)
- DLL Injection (https://www.upguard.com/blog/dll-hijacking, https://attack.mitre.org/techniques/T1055/001/)
- DLL proxying (https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence)
- Buffer Overflow
    - Stack Buffer Overflow (https://en.wikipedia.org/wiki/Stack_buffer_overflow)
    - Heap Buffer Overflow (https://en.wikipedia.org/wiki/Heap_overflow)

## Using Components with known vulnerabilities
- Using Component with Known Vulnerabilities (https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities)
- Using unmaintained/obsolete libraries 

## Insufficient logging and monitoring
- Logs (containing sensitive data) publiclly available (https://seminar.vercel.app/ch5/SecurityMisconfig/logs.html)
- Log Injection/Forging (https://owasp.org/www-community/attacks/Log_Injection)
- Logging Sensitive information (https://cwe.mitre.org/data/definitions/532)
- Lack of logging important information (https://www.paloaltonetworks.com/cyberpedia/insufficient-logging-visibility-cicd-sec10)
- Side Channel Data Leaks (https://www.infosecinstitute.com/resources/hacking/android-hacking-security-part-4-exploiting-unintended-data-leakage-side-channel-data-leakage/)

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