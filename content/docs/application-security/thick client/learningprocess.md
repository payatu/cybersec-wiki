---
title: Learning Process
---

## Contents

- [Sample vulnerable thick client applications](#Sample-vulnerable-Thick-Client-application)
- [Vulnerability ranking](#owasp-desktop-app-security-top-10)
- [Common Vulnerabilities](#some-common-vulnerabilities)

## Sample vulnerable Thick Client application

### DVTA - Damn Vulnerable Thick Client Application
https://github.com/srini0x00/dvta

- https://www.hackingarticles.in/thick-client-pentest-lab-setup-dvta-2/
- https://www.hackingarticles.in/thick-client-pentest-lab-setup-dvta-part-2/
- https://parsiya.net/blog/2018-07-15-dvta-part-1-setup/


### BetaBank
https://github.com/NetSPI/BetaFast/tree/master/BetaBank

### BetaFast
https://github.com/NetSPI/BetaFast/tree/master/BetaFast

- https://medium.com/@abhishek.offsec/hacking-the-betafast-betabank-thick-client-applications-fe8b6226f84a

<br>

## OWASP Desktop App Security Top 10

https://owasp.org/www-project-desktop-app-security-top-10/

<br>

## Some Common Vulnerabilities

- https://payatu.com/blog/thick-client-penetration-testing/

- **DLL Hijacking**
    - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
    - https://hackerone.com/reports/1636566
    - https://securitycafe.ro/2023/06/19/dll-hijacking-finding-vulnerabilities-in-pestudio-9-52/
- **DLL Side-loading**
    - https://www.mandiant.com/resources/reports/dll-side-loading-thorn-side-anti-virus-industry
- **Sensitive credentials leaked in source code on Github**
    - https://thehackernews.com/2023/01/github-breach-hackers-stole-code.html
- **Application data being stored in System Registry**
    - https://www.praetorian.com/blog/how-to-detect-and-dump-credentials-from-the-windows-registry/
    - https://medium.com/@rahisul/windows-registry-769191adce1e
- **Unsigned .exe or .dll files**
    - https://abhigowdaa.medium.com/unsigned-dll-exe-files-the-validity-of-the-certificates-86baf8722454
- **Unencrypted application data in network during transmission**
    - Use of Wireshark to analyze traffic
    - https://www.netspi.com/blog/technical/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-2-the-network/
- **Unecrypted application data stored in the computer**
    - https://blog.appsecco.com/breaking-bad-tearing-apart-a-thick-client-app-to-steal-data-7e44f8698b2a
    - https://stackoverflow.com/questions/33288/protecting-api-secret-keys-in-a-thick-client-application
- **Memory protection checks**
    - https://blog.securelayer7.net/static-analysismemory-forensics-reverse-engineering-thick-client-penetration-testing-part-4/
    - https://msrc.microsoft.com/blog/2010/12/on-the-effectiveness-of-dep-and-aslr/
    - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-memory-protection-features/ba-p/259046
- **Symlink attack**
    - https://www.exploit-db.com/papers/13199
    - https://www.darkrelay.com/post/thick-client-penetration-testing
    - https://nixhacker.com/understanding-and-exploiting-symbolic-link-in-windows/
- **SQL Injection**
    - SQLi payload for different languages can be referred from - https://securecode.wiki/docs/lang/dotnet/


