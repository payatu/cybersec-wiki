---
title: Vulnerable & Outdated Components
---

# Vulnerable & Outdated Components

Vulnerable and Outdated Components is a security vulnerability that occurs when an application uses libraries, frameworks, or software with known security vulnerabilities, unsupported versions, or missing patches, allowing attackers to exploit publicly disclosed issues to compromise the application.

---

### **Understanding Vulnerable Components**

- Applications rely on third-party libraries and frameworks
- Components may contain publicly known vulnerabilities
- Vulnerabilities are tracked using CVE identifiers
- Outdated or unsupported versions increase risk
- Attackers search for known vulnerable component versions

---

## **Attack Surfaces**

- JavaScript libraries
- Backend frameworks
- Third-party dependencies
- CMS plugins and themes (e.g. WordPress, Joomla, Drupal, Shopify)
- Web server software
- Package dependencies

---

## **Exploitation Techniques**

- **Identify outdated JavaScript library**
    
    ```jsx
    <scriptsrc="/js/jquery-1.7.2.min.js"></script>
    ```
    
    Search for known vulnerabilities in that version by using targeted search queries such as:
    
    ```jsx
    "jquery 1.7.2" (vulnerability OR exploit OR cve OR poc OR advisory) (site:nvd.nist.gov OR site:exploit-db.com OR site:snyk.io OR site:github.com)
    ```
    

- **Version disclosure in Response Headers**

```jsx
Server: Apache/2.4.49
X-Powered-By: PHP/5.6.40
```

Look for known exploits for disclosed versions by using targeted search queries such as:

```jsx
"PHP 5.6.40" (vulnerability OR exploit OR cve OR poc OR advisory) (site:nvd.nist.gov OR site:exploit-db.com OR site:snyk.io OR site:github.com)
```

---

- **Check dependency files**
    
    ```jsx
    /package.json
    /requirements.txt
    /pom.xml
    ```
    

Outdated dependencies may contain CVEs.

---

## **Detection Techniques**

#### **Manual Detection Techniques**

- Inspect JavaScript files for version numbers
- Check response headers for software versions
- Review dependency files
- Inspect CMS version disclosure
- Check static file naming patterns

Indicators of Vulnerability

- Outdated component version
- Public CVE exists
- Unsupported software version
- Version disclosed in responses

---

#### **Automated Detection Techniques**

**Dependency Scanners**

- [OWASP Dependency Check](https://github.com/dependency-check/DependencyCheck)
- [Retire.js](https://github.com/retirejs/retire.js/) (Burp Extension Available)
- [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [Software Version Reporter](https://portswigger.net/bappstore/ae62baff8fa24150991bad5eaf6d4d38) (Burp Extention)

**Vulnerability Scanners**

- [Nikto](https://www.kali.org/tools/nikto/)
- [Nuclei](https://www.kali.org/tools/nuclei/) → nuclei -u [https://target.com](https://target.com/) -tags cve, tech
- Scan for an specific CVE using: nuclei -u [https://target.com](https://target.com/) -id CVE-2021-44228

---

## **Impacts**

- Exploitation of publicly known vulnerabilities
    
    Attackers can easily identify and exploit known issues in outdated software versions by referencing public databases like the [National Vulnerability Database](https://nvd.nist.gov/vuln) and the [CVE Program](https://www.cve.org/), reducing the effort required to compromise the system.
    
- Remote code execution through vulnerable components
    
    Certain vulnerabilities such as [**CVE-2019-11043 (PHP-FPM RCE)**](https://nvd.nist.gov/vuln/detail/CVE-2019-11043), **C[VE-2021-41773 (Apache Path Traversal/RCE)](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) and** [**CVE-2021-44228 (Log4Shell)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)** may allow attackers to execute arbitrary code on the server, potentially leading to full system control and unauthorized operations.
    
- Known Vulnerable Flows in the Framework Lead to Authentication Bypass
    
    Weaknesses in outdated frameworks can allow attackers to bypass login mechanisms and gain unauthorized access without valid credentials.
    
- Information disclosure from outdated software
    
    Older versions may expose sensitive information such as configuration details, system paths, or user data, which can aid attackers in further exploitation.
    
- Privilege escalation through vulnerable dependencies
    
    Attackers with limited access can exploit vulnerabilities to gain higher privileges, potentially achieving administrative or root-level control.
    
- Full application compromise
    
    By chaining multiple vulnerabilities, attackers can completely take over the application, including its data, functionality, and underlying infrastructure.
    
- Denial of Service (DoS) / Distributed Denial of Service (DDoS)
Vulnerabilities such as [**CVE-2026-23864**](https://nvd.nist.gov/vuln/detail/CVE-2026-23864) may allow attackers to trigger resource exhaustion, leading to denial of service (DoS) and application downtime.

---

## **Tools**

- [OWASP Dependency Check](https://github.com/dependency-check/DependencyCheck), [Retire.js](https://github.com/retirejs/retire.js/), [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [Nikto](https://www.kali.org/tools/nikto/), [Nuclei](https://www.kali.org/tools/nuclei/), [Burp Suite](https://portswigger.net/burp/communitydownload)

---

## **Mitigation & Preventions**

- **Maintain inventory of all components:**
Keep an up-to-date record of all libraries, frameworks, and dependencies used in the application to easily track and manage their security status.
- **Regularly update libraries and frameworks:**
Ensure all components are updated to the latest stable versions to reduce exposure to known vulnerabilities and security flaws.
- **Remove unused dependencies:**
Eliminate unnecessary or unused libraries from the codebase to minimize the attack surface and reduce potential risks.
- **Monitor vulnerability advisories:**
Continuously monitor trusted sources such as the National Vulnerability Database and the CVE Program for newly disclosed vulnerabilities affecting your components.
- **Use supported component versions:**
Avoid using end-of-life or unsupported software, as they no longer receive security updates or patches.
- **Implement automated dependency scanning:**
Use automated tools to regularly scan for outdated or vulnerable components and receive alerts for required updates.

---

## **Good To Read**

[https://hackerone.com/reports/1430622](https://hackerone.com/reports/1430622)

[https://nvd.nist.gov/vuln/detail/CVE-2023-2621](https://nvd.nist.gov/vuln/detail/CVE-2023-2621)

[https://publisher.hitachienergy.com/preview?DocumentId=8DBD000177&languageCode=en&Preview=true](https://publisher.hitachienergy.com/preview?DocumentId=8DBD000177&languageCode=en&Preview=true)

[https://nvd.nist.gov/vuln/detail/CVE-2024-25103](https://nvd.nist.gov/vuln/detail/CVE-2024-25103)

[https://www.cve.org/CVERecord?id=CVE-2025-67779](https://www.cve.org/CVERecord?id=CVE-2025-67779)

[https://nvd.nist.gov/vuln/detail/CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)

[https://nvd.nist.gov/vuln/detail/CVE-2025-55184](https://nvd.nist.gov/vuln/detail/CVE-2025-55184)

[https://nvd.nist.gov/vuln/detail/CVE-2026-23864](https://nvd.nist.gov/vuln/detail/CVE-2026-23864)

---

## **References**

[https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/index.html](https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/index.html)

[https://www.invicti.com/blog/web-security/vulnerable-and-outdated-components-owasp-top-10](https://www.invicti.com/blog/web-security/vulnerable-and-outdated-components-owasp-top-10)

[https://www.acunetix.com/blog/web-security-zone/vulnerable-and-outdated-components-owasp-top-10/](https://www.acunetix.com/blog/web-security-zone/vulnerable-and-outdated-components-owasp-top-10/)

[https://blog.securelayer7.net/a06-vulnerable-outdated-components/](https://blog.securelayer7.net/a06-vulnerable-outdated-components/)

[https://learn.snyk.io/lesson/vulnerable-and-outdated-components/?ecosystem=python](https://learn.snyk.io/lesson/vulnerable-and-outdated-components/?ecosystem=python)

[https://www.geeksforgeeks.org/ethical-hacking/vulnerable-and-outdated-components-in-owasp-top-10/](https://www.geeksforgeeks.org/ethical-hacking/vulnerable-and-outdated-components-in-owasp-top-10/)

[https://qawerk.com/blog/vulnerable-and-outdated-components/](https://qawerk.com/blog/vulnerable-and-outdated-components/)