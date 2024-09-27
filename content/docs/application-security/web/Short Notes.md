---
title: Short Notes
---

## Command Injection 
|Description (Blog)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this blog, one can learn the following: <br> <ul> <li>What is command injection </li> <li>Impact of command Injection</li> <li>How to detect command injection vulnerability </li> <li>Cheat sheet of Command Injection</li>|[Read More](https://www.cobalt.io/blog/a-pentesters-guide-to-command-injection)|
|This article describes how to test an application for OS command injection. The tester will try to inject an OS command through an HTTP request to the application using special characters that are used in command injection.  |[Read here](https://wiki.owasp.org/index.php/Testing_for_Command_Injection_%28OTG-INPVAL-013%29) |
|This article explains command injection vulnerability by demonstrating six vulnerable programs for command injection. It also explains how to exploit those examples.|[Read More](https://owasp.org/www-community/attacks/Command_Injection)|
|In this blog, the author has covered the following: <br> <ul> <li>What’s OS Command Injection Vulnerability </li><li>What’s OS Command Injection Vulnerability</li> <li>How to detect OS Command injection</li> <li>How to exploit OS Command Injection</li> <li>How to fix (code) OS Command Injection Vulnerability</li>|[Read More](https://medium.com/@mahmoudashrafxp/os-command-injection-vulnerability-96c0fbcae7be) 

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Keynotes of the videos are: <br> <ul> <li>What is OS command injection</li><li>Executing arbitrary commands</li><li>Useful Commands </li><li>Blind OS command injection</li><li>Exploiting blind OS command injection </li><li>Ways of injecting OS </li><li>Preventing OS command injection </li>|[Read More](https://www.youtube.com/watch?v=8PDDjCW5XWw)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this section, they have explained what OS command injection is, described how vulnerabilities can be detected and exploited, spelled out some useful commands and techniques for different operating systems, and summarized how to prevent OS command injection.|[Read More](https://portswigger.net/web-security/os-command-injection)|
|Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. The aim of DVWA is to practice some of the most common web vulnerabilities, with various levels of difficulty, with a simple straightforward interface. Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. The aim of DVWA is to practice some of the most common web vulnerabilities, with various levels of difficulty, with a simple straightforward interface.|[Read More](https://github.com/digininja/DVWA)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explained OS command injection vulnerability on seedr.ru where seed_id parameter was vulnerable to OS command injection.|[Read More](https://hackerone.com/reports/1360208)|
|In this report, a hacker reported an OS Command Injection in gitlabhook. It allows execution of arbitrary code on the remote server, that waits for instructions from gitlab.|[Read More](https://hackerone.com/reports/685447)|



## Business Logic Vulnerability 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this article, the author has discussed his findings by exploiting business logic flaws in the application. <br><ul><li>Critical Parameter Manipulation or Logical Data Validation </li><li>Coupon Code Reuse </li>| [Read More](https://medium.com/armourinfosec/exploiting-business-logic-vulnerabilities-234f97d6c4c0 )|
|Weaknesses in this business logic errors identify some of the underlying problems that commonly allow attackers to manipulate the business logic of an application. | [Read More](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)|
|This article talks about the following key points: <br><ul><li>HOW DO BUSINESS LOGIC VULNERABILITIES ARISE</li><li>The IMPACT of Business logic vulnerability </li><li>Examples of business logic vulnerabilities: </li><li>Excessive trust in client-side control </li><li>Failing to handle unconventional input </li><li>Bypassing the two-factor authentication </li><li>How to prevent business logic vulnerability</li>| [Read More](https://infosecwriteups.com/web-application-business-logic-vulnerabilities-51be9c6b99fa)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This video resource could help you understand the anatomy of business logic vulnerabilities. | [Read More](https://www.youtube.com/watch?v=8l_y-d7RmQg)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this lab, you can practice what you have learned about Business logic vulnerabilities using their interactive labs which are based on real bugs that are encountered in the wild. | [Read More](https://portswigger.net/web-security/logic-flaws)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this report, Slack Enterprise Grid seems to be able to add arbitrary column to the profile of the account. | [Read More](https://hackerone.com/reports/500348)|







## Information disclosure
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This section explains the basics of information disclosure vulnerabilities and describes how you can find and exploit them. It also offers some guidance on how you can prevent information disclosure vulnerabilities on your own websites. | [Read More](https://portswigger.net/web-security/information-disclosure)|
| This blog explains about doing recon to find sensitive information disclosure and also provides a strategy to hunt for information disclosure vulnerability. | [Read More](https://hbothra22.medium.com/recon-to-sensitive-information-disclosure-in-minutes-503fc7ccdf0b)|
| This article explains a report about an information disclosure vulnerability through GET user data. | [Read More](https://medium.com/@novan.rmd/information-disclosure-through-get-user-data-a8cc8c2efdc )|
| This blog explains the methods used to find sensitive information disclosure vulnerability using wpscan. | [Read More](https://medium.com/@harrmahar/how-i-get-my-first-p1-sensitive-information-disclosure-using-wpscan-c2fba00ac361)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this video the author covered how to read JSON and XML specifically to find information disclosure vulnerabilities. She also covered how to approach a target when a URL returns JSON or XML, how to know if you've found an info disclosure - and how to exploit it! She wants to really demystify JSON/XML and make you feel more at ease with how JSON/XML works and how you can read it. She also covered other vulnerabilities that might exist when a URL returns JSON or XML. | [Read More](https://www.youtube.com/watch?v=992cxaPdaho&ab_channel=InsiderPhD)|
| This resource link provides a demonstration of PortSwigger information disclosure interactive labs. | [Read More](https://www.youtube.com/watch?v=O7Aason5plc&ab_channel=SamBowne)|
| In this presentation, Peter Yaworski walked through several information disclosure vulnerabilities, he has found in mature programs overlooked by other researchers specifically in HTML page sources and APIs. In doing so, he demonstrated the design pattern in Rails that makes this an easy mistake to make, especially when combined with a front-end JavaScript library like React or Angular. | [Read More](https://www.youtube.com/watch?v=jBi3a-dXsM8&ab_channel=Bugcrowd)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In the above link, you will find some interactive labs so that you can practice extracting different kinds of information that could be used as part of a further attack. | [Read More](https://portswigger.net/web-security/information-disclosure/exploiting )|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a short video POC which tells how a simple information disclosure vulnerability can make a huge impact on an organization. | [Read More](https://www.youtube.com/watch?v=sx62Nm66BMw&ab_channel=BugBountyProofOfConcepts%28POCs%29Disclosure )|





## File Upload Vulnerability
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this article, you will find a theoretical overview of what are the risk factors of Unrestricted File Upload, Weak Protections and Bypassing methods and some interesting test cases. You will also learn the prevention methods that must be implemented on the server to prevent unrestricted file upload.  | [Read More](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload )|
| File upload is one of the most common functionalities applications have to offer. This functionality, however, is implemented in many different forms based on the application’s use case.  In the first part of the file upload attack series, we will look at the attack surface that one gets when there’s a file upload functionality and we will focus on some of the interesting file upload attacks. | [Read More](https://blog.yeswehack.com/yeswerhackers/exploitation/file-upload-attacks-part-1/ )|
| In the final part of the File Upload Attacks series, we will be discussing the remaining attacks that one may encounter while testing File Upload functionality. We will also talk about some of the general bypasses and some tips & tricks to execute a successful attack scenario. | [Read More](https://blog.yeswehack.com/yeswerhackers/file-upload-attacks-part-2/ )|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this resource, the author has demonstrated a walkthrough of Upload Vulnerabilities lab from tryhackme.com which is a tutorial room exploring some basic file-upload vulnerabilities in websites.  | [Read More](https://www.youtube.com/watch?v=8zEoSrpsFvw )|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In the above link, you will find interactive labs that contain file upload vulnerabilities like: <br> <ul> <li>Remote code execution via web shell upload </li><li>Web Shell upload via Content-Type restrictions Bypass </li><li>Web shell upload via path traversal </li><li>Web shell upload via extension blacklist bypass </li><li>Web shell upload via obfuscated file extension </li><li>Remote code execution via polyglot web shell upload </li><li>Web shell upload via race condition </li>| [Read More](https://www.hacksplaining.com/exercises/file-upload) [Read More](https://portswigger.net/web-security/file-upload)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report contains an unrestricted file upload vulnerability where an attacker could upload a dangerous executable file.  | [Read More](https://hackerone.com/reports/808287 )|
| This report explains how an attacker can upload an unrestricted file that can lead to stored XSS. | [Read More](https://hackerone.com/reports/880099 )|
| In this report, The reporter found that it was possible to upload svg's and exe's in a reply in a conversation chain and target the receiver of the message. | [Read More](https://hackerone.com/reports/305237 )|
| In this report, a reported found an arbitrary file upload via the resume functionality at https://ecjobs.starbucks.com.cn which led to arbitrary code execution by uploading a webshell. | [Read More](https://hackerone.com/reports/506646 )|






## Broken Access Control
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Broken Access Control issues are present when the restrictions imposed are only on the front-end and the back-end APIs are never secured. The blog discusses various scenarios encountered while testing applications for Broken Access Control like: <br><ul><li>IDOR in Password Vault</li><li>Breaking the Business Logic in Energy Tender Management Platform </li><li>Pattern-based Shipment IDs </li><li>Using the Database of Another User </li><li>Analyzing the Flow of Requests </li>| [Read More](https://payatu.com/blog/prateek.thakare/broken-access-control )|
| In this document, you will find a theoretical overview of what are the different common access control vulnerabilities includes and also example attack scenarios. You will also learn the prevention methods that must be implemented on the server to prevent broken access control. | [Read More](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)|
| In this section, we will discuss what access control security is, describe privilege escalation and the types of vulnerabilities that can arise with access control, and summarize how to prevent these vulnerabilities. | [Read More](https://portswigger.net/web-security/access-control)|
| A Comprehensive Guide to Broken Access Control which includes:<br><ul><li>Introduction </li><li>What is Broken Access Control? </li><li>Access Control Types </li><li>Access Control Policy </li><li>Access Control Security Models </li><li>Some Common Attacks </li><li>Real World Scenarios </li> <li>Remediation Guidelines </li><li>Conclusion</li>| [Read More](https://medium.com/purplebox/broken-access-control-f82235ddf888)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Keynotes of the resource are: <br> <ul> <li>Introduction to Access control bugs</li><li>Simple numeric IDOR</li> <li>GUID based IDOR </li> <li>Hash based IDOR</li> <li>Request Methods  </li> <li>Local File Inclusion and Path Traversal </li> <li>Parameter Manipulation </li> <li>Logic Flaws </li> <li>Auxiliary Tips </li><li>Likely parameters/keys to check for IDOR’s</li>| [Read More](https://www.youtube.com/watch?v=94-tlOCApOc)|
| In this tutorial, you will learn how to test for broken access control and achieve privilege escalation on web applications. The author goes from a manual to semi-automated approaches.  | [Read More](https://www.youtube.com/watch?v=TJQpOrtet8E&ab_channel=thehackerish)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| The above link contains lab from attackdefense.com in which the following vulnerabilities are covered: <br> <ul> <li>CVE-2018-9038</li><li>Vulnerable Apache </li><li>Directory Traversal </li><li>Remote File Inclusion I </li><li>Remote File Inclusion II </li><li>Insecure Direct Object Reference </li><li>Insecure Direct Object Reference II </li><li>Local File Inclusion </li><li>BloofoxCMS </li><li>Path Traversal </li>| [Read More](https://attackdefense.com/listingnoauth?labtype=webapp-owasp-top10&subtype=webapp-owasp-top10-bac)|
|This lab has the following sections on REST API Security which you can solve: <br> <ul> <li>Broken Object Level Auth I </li><li>Broken Function Level Auth I </li><li>Broken Authentication I </li><li>Excessive Data Exposure I </li><li>Mass Assignment I </li><li>Weak Password </li><li>Broken Authentication II </li><li>Mass Assignment II </li><li>Broken Function Level Auth II </li><li>Command Injection I </li><li>Command Injection II </li><li>SQL Injection </li><li>Race-Condition </li><li>Security Misconfiguration </li><li>Improper Input Validation I</li><li>Improper Input Validation II </li><li>Parameter Tampering I </li><li>Dictionary Attack </li><li>Misconfigured Permissions I </li><li>Export injection: Arbitrary File Read </li><li>Export Injection: Internal HTTP Resource </li><li>Export Injection: Port Scan </li><li>Vulnerable Forum – XSS </li> <li>Insecure Local Storage </li> | [Read More](https://attackdefense.com/listingnoauth?labtype=rest&subtype=rest-api-security)|
| This is a Laravel App which the owners used for several demos which are vulnerable to a number of vulnerabilities on the OWASP API top 10. This is not a CTF, the bugs are quite clear and not hidden, however I suspect this will be a useful demo! In this lab, you will find the following OWASP vulnerabilities: <br>Find out more about the [OWASP API Top 10](https://owasp.org/www-project-api-security/) <br> <ul> <li>API1:2019 Broken Object Level Authorization</li><li>API2:2019 Broken User Authentication</li><li>API3:2019 Excessive Data Exposure </li><li>API5:2019 Broken Function Level Authorization </li><li>API6:2019 Mass Assignment </li><li>API7:2019 Security Misconfiguration </li> | [Read More](https://github.com/InsiderPhD/Generic-University)|
|Following are the various access control vulnerabilities that are provided in the above link by PortSwigger: <br><ul><li>Unprotected admin functionality </li><li>Unprotected admin functionality with unpredictable URL</li><li>User role controlled by request parameter </li><li>User role can be modified in user profile </li><li>User ID controlled by request parameter </li><li>USER ID controlled by request parameter with unpredictable USER IDs</li><li>USER ID controlled by request parameter with data leakage in redirect </li><li>USER ID controlled by request parameter with password disclosure</li><li>Insecure Direct Object Reference </li><li>URL-based access control can be circumvented </li><li>Method-based access control can be circumvented </li><li>Multi-step process with no access control on one step </li><li>Referer-based access control </li> | [Read More](https://portswigger.net/web-security/access-control)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|The End Point notary.acronis.com Blocks access to the panel if you are not an authenticated user. More is possible to access some functions of the panel by adding the .html at the end  | [Read More](https://hackerone.com/reports/833735 )|
|This report explains Insufficient Access Control On Registration Page of Webapps Website Allows Privilege Escalation to Administrator  | [Read More](https://hackerone.com/reports/796379 )|
| This report explains Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or using a custom API attack tool | [Read More](https://hackerone.com/reports/895172 )|
| In this report, a reporter explains an IDOR to view order information of users and personal information. | [Read More](https://hackerone.com/reports/1323406 )|









## Insecure Deserialization 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This blog explains an insecure deserialization vulnerability in a private program that leads to remote code execution.  | [Read More](https://medium.com/bugbountywriteup/the-story-of-a-rce-on-a-java-web-application-2e400cddcd1e)|
|This blog contains the following key points: <br><ul><li>What is insecure deserialization </li><li>How do you know if the application is vulnerable to insecure deserialization? </li><li>How to prevent insecure deserialization</li>  | [Read More](https://medium.com/blog-blog/insecure-deserialization-e5398e83defe)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a great resource to learn about PHP Deserialization vulnerabilities by ippsec. | [Read More](https://www.youtube.com/watch?v=HaW15aMzBUM )|
|This resource explains the basic concepts of an Insecure Deserialization vulnerability by attacking a web app written in python. | [Read More](https://www.youtube.com/watch?v=jwzeJU_62IQ )|
| This resource could help you understand JAVA insecure deserialization by john hammond.  | [Read More](https://www.youtube.com/watch?v=GjwduwSltNU)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Following are the various insecure deserialization vulnerabilities that are provided in the above link by PortSwigger: <br> <ul> <li>Modifying serialized objects </li><li>Modifying serialized data types </li><li>Using application functionality to exploit insecure deserialization</li><li>Arbitrary objection injection in PHP </li><li>Exploiting Java deserialization with Apache Commons </li><li>Exploiting PHP deserialization with a pre-built gadget chain </li><li>Exploiting Ruby deserialization using a documented gadget chain </li><li>Developing a custom gadget chain for Java deserialization </li><li>Developing a custom gadget chain for PHP deserialization </li><li>Using PHAR deserialization to deploy a custom gadget chain </li>| [Read More](https://portswigger.net/web-security/deserialization)|
|In this lesson, you will learn how to use NG SAST to identify and fix areas of your code that facilitate insecure deserialization issues.  | [Read More](https://application.security/shiftleft/exercises/sl-deserialization)|
| This is simple Java client and server application that implements a custom network protocol using the Java serialization format to demonstrate Java deserialization vulnerabilities. | [Read More](https://github.com/NickstaDB/DeserLab)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains Remote Code Execution via Insecure Deserialization in Telerik UI  | [Read More](https://hackerone.com/reports/838196)|
|This report explains another Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935) | [Read More](https://hackerone.com/reports/1174185)|
|This report explains Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce | [Read More](https://hackerone.com/reports/403083)|





## OAuth authentication Vulnerabilities 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this part of blog, the author has discussed about<br><ul><li>What is OAuth 2.0? </li><li>OAuth Entities </li><li>OAuth Flows (Grant Types) </li><li>Authorization code grant </li><li>Implicit Grant </li> | [Read More](https://payatu.com/blog/anubhav.singh/oauth-grant-types)|
|In this blog, the author has explained: <br> <ul> <li>What is OAuth </li><li>Where is it used </li><li>OAuth Flows (Grant Types) </li><li>How does OAuth Work </li><li>Authorization Code grant (aka server-side flow) </li><li>Implicit Grant (aka client-side flow) </li>  | [Read More]( https://infosecwriteups.com/oauth-2-0-hacking-simplified-part-1-understanding-basics-ad323cb4a05c)|
|In this blog, the author has discussed the following common vulnerabilities that arise in the client application’s implementation of OAuth as well as in the configuration of the OAuth service itself: <br> <ul> <li>Improper implementation of the implicit grant type </li><li>Flawed CSRF protection </li><li>Leaking authorization codes and access tokens </li><li>Flawed scope validation </li><li>Unverified user registration </li><li>Host header injection </li><li>Reusable OAuth access token  </li> | [Read More](https://infosecwriteups.com/oauth-2-0-hacking-simplified-part-2-vulnerabilities-and-mitigation-d01dd6d5fa2c)|
|In this article, the author went through the most common security vulnerabilities encountered in applications that use the OAuth protocol. The protocol itself is reliable but it relies heavily on web developer awareness when implementing authorization, which makes this topic extremely important for developers to keep their user’s accounts and data secure. It also contains best practices to help mitigate the danger of bad OAuth implementation.  | [Read More](https://medium.com/swlh/oauth-vulnerabilities-implementing-secure-authorization-in-your-web-application-3b9517b34798)|
|This is a write-up of a chain of vulnerabilities (OAuth Misconfiguration, CSRF, XSS, and Weak CSP) that allowed the author to take over a user account using a single interaction. This was a usual Project Management Web Application, using Microsoft's OAuth 2.0 to authorize their users to allow them access to the application.  | [Read More](https://blog.dixitaditya.com/oauth-account-takeover)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Keynotes of the resource are: <br> <ul> <li>What is OAuth 2.0 </li><li>Uses of OAuth 2.0</li><li>Entities in OAuth 2.0 </li><li>Types of Flows of OAuth 2.0 </li><li>Authorization Code Grant Flow </li><li>Implicit Grant Flow </li><li>Practical Exploitation </li><li>Reusing Access Tokens </li><li>Redirect_uri Not Validated </li><li>CSRF</li>| [Read More](https://www.youtube.com/watch?v=0T8WG2liEC0)|
|Keynotes of the resource are: <br> <ul> <li>History of OAuth</li><li>OAuth 2.0 Basics </li><li>How OAuth 2.0 works</li><li>Authorization Code Grant </li><li>Implicit Grant </li><li>Where OAuth 2.0 is used </li><li>Attacks on OAuth 2.0 integrations </li><li>Token Stealing with POC </li><li>Code Stealing  </li><li>Token impersonation </li> | [Read More](https://www.youtube.com/watch?v=X0mV9HXbKHY)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Following are the labs in this topic that you will find from the above link: <br> <ul> <li>Authentication bypass via OAuth impliicit flow </li><li>Forced OAuth profile linking  </li><li>OAuth account hijacking via redirect_uri </li><li>Stealing OAuth access tokens via an open redirect </li><li>SSRF via OpenID dynamic client registration </li><li>Stealing OAuth access tokens via a proxy page </li>  | [Read More](https://portswigger.net/web-security/oauth)|
|This project contains a vulnerable OAuth 2.0 server, a vulnerable OAuth 2.0 classic web application client, and an attackers site exploiting it all.  | [Read More](https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications/tree/master/insecureapplication)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains Misconfigured oauth leads to Pre account takeover.  | [Read More](https://hackerone.com/reports/1074047)|
|This report explains how the reporter steals Users OAuth Tokens through redirect_uri parameter.  | [Read More](https://hackerone.com/reports/665651)|





## HTTP Request Smuggling 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This blog explains the following: <br> <ul> <li>What is HTTP Request Smuggling</li><li>What is the impact of HTTP Request Smuggling Attacks </li> <li>HTTP Request Smuggling Examples </li> <li>Advanced HTTP Request Smuggling Attacks </li> <li>How to mitigate an HTTP Request Smuggling Vulnerability </li>  | [Read More](https://www.imperva.com/learn/application-security/http-request-smuggling/)|
|This blog contains different attack scenarios with corresponding PoCs that are given below: <br><ul><li>CL.TE </li><li>TE.CL </li><li>TE.TE </li> | [Read More](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)|
|In this article: <br> <ul> <li>How Does an HTTP Smuggling Request Attack Work? </li><li>Which HTTP Features Make HTTP Request Smuggling Possible? </li><li>Keep Alive Mode </li><li>Pipelining </li><li>Chunks</li><br>Types of HTTP Smuggling <br><li>CL-TE </li><li>TE-CL </li><li>TE-TE Behavior: Obfuscating the TE Header </li><br>Advanced HTTP Request Smuggling Attacks<br> <li>Bypassing Security Filters</li><li>Replacement of Regular Response </li><li>Credentials Hijacking </li><br>HTTP Request Smuggling Prevention<br><li>Prioritize Transfer-Encoding over Content-Length </li>  <li>Disallow Requests with Both Content-length and Transfer Encoding </li>  <li>Disallow Malformed Transfer-Encoding Headers </li>      | [Read More](https://brightsec.com/blog/http-request-smuggling-hrs/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Using the above resource link, you will learn how HTTP/2 request smuggling works, explained through the medium of beer, and how this vulnerability was incorporated into the Web Security Academy labs | [Read More](https://www.youtube.com/watch?v=CpVGc1N_2KU)|
|In the video the author present and explain two reports from Hackerone that show how a bug hunter hacked Slack and Zomato, earning $6,500 and $5,000 respectively.  | [Read More](https://www.youtube.com/watch?v=gzM4wWA7RFo)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Following are the labs in this topic that you will find from the above link: <br> <ul> <li>HTTP Request smuggling, basic CL.TE vulnerability </li><li>HTTP Request smuggling, basic TE.CL vulnerability </li><li>HTTP Request smuggling, obfuscating the TE header </li><li>HTTP request smuggling, confirming a CL.TE vulnerability via differential responses </li><li>HTTP request smuggling, confirming a TE.CL vulnerability via differential responses </li><li>Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability </li><li>Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability </li><li>Exploiting HTTP request smuggling to reveal front-end request rewriting</li><li>Exploiting HTTP request smuggling to capture other user’s requests </li><li>Exploiting HTTP request smuggling to deliver reflected XSS </li><li>Response queue poisoning via H2.TE request smuggling</li> <li>H2.CL request smuggling </li> <li>HTTP/2 request smuggling via CRLF injection </li> <li>HTTP/2 request splitting via CRLF injection </li> <li>Exploiting HTTP request smuggling to perform web cache poisoning </li> <li>Exploiting HTTP request smuggling to perform web cache deception </li> <li>Bypassing access controls via HTTP/2 request tunneling </li> <li>Web cache poisoning via HTTP/2 request tunneling </li> | [Read More](https://portswigger.net/web-security/request-smuggling)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains how console.helium.com was vulnerable to CL.TE (Front end server uses Content-Length, Back-end Server uses Transfer-encoding) HTTP request smuggling attack.  | [Read More](https://hackerone.com/reports/867952)|
|This particular vulnerability abuses the CLTE variant of HTTP Request Smuggling as described in [PortSwigger's blog](https://portswigger.net/web-security/request-smuggling). The domain api.flocktory.com was found to be vulnerable to this attack through [Defparam's smuggler tool](https://github.com/defparam/smuggler).  | [Read More](https://hackerone.com/reports/955170)|
|This report explains how an attacker can poison the TCP / TLS socket and add arbitrary data to the next request. Depending on the functionality of the website, this can be used to bypass front-end security ruls, internal system access, poison the web cache, and launch various attacks on users who actively activate the site.  | [Read More](https://hackerone.com/reports/1120982)|





## JSONP Attack 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This writeup is about exploiting JSONP to extract private data from API endpoints and bypassing the security check by the server.  | [Read More](https://infosecwriteups.com/exploiting-jsonp-and-bypassing-referer-check-2d6e40dfa24)|
|In this blog, the author has explained JSONP Attack for Web Security Researchers that contains the following: <br> <ul> <li>Security Issue with JSONP </li> <li>Working Mechanism of JsonP Attack </li> <li>Requirements to Perform JSONP Attack</li>  | [Read More](https://payatu.com/blog/arjuns/Jsonp-attack)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a great video resource to know more about JSON Padding attack, it has been covered so nicely in this video. <br><ul><li>Malware site initiates XHR to profile data </li><li>Same origin policy bypass </li><li>JSON Hijacking</li> | [Read More](https://www.youtube.com/watch?v=9SqagAKYhy4)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains exploiting JSONP callback on /username/charts.json endpoint that leads to information disclosure despite user's privacy settings  | [Read More](https://hackerone.com/reports/361951)|
|In this report, the reporter has bypassed Same Origin Policy with JSONP APIs and Flash. You will find a detailed writeup of the vulnerability [here](https://blog.miki.it/2014/7/8/abusing-jsonp-with-rosetta-flash/).  | [Read More](https://hackerone.com/reports/10373)|



## Cross-site WebSocket Hijacking 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this section, the author has explained cross-site WebSocket hijacking (CSWSH), described the impact of a compromise, and spelled out how to perform a cross-site WebSocket hijacking attack. | [Read More](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)|
|In this blog, the author has discussed a scenario where developers might use WebSockets in a way to open up their applications to a vulnerability, Cross-Site WebSocket Hijacking (CSWSH) | [Read More](https://christian-schneider.net/CrossSiteWebSocketHijacking.html )|
|In this blog, we will look at the WebSocket protocol and the CSWSH vulnerability and how common it is on the open Internet. In the end, the author provided a cswsh-scanner utility and resources, which you can use to test how WebSocket applications can be compromised.  | [Read More](https://infosecwriteups.com/cross-site-websocket-hijacking-cswsh-ce2a6b0747fc)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this video resource it is explained that what could go wrong between client and server real time web socket communication and what traps we can fall into if we want to implement this functionality on our site.  | [Read More](https://www.youtube.com/watch?v=lrPPMDNpgdY)|
|In this video, the video creator has explained a good article of portswigger on web socket hijacking and, he solved some of the labs of web socket hijacking on portswigger for better understanding.  | [Read More](https://www.youtube.com/watch?v=sysyhbjWmdY)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this lab, you will find an online shop that has a live chat feature implemented using WebSockets that is vulnerable to cross-site websocket hijacking  | [Read More](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this report it has been explained that even after changing the origin header value with malicious origin, the web socket server responding with successful 101 handshake which means web socket server is not verifying the origin while opening the connection. | [Read More](https://hackerone.com/reports/274324)|
|In this report, the reporter reported a cross-site websocket hijacking vulnerability in socket.io that allows an attacker to bypass origin protection using special symbols include "`" and "$"  | [Read More](https://hackerone.com/reports/931197)|



## CRLF Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This post contains a short description about what is CRLF and an example.  | [Read More](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)|
|In this blog, the author has discussed: <br> <ul> <li>What are CRLF Injection Attacks</li><li>What is HTTP Response Splitting </li><li>Finding and Mitigating CRLF Injections </li> | [Read More](https://www.acunetix.com/websitesecurity/crlf-injection/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|You can watch this tutorial to learn about CRLF Injection and better understand the risk it brings to the security of your applications.  | [Read More](https://www.youtube.com/watch?v=RtFFqCe85Tk)|
|The video will teach you how you can find CRLF Injection using some of the methods. We will also learn how to use BURPBOUNTY Extension in Burp Suite to Automate CRLF Injection. With the help of CRLF Injection we can find vulnerabilities like XSS, Cookies Injection, Open Redirection.  | [Read More](https://www.youtube.com/watch?v=dQnJj6JfPwA)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This interactive lab demonstrates HTTP/2 request splitting via CRLF injection vulnerability. | [Read More](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this report, the reporter explained that https://ads.twitter.com was vulnerability to HTTP response splitting in the endpoint https://ads.twitter.com/subscriptions/mobile/landing that allows an attacker to add a malicious header in the response headers.  | [Read More](https://hackerone.com/reports/446271)|
|This report explains how the reporter discovered the endpoint at www.starbucks.com/email-prospectt that was affected by a CRLF injection / HTTP response splitting issue.  | [Read More](https://hackerone.com/reports/858650)|



## Remote File Inclusion 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This blog states the diffrences between RFI and LFI, some RFI examples and also explains how you can minimize the risk of RFI attacks through proper input validation and sanitization.  | [Read More](https://www.imperva.com/learn/application-security/rfi-remote-file-inclusion/)|
|In this short blog, you will find a basic example of a RFI vulnerability.  | [Read More](https://www.acunetix.com/blog/articles/remote-file-inclusion-rfi/ )|
|This post contains guides in which you will learn how to test for remote file inclusion vulnerability | [Read More](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In these resource, the author has exploited a Remote File Inclusion vulnerability in dvwa application. | [Read More](https://www.youtube.com/watch?v=MHBoCVvzXzc) [Read More](https://www.youtube.com/watch?v=EjauGmb_wDU)|
|The above resource link explains a walkthrough of a room named File Inclusion from tryhackme.com.  | [Read More](https://www.youtube.com/watch?v=Z-dz3LiNVAE)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| NA | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains how it was able to perform remote file inclusion on vulnerable application. | [Read More](https://hackerone.com/reports/14092)|



## JSON Web Token Attacks 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this lab walkthrough series, we go through selected lab exercises on our AttackDefense Platform.  | [Read More](https://blog.pentesteracademy.com/hacking-jwt-tokens-client-side-token-decode-9db43f10a3eb)|
|The above article is to create awareness about common JWT vulnerabilities. In the article, you will get to know about JSON Web Token, the structure of JSON Web Token and various methods to exploit JSON Web Tokens.  | [Read More](https://medium.com/@sajan.dhakate/exploiting-json-web-token-jwt-73d172b5bc02)|
|In this blog post the author has discussed what JWTs are and common vulnerabilities that come along with them such as: <br> <ul> <li>Brute Force Secret </li> <li>None Algorithm </li><li>RSA Vs HMAC </li><li>Incorrect Implementation </li> | [Read More](https://trustfoundry.net/jwt-hacking-101/)|
|This blog also explained basics attacks like None Algorithm, changing algorithm from RS256 to HS256, signature not being checked, cracking the secret key, use arbitrary files to verify. It also explained advanced attacks like SQL injection, forged header parameter and HTTP response header injection.  | [Read More](https://infosecwriteups.com/attacking-json-web-tokens-jwts-d1d51a1e17cb)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this resource, the author has explained how to bypass JWT signature check in weak implementations.  | [Read More](https://www.youtube.com/watch?v=ghfmx4pr1Qg) [Read More](https://www.youtube.com/watch?v=6r6148qGuis)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| There are multiple vulnerabilities within JSON Web Tokens. This is a quick and easy lab for you to understand the fundamentals of JWTs and how to exploit them. | [Read More](https://jwt-lab.herokuapp.com)|
|It is quite a simple lab, and the goal is to modify the token so that it says you are currently the Admin user. The following challenges are covered in this lab: <br> <ul> <li>None Algorithm </li><li>Exposed Key </li><li>Signature Not Checked </li><li>Weak Signature </li><li>Vulnerable Kid </li> | [Read More](https://adamc95.medium.com/json-web-token-lab-guide-c402857fa44c)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this report, the reporter discovered an insecure Zendesk SSO implementation by generating JWT client-side. | [Read More](https://hackerone.com/reports/1210502) [Read More](https://hackerone.com/reports/638635)|





## NoSQL Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This blog explains a mongoDB injection example in a PHP Application and also how to avoid NoSQL injections.  | [Read More](https://www.acunetix.com/blog/web-security-zone/nosql-injections/)|
|In this blog, you will learn: <br> <ul> <li>What is NoSQL database? </li> <li>How can you find NoSQL Injection?</li> <li>Javascript Injection in query</li> <li>Mitigation </li>  | [Read More](https://medium.com/rangeforce/nosql-injection-6514a8db29e3)|
|In this blog, you will learn: <br> <ul> <li>What is NoSQL database? </li> <li>How can you find NoSQL Injection?</li> <li>Javascript Injection in query</li> <li>Mitigation </li>  | [Read More](https://medium.com/rangeforce/nosql-injection-6514a8db29e3)|
| Following are the contents of this blog: <br><ul><li>What is NoSQL Injection? </li><li>NoSQL Databases </li><li>NoSQL Injection</li><li>How do NoSQL Injection Works? </li><li>How to Prevent NoSQL Injections? </li><li>Secure Coding Practices </li><li>Input Validation</li><li>Least Privilege Policy </li><ul> | [Read More](https://www.indusface.com/blog/what-is-nosql-injection-attack-and-how-to-prevent-it/) | 


|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Keynotes of the above resource are as follows: <br> <ul> <li>What is NoSQL </li><li>SQL vs NoSQL databases </li><li>SQL vs NoSQL injection </li><li>Lab Demo </li><li>Code Analysis </li><li>Exploitation of NoSQLi </li> | [Read More](https://www.youtube.com/watch?v=cuqkhLkekY4)|
|Keynotes of the above resource are as follows: <br> <ul> <li>What is NoSQL injection (NoSQLi)?  </li><li>How does NoSQLi compare to SQLi? </li><li>Evaluate MongoDb's claim that "traditional SQL injection attacks are not a problem" in MongoDb  </li><li>Evaluate how MongoDb can be exploited through BSON injection </li><li>Understand the execution contexts that queries are evaluated in (and how they can be exploited)  </li>| [Read More](https://www.youtube.com/watch?v=qamUR5sn0Bo)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this lab, the owner have built two different scenarios in this lab, an equivalent of the SQLi " or 1=1" vulnerability and also a new type of attack, which is specific to NoSQL, script injection.  | [Read More](https://digi.ninja/projects/nosqli_lab.php)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains Pre-Auth Blind NoSQL Injection leading to Remote Code Execution | [Read More](https://hackerone.com/reports/1130721)|
| This report explains Account takeover vulnerability due to blind MongoDB injection in password reset | [Read More](https://hackerone.com/reports/386807)|




## HTML Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This document explains the testing methodology for HTML injection.  | [Read More](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)|
|This blog covers the following topics: <br> <ul> <li>What is HTML? </li><li>Introduction to HTML Injection </li><li>Impact of HTML Injection </li><li>HTML Injection v/s XSS </li><li>Types of Injection </li><li>Stored HTML </li><li>Reflected HTML </li><li>Reflected GET </li><li>Reflected POST </li><li>Reflected current URL </li><li>Mitigation Steps </li> | [Read More](https://www.hackingarticles.in/comprehensive-guide-on-html-injection/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This video explains the basics of HTML injection and performed HTML injection on vulnerable application (OWASP Mutillidae II)  | [Read More](https://www.youtube.com/watch?v=sLdxy1u2pdo )|
| This video discusses basic concepts of HTML injection. | [Read More](https://www.youtube.com/watch?v=x6u52n3TjiI)|
| This video discusses how to exploit HTML injection with tag attribute. | [Read More](https://www.youtube.com/watch?v=h9HB_VVN0hU)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This vulnerable lab is an instance of the OWASP bWAPP project as a docker container. In that instance, you can find html injection vulnerability.  | [Read More](https://github.com/raesene/bWAPP)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains a HTML injection in email which leads to an attacker can trick victim to click on such hyperlinks to redirect him to any malicious site and can host a XSS page | [Read More](https://hackerone.com/reports/1248585)|
| This report explains a HTML injection vulnerability on mycrypto.com | [Read More](https://hackerone.com/reports/324548)|




## XPATH Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This document explains XPATH injection using an example of a web application that uses XPath to query an XML document. | [Read More](http://projects.webappsec.org/w/page/13247005/XPath%20Injection)|
| In this blog, the author has explained XPATH Injection using a scenario in which a website uses XML for storing user's credentials and other information. | [Read More](https://medium.com/@shatabda/security-xpath-injection-what-how-3162a0d4033b)|
|In this blog, you will understand XPATH injection with practical examples.  | [Read More](https://infosecwriteups.com/understanding-xpath-injection-with-practical-examples-6aa81043e4aa)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Keynotes of the above resource are: <br> <ul> <li>What is XPATH </li><li>XPath Query </li><li>Demo </li><li>The owner has walked us through with an example of actual exploiting with XPath injection </li> | [Read More](https://www.youtube.com/watch?v=rFXDr5KVdAc)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains how Xpath Injection query executed in java application.  | [Read More](https://hackerone.com/reports/824925)|




## CSS Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This document provides a testing guide for CSS injection. | [Read More](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection)|
|This blog explains exfiltration via CSS injection in a real site where the author has discussed data exfiltration from input elements.  | [Read More](https://infosecwriteups.com/exfiltration-via-css-injection-4e999f63097d)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In these video resources, the video creator has explained how the user supplied malicious input becomes a part of CSS property value which can result into executing javascript.  | [Read More](https://www.youtube.com/watch?v=sf7vjnVX4Gk) [Read More](https://www.youtube.com/watch?v=cp-yTK7dJJk)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains CSS injection in avito.ru via IE11.  | [Read More](https://hackerone.com/reports/276747)|
|This report explains how CSS Injection on /embed/ via bgcolor parameter leaks user's CSRF token and allows for XSS.  | [Read More](https://hackerone.com/reports/386334)|
|This report explains CSS injection via BB code tag.  | [Read More](https://hackerone.com/reports/587727)|





## SMTP/IMAP Command Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This document provides a testing guide for SMTP Injection. | [Read More](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection)|
| This blog explains SMTP injection using a lab walkthrough of Haraka using metasploit. Haraka is a lab on AttackDefense Platform.  | [Read More](https://blog.pentesteracademy.com/haraka-smtp-command-injection-d3bd46ac3b21)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Keynotes of the above resource are as follows: <br> <ul> <li>What is email header injection </li><li>What is IMAP SMTP injection? </li><li>What is SMTP injection?  </li><li>What is IMAP SMTP injection?  </li><li>What is email injection attack? </li><li>What is email header injection?</li>  | [Read More](https://www.youtube.com/watch?v=kV50llAIgXI)|
| The above resource talks about mail header injection in detail. | [Read More](https://www.youtube.com/watch?v=zIWaxBCr3m4 )|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This vulnerable lab is an instance of the OWASP bWAPP project as a docker container. In that instance, you can find smtp injection vulnerability.  | [Read More](https://github.com/raesene/bWAPP)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this report SMTP was vulnerable to RCPT TO/MAIL FROM injection due to lack of input validation and conformance to the SMTP protocol.  | [Read More](https://hackerone.com/reports/137631)|
| In this report it is explained how the vulnerability allows a MITM attacker between a mail client and Dovecot to inject unencrypted commands into the encrypted TLS context, redirecting user credentials and mails to the attacker. | [Read More](https://hackerone.com/reports/1204962)|
| This report explains how SMTP header injection on vulnerable application leads to mass arbitrary email sending. | [Read More](https://hackerone.com/reports/347439)|




## LDAP Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This blog explains how LDAP injection can be used to bypass authentication and also discusses about remediation for LDAP Injection.  | [Read More](https://gupta-bless.medium.com/ldap-injection-from-a-developers-perspective-7b5c8f8b2684)|
| This blog discusses following: <br> <ul> <li>What is an LDAP Injection? </li><li>How do LDAP Injection work? </li><li>What types of LDAP injection attacks are there? </li><li>How to prevent LDAP injection attacks </li> <li>Difference between SQL injection and LDAP injection.</li> | [Read More](https://www.techtarget.com/searchsoftwarequality/definition/LDAP-injection)|
|In this article, you will learn <br> <ul> <li>What is LDAP Injection? </li><li>How Do LDAP Injection Attacks Work? </li><li>Types of LDAP Injections </li><li>Access Control Bypass </li><li>Elevation of Privileges </li><li>Information Disclosure </li><li>LDAP Injection Examples Using Logical Operators </li><li>AND LDAP Injection </li><li>OR LDAP Injection </li><li>BLIND LDAP Injections </li><li>AND Blind LDAP Injection </li><li>OR Blind LDAP Injection </li><li>How to Prevent LDAP Vulnerabilities </li><li>Sanitize Inputs and Check Variables </li><li>Don’t Construct Filters by Concatenating Strings </li><li>Use Access Control on the LDAP Server </li> </li>Restrict User Requests in Other Ways </li>Dynamic Application Security Testing (DAST) </li>  | [Read More](https://brightsec.com/blog/ldap-injection/)|
|Table of contents for this blog: <br> <ul> <li>What is LDAP injection? </li><li>How does LDAP injection work? </li><li>How can your organization defend against LDAP injection attacks?</li> | [Read More](https://www.synopsys.com/glossary/what-is-ldap-injection.html)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A| [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|




## CSV Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this article, you will learn about CSV injection and also get to know about some of the functions which can be used by attackers to inject malicious payloads. | [Read More](https://payatu.com/csv-injection-basic-to-exploit/)|
|This article has covered the following topics: <br> <ul> <li>What are CSV files? </li><li>Spreadsheets and Formulas </li><li>CSV injection </li><li>Malicious Links</li><li>CSV applications </li><li>Dynamic Data exchange </li><li>How to mitigate CSV injection attacks </li>| [Read More](https://medium.com/cryptogennepal/what-is-a-csv-injection-attack-9208b54b4598)|
| This blog discusses CSV/Formula injection and how does it happen. It also explains two ways by which CSV injection can affect the users.   | [Read More](https://medium.com/@shatabda/security-csv-or-formula-injection-what-how-88cefba8e3df)|


|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This resource explains how CSV injection works and it covers basics of CSV injection attack such as executing commands and adding links in excel file.  | [Read More](https://www.youtube.com/watch?v=NmtsyWixoo4)|
|This is a video resource which will help you understand CSV injection in depth as they have demonstrated it in XVWA lab.  | [Read More](https://www.youtube.com/watch?v=FxXeiOd-nPs)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains that if the application does not escape or sanitize user input properly in excel file then any malicious user can take advantage of this vulnerability and can run base OS commands on any anonymous user account.  | [Read More](https://hackerone.com/reports/386116)|
|In this report the author has explained how he was able to bypass mitigations on CSV injection with different/custom payload and achieved CSV injection vulnerability.  | [Read More](https://hackerone.com/reports/118582)|



## LOG Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This blog discusses log injection vulnerability along with an example scenario where an attacker can forge the logs by inserting a fake record.  | [Read More](https://medium.com/@shatabda/security-log-injection-what-how-a510cfc0f73b)|
|In this blog, the author has discussed about  <br> <ul> <li>What are logs </li><li>Different types of logs </li><li>Log injection vulnerability </li><li>Mitigation </li>  | [Read More](https://www.geeksforgeeks.org/log-injection/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This resource is a video POC in which the attacker has performed Log file injection with the help of LFI and achieved system code execution.  | [Read More](https://www.youtube.com/watch?v=fyubF6VAagY)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|




## Insecure Direct Object Reference (IDOR) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This blog is Part-1 of the series, you will learn about these topics: <br> <ul> <li>Intro to IDOR </li><li>What is IDOR </li><li>Implications of IDOR </li><li>How to find IDOR’s </li> | [Read More](https://vickieli.medium.com/intro-to-idor-9048453a3e5d)|
|In the final part of the blog, the author has discussed about: <br> <ul> <li>Unsuspected places to look for IDOR’s </li><li>HTTP Parameter Pollution </li><li>Blind IDORs </li><li>How to increase the impact of IDOR </li> | [Read More](https://vickieli.medium.com/how-to-find-more-idors-ae2db67c9489)|
| In this blog, the author has examined the IDOR vulnerability topic in three main topics that are: <br> <ul> <li>Problem Definitions</li><li>AuthMatrix </li><li>Demo </li><li>Mitigation </li><li>Testing with AutoChrome </li> | [Read More](https://medium.com/@aysebilgegunduz/everything-you-need-to-know-about-idor-insecure-direct-object-references-375f83e03a87)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This resource will help you to understand the cause of vulnerability, vulnerable code and it covers basics of the IDOR (insecure direct object reference) vulnerability. | [Read More](https://www.youtube.com/watch?v=rloqMGcPMkI)|
| Key notes of this resource are: <br> <ul> <li>Theory: What is IDOR and how to find them  </li><li>Case studies: 7 examples of IDOR which have been paid out  </li><li>Practical burp: Looking at the hacker101 CTF level “Postbook”</li>  | [Read More](https://www.youtube.com/watch?v=viWzbPuGqpo)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a portswigger academy lab which is good for practicing insecure direct object reference (IDOR) vulnerability. | [Read More](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains how an attacker was able to edit and remove courses from other user's account. Even an attacker could remove all courses of all users by iterating through the course id.  | [Read More](https://hackerone.com/reports/227522)|
|In this report it is explained that a simple tampering of user id parameter can lead to leak information of other users.  | [Read More](https://hackerone.com/reports/751577)|
|This report explains IDOR, In the application any malicious user can iterate through the order ID to view other user’s details or order information.  | [Read More](https://hackerone.com/reports/287789)|




## Web Cache Poisoning 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This blog covers the following topics: <br> <ul> <li>What is Web Cache </li><li>Types of Caches </li><li>Cache Keys </li><li>Web Cache Poisoning </li><li>Ways of Cache Poisoning </li><li>Impact of a web cache poisoning </li><li>Methodology to find cache poisoning vulnerability </li><li>How to prevent web cache poisoning </li> | [Read More](https://medium.com/webappsec/web-cache-poisoning-29d7dcd7bd2c)|
| This section talks about what web cache poisoning is and what behaviors can lead to web cache poisoning vulnerabilities. It also looks at some ways of exploiting these vulnerabilities and suggests ways you can reduce your exposure to them.  | [Read More](https://portswigger.net/web-security/web-cache-poisoning)|
| This blog discusses a critical web cache poisoning vulnerability. The author has also discussed web poisoning attacks and how to validate web cache poisoning. | [Read More](https://infosecwriteups.com/finding-my-first-critical-web-cache-poisoning-6f956799371c?gi=ff276a00bde4)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Key notes of this resource are: <br> <ul> <li>Introduction </li><li>What is cache </li><li>Cache keys </li><li>How does web cache poisoning work </li><li>Lab </li><li>summary </li> | [Read More](https://www.youtube.com/watch?v=N6F2vngktrw)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains a scenario of web cache poisoning in which an attacker can alter web cache and make applications unavailable to other users as long as they wish.  | [Read More](https://hackerone.com/reports/1183263)|
|This report explains how they have performed web cache poisoning with different request headers (unkeyed input) to poison the cache. Cache poisoning is caused by different requests hitting the same cache. With web cache vulnerability it is possible to perform attacks such as XSS, javascript injection and open redirection etc.  | [Read More](https://hackerone.com/reports/1010858)|



## SQL Injection (Multiple Cases) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a beginner guide to understand what causes SQL vulnerability to arise. With this reference, you can learn: <br> <ul> <li>How injected payload gets concatenated with backend code. </li><li>Overview of Vulnerability, Threat Modeling and Risk Factors. </li><li>How to avoid SQL injection vulnerability. </li><li>Review code for SQL injection vulnerability. </li><li>How to test for SQL injection vulnerability. </li><li>How to bypass the web application Firewall.</li>| [Read More](https://owasp.org/www-community/attacks/SQL_Injection)|
| This guide covers a couple of topics for SQL injection mentioned below: <br> <ul> <li>Injection Detection. </li><li>DBMS Identification.</li><li>njection Techniques.</li><li>Attack Queries. </li>| [Read More](https://sqlwiki.netspi.com/)|
| It is a beginner guide to detect and exploit blind SQL injection. Using SQL injection vulnerability, how one can perform: <br> <ul> <li>Time bases blind SQLi. </li><li>Parameters that should be tested for SQLi. </li><li>Payload list for MySQL blind (Time Bases). </li><li>Payload list for Microsoft SQL Server Blind (Time Bases). </li><li>Oracle Blind (Time Bases). </li><li>Generic Time-Based SQL injection payloads.</li><li>Detection and Exploitation.</li><li>Blind SQL injection in JSON.</li><li>Blind SQL injection in Graphql.</li><li>Http header based (Error based, Time Based).</li><li>Blind SQL injection exploitation via SQLMAP.</li> <li>Blind SQL injection WAF bypass (tamper).</li> <li>SQL detection payload (Generic Error).</li> <li>SQL Injection Auth Bypass.</li>  | [Read More](https://ansar0047.medium.com/blind-sql-injection-detection-and-exploitation-cheatsheet-17995a98fed1)|
| This guide may help you while hunting for SQL injection vulnerabilities. With this reference any individual can learn things such as: <br> <ul> <li>What is SQL injection</li><li>Entry point detection</li><li>Comments in SQL</li><li>Confirming Vulnerability with logical operations.</li><li>Confirming vulnerability with Timing.</li><li>Backend Identification.</li><li>Exploiting Union Based SQL injection.</li><li>Extracting of databases name, tables and columns.</li><li>Exploitation of hidden union based</li><li>Exploiting error based.</li><li>Exploiting Blind SQLi.</li><li>Exploiting Error Blind SQLi.</li><li>Exploiting Time Based SQLi.</li><li>Stacked Queries.</li><li>Out of band exploitation.</li><li>Automated Exploitation.</li><li>Authentication Bypasses.</li><li>Polyglot Injection. </li><li>Modify password of existing Object/User.</li><li>SQL Truncation Attack.</li><li>MySQL Insert time-based checking</li><li>ON DUPLICATE KEY UPDATE</li><li>Extract information</li><li>Using decimal or hexadecimal</li><li>Routed SQL injection</li><li>WAF Bypass </li> | [Read More](https://book.hacktricks.xyz/pentesting-web/sql-injection)|


|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A| [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A| [Read More]()|




## Server-Side Request Forgery (SSRF) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a beginner guide to exploit Server-Side Request Forgery. Using SSRF vulnerability, how one can perform: <br> <ul> <li>Local/Remote Port Scan </li><li>Local File Read (using file:///) </li><li>Interact with internal apps/service/network </li><li>RCE by chaining services on internal network </li><li>Read metadata cloud (AWS, Azure, Google Cloud, Digital Ocean) </li><li>Reflected XSS/CSRF</li>| [Read More](https://infosecwriteups.com/exploiting-server-side-request-forgery-ssrf-vulnerability-faeb7ddf5d0e)|
|This Guide-To-SSRF may help you learn SSRF vulnerability with different techniques with references. It covers:<br> <ul> <li>The Basics.</li><li>Server-Side Request Forgery Prevention.</li><li>Powerful tools for automation of finding SSRF bug.</li><li>SSRF Techniques (Mindmap).</li><li>Writeups.</li><li>HackerOne Reports.</li><li>PayloadAllTheThings SSRF. </li>| [Read More](https://github.com/MustafaSky/Guide-to-SSRF)|
|It is a basic approach to SSRF attack that covers: <br> <ul> <li>SSRF definition.</li><li>SSRF Types. </li><li>Blind SSRF.</li><li>Detected SSRF.</li><li>Why does SSRF occur.</li><li>Impact of SSRF attack.</li><li>Approaching the SSRF such import function.</li><li>Web Hooks.</li><li>Bypassing Basic Filters.</li><li>Reading the AWS Metadata.</li>| [Read More](https://payatu.com/blog/arjuns/a-basic-approach-to-ssrf)|
| In this complete guide to Server-Side Request Forgery, an individual can learn:<br> <ul> <li>How Does an SSRF Attack Take Place</li><li>SSRF Attacks Against the Server Itself</li><li>SSRF Attacks Against Other Back-End Systems</li><li>Circumventing Common SSRF Defenses</li> | [Read More](https://www.prplbx.com/resources/blog/ssrf-guide/)|
|This is a bug writeup which was found on vimeo upload function, eventually functionality was vulnerable to SSRF attack, follow this reference to know more: <br> <ul> <li>The Journey.</li><li>Detection.</li><li>Exploitation.</li>  | [Read More](https://dphoeniixx.medium.com/vimeo-upload-function-ssrf-7466d8630437)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|




## XXE Injection (XML Entity Injection) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|It is a beginner guide to understand XXE vulnerability at surface level. Some of the examples are explained in simple terms. Topics that have been covered: <br> <ul> <li>Description.</li><li>Risk Factors</li><li>Examples</li><li>Accessing a local resource</li><li>Remote Code Execution</li><li>Disclosing /etc/passwd or other targeted files </li> | [Read More](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)|
|It is a guide that lets you deep dive into XXE Injection vulnerability. Things & Topics that can be learned with this reference:<br> <ul> <li>XML and its ENTITYs</li><li>Injection Fun</li><li>Sneaking Out of Band</li><li>Pass the SOAP</li><li>Recon with XXE</li>  | [Read More](https://www.synack.com/blog/a-deep-dive-into-xxe-injection/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|




## Directory Traversal  
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this beginner guide of OWASP, directory traversal is explained with some examples. It covers:<br> <ul> <li>Overview or Description of the vulnerability.</li><li>How to Avoid Path Traversal Vulnerabilities</li><li>How to Test for Path Traversal Vulnerabilities</li><li>Request variations</li><li>OS specific</li><li>Examples</li><li>Absolute Path Traversal. </li> | [Read More](https://owasp.org/www-community/attacks/Path_Traversal)|
|It is a beginner guide to learn directory traversal vulnerability. These are the topics that are explained in the blog:<br> <ul> <li>What is a Directory Traversal attack?</li><li>What an attacker can do if your website is vulnerable.</li><li>Example of a Directory Traversal attack via web application code.</li><li>Example of a Directory Traversal attack via web server.</li><li>How to check for Directory Traversal vulnerabilities.</li><li>Preventing Directory Traversal attacks.</li> | [Read More](https://www.acunetix.com/websitesecurity/directory-traversal/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A| [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|N/A | [Read More]()|





## Cross-Site Request Forgery (CSRF) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a beginner guide to better understand CSRF vulnerability. CSRF prevention and some of the examples are explained in this guide: <br> <ul> <li>Overview and description of vulnerability.</li><li>Review code for CSRF vulnerability.</li><li>Test and prevention for CSRF vulnerability.</li><li>Prevention measures that do NOT work</li><li>How does the attack work with Examples.</li> | [Read More](https://owasp.org/www-community/attacks/csrf)|
|In this Cross-Site Request Forgery guide, you will learn all about CSRF attacks (Concepts) and CSRF protection: <br> <ul> <li>Key Concepts of Cross-Site Request Forgery</li><li>How Cross-Site Request Forgery Attacks Work</li><li>Executing a CSRF Attack</li><li>Another Cross Site Request Forgery Example</li><li>Preventing Cross-Site Request Forgery Vulnerabilities</li><li>Finding and Remediating Cross-Site Request Forgery Vulnerabilities</li>  | [Read More](https://www.veracode.com/security/cross-site-request-forgery-guide-learn-all-about-csrf-attacks-and-csrf-protection)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This is an awesome video resource to get to know about CSRF vulnerability. Here CSRF is explained in depth from basic to advanced it also covers Json based CSRF. | [Read More](https://www.youtube.com/watch?v=eWEgUcHPle0)|
|This video resource will help you to understand how CSRF Token works and to be protected against CSRF attacks.  | [Read More](https://www.youtube.com/watch?v=Ub5TLow9GL4)|
|Key notes of this resource are: <br> <ul> <li>What is CSRF </li><li>CORS and CSRF </li><li>Preventing CSRF Attacks </li><li>CSRF Token  </li><li>What is the Impact </li><li>What makes them great first bug </li><li>How to find them </li><li>CSRF at that lead to submit your request automatic with </li><li>CSRF trial 14 days express subscription </li><li>File upload plugin: CSRF (delete all attached file) </li><li>Account takeover at due to no CSRF protection in connecting yahoo account  </li><li>CSRF leads to self-stored XSS </li><li>CSRF on periscope web Oauth authorization endpoint yet another </li><li>Tips and tricks to finding CSRF</li>| [Read More](https://www.youtube.com/watch?v=ULvf6N8AL2A)|
| Key notes of this resource are: <br> <ul> <li>Introduction  </li><li>Agenda </li><li>What is CSRF Vulnerability </li><li>How to find CSRF vulnerabilities </li><li>How to exploit CSRF vulnerabilities </li><li>How to prevent CSRF vulnerabilities </li><li>Resources </li> | [Read More](https://www.youtube.com/watch?v=7bTNMSqCMI0)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This above link is the reference of portswigger which can be a plus to understand exploitation and prevention of CSRF vulnerabilities. These are the following labs that you will find in this above link: <br> <ul> <li>CSRF vulnerability with no defenses</li><li>CSRF where token validation depends on request method</li><li>CSRF where token validation depends on token being present </li><li>CSRF where token is not tied to user session </li><li>CSRF where token is tied to non-session cookie </li><li>CSRF where token is duplicated in cookie </li><li>CSRF where Referer validation depends on header being present </li><li>CSRF with broken Referer validation  </li> | [Read More](https://portswigger.net/web-security/csrf)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains how it was possible to bypass CSRF protection in the application.   | [Read More](https://hackerone.com/reports/834366)|
|This issue could not be exploited directly. It’s a path traversal leading to limited CSRF on GET request on two endpoints.	  | [Read More](https://hackerone.com/reports/301862)|




## Cross-Site Scripting (XSS) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a beginner guide to understand the basics of cross-site scripting vulnerability, impact and its types. Things that you can learn from this reference: <br> <ul> <li>What is cross-site scripting</li><li>Reflected cross site scripting</li><li>Stored cross site scripting</li><li>DOM based cross-site scripting </li><li>Impact of cross-site scripting </li><li>Blind cross-site scripting </li><li>Self-XSS </li><li>Prevention of cross site scripting</li> | [Read More](https://blog.intigriti.com/hackademy/cross-site-scripting-xss/)|
|This pentester’s guide to understand cross-site scripting may help you learn basics of cross-site scripting and it also contains number of the payloads with different context that can be used later on while hunting for this specific vulnerability: <br> <ul> <li>What is a Cross-Site Scripting Attack </li><li>What’s the Impact of XSS </li><li>How to Exploit XSS </li><li>Cross-Site Scripting (XSS) Cheatsheet </li><li>Restrictions Bypasses </li><li>WAF Bypasses</li><li>How to Prevent It </li> | [Read More](https://www.cobalt.io/blog/a-pentesters-guide-to-cross-site-scripting-xss)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|N/A  | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|





## Cross Origin Resource Sharing (CORS) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This guide will help you to understand some topics of cross origin resource sharing such as: <br> <ul> <li>Description of CORS</li><li>HTTP Request Headers in CORS </li><li>HTTP Response Headers</li><li>CORS Preflight Request </li> | [Read More](https://medium.com/iocscan/cross-origin-resource-sharing-cors-65b536b361ae)|
|In this guide you will get to know more about CORS vulnerability and its concepts with examples: <br> <ul> <li>Cross-Origin Resource Sharing (CORS) Overview </li><li>What requests use CORS </li><li>Examples of access control scenarios</li><li>Preflight requests </li><li>Preflight requests and redirects </li><li>Requests with credentials </li><li>Preflight requests and credentials </li><li>Credentialed requests and wildcards </li><li>HTTP response headers </li><li>Access-Control-Expose-Headers </li><li>Access-Control-Allow-Credentials </li><li>Access-Control-Allow-Methods </li> | [Read More](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#requests_with_credentials)|
| This is the beginner guide to understand CORS misconfiguration and what is the root cause of CORS Vulnerability. Topics that you will get in this guide: <br> <ul> <li>About CORS </li><li>Request Headers and Response Headers </li><li>Input Validation </li><li>How to Test </li><li>CORS Misconfiguration </li><li>Wildcard Access-Control-Allow-Origin </li><li>Dynamic CORS Policy</li><li>Input Validation Weakness</li><li>Remote XSS with CORS</li><li></li> | [Read More](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)|
|This portswigger guide will help you to understand everything that you should know about CORS and it has labs also that you can use to exploit CORS Misconfiguration: <br> <ul> <li>What is CORS </li><li>Same-origin policy </li><li>Relaxation of the same-origin policy</li><li>Vulnerabilities arising from CORS configuration issues </li><li>Server-generated ACAO header from client-specified Origin header </li><li>Errors parsing Origin headers </li><li>Whitelisted null origin value </li><li>Exploiting XSS via CORS trust relationships</li><li>Breaking TLS with poorly configured CORS </li><li>Intranets and CORS without credentials</li><li>How to prevent CORS-based attacks </li> | [Read More](https://portswigger.net/web-security/cors)|
|This is research on exploiting CORS misconfiguration for bitcoin and bounties by James Kettle: <br> <ul> <li>What is CORS </li><li>CORS for hackers </li><li>Hidden in plain sight </li><li>The null origin </li><li>Breaking parsers </li><li>Breaking HTTPS </li><li>Abusing CORS without credentials </li><li>Vary: origin </li><li>Client-Side cache poisoning </li><li>Server-Side cache poisoning </li> | [Read More](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this video resource you will learn what is CORS and Why we need it. You will understand how we can bypass the same origin policy with CORS and how HTTP headers are used to customize CORS implementation.  | [Read More](https://www.youtube.com/watch?v=h-WtIT6gCBk)|
| Key notes of this resource are: <br> <ul> <li>Introduction </li><li>Web security academy course </li><li>Agenda </li><li>What is CORS vulnerability  </li><li>How to find CORS vulnerability </li><li>How to exploit CORS vulnerability </li><li>How to prevent CORS vulnerability </li><li>Resources </li>| [Read More](https://www.youtube.com/watch?v=t5FBwq-kudw)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Above link is a reference to portswigger academy where you can practice CORS vulnerabilities. This above link contains the following labs: <br> <ul> <li>CORS vulnerability with basic origin reflection </li><li>CORS vulnerability with trusted null origin </li><li>CORS vulnerability with trusted insecure protocols</li><li>CORS vulnerability with internal network pivot attack</li>  | [Read More](https://portswigger.net/web-security/cors)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains how CORS misconfiguration could lead to disclosure of sensitive information. | [Read More](https://hackerone.com/reports/426165)|
| In this reports, it shows how CORS misconfiguration in nordvpn led to leak private information, Account takeover. | [Read More](https://hackerone.com/reports/758785)|
| This report explains how CORS misconfigured found on niche.com, Using this misconfiguration attacker can do many actions depending on the functionality of application. | [Read More](https://hackerone.com/reports/426147)|




## Clickjacking 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a basic guide on performing clickjacking attacks which includes these topics: <br> <ul> <li>What is Clickjacking </li><li>A live demo </li><li>Preventing clickjacking attacks </li><li>Content-Security-Policy </li><li></li> | [Read More](https://www.appsecmonkey.com/blog/clickjacking)|
| This guide will help you to understand the anatomy of clickjacking attacks with sample application: <br> <ul> <li>What is Clickjacking </li><li>What is Clickjacking </li><li>Types of Clickjacking Attacks </li><li>Clickjacking in Action </li><li>Set up the environment </li><li>Launch the clickjacking attack </li><li>Anatomy of the attack</li><li>Differences with CSRF </li><li>Prevent Clickjacking Attacks</li> | [Read More](https://auth0.com/blog/preventing-clickjacking-attacks/)|
|In this reference clickjacking attack is explained in detail with example and also you can use this reference to know if your website is vulnerable to clickjacking attack with some simple steps: <br> <ul> <li>Clickjacking Overview </li><li>Clickjacking Examples </li><li>Clickjacking Impact </li><li>Clickjacking Prevention</li><li>How To Check If My Site Is Vulnerable </li> | [Read More](https://www.acunetix.com/blog/web-security-zone/defend-against-clickjacking-attacks/)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Key notes of this resource are: <br> <ul> <li>Example </li><li>How it works </li><li>Variations </li><li>False Reporting</li><li>Mitigations </li> | [Read More](https://www.youtube.com/watch?v=jcp5t8PsMsY)|
| Key notes of this video resource are: <br> <ul> <li>Intro </li><li>Lab Overview </li><li>What is an iframe </li><li>Cascading style sheets </li><li>Crafting the payload </li><li>Solving the lab</li><li>Conclusion</li> | [Read More](https://www.youtube.com/watch?v=_tz0O5-cndE)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Following are the labs in this topic that you will find from the above link: <br> <ul> <li>Basic clickjacking with CSRF token protection </li><li>Clickjacking with form input data prefilled from a URL parameter </li><li>Clickjacking with a frame buster script </li><li>Exploiting clickjacking vulnerability to trigger DOM-based XSS</li><li>Multistep clickjacking</li>  | [Read More](https://portswigger.net/web-security/clickjacking)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this report the author has explained how he was able to find clickjacking on vulnerable websites, by that he was able to load iframes on vulnerable websites. Keystrokes can also be hijacked with clickjacking.  | [Read More](https://hackerone.com/reports/405342)|
| In this report the author has found that the application is vulnerable to clickjacking on authenticated pages which could be critical, an attacker can exploit it to change user's details. | [Read More](https://hackerone.com/reports/765355)|



## Server-Side Template Injection (SSTI) 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this beginner guide, you will learn about SSTI basics and Remote code execution on JINJA2 Template: <br> <ul> <li>What is template </li><li>What is server-side template injection </li><li>How is that exploitable </li><li>Remote Code execution</li><li>Show me the source code of the vulnerable app </li><li>Tplmap Tool.</li>  | [Read More](https://secure-cookie.io/attacks/ssti/)|
|In this reference, there is a basic lab solution example of SSTI vulnerability available on portswigger, Number of labs are available on the portswigger academy to practice this vulnerability: <br> <ul> <li>Template Inejction Description </li><li>Vulnerability Detection </li><li>Identification </li><li>Exploitation </li> | [Read More](https://jaypomal.medium.com/server-side-template-injection-lab-1-basic-ssti-ff2acf1d2d84)|
|This is an article on Server-side Request forgery (SSTI) by James Kettle available on portswigger, in which you will get to learn in depth about the vulnerability: <br> <ul> <li>Introduction </li><li>Template Injection methodology</li><li>Exploit development (for different templates) </li><li>Case study: Alfresco </li><li>Case study: XWiki Enterprise </li><li>Mitigations - templating safely</li>   | [Read More](https://portswigger.net/research/server-side-template-injection)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a video resource that could help you initially to learn SSTI (Sever side temple injection). It covers basics of SSTI, Template engine, Template injection and language specific templates. | [Read More](https://www.youtube.com/watch?v=SN6EVIG4c-0)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Following are the labs in this topic that you will find from the above link: <br> <ul> <li>Basic server-side template injection</li><li>Basic server-side template injection (code context) </li><li>Server-side template injection using documentation </li><li>Server-side template injection in an unknown language with a documented exploit</li><li>Server-side template injection with information disclosure via user-supplied objects </li><li>Server-side template injection in a sandboxed environment</li><li>Server-side template injection with a custom exploit </li> | [Read More](https://portswigger.net/web-security/server-side-template-injection)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains server-side template injection in return magic email templates. It is not fully exploited SSTI but a kind of template injection. | [Read More](https://hackerone.com/reports/423541)|



## Local File Inclusion 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This guide has a brief definition of Local file inclusion vulnerability with example code: <br> <ul> <li>What is LFI </li><li>Basic vulnerable PHP Code to LFI </li><li>Directory Traversal </li><li>Finding and Preventing Local File Inclusion (LFI) Vulnerabilities </li>| [Read More](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)|
|In this guide, LFI is explained in depth with example and vulnerable code and some important things that you can add to your checklist while looking for this vulnerability such as: <br> <ul> <li>What is a Local File Inclusion (LFI) vulnerability </li><li>Identifying LFI Vulnerabilities within Web Applications </li><li>PHP Wrappers </li><li>LFI via /proc/self/environ </li><li>Null Byte Technique </li><li>Truncation LFI Bypass</li><li>Log File Contamination </li><li>Email a Reverse Shell  </li>| [Read More](https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This resource covers basics of Local file inclusion vulnerability and they have demonstrated the attack on OWASP mutillidae lab. | [Read More](https://www.youtube.com/watch?v=kcojXEwolIs)|
| In this video resource you will learn local file inclusion vulnerability with john hammond, He has explained it in a simple way. | [Read More](https://www.youtube.com/watch?v=O7-qHZFxjgk)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this report local file inclusion was found on registration page from which an attacker can read local files on the web server that they would normally not have access to.  | [Read More](https://hackerone.com/reports/1007799)|
|In this report the author found LFI in concrete5 version 5.7.3.1 which was vulnerable to this attack as it was not validating the path and user input properly from incoming request during the dispatching process.  | [Read More](https://hackerone.com/reports/59665)|
|This report explains local file inclusion vulnerability found in yahoo subdomain. It’s a bit complex to understand, click on the above link to see the report.  | [Read More](https://hackerone.com/reports/7779)|




## Using components with known vulnerabilities  
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this guide it is well explained for beginner to understand what type of vulnerability this is with example: <br> <ul> <li>What are Components with Known Vulnerabilities </li><li>How to identify known vulnerabilities </li><li>How to prevent exposure to known vulnerabilities</li><li>Examples of Using Components with Known Vulnerabilities in the world </li><li>How to classify a vulnerability </li> | [Read More](https://d0znpp.medium.com/a9-using-components-with-known-vulnerabilities-%EF%B8%8F-top-10-owasp-2017-1b9ff6cf9e50)|
|In this guide, components with known vulnerability is explained in brief. A beginner can learn about this vulnerability using this reference: <br> <ul> <li>What is Using components known vulnerabilities</li><li>A Scenario </li><li>How to Prevent</li>  | [Read More](https://fazalurrahman2005.medium.com/9-using-components-with-known-vulnerability-security-basics-a1165ba5758f)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A  | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this report it is explained that the application uses wordpress and allows users to load multiple JS and CSS Files at once that lead to DOS attack.  | [Read More](https://hackerone.com/reports/694467)|




## Missing Security Headers 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This guide is helpful for those who want to know why security headers are important in web application security: <br> <ul> <li>How important are HTTP security headers </li><li>Client-side attacks </li><li>What are the security headers </li><li>Conclusion </li> | [Read More](https://medium.com/@SundownDEV/how-important-are-http-security-headers-ad511848eb95)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Key notes of the videos are: <br> <ul> <li>Introduction  </li><li>HTTP Security Header Overview </li><li>Example1: X-Frame-Options </li><li>Example2: Content Security Policy (CSP) </li><li>Example3: Strict Transport Security (HSTS) </li><li>Example4: Cross-Origin Resource Sharing (CORS) </li><li>Example5: Cookie Security Flags (HttpOnly) </li><li>Summary   </li> | [Read More](https://youtu.be/064yDG7Rz80)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This report explains that, how missing security headers such as X-Frame-Options and CSP Header can be a cause of vulnerability such as Clickjacking.  | [Read More](https://hackerone.com/reports/64645)|
|Both above reports have explained how a missing security header such as X-Content-Type-Options can lead to MIME Sniffing vulnerability.  | [Read More](https://hackerone.com/reports/369979) [Read More](https://hackerone.com/reports/6935)|




## URL/Open Redirection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This reference is to understand what you can perform with open redirect attacks such as XSS and token leakage: <br> <ul> <li>What is Open Redirection </li><li>Finding open URL redirects and Parameters </li><li>Leak tokens via mis-configured apps/login flows </li><li>Bypassing blacklists for SSRF/RCE </li><li>XSS via javascript:alert(0) </li><li>Common bypasses  </li> | [Read More](https://www.bugbountyhunter.com/vulnerability/?type=open_redirect)|
| It is a private bug bounty story of open redirection in which open redirection vulnerability is explained with some common vulnerable parameters: <br> <ul> <li>What is an Open-redirection Vulnerability </li><li>Some resources </li><li>Common Parameters </li><li>What happens in open-redirection </li><li>Private Bug Bounty Story </li><li>Open-redirection leads to SSRF </li><li>Impact of Open-redirection </li> | [Read More](https://infosecwriteups.com/open-redirection-leads-to-a-bounty-d94029e11d17)|
| This is reference of portswigger which helps you to understand the cause of vulnerability and remediation also: <br> <ul> <li>Description</li><li>Remediation </li><li>References </li><li>Vulnerability classifications</li> | [Read More](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Key notes of this resource are: <br> <ul> <li>Intro </li><li>Lab Overview </li><li>Discover directory traversal </li><li>Discover Open Redirect </li><li>Setup attacker’s page</li><li>Build information disclosure script </li><li>Try out exploit  </li><li>Solve the lab</li><li>Conclusion </li>| [Read More](https://www.youtube.com/watch?v=grkMW56WX2E)|
| This resource helps you to understand the vulnerable code for open redirection and where the redirection is used in the application and how you can test for open redirection vulnerabilities. | [Read More](https://www.youtube.com/watch?v=4Jk_I-cw4WE)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|In this lab, they have explained what DOM Based open redirection is, described how this type of vulnerability can be detected and exploited.  | [Read More](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains open redirect vulnerability, application domain allows redirections of which an attacker take advantage for phishing like attacks. | [Read More](https://hackerone.com/reports/504751)|
| In this report a parameter was vulnerable to open redirect flaw, attacker can simply take advantage of trusted application to redirect end user to the phishing pages which result’s application users at risk. | [Read More](https://hackerone.com/reports/311330)|
| Another report for open redirect vulnerability, in this report they used simple bypass to achieve open redirect vulnerability. | [Read More](https://hackerone.com/reports/692154)|




## Client-Side Template Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|It is a simple client-side template injection bug blog on some program which leads to stored XSS: <br> <ul> <li>Application framework </li><li>Try XSS Payload </li> | [Read More](https://payatu1-my.sharepoint.com/:w:/r/personal/hardeep_payatu_io/_layouts/15/doc2.aspx?sourcedoc=%7B3e9fbff3-d8fb-45f9-9e0d-6b19003cd098%7D&action=edit&wdPid=6d10584d)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|



## HTTP Parameter Pollution 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a bug bounty blog on some program which was vulnerable to HTTP Parameter Pollution vulnerability: <br> <ul> <li>Summary</li><li>Example </li><li>Technologies and their parameter parsing</li><li>How I find this vulnerability </li><li>Mitigation</li>  | [Read More](https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654)|
| This is a simple blog explaining HTTP Parameter Pollution Vulnerability: <br> <ul> <li>What is HPP Vulnerability </li><li>The Server Parameter Order </li><li> How to prevent Parameter Pollution</li> | [Read More](https://alonnsoandres.medium.com/http-parameter-pollution-ff14df6b018)|
| This reference will help you to understand the vulnerability in depth and also you will get to know how automation helps you find this vulnerability: <br> <ul> <li>What exactly is HPP</li><li>Things you need to know before exploitation of HPP </li><li>Scenarios </li><li>How to exploit </li><li>Tool that you can use for HPP</li><li>Some Pro things that you can do with HPP</li> | [Read More](https://infosecwriteups.com/behind-the-scene-http-parameter-pollution-534b4fa2449c)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|Key notes of this resource are: <br> <ul> <li>Intro </li><li>Example </li><li>Classic Example </li><li>Flexible Example</li> | [Read More](https://www.youtube.com/watch?v=QVZBl8yxVX0)|
| Key notes of this resource are <br> <ul> <li>Lab Overview </li><li>Analyse caching </li><li>Find XSS Vulnerability  </li><li>HTTP Parameter pollution  </li><li>Try Out exploit </li><li>Conclusion</li> | [Read More](https://www.youtube.com/watch?v=4P8d11JKvcs)|
| In this resource they have used OWASP multillidae II lab to explain and perform HTTP parameter pollution attack| [Read More](https://www.youtube.com/watch?v=UWdoMV4Y_VE)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This is a portswigger academy lab vulnerable to web cache poisoning attack but to solve this challenge you will need to perform parameter pollution attack to cache the malicious response on the server.  | [Read More](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains parameter pollution in social sharing buttons. | [Read More](https://hackerone.com/reports/105953)|
| This report explains how an attacker was able to add malicious parameters into the iframe using HTTP parameter pollution technique with semicolon which allows loading external greenhouse forms. | [Read More](https://hackerone.com/reports/1011243)|




## Host Header Injection 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|This is a basic guide of host header injection vulnerability, which covers these topics: <br> <ul> <li>What is HTTP Header Injection </li><li>Causes</li><li>Example </li><li>Consequences </li><li>Vulnerable code </li><li>Remediation</li><li>Labs for Practice </li> | [Read More](https://medium.com/codex/http-header-injection-4ba857fb9a16)|
|In this beginner guide, identification and escalation of Host Header Injection attack is explained: <br> <ul> <li>What is an HTTP Header </li><li>What is a HOST Header</li><li>What is a FORWARDED Header</li><li>What is the HOST header attack </li><li>What exactly could be the flaw, where it could go wrong </li><li>How to test if the application could be vulnerable to Host Header injections </li><li>What you as an attacker can do </li><li>Escalate the attack </li><li>Perform web cache poisoning</li><li>Perform web cache poisoning </li><li>Cause a redirect to an attacker-controlled domain </li><li>Manipulate password reset functionality</li><li>Cause a redirect to restricted internal sites — SSRF </li> | [Read More](https://infosecwriteups.com/identifying-escalating-http-host-header-injection-attacks-7586d0ff2c67)|
| In this blog you will learn how this host header injection vulnerability can lead to account takeover: <br> <ul> <li>About Host-Header </li><li>How to bypass </li><li>What vulnerability we can exploit by changing host header</li><li>Working </li><li>Exploitation</li><li>Remediation</li> | [Read More](https://gupta-bless.medium.com/exploiting-host-header-injection-5554fef7e25)|
| This is a portswigger reference of Host Header Injection attack explaining the vulnerability and how do it arise: <br> <ul> <li>HTTP Host header attacks </li><li>What is the HTTP Host header </li><li>What is the purpose of the HTTP Host header</li><li>What is an HTTP Host header attack </li><li>How do HTTP Host header vulnerabilities arise</li><li>Exploiting HTTP Host header vulnerabilities </li><li>How to prevent HTTP Host header attacks </li>| [Read More](https://portswigger.net/web-security/host-header)|
| This is another portswigger reference. It contains different labs to practice exploitation of the vulnerability: <br> <ul> <li>How to test for vulnerabilities using the HTTP Host header </li><li>Supply an arbitrary Host header </li><li>Check for flawed validation </li><li>Send ambiguous requests</li><li>Inject duplicate Host headers </li><li>Supply an absolute URL </li><li>Other techniques</li><li>Inject host override headers </li><li>Password reset poisoning </li><li>Web cache poisoning via the Host header </li><li>Exploiting classic server-side vulnerabilities </li><li>Accessing internal websites with virtual host brute-forcing </li><li>Routing-based SSRF</li><li>SSRF via a malformed request line</li> | [Read More](https://portswigger.net/web-security/host-header/exploiting)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This resource has a good explanation of host header injection vulnerabilities. The video owner has explained host header injection from portswigger and explained some of the techniques or test cases. | [Read More](https://www.youtube.com/watch?v=2ScSGAs1m30)|
| This resource is a video POC of password reset poisoning attack in which attacker inject a malicious host in host header and get the password reset token on their host. | [Read More](https://www.youtube.com/watch?v=yeOcQFNjSPM)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains how vulnerable host headers led to open redirection vulnerability and other vulnerabilities may also arise such as web cache poisoning and XSS. | [Read More](https://hackerone.com/reports/1098948 )|
| This report explains how one can perform password reset poisoning attack through host header if vulnerable and get the token on attacker server and further using that token to take over the vicitm account. | [Read More](https://hackerone.com/reports/698416)|





## Billion Laugh Attack
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| It is a beginner guide to understand how one can perform billion laugh attack on the target application: <br> <ul> <li> Billion Laughs Attack </li><li>XML Parser </li><li>DTD’s </li><li>Internal & External entities </li><li>YAML Parser</li> | [Read More](https://medium.com/dsc-sastra-deemed-to-be-university/billion-laughs-attack-e7b0d5149372)|
| This is a simple guide to understand the vulnerability and to know how you can find and exploit this vulnerability in applications: <br> <ul> <li>What is the billion laughs attack </li><li>What is the difference </li><li>Simple SVG Upload in POST request </li><li>Billion Laughs attack SVG Payload in POST request </li><li>How can you find and exploit this vulnerability in websites </li><li>Credits and Extra Resources</li> | [Read More](https://infosecwriteups.com/kill-em-with-laughter-the-billion-laughs-attack-through-image-uploads-4e9c57ca6434)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this video you will learn how a website that deals with XML can be abused to perform billion laugh attack due to inline macros feature. | [Read More](https://www.youtube.com/watch?v=WQUiub2hc0c)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains that one application unsafely parses user provided XML and lead to recursive entity expansion and a subsequent billion laughs attack. | [Read More](https://hackerone.com/reports/506791)|
| This report explains the same thing that the application does not protect against recursive entity expansion when loading configuration. | [Read More](https://hackerone.com/reports/509315)|





## Session Attack 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this guide you will learn session related vulnerabilities that how one can perform these attacks: <br> <ul> <li>Session Fixation </li><li>Session Hijacking </li><li>Session Prediction</li><li>Defense Methods </li>| [Read More](https://medium.com/@mena.meseha/session-attacks-and-defense-methods-97afa42e27f9)|
| This is a brief overview of session hijacking vulnerability, and this blog covers these topics: <br> <ul> <li>Introduction </li><li>What is Session Hijacking </li><li>What are the attack vectors of Session Hijacking </li><li>Cross-Site Scripting</li><li>Packet Sniffing </li><li>Guessing / Brute forcing </li><li>Mitigating Session Hijacking Attacks</li> | [Read More](https://medium.com/ax1al/session-hijacking-a-brief-overview-e65480e887cb)|
| This is another reference to understand how one can perform session hijacking attack and also how can you prevent application from this attack: <br> <ul> <li>What is session hijacking </li><li>How do we fix it </li><li>HttpOnly & Secure Flag </li><li>Conclusion</li> | [Read More](https://ramesh-lingappan.medium.com/session-hijacking-and-how-to-stop-it-711e3683d1ac)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
|  Key notes of the resource are: <br> <ul> <li>Understanding the danger </li><li>Understanding Sessions and how they work </li><li>Session Hijacking </li><li>Types of CSRF Attack and how they work </li><li>How to defend against CSRF attacks</li> | [Read More](https://www.youtube.com/watch?v=oI7dX6DWyTo)|
|  In this video you will learn: <br> <ul> <li>Session management attacks</li><li>What is session token  </li><li>Common session ID name </li><li>Session Expiration  </li><li>Session ID Length</li><li>Session ID Entropy</li>  | [Read More](https://www.youtube.com/watch?v=JcsK0EycAlg)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This report explains how weak session ID implementation can be leveraged by attackers to keep the victim session active even after the password change. | [Read More](https://hackerone.com/reports/272839) [Read More](https://hackerone.com/reports/216294)|




## Insufficient Logging and Monitoring 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| This is a beginner guide to understand security basics of insufficient logging and monitoring: <br> <ul> <li>About insufficient logging and monitoring</li><li>Example </li><li>How can this be mitigated</li> | [Read More](https://fazalurrahman2005.medium.com/10-insufficient-logging-and-monitoring-security-basics-dff570155881)|
| This guide has a brief explanation of insufficient logging and monitoring with some examples: <br> <ul> <li>Insufficient Logging & Monitoring </li><li>Brief explanation</li><li>Example attack scenario </li><li>How to prevent </li><li>Conclusion </li>| [Read More](https://medium.com/strike-sh/owasp-api-10-insufficient-logging-monitoring-82aea6ca44cb)|
| In this reference you will get to know why insufficient logging and monitoring was added to the owasp list and how do you identify and leverage insufficient logging and monitoring vulnerabilities: <br> <ul> <li>What is insufficient logging & monitoring </li><li>How do you detect insufficient logging & monitoring </li><li>How do you prevent insufficient logging & monitoring</li><li>How do you protect your system from insufficient logging & monitoring</li><li>How can insufficient logging & monitoring be leveraged in an attack </li><li>How can I learn more about OWASP top 10 vulnerabilities</li> | [Read More](https://resources.infosecinstitute.com/topic/2017-owasp-a10-update-insufficient-logging-monitoring/)|
| In this reference you will get to know about insufficient logging and monitoring and how insufficient logging and monitoring affects businesses: <br> <ul> <li>What is Insufficient Logging & Monitoring </li><li>How does Insufficient Logging & Monitoring affect business </li><li>Example Attack Scenarios</li><li>Preventive measures against Insufficient Logging & Monitoring</li> | [Read More](https://d0znpp.medium.com/insufficient-logging-monitoring-%EF%B8%8F-what-you-need-to-know-f499f454affa)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| Key Notes of this video are: <br> <ul> <li>Intro </li><li>Logging </li><li>What to Log </li><li>Spilling Information </li><li>Data breach statistics</li><li>Logging and Monitoring</li><li>Too Much vs Too Little </li><li>Integrity Controls </li>| [Read More](https://youtu.be/IFF3tkUOF5E)|
| This video has covered the basics of insecure logging and monitoring vulnerabilities such dictionary attack, the root cause of insecure logging and monitoring, how intruder do exploitation process on this vulnerability and prevention. | [Read More](https://www.youtube.com/watch?v=g6RYjDfyTek)|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A  | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|





## SSL Related Vulnerabilities 
|Description (Blogs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| We have two references part 1 & part 2 in which the author has explained the top 10 SSL Security Vulnerabilities and Solutions: <br>Part1: <br><ul><li>Security Concepts: </li><li>Vulnerability 1- Birthday attacks against TLS ciphers with 64bit block size vulnerability (Sweet32)  </li><li>Vulnerability 2 – SSL Server Has SSLv3 Enabled Vulnerability </li><li>Vulnerability 3 – SSL/TLS use of weak RC4 cipher </li><li>Vulnerability 4 – SSLv3 Padding Oracle Attack Information Disclosure Vulnerability (POODLE)</li> | [Read More](https://blogs.sap.com/2017/05/07/top-10-ssl-security-vulnerability-and-solution-part-1/)|
|Part2: <br> <ul> <li>Vulnerability 5 – SSL/TLS Server supports TLSv1.0 </li><li>Vulnerability 6 – SSLv3.0/TLSv1.0 Protocol Weak CBC Mode Server-Side Vulnerability (BEAST) </li><li>Vulnerability 7 – SSL/TLS Server Factoring RSA Export Keys (FREAK) vulnerability </li><li>Vulnerability 8 – SSL Server Has SSLv2 Enabled Vulnerability </li><li>Vulnerability 9 – HTTP TRACE / TRACK Methods Enabled </li><li>Vulnerability 10 – SSL Certificate Vulnerabilities </li> | [Read More](https://blogs.sap.com/2017/05/04/top-10-ssl-security-vulnerability-and-solution-part-2/)|
| In this guide you will learn how to identify SSL/TLS vulnerabilities and attack them: <br> <ul> <li>LAB SETUP </li><li>Attacker Machine </li><li>DoS Attack (SSL Renegotiation Attack)</li><li>Man-In-The-Middle (Sweet32 Birthday Attack)</li><li>Mitigations </li><li>Other Command-line Tools to test SSL/TLS </li><li>References</li> | [Read More](https://infosecwriteups.com/identifying-vulnerabilities-in-ssl-tls-and-attacking-them-e7487877619a)|

|Description (Resources)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Labs)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| N/A | [Read More]()|

|Description (Reports)|Link|
|----|---------|
|<img width=5900/>|<img width=100/>|
| In this report, it is explained that how some bad practices can lead to OpenSSL Padding Oracle attack and other SSL related issues. It mainly occurs when application uses weak cipher suits. | [Read More](https://hackerone.com/reports/194761)|





 





