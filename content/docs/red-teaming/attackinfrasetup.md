---
title: Infra Setup
---

# attackInfraSetup

## C2/Post-Exploitation Framework selection

During a red team engagement, choosing the right C2 framework is one of the most important step. The right C2 framework has to be Flexible, Agile and Resilient against blue team’s preventive actions. It has to standup and last for many weeks/months till the red team engagement is active. Forget about using Metasploit during red team engagements. It’s a great exploitation framework for a traditional Pentest but when it comes to engagements which lasts for weeks to months then Metasploit is not the right tool. We can either write our own framework or use something which is already tried and tested. Writing your own C2 framework would be another big project and needs a whole lot of expertise and time. We would choose something which is already available and used by experts around the globe.

After a whole lot of search and discussion, I zeroed down to two options for this:

**CobaltStrike** – Best framework available for red team engagements. Has a lot of amazing features which you can’t find anywhere else. Kudos to rsmudge for creating this superb tool. Anything that good doesn’t comes for free. It is available for a price tag of 3500$/year.

**Powershell Empire** – Another great tool which can be used for creating payloads as well as for post exploitation. Empire is a pure powershell post-exploitation agent built on cryptologically-secure communications and a flexible architecture. The good part is that it is open source and completely free. Kudos to these guys for creating this awesome tool – @harmj0y, @sixdub, @enigma0x3 and more.

We will be using powershell Empire for now as it is an amazing tool available for free and it is open source which can be used by everyone. It is better to go the powershell empire official website and check it out. They have maintained a very concise usage documentation over there.

Though, I would mention as why I selected powershell Empire as an appropriate post-exploitation framework.

1. Flexible and Resilient – Unlike Metasploit, where if your listener dies once, you loose the connection. Empire agents can keep trying to communicate back to you till it finishes the number of connection attempts you have defined while setting up the payload. The agents information is stored in a sqlite file which can be fetched when you launch empire again. Once you have defined the parameters for a listener, it doesn’t changes unless you explicitly do it so. No need to setup the listener again and again. Since, it is open source and modular, you can use your own powershell scripts inside empire.
2. Uses powershell & Python – Given that, we are targeting an organization and majority of times, their infrastructure would mostly consist of windows systems, using powershell is a safe bet here. Empire needs at least powershell v2.0 to run which is available from Win Vista to Win 10. It wouldn’t work on Win XP systems though. It also gives us the advantage of bypassing application whitelisting which is implemented in many organizations since powershell is available by default and we are not dropping or executing any new executable. For any unix based hosts, we can use python based empire agents.
3. Proxy aware payloads – It automatically picks up the proxy and the cached creds from the system which is in use currently and use that to communicate to the C2 server. A lot of traditional tools and payloads fail here as they can’t pick up the proxy automatically unless specified explicitly. Since, we are aiming here at a fortune 500 company, it’s definitely gonna be using a proxy for any kind of web requests.
4. Malleable C2 profiles – The C2 profile means the indicators in the agent communication to the C2. It includes the listener protocol, http url, user agent, callback time, lost limit, jitter, encryption key, etc. AV vendors write signatures based on these indicators. A lot of times, the default parameters are used which can lead to the detection, removal of the payload and blockage of the communication between the organization and the C2 domain. These indicators can be changed while creating the payload to evade detection.
5. Can run powershell agents without running powershell.exe – Since, powershell is being heavily abused by malware authors, a lot of organizations either completely block powershell.exe execution or log every activity that is made from powershell.exe which can be then given to a central log analysis tool which might raise an alarm on any suspicions activity. To counter this, we can actually launch powershell without running powershell.exe. Empire gives us few options to do so.
6. Comes pre loaded with Invoke-Obfuscation module – Empire has an options to obfuscate all the source code, stagers and the payloads with different level of obfuscations. Helps a lot in evading signature based AV detection process.
7. Reliable persistence modules – It has few very reliable persistence modules which works perfectly. Using WMI for persistence is my favorite one.
8. Lots of post-exploitation modules – It has lots of great post exploitation modules written in powershell which can be used for information gathering, lateral movement, hash dumping and system management.
9. Different listener options – Unlike Metasploit which maintains a constant TCP connection with the C2 server, empire can communicate over http with a custom delay and jitter in between, thus making it very difficult to detect C2 traffic. It has a lot of listener options which can include http\_hop or even dropbox as C2.

![Empire Home Page](https://kbassets.sgp1.digitaloceanspaces.com/1563270934477-Empire_home_page.png)

Empire Home Page ![Empire http listener options](https://kbassets.sgp1.digitaloceanspaces.com/1563271370841-Empire-http_listener_options.png) Empire http listener options ![Empire stager options](https://kbassets.sgp1.digitaloceanspaces.com/1563271446257-empire_stager_options.png) Empire stager options

## C2 infra setup

Our C2\(Command & Control\) infrastructure would consist of our C2 servers, Redirectors, Phishing servers and payload delivery servers. For the Redteam engagement, we need to deploy a Resilient C2 infrastructure which can stand for weeks and months depending on the duration of the engagement. The infrastructure has to be agile and strong enough to withstand the blue team’s preventive actions.

For example, The moment when the blue team finds out that there organization has been compromised and they start identifying the C2 traffic, they will start blocking your C2 domains as a preventive step. Your C2 infrastructure should be such that it should keep standing when blue teams have started taking down your campaign.

![](https://kbassets.sgp1.digitaloceanspaces.com/1563278269393-Traditional_pentest.png) Traditional Pentest Infra

#### Segregation

You have to setup multiple C2 servers, multiple Redirectors, phishing servers or payload delivery servers during the engagement. All of this has to be on a different server. We need to segregate our infra as that would give us the required flexibility and Resilience. For example, If your phishing server got caught during the campaign and the blue team blocked the email sending domain, you would not loose control over the hosts you already own as your C2 server is hosted on a different server and domain.

Your short haul and long haul C2 servers should be hosted on different domains as well. Generally, short haul C2 would get caught easily during the course of engagement. Segregation between short haul and long haul C2 would allow you to persist for long period.

Short haul C2 servers are those kind of servers on which you would receive callbacks after every few seconds. This is the one which would be used to actually execute commands on the victim’s machine in real time. Long haul C2 servers are those on which you would receive callbacks after every few hours. This would help us to persist and evade malicious traffic detection.

Segregating your infra provides you the flexibility and Resilience against blue team’s preventive actions. Here is a sample diagram of modern red team infrastructure.

![Sample Redteam Infra](https://kbassets.sgp1.digitaloceanspaces.com/1563358198807-redteam_infra.png) Sample Redteam Infra

#### Redirection

Redirectors can be placed in the front of each C2 server to protect our core infrastructure from getting identified and blocked. Using a Redirector in front of the C2 server has a lot of advantages:

* Prevents the identification of our core C2 infra – Our core infra would stay hidden even when blue team finds out what domains the malware is communicating to. If they start to block the domains, we can quickly switch to a different Redirector running on a different domain in real time. This would save up our effort and time to setup another server with the C2 framework and the required tools.
* confusion – It can confuse the blue teams when they start their investigation and start burning our domains. Only the C2 traffic would be redirected to the original C2 server but if anyone else tries to investigate the C2 domain, the Redirector server would redirect the traffic to another legit website.

We can implement two different kinds of redirection:

* **Dumb pipe redirection**

We can perform dump pipe redirection using Socat or IPtables. It will forward all the incoming traffic to the C2 server. The only advantage of using a dump pipe Redirector is that our original C2 server would stay hidden. It can be implemented using either IPtables or Socat. Socat is easier to use that configuring rules in IPtables. Socat is a command line based utility that establishes two bidirectional byte streams and transfers data between them.

This is the basic syntax for Socat which will forward all the incoming TCP traffic on port 80 to the specified remote host on port 80.

`Socat TCP4-LISTEN:80,fork TCP4:<REMOTE-HOST-IP-ADDRESS>:80`

![Dump pipe redirection](https://kbassets.sgp1.digitaloceanspaces.com/1563358642112-dumb_pipe_redirection123.png) Dump pipe redirection

* **Smart redirection**

Smart redirection means forwarding all the C2 traffic to the C2 server and redirecting all other traffic to a legit website. This counters the blue team investigative attempts to uncover our C2. Anybody visiting the C2 domain would get redirected to another legitimate site. The same applies for tools like curl, wget or any web scanner. This improves the resilience of your C2 infrastructure.

![Smart Redirection](https://kbassets.sgp1.digitaloceanspaces.com/1563358718665-smart_redirection123.png) Smart Redirection

One of the easiest ways to implement smart redirection is to use mod\_rewrite.

mod\_rewrite has the ability to perform conditional redirection based on request attributes, such as URI, user agent, query string, operating system, and IP. Apache mod\_rewrite uses htaccess files to configure rulesets for how Apache should handle each incoming request.

First, we have to customize our Empire C2 with the kind of web traffic we are trying to blend in. Here, in this example I have tried to emulate my C2 traffic as Microsoft live email traffic. You could change the user agent, web url’s, server headers according the web service you are trying to emulate. If any tool or person is monitoring the http network traffic, It wouldn’t look malicious as it is similar to the outlook email traffic.

It would look like as it is an Outlook app installed on someone’s desktop or mobile phone which is trying to sync with the inbox after every few minutes. In this example, any kind of traffic which does not match our C2 traffic would get redirected to [https://login.microsoftonline.com](https://login.microsoftonline.com), thus reducing the level of suspicion. This has been discussed more in the AV Evasion part of this post.

In order to setup smart redirection, you need to configure your C2 server as well as the Redirector server. Below are the exact details as how to configure your C2 server and your Redirector server for smart redirection.

**Setting up the C2 server**

```text
listeners
uselistener http
set Name microsoft
set DefaultJitter 0.6
set DefaultDelay 11
set DefaultProfile /owa/mail/inbox.srf,/owa/mail/drafts.srf,/owa/mail/archive.srf|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; yie11; rv:11.0) like Gecko|Accept:*/*
set Host http://[Redirector-ip]:80
```

save the above text as microsoft.profile and start powershell empire with the following command

`./empire -r microsoft.profile (would start empire with the microsoft profile)`

======= ![Empire http listener options](https://kbassets.sgp1.digitaloceanspaces.com/1563271370841-Empire-http_listener_options.png) Empire http listener options

### Using SSL for your C2 traffic

C2 communication over https has great advantages when it comes to bypassing AV/IDS detection which we will discuss in AV Evasion part. ![Encrypted C2 Communication](https://kbassets.sgp1.digitaloceanspaces.com/1563361638182-encrypted_C2_communication.png) Encrypted C2 Communication

### Log management

During an engagement, you must implement some sort of log management process. Logging your C2/Redirector server’s network activities has a lot of advantages:

* Situational Awareness – You would be aware of the blue team’s investigative efforts. Logs would give you a great deal of information as what exactly is the blue team trying to do on your server.

Are they using curl/wget? Are they trying to run a port scan on your server? Are they running some web vulnerability scanner/dirbuster on your server? Did they try to access your server from their browser? What was the user-agent? From what time period they were active? What timezone they are working in? What’s their Public IP address? Is it the same as the organisation’s public IP address? What are they trying to uncover? Is it an external entity trying to hack into your server?

* Resilence – You can easily find out if they have started their attempt to uncover your C2 server and depending on the situation, you can change the agent’s C2 server on the fly before they block that domain. Empire’s gives you the option to spawn a new agent on a different listener.

![Redirector Server Apache Logs](https://kbassets.sgp1.digitaloceanspaces.com/1563361768697-redirector_logs.png) Redirector Server Apache Logs

Just by looking at the apache access logs, you can find out a lot of details like – IP address, TimeStamp, Url accessed, response code, User agent.

This will easily give out if anyone else other then your empire agent has tried to access the webserver since it’s response code would be ‘302’. A simple ‘grep’ and ‘cut’ would reveal the blue teams’s investigative attempt.

When you have a lot of C2 and Redirector servers, It’s advisable to use a central log server & management tool which can alert you if any suspicious activity occurs. The selection of the right log management tool is dependent on the size of the infrastructure and your familiarity with the tool and I leave that on you.

