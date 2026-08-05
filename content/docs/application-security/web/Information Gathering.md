---
title: Information Gathering
---

# Information Gathering

## Information Gathering: Why It Matters

Information gathering is the **first and most important phase of web application security testing**. In this stage, a tester collects as much information as possible about the target website or application.

1. **Understanding the Target**
    
    Helps identify the website structure, technologies used, servers, domains, and frameworks.
    
2. **Identifying Attack Surface**
    
    Reveals entry points such as subdomains, directories, APIs, login pages, and parameters that could be tested for vulnerabilities.
    
3. **Finding Potential Weaknesses**
    
    Information like software versions, plugins, and configurations can expose known vulnerabilities.
    
4. **Planning the Security Testing**
    
    The gathered data helps security testers decide which tools, techniques, and attacks to use.
    
5. **Reducing Time and Effort**
    
    Proper reconnaissance helps focus on the most vulnerable areas instead of testing blindly.
    

## Types

- **Active Recon**

It is a process to gather information by directly interacting with the target.

- **Passive Recon**

It is a process to gather information without interacting with the target.

## Types of Information

- Subdomains
- Data Breaches
- Endpoints
- Usernames
- Server side technology

## Passive Recon

### Tech Profiling

These are browser extensions that helps to map the tech profile of the web application.

- **`Wappalyzer`**
- **`WhatRuns`**
- **`BuiltWith`**
- **`nuclei`**
    
    This tool helps to find out the technology stack, CVEs, Missing HTTP headers etc and uses nuclei templates.
    
    ```jsx
    nuclei -u http://target.com -f --headless
    ```
    
    - **`-f`** used for following redirects
    - **`--headless`** helps to run the tool in browser environment

### Meta Files

- **`robots.txt`**
- **`sitemap.xml`**
- **`humans.txt`**
- **`security.txt`**

### Search Engines

- Google
- Shodan
- DuckDuckGo
- Baidu
- ZoomEye
- Censys
- AlienVault ([https://otx.alienvault.com/](https://otx.alienvault.com/))

### Dorking

- **`Google`**
    
    
    | **Filter** | **Description** | **Example** |
    | --- | --- | --- |
    | intext | Searches for the occurrences of keywords all at once or one at a time. | `intext:"keyword"` |
    | inurl | Searches for a URL matching one of the keywords. | `inurl:"keyword"` |
    | allinurl | Searches for a URL matching all the keywords in the query. | `allinurl:"keyword"` |
    | intitle | Searches for occurrences of keywords in title all or one. | `intitle:"keyword"` |
    | allintitle | Searches for occurrences of keywords all at a time. | `allintitle:"keyword"` |
    | site | Specifically searches that particular site and lists all the results for that site. | `site:"www.google.com"` |
    | filetype | Searches for a particular filetype mentioned in the query. | `filetype:"pdf"` |
    | cache | Shows the version of the web page that Google has in its cache. | `cache:www.google.com` |
    
    ```bash
    site: target.com filetype: env
    ```
    
    ```bash
    site:target.com intext:password intext:username intext:secret
    ```
    
    ```bash
    site: target.com inurl: credentials inurl: password
    ```
    
- **`Github`**
    
    [https://github.com/RobinRana/githubRecon/blob/main/Gdorklinks.sh](https://github.com/RobinRana/githubRecon/blob/main/Gdorklinks.sh)
    
    This is an automated script that helps to create some of the dorks to search through the public github repositories.
    
    ```
    bash Gdorklink.sh example.com 
    ```
    

### Acquisitions

An acquisition is a business transaction where one company purchases another, gaining control through the purchase of its shares or assets

- One can gather acquisitions from **`crunchbase`**

```
https://www.crunchbase.com/discover/acquisitions
```

### ASN (Autonomous System Numbers)

It is a unique identifier assigned to an Autonomous System (AS), which is a collection of IP networks under a single administrative entity, such as an ISP or a large organization.

- From online at [bgp.he.net](http://bgp.he.net)

```
https://bgp.he.net/
```

- **`BGP View API`**

```
curl -s https://api.bgpview.io/search?query_term=<company_name> | jq -r | grep -i '"asn"' | cut -d : -f2 | tr -d ','
```

- **`Nmap`**

```
nmap --script=asn-query.nse -T2 -Pn target.com
```

### Amass Intel

[https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)

- Amass intel  scan can be used to extract subdomains, apex domains, IPs from ASN

```
amass intel -asn 1234
```

- Automated bash script

```
#!/bin/bash
# Save the file with name ASN containing the ASN numbers (eg: ASN1234)

for i in $(cat ASN)
do
    x=$(echo "$i" | tr -d 'ASN')
    output=$(amass intel -asn "$x")
    echo "$output"
done
```

### Shosubgo

[https://github.com/incogbyte/shosubgo](https://github.com/incogbyte/shosubgo)

- It is shodan based tool to extract subdomains

```
shosubgo -d example.com -s shodan_api_key_here
```

- **`-d`** is used to specify the domain name
- **`-s`** is used to specify the shodan API key which one can get from their shodan account

### Karma v2

[https://github.com/Dheerajmadhukar/karma_v2](https://github.com/Dheerajmadhukar/karma_v2)

- A shodan based tool collect the subdomains through Osint

```
bash karmav2 -d example.com -l -1 -deep
```

- **`-d`** is used to specify the target domain
- **`-l`** is used to specify the number of results to download
- **`-deep`** flag allow to support all modules
- Collecting the  subdomains and apex domains from the output directory

```
awk -F '::' '{for (i=1; i<=NF; i++) if ($i ~ /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) print $i}' <file_name_here>
```

- Collecting the IPv4 addresses

```
awk -F '::' '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i}' <file_name_here>
```

### Cloud

- One can gather cloud dumped information from [**`https://kaeferjaeger.gay/`](https://kaeferjaeger.gay/)**
- An automated script

```bash
echo "[*] Extracting domains, ips from cloud"
platforms=(amazon google microsoft digitalocean oracle)
mkdir cloud
for i in $platforms; do mkdir cloud/$i; cd cloud/$i; wget https://kaeferjaeger.gay/sni-ip-ranges/$i/ipv4_merged_sni.txt; cd ../../ ;done
cat cloud/*txt | grep -Po "(.+\.$1)" | cut -d '-' -f1 | tr -d ':[],' | sed 's/443/\ /g' > ../assets/ip/cloud.ips 
cat cloud/*txt | cut -d '-' -f3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 | sed 's/\ /\n/g' |  grep -Po "(.+\.$1)" | tr -d ',[]' | sort -u > ../assets/domain/cloud.sub-domains
echo "[-]Done"
```

### whoxy.com

```bash
https://api.whoxy.com/?key=<your_api_key_here>&reverse=whois&keyword=<company_name_here>&mode=domains
```

### Ad / Analytic Tracker Code

When websites use third-party services like Google Analytics, New Relic, or similar analytics tools, they embed `unique tracking codes` (usually in the form of JavaScript snippets) into their pages. These codes help track visitor behavior, monitor performance, or manage ads across different domains.

- Same Tracking Codes Across Domains: Often, an organization uses the same analytics tracking codes across multiple domains or subdomains. For example, if a company owns multiple websites or web applications, they might use the same Google Analytics ID on all of them to aggregate data.
- Collect the builtwith cookie from ⇒ **`https://pro.builtwith.com/`**
- **`getrelationship.py`**

[https://github.com/m4ll0k/BBTz/blob/master/getrelationship.py](https://github.com/m4ll0k/BBTz/blob/master/getrelationship.py)

```bash
python3 getrelationship.py example.com <the-builwith-cookie>
```

### Github-Subdomains

[https://github.com/gwen001/github-subdomains](https://github.com/gwen001/github-subdomains)

- This Go tool performs searches on GitHub and parses the results to find subdomains of a given domain.
- Get your github api key from ⇒ [**`https://github.com/settings/tokens`**](https://github.com/settings/tokens)

```bash
github-subdomains -d example.com -t github_api_key_here -o outputfile.txt
```

### SubreconGPT

[https://github.com/jhaddix/SubreconGPT](https://github.com/jhaddix/SubreconGPT)

```bash
chaos -d example.com --key your_chaos_key_here | python subrecongpt.py --apikey YOUR_OPENAI_API_KEY
```

### Crt.sh

- [crt.sh](http://crt.sh) can be used to get the Certificate Transparency Logs. Certificate transparency is the process to verify the assigned SSL certificates.
- Check certificate transparency from ⇒ [**`https://crt.sh`**](https://crt.sh)

```bash
curl -s https://crt.sh/\?q=<company_domain_name>\&output=json | jq . | grep 'common_name' | tr -d ',":' | awk '{print $2}' | sort -u
```

### Amass enum

```bash
amass enum -brute -d example.com -w wordlists.txt -r resolvers.txt  
```

- **`enum`**  s the operational module that carries out the actual asset discovery and network mapping process for a given domain
- **`-brute`** to brute-force
- **`-r`** for resolvers that one can download from here ⇒ [https://github.com/blechschmidt/massdns/blob/master/lists/resolvers.txt](https://github.com/blechschmidt/massdns/blob/master/lists/resolvers.txt)

### Subfinder

`subfinder` is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed. 

```bash
subfinder -d example.com -o output.txt
```

### BBOT

This tool is used to scan the target domain and look for CVEs, CNAMEs, s3 buckets etc

[https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)

```bash
bbot -m otx -t example.com
```

### Puredns

**puredns** is a fast domain resolver and subdomain bruteforcing tool that can accurately filter out wildcard subdomains and DNS poisoned entries.

[https://github.com/d3mondev/puredns](https://github.com/d3mondev/puredns)

```bash
puredns bruteforce wordlists.txt example.com -r resolvers.txt -w output.txt
```

### Dnsgen

Used for permuted scanning and find the new subdomains 

```bash
cat sub-domain-file.txt | dnsgen - | puredns resolve -r resolvers.txt 
```

### httprobe

This tool is used to look for live URLs

```bash
cat all_subdomains.txt | httprobe > live_domains.txt
```

### Webanalyze

This tool helps to look for the technology stack

```bash
https://github.com/rverton/webanalyze
```

### Waymore

The idea behind **waymore** is to find even more links from the Wayback Machine (plus other sources) than other existing tools.

[https://github.com/xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore)

```sql
waymore -i target.com -mode B
```

### xnLinkFinder

It extracts different URLs and endpoints from the JS and HTML files of the target domain.

[https://github.com/xnl-h4ck3r/xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder)

```sql
python3 xnLinkFinder.py -i ~/directory/to/xml/files -sp https://www.target.com -sf target.com -o output.txt
```

### Javascript Analysis

- **`JS Finder`**
    
    https://github.com/kacakb/jsfinder?tab=readme-ov-file
    
    - Reading URLs from the JS files
    
    ```jsx
    echo http://target.com | jsfinder -read -s -o out.txt 
    ```
    
    ```jsx
    jsfinder -l list.txt -read -s -o out.txt
    ```
    
- **`Secret Finder`**
    
    SecretFinder is a python script based on [LinkFinder](https://github.com/GerbenJavado/LinkFinder), written to discover sensitive data like apikeys, accesstoken, authorizations, jwt,..etc in JavaScript files. It does so by using jsbeautifier for python in combination with a fairly large regular expression. The regular expressions consists of four small regular expressions. These are responsible for finding and search anything on js files.
    
    [https://github.com/m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder)
    
    ```jsx
    python3 SecretFinder.py -i http://target.com -e -H "Cookie: cookie-here" -o cli
    ```
    
    - **`-o`** to specify the output method
        - cli
        - results.html

### SSL / TLS Scanner

This tool helps to scan the SSL and TLS flaws from command line 

[https://github.com/testssl/testssl.sh](https://github.com/testssl/testssl.sh)

```jsx
./testssl.sh HOST_OR_IP
```

- **`BurpExtension - SSL Scanner`**

### theHarvester

- This helps to find subdomains, URLs, email addresses

```bash
theHarvester -d target.com -b all
```

- `-d` option is used to specify the target domain
- `-b` stands for **data source (search engine or service)**.
- `all` means the tool will search **all available data sources** such as:
    - Google
    - Bing
    - Yahoo
    - DuckDuckGo
    - LinkedIn
    - Shodan
    - other OSINT sources

### Automated Recon Frame-works

- **`Recon-ng`**
    
    [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)
    
- **`Recon For the Win`**
    
    [https://github.com/six2dez/reconftw](https://github.com/six2dez/reconftw)
    
    ```bash
    ./reconftw.sh -d target.com <flags> <options>
    ```
    
- **`SpiderFoot`**
    
    [https://spiderfoot.org/](https://spiderfoot.org/)
    

### Breach Databases

**Breach databases** are online services used in **Cybersecurity** and **Open Source Intelligence** (OSINT) to check whether **emails, usernames, passwords, or other personal data have been exposed in past data breaches**.

- **`HaveIBeenPwned`**
    
    [https://haveibeenpwned.com/](https://haveibeenpwned.com/)
    
    - Allows users to **check if their email or phone number was involved in a data breach**.
    - Searches through **billions of leaked accounts** from breaches such as websites, apps, or online services.
    - Shows:
        - Which website was breached
        - What type of data was leaked (email, password, name, etc.)
- **`Breached`**
    
    [https://dehashed.com/search](https://dehashed.com/search)
    
    - A **more advanced breach database search engine** used by security researchers and penetration testers.
    - Allows searching by:
        - Email
        - Username
        - Domain
        - IP address
        - Name
    
    It can reveal:
    
    - Emails
    - Password hashes
    - Usernames
    - Phone numbers
    - IP addresses

### Rocket Reach

[https://rocketreach.co/](https://rocketreach.co/)

- Purpose
    - Employee contact details
    - Role discovery
    - Executive targeting
- Search
    - Company name
    - Person name

### Hunter.io

[https://hunter.io/](https://hunter.io/)

- Purpose
    - Discover verified corporate emails
    - Email pattern recognition

```bash
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_API_KEY"
```

### URL Scan

https://urlscan.io/

- Purpose
    - Technology Stack
    - Endpoints
    - Analyze JS

```bash
domain: "linkedin.com"
```

### Virus Total

https://www.virustotal.com/

- Purpose
    - Subdomain discovery
    - Historical IP mapping
    - Infrastructure correlation

```bash
curl --request GET --url https://www.virustotal.com/api/v3/domains/target.com --header 'x-apikey: YOUR_API_KEY'
```

### Employee Enumeration Techniques

- Github Enumeration
    
    [https://github.com/gwen001/github-search/blob/master/github-employees.py](https://github.com/gwen001/github-search/blob/master/github-employees.py)
    
    ```bash
    python3 github-employees.py -m github -f facebook-dev-cookie -t "company-name-here"
    ```
    

## Active Recon

### Domain Registration Information

- **`whois`**
    - Helps to extract the registrar information and nameservers
    
    ```
    whois target.com
    ```
    

### DNS Enumeration

These tools helps to find different records like 

- A
- AAAA
- TXT
- MX
- CNAME
- NS
- **`dnsrecon`**
    
    ```
    dnsrecon -d target.com
    ```
    
- **`fierce`**
    
    ```
    fierce --domain target.com
    ```
    
- **`dnsenum`**
    
    ```
    dnsenum target.com
    ```
    
- **`dig`**
    
    ```
    dig axfr @<name-server-here> example.com
    ```
    
    - Here we are using the **`axfr`** protocol to zone transfer the DNS records of the target domain
- **`host`**
    - It helps to look for the A and AAAA records of the domain.
    
    ```
    host target.com
    ```
    

### Firewall Detection

- **`wafw00f`**
    - It extract the firewall information of the target
    
    ```
    wafw00f -a target.com
    ```
    

### Web Crawlers

These helps to find different URLs and endpoints by active crawling and extracting the JS files 

- **`gospider`**
    
    [https://github.com/jaeles-project/gospider](https://github.com/jaeles-project/gospider)
    
    ```
    gospider -q -s https://example.com -w -d 0 -H "Cookie: cookie-here"
    ```
    
    - -q is used to extract extra information like subdomains, URLs, status code etc
    - -w is used to include the subdomains while crawling
    - -d is used to control the depth level
    - -H is used to add any custom header with a value
- **`hakrawler`**
    
    [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler)
    
    ```
    echo https://example.com | hakrawler -subs -d 3
    ```
    
    - -subs is used to include the subdomains during crawls
    - -d is used to control the depth of crawl
- **`katana`**
    
    [https://github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana)
    
    ```
    katana -u https://example.com
    ```
    

### Endpoints Finding

- **`LinkFinder`**
    - This tool extract all the URLs and endpoints from JS files
    
    [https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)
    
    ```
    python3 linkfinder.py -i https:/example.com -d
    ```
    
    - -i flag takes input a domain, URL, JS file
    - -d is used to enable the domain filtering mode, so it will extract only the internal endpoints
- **`Subdomanizer`**
    - SubDomainizer is a tool designed to find hidden subdomains and secrets present is either webpage, Github, and external javascripts present in the given URL. This tool also finds S3 buckets
    
    [https://github.com/nsonaniya2010/SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer)
    
    ```
    python3 SubDomainizer.py -u https://example.com
    ```
    

### Web Cloning

- **`httrack`**
    - This tool is used to clone the target application and create a directory path along with files in the local system
    
    ```
    httrack 
    ```
    

### Directory Brute-forcing

- **`ffuf`**
    
    [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)
    
    ```
    ffuf -w /path/to/wordlists:FUZZ -u http://target.com -e .php -H "Host: FUZZ.target.com" -mc all -fc 400 -fs 162
    ```
    
    - -w to specify the wordlists
    - -u is used to specify the target URL
    - -e used for adding extension
    - -H is sued for adding custom HTTP header
    - -mc is the match code and with all value it will show every result
    - -fc is used for filtering the results on the basis of status code
    - -fs is used to filter out the results on the basis of size of the http response.
- **`gobuster`**
    
    ```bash
    gobuster dir -w /usr/share... -u http://evil.com -x .php,.txt -H "User-Agent: ..." -s 200-500 -hl 162
    ```
    
    - **`dir`** is a module to start a directory brute-forcing
    - -x used for extension
    - Simple Host Header Injection
    - Via Middleware
    - Using Dangling Markup Injection
    - -s is used to include all the status code results
    - -hl used to filter out the size of the response
- **`dirsearch`**
    
    ```bash
    dirsearch -u http://target.com -i 200-500 -x 404 -e php,txt -r -H "Cookie: cookie-here" --exclude-sizes=162
    ```
    
    - -u is used to specify the URL
    - -i for including the responses in the results
    - -x for excluding the responses in the results
    - -e is used for including the extensions
    - -r is used for recursive directory bruteforcing
    - -H is used to include the custom HTTP headers
    - **`--exclude-sizes`** is used to filter out the HTTP response sizes
- **`feroxbuster`**
    
    ```bash
    feroxbuster -u http://target.com -w <wordlist> -x pdf,php,txt -r -d 2 -H "Cookie: cookie-here"
    ```
    
    - -x is used to specify the extensions
    - -H is used to add the custom headers
    - -r is used for recursive mode
    - -d is used to specify the recursion depth for brute-forcing the directories

### Subdomain Brute-forcing

- **`ffuf`**
    
    ```bash
    ffuf -u http://target.com -w /usr/share/...:FUZZ -H "Host: FUZZ.target.com" -mc all -fc 404 -fs 162
    ```
    
    - **`-mc all`**  is used to list all status code results
    - -fc is used to filter out the stratus codes
    - -fs is used to filter out the results on the basis of  response size.
- **`dnsenum`**
    
    ```bash
    dnsenum --enum example.com -f /usr/sahre/wordlists/.. -r
    ```
    
    - `enum` enables full DNS enumeration on the target
    - -f is used to specify the wordlists
    - -r  is sued to enables the recursive enumeration of the target domain
- **`gobuster`**
    
    ```bash
    gobuster dns -d example.com -w wordlist.txt
    ```
    
    - dns is used to enable the subdomain enumeration mode
    - -d is used to specify the target domain name
    - -w is used to specify the wordlists

### Parameters Discovery

- **`Arjun`**
    
    Arjun can find query parameters for URL endpoints. If you don't get what that means, it's okay, read along.
    
    [https://github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun)
    
    ```jsx
    arjun -u http://example.com/user/profile --headers "Cookie: cookie-here" -t 100 -d 1000
    ```
    
    - **`-u`** to specify the URL endpoint
    - **`--headers`** to add custom headers
    - **`-t`** for threads
    - **`-d`** for delay between two requests
    - **`-i`** to scan all the endpoints from a list of targets
- **`x8`**
    
    The tool aids in identifying hidden parameters that could potentially be vulnerable or reveal interesting functionality that may be missed by other testers. Its high accuracy is achieved through line-by-line comparison of pages, comparison of response codes, and reflections.
    
    [https://github.com/Sh1Yo/x8](https://github.com/Sh1Yo/x8)
    
    ```jsx
    x8 -u http://url1.com http://url2.com -w <wordlist> -X GET -H "Cookie: cookie-here" -d 1000
    ```
    
    - **`-d`** is used for delay between two requests

### Port Scanning

- **`nmap`**  [https://nmap.org/](https://nmap.org/)
    - This tool helps to scan for open ports and the services running one those.
    
    ```jsx
    nmap -sV -A -sC -Pn -T3 -p- -oA nmap/results 10.10.10.10
    ```
    
    - -sV is used to specify the version enumeration
    - -A is sued to enable the agresive scanning
    - -sC is used to enable the nmap by default scripts
    - -Pn is used to specify the nmap tool for not sending any ICMP packets
    - -T is used to epcify the scanning speed and it has different values like 2,3.4,5 and by default is set to 3
    - -p is used to specify the port number and -p- is used to specify the all ports
    - -oA is used for saving the output in all formats
- **`rustscan`**
    - The Modern Port Scanner. **Find ports quickly (3 seconds at its fastest)**. Run scripts through our scripting engine (Python, Lua, Shell supported).
    
    [https://github.com/bee-san/RustScan](https://github.com/bee-san/RustScan)
    
    ```jsx
    rustscan --addresses 10.10.10.10/24 -t 500 -b 1500 -- -A
    ```
    
    - -t is used for specifying the number of threads
    - -b is used for specifying the batch size, like here in one batch it scan 1500 ports. Rustscan does not scan all the ports at once
    - -A option is used for passing the data to nmap inputs

### Scanning Network Range

- Scanning an entire subnet
    
    ```jsx
    nmap 172.162.1.0/24
    ```
    

## **References:**

[https://medium.com/dvlpr/penetration-testing-methodology-part-1-6-recon-9296c4d07c8a](https://medium.com/dvlpr/penetration-testing-methodology-part-1-6-recon-9296c4d07c8a)

[https://blog.fikara.io/information-gathering-in-bug-bounty](https://blog.fikara.io/information-gathering-in-bug-bounty)

[https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-secrets-in-bug-bounty-targets](https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-secrets-in-bug-bounty-targets)

[https://medium.com/@Land2Cyber/bug-bounty-hunting-101-8-essential-tools-for-website-information-gathering-9b8d0083a83f](https://medium.com/@Land2Cyber/bug-bounty-hunting-101-8-essential-tools-for-website-information-gathering-9b8d0083a83f)

[https://www.yeswehack.com/learn-bug-bounty/recon-series-recap-reconnaissance-footprinting](https://www.yeswehack.com/learn-bug-bounty/recon-series-recap-reconnaissance-footprinting)

[https://www.intigriti.com/researchers/blog/hacking-tools/crafting-your-bug-bounty-methodology-a-complete-guide-for-beginners](https://www.intigriti.com/researchers/blog/hacking-tools/crafting-your-bug-bounty-methodology-a-complete-guide-for-beginners)

[https://www.recordedfuture.com/threat-intelligence-101/tools-and-technologies/osint-tools](https://www.recordedfuture.com/threat-intelligence-101/tools-and-technologies/osint-tools)