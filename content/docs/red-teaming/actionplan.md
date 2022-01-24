---
title: Action Plan
description: Sample action plan
published: true
date: '2020-07-10T10:53:40.875Z'
tags: null
editor: markdown
---

# Sample Red Team Activity Action Plan

Red team action plan can differ according to different situations. This is a sample action plan which we made for a huge Indian IT service company.

## Pre-Recon \(To be repeated everyday with the newly gained information\)

Digital data collection techniques:

* Profiling of individuals related to the relevant location. Further classification into high value targets and highly vulnerable target.
* Data to be gathered Initially via LinkedIn followed by other social media sites. If initial access to the credentials of any target is obtained then the data from outlook and knome \(internal portal\) is to be used to gain additional information regarding the target.
* All the gathered so far will be used for the formation of phishing and payload delivery.
* Check Google maps for the physical layout of the facility.
* Subdomain discovery/Dir enum/Port scanning/Manual web app pentest for critical vulns – would be done by offsite Pune team.

Physical data collection techniques:

* Fake surveys to be conducted near the “smoking hub” near the site to collect location specific data of employees. \(Name, Number, Email, preferences / hobbies\)
* Attempts to exfiltrate more data using vishing to be made with the data gain from the above steps.

## Recon visit

Behavioral analysis on entry points:

* whether the bag is being checked 
* whether guard is frisking or looking at the ID
* Whether we can observe if tail-gaiting is possible
* What is the ideal time for lunch?
* What time does guard changes?
* How many guards are present at the front door?
* Where do people generally go for lunch/smoking?
* Any other possible entry points? Fire-Exit gates?
* Wifi Access points visible from outside? Authentication scheme?
* Try to attempt RFID card cloning via social engg.

## Physical Intrusion

Gain access inside the facility

* Using Fake employee card and tailgating or cloned RFID card.

Perform an active recon:

* Get an idea of Building navigation, Canteen, etc
* Get an idea of ideal places where we can sit for a long time.
* Wifi Access points? Authentication scheme? Clone captive portal.
* Get into an ODC/open bay area via tail-gaiting.

Attempt to gain access to a machine:

* Unattended Machine - try to bypass windows password via konboot and login into the system.

Pretext for Convincing an employee to give us his system for few minutes:

* Impersonating as someone from IT team - 'Your system is non-compliant. We need to install patches to this system to make this compliant or this system would be locked by the admin'. Here, again we would have to use konboot to bypass password or convince the employee to not logout of the system.
* Impersonating as someone from IT team for Audit - 'We need to perform a general Audit of this system as we have noticed few irregularities and the security team needs confirmation whether the system is secure to use or not. We might need to patch the system properly or delete creds stored in plaintext.' The benefit here is that the employee would have to be logged in and hand over the system to us. we can either say that we are from the same building or we have come from another office.

Note: Need to get few important names in security and an Audit letter from the corresponding person.

Once we have access to the machine, collect the following info:

* Public IP address, Private IP address details, Proxy details and Mac address.
* Browsers in use - version, default browser
* Is internet accessible from the machine directly
* systeminfo details, users logged in, Domain admins, password policy, etc
* Whether the C drive is encrypted using Bitlocker?
* Whether we have admin access to the machine?
* Powershell version installed - can we downgrade to 2.0 if Win 10 is there.
* AV/EP products installed and what other important services are running.
* Check internet connection after removing proxy as well.
* Dump lsass.exe using procdump and upload it to our webserver.

Get all these details on a text file and upload it to our server. would host a fake webpage on a fake audit domain with upload functionality where we would upload all these details from the user computer itself.

Make the employee sign a paper which will include his email, name, user id and signature. This paper would server 2 purpose – one is to convince the employee that a successful audit has happened and other is to collect data which will serve as a proof of successful SE attempt in our report.

If the situation is right, place our malware on the system after downloading it from our webserver which would give us reverse shell and also make it persist.

If we have less time, we can use HID device to deliver malware.

Put the LAN turtle after configuring it with the network details we got in the first step and check if we receive the reverse connection or not.

Dumpster diving – Check for any sensitive unattended papers lying around with network diagram, credentials, Financial data, etc

## Post-Exploitation/ Setup fake Wifi captive portal

Continue with the post-exploitation from base if managed to get a reverse shell from the network.

If we could not get a reverse shell from last day activity, we would need to continue the post exploitation assessment sitting from the office:

* Intrude successfully again into the office and take a comfortable seat where we can sit for a long time.
* We can either use one of their machine to boot up kali from our USB or connect our machine to their network.
* If enterprise wifi is there, we can connect to that wifi as well.
* We can also install a small wifi router and keep the SSID broadcast hidden. We can connect to the internal network then sitting somewhere else around that area.

Setup fake wifi captive portal to capture creds \(keep it at last for the detection risk\)

Continue with the Post-exploitation.

Post-Exploitation Goals:

* Privilege escalation, pivoting and Lateral movement to other networks.
* Use Windows system binaries only as much as possible instead of loading any external script or exe.
* Obtain sensitive documents from each pc you compromise.
* After priv esc, dump lsass.exe, upload it to our webserver and get the Hash or the plaintext creds of the user.
* Try to get domain admin creds or hash via any means.
* Try to find sensitive creds stored on the PC like passwords to any important webservice, sharepoint urls, file servers, etc.
* Try to get access to the Domain controller machine via domain admin creds.
* If nothing works, we might need to check for common exploits like MS17-010 in the whole subnet.
* Exploiting AD Misconfigurations.

## Phishing attempt/Malware delivery

Continue with the Post-exploitation. Phishing \(Credential Harvesting\):

* Clone of company's internal web applications
* Pre-Defined templates for phishing email

## Data Exfiltration

* Compress the files into a zip file and upload it to our upload portal in order to evade DLP.
* Use Powershell script to compress any file. \(Practice\)
* Upload that zip file to our C2 server or use curl to upload the file to a web portal. \(Practice\)
* Other techniques for Data exfiltration \(practice\)

## Day After

Continued Phishing attempt/Malware delivery Continue with the Post-exploitation.

* The same would be repeated for all the locations with incorporating the learnings we got in the previous exercises.

