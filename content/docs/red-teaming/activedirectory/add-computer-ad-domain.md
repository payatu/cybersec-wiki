---
title: Add Computer to AD Domain
---

# Adding Computer to AD Domain

In this part, we will be adding computer to the Active Directory domain. These computers can be used to login for any user which is added in the domain.

## Change DNS server

* Login to the local computer/VM and follow the following steps.
* Go to network properties to set up DNS server. Type `ncpa.cpl` in RUN to open network and sharing center.
* Add Domain Controller IP in the DNS server, since the DC itself is the DNS Server.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551946355245-add-01.png)

## Change Computer Name

* Set a name that helps you to identify the server or computer and which server is DC, File Server, DHCP server etc.
* Go to system properties and change the computer name. Type `sysdm.cpl` in RUN to open system properties. Click on `Change`

![](https://kbassets.sgp1.digitaloceanspaces.com/1551946355245-add-02.png)

* Select `Member of` and add the AD domain created. I created domain `ecorp.com`. This will add the system to the domain.
* Click `Ok` and enter authenticated user's credentials to add system into domain.

## Who should be able to add computers into domain?

This setting should be changed. If you don’t change this, any standard domain user would be able to join their machines to the domain. And If they do, they become Owner of the computer objects in AD \(from ACL point of view\) and additionally have `ACCESS_CONTROL` flag which means they can read confidential attributes for that object \(for example LAPS passwords etc.\). Delegation should be used instead of default setting.

