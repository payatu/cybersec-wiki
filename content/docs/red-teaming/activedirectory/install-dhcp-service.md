---
title: Install DHCP Service
---

# DHCP Service

Hosting DHCP through a Windows box in Active Directory gives us plenty of benefits, chief among them being that DHCP leases will automatically be added to our DNS servers. It's also incredibly easy to setup.

For the purposes of our lab, we can just host DHCP on the Domain Controller. This isn't something you'd typically see in production except for maybe in very very tiny networks. In a production environment you typically want your domain controllers dedicated to domain controlling. Adding extra roles to the DCs increases risk, patching overhead and the chance that they're going to crash cause of something stupid.

## Install DHCP service

* Login to your DC and start the `Add Roles and Features` wizard. This time we're going to add the `DHCP Server Role`. When prompted to add the required features, select `Add Features`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222930-install-dhcp-01.png)

* After that, keep clicking `Next` until you get the option to `Install`, then click that.
* Once the install has finished, we can configure the DHCP server by clicking on the `Notification` button in Server Manager and selecting `Complete DHCP configuration`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222933-install-dhcp-02.png)

* Click Next &gt; Next &gt; Finish.

## Configure DHCP Server

* In `Server Manager` click on the `Tools` menu in the upper right and select `DHCP`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222933-install-dhcp-03.png)

* Expand your domain on the left-hand side, right click IPv4 and select Add New Scope

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222943-install-dhcp-04.png)

* Click Next through the Wizard. When prompted, name your DHCP scope. I named it `Lab`.
* When prompted for the scope, create a range of **50 to 100** IPs within your network and set your subnet mask appropriately.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222948-install-dhcp-05.png)

* Keep clicking `Next` in the wizard you're asked if you'd like set additional options, select `Yes` and click `Next`.
* For the router address, enter the address that you set for the LAN interface on the **PFSense VM** \(the same address that you put as the default gateway on the Domain Controller\). For this lab, I'm using `10.10.10.2`. Click `Add` then click `Next`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551941222948-install-dhcp-06.png)

* Keep clicking `Next` until you get to the end of the wizard.

