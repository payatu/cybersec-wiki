---
title: Create Forest
description: Create AD Forest
published: true
date: '2020-05-26T06:47:07.475Z'
tags: null
---

# Create Forest

The first thing we require to build AD environment is a Forest. A Forest is a collection of domains. We will also be adding a domain to our Forest. I will name my domain `ecorp.com`. You are free to choose your domain name. There are few steps to perform before creating a forest.

Following are the steps to create an AD forest for the first time. This will also create a new domain.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855814243-AD-create-forest-steps.jpg)

## Assign an IP address

It's a good practice to assign a static IP address to a Domain Controller. In the next steps we will be promoting the server to a Domain Controller, so we will assign a static IP address first.

* Go to network properties to assign IP to the machine. Type `ncpa.cpl` in RUN to open network and sharing center. 

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855862263-AD-setup-ip-01.png)

* Click on properties and select `Internet Protocol Version 4 (TCP/IPv4)`. Click on `Properties`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855862264-AD-setup-ip-02.png)

* Set static IP address. The address which I am using is the subnet `10.10.10.0/24` and the IP assigned to this machine will be `10.10.10.199` with subnet mask of `255.255.255.0`.
* Since this is also going to be our DNS server. I will add this machine to DNS server as well. The other DNS server `8.8.8.8` is the Google DNS server, used as a fallback server.
* Default Gateway is `10.10.10.2` which is a proxy server. We will discuss about setting up proxy server later.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855862264-AD-setup-ip-03.png)

* Click on `OK`.
* **PS:** Since our proxy is not set-up, the internet will not work.

## Change Computer Name

A meaningful name is required so that administrators can remember which server is DC, File Server, DHCP server etc. Go to system properties and change the computer name. Type `sysdm.cpl` in RUN to open system properties and change computer name.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855953067-AD-change-computer-name-01.png)

* Reboot machine to apply changes.

## Installing the ADDS Role

* Go to `Server Manager` and click `Add roles and features`

![](https://kbassets.sgp1.digitaloceanspaces.com/1551854818687-AD-ADDS-01.jpg)

* Select the first option: – `Role-based or feature-based installation`

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855991631-AD-ADDS-02.jpg)

* Click next until you reach the step to select roles. Select `Active Directory Domain Services` and click `Add Features` to the window that pops up. Click next.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855991640-AD-ADDS-03.jpg)

* **PS:** It shows `(installed)` because I have already installed the Service. If you are doing it for the first time, it will not show as installed.
* Keep clicking `Next` until it installs roles and features. It takes some time to install the roles.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855991649-AD-ADDS-04.jpg)

## Promoting the server to a Domain Controller

* After the roles and features are installed, it will show an exclamation mark in the Server Manager. Click this to select the option to `Promote this Server to Domain Controller`

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855991656-AD-ADDS-05.jpg)

## Create a forest and enter a domain name

* After promoting the server to Domain Controller, we get an option to add a forest. Select `Add a New Forest` and enter a domain name. I named the forest as `ecorp.com`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551855991664-AD-ADDS-06.jpeg)

* Click next. On the next screen, leave the defaults as it is and create a recovery password. This is called `DSRM` password. This password provides the administrator with a kind-of backdoor to the AD database in case there is some issue with the domain or when you need to restore/recover the AD database.
* Just accept the defaults in the next series of prompts. It will check some pre-requisites and show some warnings, that’s Okay. Click `Install`.
* Now in the backend, installation and configuration of Active Directory and DNS will take place and then the server will reboot.
* After the reboot, your domain controller is ready! A logon screen will appear. You can log in using the same Administrator account.
* Please note that now the account is promoted to a Domain Administrator as the computer is a Domain Controller now. Below is the format for login:

```text
Username– ecorp\Administrator

Password– XXXXXXXXX
```

