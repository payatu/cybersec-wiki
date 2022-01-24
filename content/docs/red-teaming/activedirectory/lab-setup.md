---
title: Lab Setup
description: Active Directory Lab Overview
published: true
date: '2020-05-26T06:55:11.122Z'
tags: null
---

# Lab Setup

Here we will be looking at various Active Directory concepts and set up an Active Directory environment Lab.

## Current Lab status

### VMware images

* Windows Server 2016 used for Active Directory Domain Services \(ADDS\).
  * Storage: 30GB
  * RAM: 2 GB
  * Network Adapter: Host Only
* 2 x Windows 7 Ultimate/Enterprise
  * Storage: 30GB
  * RAM: 1.2 GB
  * Network Adapter: Host Only
* pfSense Firewall
  * Storage: 5 GB
  * RAM: 256 MB
  * Network Adapter 1: Host Only
  * Network Adapter 2: NAT

### Active Directory Environment

* Domain: `ecorp.com`
* Domain admins: 2
* Domain users: 2
* Domain Controllers: 1

The entire Active Directory environment will be behind the firewall. The firewall will also act as a proxy server, which means all the network traffic will be routed through the firewall.

