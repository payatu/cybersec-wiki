---
title: Introduction
---

# Introduction

Active Directory is a collection of technologies used to manage a group of users and computers. This collection of users and computers falls under a domain. A domain is referred to by its name. Older networks \(say.. before Windows 2008\) typically had a single name, for example LAB. Nowadays, domains are named using a more typical domain name structure. Typically, companies will have their Active Directory domain as a subdomain of their main domain for example, ad.company.com. For this lab though, our domain will simply be **ecorp.com**.

Another term that you'll see is Forest, which is a collection of domains. A domain is always part of a forest, even if there's just one domain. Following is the image of AD forest. A forest is composed of one or more trees. Unlike a tree, a forest can contain several non-contiguous namespaces.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551766812042-AD-forest.jpg)

## What Services make an Active Directory domain

As mentioned before AD is a collection of services. For the purpose of our simple lab all of these services are going to be handled by a single server, our Domain Controller. In production network, you'll have multiple domain controllers for resiliency \(very bad things happen if your DCs vanish from your domain\)

## Active Directory Related Definitions

### AD Database

The information on user identity, computers, groups, services and resources etc. is stored in Active Directory database which is made up of a single file named ntds.dit. By default, it is stored in the %SYSTEMROOT%\NTDS folder.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551766730494-AD-database.jpg)

### Group Policies

Group Policy is used to define user, security and networking policies at the machine level. Administrators can apply group policies from a centralized location to the whole domain or few computers/users.

## Services Run by Active Directory

### DNS

DNS is absolutely vital for Active Directory to work. Active Directory relies on a series of DNS records to establish what services are available on the domain and who provides what. For the most part, these records are managed automatically, all we need to worry about right now is making sure DNS is available.

### LDAP

Lightweight Directory Access Protocol. This service is responsible for keeping track of what is on the network

### Kerberos

Kerberos handles Single Sign On throughout the domain. It is what allows you to use one username and password to log into multiple computers throughout the domain.

### SMB

SMB is used to share files throughout a domain. Domain Controllers use it to share group policy objects among other things.

All of these services are installed and configured when you install the Active Directory Domain Services role in Windows Server.

