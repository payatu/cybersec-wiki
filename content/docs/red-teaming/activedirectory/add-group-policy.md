---
title: Add Group Policy
description: Add Group Policies
published: true
date: '2020-05-26T06:52:45.359Z'
tags: null
---

# Add Group Policy

Group Policy is one of the main reasons Active Directory has been so successful. It allows you to granularly configure User and Computer settings throughout a domain.

We're going to go ahead and turn off Windows Firewall for Computers in our `Lab\Computers` OU. While this is obviously bad practice, it's a nice example of `Group Policy` settings and is fairly typical in production Windows environments.

## Creating Group policy objects

* Go to start menu and open `Group Policy Management`.

![Open Group Policy management](https://kbassets.sgp1.digitaloceanspaces.com/1551949197081-open-group-policy-mgmt.png)

* Expand out Forest &gt; Domains &gt; ecorp.com &gt; Lab. Right click the `Computers` OU and choose `Create a GPO in this domain...`

![Add Group policy](https://kbassets.sgp1.digitaloceanspaces.com/1551949197067-ad_lab_group_policy02.png)

* Name the GPO `Firewall Rules`

![Name Group Policy](https://kbassets.sgp1.digitaloceanspaces.com/1551949197069-ad_lab_group_policy_03a.png)

* Right click the newly created GPO and choose `Edit`

![Edit Group Policy](https://kbassets.sgp1.digitaloceanspaces.com/1551949197069-ad_lab_group_policy_03b.png)

* In the `Group Policy Managment Editor` window that opens up, expand Computer Configuration &gt; Policies &gt; Windows Settings &gt; Security Settings &gt; Windows Firewall.. and select `Windows Firewall..`. Click the `Windows Firewall Properties` link

![Select Firewall](https://kbassets.sgp1.digitaloceanspaces.com/1552025879997-ad_lab_group_policy_04.png)

* This brings up a standard Windows firewall settings window. Set the Firewall to `Off` and click **OK**.

![Disable Firewall](https://kbassets.sgp1.digitaloceanspaces.com/1551949197080-ad_lab_group_policy_04a.png)

## Things to know about Group Policies

Group Policy takes some time to take effect. Computers will check for updates every 45 minutes or so. You can speed this up by running gpupdate on the computer that you want to update You can also just reboot the computer, it will pull new updates when it boots.

You'll notice that Group Policy settings are split between User and Computer and sometimes the same setting exists in both areas \(for example, a lot of Internet Explorer settings\). A common mistake is setting something in the Computer settings and then applying that GPO to an OU full of users \(or vice versa\). Those settings won't take effect since they have nothing to act on.

