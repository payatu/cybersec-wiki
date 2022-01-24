---
title: Add Users to AD Domain
description: Add users in the AD domain
published: true
date: '2020-05-26T06:49:29.555Z'
tags: null
---

# Adding users to the AD Domain

Now that we have set up Active Directory service, we will add some users to it. We can also assign various roles to the users. In this part, we will be assigning **Domain Admins** role to some of the users. I will be creating following 4 users:

* 2 x Domain Admins
* 2 x Domain Users

Users with **Domain Admins** role has the permission to add or remove users/computers, change group policies, install services and many other permissions. Members of this group have full control of the domain. By default, this group is a member of the Administrators group on all domain controllers, all domain workstations, and all domain member servers at the time they are joined to the domain.

Users with **Domain User** \(default role\) does not have any special permissions available. They can only login to a machine and work in there environment. The credentials of a Domain User is stored in the **Active Directory Database**.

## To add a user in the domain

* In the domain controller, open `Active Directory Administrative Center`
* In the left hand corner, change the view to tree view.
* You can see that we have already created an **OU** named `Lab`.

![Show OUs](https://kbassets.sgp1.digitaloceanspaces.com/1551944944109-adac-show-ou.png)

* We have already created two OU's inside `Lab` OU, which are `Computers` and `Users` where we add computers and users to the domain.
* Go to the `Users` OU and right click on the right section.
* Click on New -&gt; User

![Add new user](https://kbassets.sgp1.digitaloceanspaces.com/1551944944090-adac-add-new-user.png)

* Enter user details including the password.

![Add user details](https://kbassets.sgp1.digitaloceanspaces.com/1551944944098-adac-add-user-details.png)

* To add a group policy, Click on `Member of` from the left side options.
* If you want to add the user in the `Domain Admins` group, click on the `Add` button on the right side and enter `Domain Admins` in the input field saying `Enter the object names to select`, and click on `OK`.

![Add user to domain admins](https://kbassets.sgp1.digitaloceanspaces.com/1551944944104-adac-add-user-to-domain-admin-group.png)

* Done. Click on `Ok` on the bottom right.

![Added user to domain admin group](https://kbassets.sgp1.digitaloceanspaces.com/1551944944086-adac-added-user-to-domain-admin-group.png)

