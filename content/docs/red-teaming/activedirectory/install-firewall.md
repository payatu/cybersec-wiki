---
title: Install Firewall
---

# Install Firewall

So far, our network was **Host-Only** network, which means the machines are yet not connected to the Internet. They can communicate with themselves within the network but not outside the network.

We will set up a firewall which will be connected to the internet as well as to the machines inside the network. This will also work as a gateway, which will route all the network traffic.

We will install [pfSense](https://www.pfsense.org/) VM, which is a simple firewall based on BSD Operating Systems.

## Building our Firewall VM

Provision a new VM for the Firewall. It doesn't have to be anything fancy, 1 vCPU, 256MB of RAM and 5GB of HDD should cover it. Make sure that when you're creating the VM, you choose FreeBSD 64-bit. We will add 2 network adapters:

* Network Adapter 1: Host-Only Network
* Network Adapter 2: NAT

![](https://kbassets.sgp1.digitaloceanspaces.com/1551940442517-vm-setup-01.png)

**Host-Only** network will be used to communicate with machines in the AD environment network. **NAT** will be used to communicate with the internet.

## Installing pfSense

* Download the [iso](https://www.pfsense.org/download/) from the website, and boot the VM off it.
* When prompted Press `I` to start the Installer. Choose `Accept These Settings` and then `Quick/Easy Install`.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551940442500-install-vm-01.png)

* When prompted, choose `Standard Kernel` and then reboot when prompted.

> Make sure to **unmount the ISO from the VM** before the machine boots back up.

## Setting up pfSense

* When pfSense is booted, you will be presented with a menu.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551940442501-install-vm-02.png)

We need to configure the LAN interface to work properly for our Host-Only network. To do this, from the PFSense menu, press `2` to select `Change IP Addressing` and `2` again to select the `LAN Interface`. You'll then run through a series of prompts to setup the router. Here are the answers:

* **New LAN IPv4 Address:** The address we give this interface should be the same address you used as the **gateway address** when you setup the IP address on the **Domain Controler** in the previous part. In the example, I used `10.10.10.2`
* **New LAN Subnet Bit Count:** This depends on how you setup your **Host-Only network**, but it's probably `24`.
* **Upstream Gateway Address:** Just press enter, we don't need an upstream IP for a LAN interface.
* **New LAN IPv6 Address:** Just press enter, we're not using IPv6 for routing.
* **Enable DHCP Server on LAN?:** `N`, we want to disable the DHCP server in pfSense.
* **Revert to HTTP?:** `N`, We do not want to use HTTP for the admin interface.

![](https://kbassets.sgp1.digitaloceanspaces.com/1551940442516-install-vm-03.png)

Our pfSense box is now set up. There's a ton more we can do with pfSense, it will definitely be able to grow with you if you start building more complicated labs, for now though this is all we need for our simple lab setup.

