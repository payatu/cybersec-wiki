---
title: Password Cracking
description: Password cracking in cloud
published: true
date: '2020-07-10T10:22:25.465Z'
tags: null
editor: markdown
---

# Password Cracking in Cloud

AWS p3.16xlarge instance offers decent hardware for cracking hashes. This post is a cheat sheet for configuring an instance and start cracking hashes in no time. The p3.16xlarge instance type isn't available in the instance type list by default, and a support ticket has to be raised to get it enabled for your account \(Probably because it is expensive - 25$/Hour\). In my case it only took a few hours to get it enabled.

## Setup Environment

* Execute the following commands to install the requirements

```text
sudo apt-get update && sudo apt-get install -y build-essential linux-headers-$(uname -r) p7zip-full linux-image-extra-virtual
```

* This will update everything and install the required packages. Then edit the `/etc/modprobe.d/blacklist-nouveau.conf` file and add the following:

```text
blacklist nouveau
blacklist lbm-nouveau
options nouveau modeset=0
alias nouveau off
alias lbm-nouveau off
```

* Then run the following commands

```text
$ echo options nouveau modeset=0 | sudo tee -a /etc/modprobe.d/nouveau-kms.conf
$ sudo update-initramfs -u
$ sudo reboot
```

* Now all that's left is to download the NVIDIA Drivers and Hashcat.
* To install the drivers download the latest version from the NVIDIA website.

```text
$ wget http://us.download.nvidia.com/tesla/410.104/NVIDIA-Linux-x86_64-410.104.run
$ sudo /bin/bash NVIDIA-Linux-x86_64-410.104.run
```

* To Download Hashcat download the latest version of hashcat

```text
$ wget https://hashcat.net/files/hashcat-5.1.0.7z
$ 7za x hashcat-5.1.0.7z
```

## Hashcat basic usage

```text
$ sudo ./hashcat64.bin --args
```

## Common modes

* Modes are specified using the **-m**  commandline parameter.

| Mode | Name |
| :--- | :--- |
| 5500 | NTLM |
| 5600 | NTLM v2 |
| 13100 | Kerberos |
| 400 | Wordpress |
| 10 | Joomla |
| 1800 | Unix Type 6 \(SHA-512\) \(Common format of shadow files\) |

## Modes of attacks

There are several approaches to cracking hashes. Given a hash we can either check it against a list of passwords \( word list\) or try to brute force all the characters \( Doesn't work well with very long and complex passwords\) or have some modifications done on the existing word list, for example append 123 after every entry in our wordlist.

### Dictionary attack

* The dictionary attack, or “straight mode,” is a very simple attack mode. It is also known as a “Wordlist attack”.
* All that is needed is to read line by line from a textfile \(aka “dictionary” or “wordlist”\) and try each line as a password candidate.
* The command for the Dictionary Attack in hashcat is **-a 0**

### Combinator attack

* Each word of a dictionary is appended to each word in a dictionary.

#### Input

```text
pass
12345
omg
Test
```

#### Output

```text
passpass
pass12345
passomg
passTest
12345pass
1234512345
12345omg
12345Test
omgpass
omg12345
omgomg
omgTest
Testpass
Test12345
Testomg
TestTest
```

#### Usage

* The command for the Combinator Attack in hashcat is **-a 1**
* You need to specify exactly 2 dictionaries in your command line

```text
./hashcat64.bin -m 0 -a 1 hash.txt dict1.txt dict2.txt
```

### Mask attack

* Try all combinations from a given keyspace just like in Brute-Force attack, but more specific.

#### Masks

For each position of the generated password candidates we need to configure a placeholder. If a password we want to crack has the length 8, our mask must consist of 8 placeholders.

* A mask is a simple string that configures the keyspace of the password candidate engine using placeholders.
* A placeholder can be either a custom charset variable, a built-in charset variable or a static letter.
* A variable is indicated by the ? letter followed by one of the built-in charset \(l, u, d, s, a\) or one of the custom charset variable names \(1, 2, 3, 4\).
* A static letter is not indicated by a letter. An exception is if we want the static letter ? itself, which must be written as ??.

#### Output

```text
aaaaaaaa
aaaabaaa
aaaacaaa
.
.
.
aaaaxzzz
aaaayzzz
aaaazzzz
baaaaaaa
baaabaaa
baaacaaa
.
.
.
baaaxzzz
baaayzzz
baaazzzz
.
.
.
zzzzzzzz
```

#### Built-in charsets

* ?l = abcdefghijklmnopqrstuvwxyz
* ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
* ?d = 0123456789
* ?h = 0123456789abcdef
* ?H = 0123456789ABCDEF
* ?s = «space»!"\#$%&'\(\)\*+,-./:;&lt;=&gt;?@\[\]^\_\`{\|}~
* ?a = ?l?u?d?s
* ?b = 0x00 - 0xff

#### Usage

```text
Command: -a 3 ?l?l?l?l?l?l?l?l
Keyspace: aaaaaaaa - zzzzzzzz

Command: -a 3 -1 ?l?d ?1?1?1?1?1
Keyspace: aaaaa - 99999

command: -a 3 password?d
keyspace: password0 - password9

command: -a 3 -1 ?l?u ?1?l?l?l?l?l19?d?d
keyspace: aaaaaa1900 - Zzzzzz1999

command: -a 3 -1 ?dabcdef -2 ?l?u ?1?1?2?2?2?2?2
keyspace: 00aaaaa - ffZZZZZ

command: -a 3 -1 efghijklmnop ?1?1?1
keyspace: eee - ppp
```

### Hybrid attack

* Basically, the hybrid attack is just a Combinator attack. One side is simply a dictionary, the other is the result of a Brute-Force attack. In other words, the full Brute-Force keyspace is either appended or prepended to each of the words from the dictionary. That's why it's called “hybrid”.
* Alternatively you can use Mask attack or Rule-based attack to replace the brute-force side.

#### Usage

* If the **example.dict** contains

```text
password
hello
```

* The configuration

```text
$ ... -a 6 example.dict ?d?d?d?d
```

generates the following candidates:

```text
password0000
password0001
password0002
.
.
.
password9999
hello0000
hello0001
hello0002
.
.
.
hello9999
```

* It also works in the opposite side!
* The configuration

```text
$ ... -a 7 ?d?d?d?d example.dict
```

generates following password candidates:

```text
0000password
0001password
0002password
.
.
.
9999password
0000hello
0001hello
0002hello
.
.
.
9999hello
```

