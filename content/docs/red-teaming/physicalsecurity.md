---
title: Physical Security
description: Breaching Physical security in Red Team
published: true
date: '2020-07-10T10:28:48.967Z'
tags: null
editor: markdown
---

# Physical Security

### Introduction

During a redteam assessment, bypassing physical security and gaining access to the building can be done via these techniques:

1. Clone employee's RFID card and use that to enter the premises
2. Tail gate while wearing a fake ID Card/Lanyard. Jump through the fences/walls or find an entry point where the employee ID card is not scanned/checked.
3. Getting inside the building via Social engineering

Each of the above techniques are discussed in detail below.

## RFID Cloning

RFID cloning is a huge topic in itself. For our purpose, We will only discuss the RFID cloning techniques according to a redteam perspective.

There are a number of RFID authentication technologies commonly used in access cards and I've encountered these in my experiences:

### HF \(High Frequency cards\)

* HID iClass \(13.56 MHz\)
* MIFARE Classic \(13.56 MHz\)

### LF \(Low Frequency cards\)

* Indala \(125 kHz\)
* HID ProxCard \(125 kHz\)
* EM4100x \(125 kHz\)

Generally, there is no authentication scheme in Low frequency cards and it is very easy to clone them. High frequency cards have authentication schemes inbuilt in them and the data is encrypted with a key which makes them harder to read and clone without the key.

The only possibility to clone HF cards are if:

* The HF card is using a default encryption key
* The HF card keys can be cracked \(Implementation flaw in the authentication algorithm for specific cards\)

We use standalone proxmark3 to copy RFID card data. It has two antennas, one HF and one LF. In a realtime scenario, We need to hide our Proxmark device into a stealth package, Press the physical cloning button on it and bring it near to the employee's ID card in order to clone it. The Proxmark will start emulating the cloned card if we were successful in reading the card and it can also copy the cloned card data onto another blank card with the press of a button.

![Proxmark-1](https://kbassets.sgp1.digitaloceanspaces.com/1562915030696-proxmark_1.jpg){: style="height:700px;width:500px"} ![Proxmark-2](https://kbassets.sgp1.digitaloceanspaces.com/1562916754509-proxmark_2.jpg)

Generally, LF cards can be easily cloned using the above technique.

## Printing Fake ID Card and Tail gating

Employees often upload their company's ID card pictures onto social media which can be easily found via a simple google search. ID card samples of particular organisation can also be found on their facebook page where the employees are wearing their ID card in a group photoshoot.

We can design and print a fake ID card/Lanyard from the data gathered during OSINT phase and use that to enter the campus while tail gating.

`Tailgating is often described as the passage of unauthorised personnel, either forced or accidental, behind that of an authorised user.`

Tips for tail gating:

* Do a recon first before attempting to tail gate. From the recon, you need to gather data on behavioural patterns like - What number of guards are present at the scene? How attentive they are? If any legit employee is actually trying to tail gate? For how much time the gate remains open after an employee gets in? Is there any other door which provides direct access to the building bypassing the RFID door - Fire exit door, Entry from parking lot, etc.
* From my experience, tail gating through a single glass/wooden door is much easier than tail gating through metro style doors. Always try to attempt to tail gate though the glass/wooden door rather than through the metro style door.
* Always try to tail gate when there are multiple people trying to enter the building - after lunchbreaks or smokebreaks.
* Guards are more attentive in the morning. They become more relaxed as the day passes by. After lunch break is a good time to get in.
* Blend in with other employees before attempting to tail gate.
* Do not maintain a distinctive look from other employees. Try to match the dress code with other employees and keep a generic hairstyle.
* Maintain a calm and relaxed behaviour/face while tail gating or social engineering.
* Always put your fake ID card on the RFID reader when tail gating even when it's fake. It will avoid suspicion.

## Getting in via social engineering

In small offices, where the number of people are less and guards remember the faces of employees, It's tough to get in via tail gating or RFID cloning. One such example of this could be a bank or a transport company's back office. We can perform social engineering on employees to get in there.

* Carry a fake letter with the company's letterhead which states that a person of a higher authority has sent you here. Forge a signature on that letter of a person of higher authority.
* Impersonate yourself as someone being sent from a higher authority to perform routine security/network audit.
* A little intimidation works sometimes in such situations.

