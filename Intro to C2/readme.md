---
title: "THM - # Intro to C2"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Intro to C2"
categories:
  - THM
---

<center>
<img src=https://github.com/enum-more/obsidian_vault/raw/main/Intro%20to%20C2/redteamfundametals.png/>
</center>

The given box ```Intro to C2``` is a Linux machine with an IP address of ```10.10.135.22```

- [TryHackMe-  Intro to C2](#tryhackme---razorblack)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
	  - [Redis](#redis)
	  - [SMB](#smb)
  - [Post Escalation](#post-escalation)
	  - [SMB Reverse-Shell](#smb-reverse-shell)
  - [Privilege Escalation](#privilege-escalation)
	  - [BloodHound Enumeration](#bloodhound-enumeration)
	  - [Exploiting the GPO](#exploiting-the-gpo)

## Recon

### Nmap Scan Result