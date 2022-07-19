---
title: "THM - # VulnNet: Active"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # VulnNet: Active"
categories:
  - THM
---

The given box ```VulnNet: Active``` is a Linux machine with an IP address of ```10.10.135.22```

- [TryHackMe- VulnNet:Active](#tryhackme---razorblack)
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
