---
title: "THM - # Enumerating Active Directory"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Enumerating Active Directory"
categories:
  - THM
---

The given box ```Enumerating Active Directory``` is a AD machine with an IP address of ```10.10.135.22```

- [TryHackMe- Enumerating Active Directory](#tryhackme---Enumerating-Active-Directory)
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

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/adenumeration/attacking-ad.png" />
</center>

## Recon

### Nmap Scan Result
