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

```shell
root@ip-10-10-82-10:~# service postgresql start
root@ip-10-10-82-10:~# service postgresql status
\u25cf postgresql.service - PostgreSQL RDBMS
   Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor prese
   Active: active (exited) since Mon 2022-07-18 15:22:16 BST; 1min 46s ago
  Process: 1483 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
 Main PID: 1483 (code=exited, status=0/SUCCESS)

Jul 18 15:22:16 ip-10-10-82-10 systemd[1]: Starting PostgreSQL RDBMS...
Jul 18 15:22:16 ip-10-10-82-10 systemd[1]: Started PostgreSQL RDBMS.
```

```shell
root@ip-10-10-82-10:~# su ubuntu
ubuntu@ip-10-10-82-10:/root$ msfdb delete
[?] Would you like to delete your existing data and configurations?: yes
No data at /home/ubuntu/.msf4/db, doing nothing
MSF web service is no longer running
ubuntu@ip-10-10-82-10:/root$ msfdb init
Creating database at /home/ubuntu/.msf4/db
Starting database at /home/ubuntu/.msf4/db...success
Creating database users
Writing client authentication configuration file /home/ubuntu/.msf4/db/pg_hba.conf
Stopping database at /home/ubuntu/.msf4/db
Starting database at /home/ubuntu/.msf4/db...success
Creating initial database schema
[?] Initial MSF web service account username? [ubuntu]: msf
[?] Initial MSF web service account password? (Leave blank for random password): 
Generating SSL key and certificate for MSF web service
Attempting to start MSF web service...failed
[!] MSF web service does not appear to be started.
Please see /home/ubuntu/.msf4/logs/msf-ws.log for additional details.
```

```shell
root@ip-10-10-82-10:~# cd /opt/armitage/release/
root@ip-10-10-82-10:/opt/armitage/release# cd unix/
root@ip-10-10-82-10:/opt/armitage/release/unix# clear
root@ip-10-10-82-10:/opt/armitage/release/unix# ls
armitage      armitage-logo.png  cortana.jar  readme.txt  whatsnew.txt
armitage.jar  build.txt          license.txt  teamserver
root@ip-10-10-82-10:/opt/armitage/release/unix# ./teamserver 10.10.82.10 thm
[*] Generating X509 certificate and keystore (for SSL)
[*] Starting RPC daemon
[*] MSGRPC starting on 127.0.0.1:55554 (NO SSL):Msg...
[*] MSGRPC backgrounding at 2022-07-18 15:26:04 +0100...
[*] MSGRPC background PID 3071
[*] sleeping for 20s (to let msfrpcd initialize)
cd [*] Starting Armitage team server
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by org.postgresql.jdbc.TimestampUtils (file:/opt/armitage/release/unix/armitage.jar) to field java.util.TimeZone.defaultTimeZone
WARNING: Please consider reporting this to the maintainers of org.postgresql.jdbc.TimestampUtils
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
[*] Use the following connection details to connect your clients:
	Host: 10.10.82.10
	Port: 55553
	User: msf
	Pass: thm

[*] Fingerprint (check for this string when you connect):
	966a651f2342fbd98e6933594e81ac133a881098
[+] feel free to connect now, Armitage is ready for collaboration
[+] tryhackme joined
[*] Warning: checkError(): javax.net.ssl.SSLException: Connection reset at server.sl:100
[+] tryhackme joined
```

```shell
root@ip-10-10-82-10:/opt/armitage/release/unix# ./armitage 
[*] Used the incumbent: 10.10.82.10
[*] Starting Cortana on 10.10.82.10
[*] Starting Cortana on 10.10.82.10
[*] Creating a default reverse handler... 0.0.0.0:16018
[*] Remote Exploits Synced
```