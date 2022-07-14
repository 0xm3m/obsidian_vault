```bash
nmap -vv --reason -Pn -T4 -sU -sV -p 53 --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_nmap.txt" -oX "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/xml/udp_53_dns_nmap.xml" 10.10.25.148
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_nmap.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_nmap.txt):

```
# Nmap 7.92 scan initiated Thu Jul 14 21:24:47 2022 as: nmap -vv --reason -Pn -T4 -sU -sV -p 53 "--script=banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/xml/udp_53_dns_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.19s latency).
Scanned at 2022-07-14 21:24:47 IST for 44s

PORT   STATE SERVICE REASON               VERSION
53/udp open  domain  udp-response ttl 127 (generic dns response: SERVFAIL)
|_dns-cache-snoop: 0 of 100 tested domains are cached.
|_dns-nsec3-enum: Can't determine domain for host 10.10.25.148; use dns-nsec3-enum.domains script arg.
|_dns-nsec-enum: Can't determine domain for host 10.10.25.148; use dns-nsec-enum.domains script arg.
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.92%I=7%D=7/14%Time=62D03C5C%P=aarch64-unknown-linux-gnu%
SF:r(NBTStat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAA
SF:AAAAAAAAAAAAA\0\0!\0\x01");

Host script results:
|_dns-brute: Can't guess domain of "10.10.25.148"; use dns-brute.domain script argument.

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:25:31 2022 -- 1 IP address (1 host up) scanned in 43.74 seconds

```
