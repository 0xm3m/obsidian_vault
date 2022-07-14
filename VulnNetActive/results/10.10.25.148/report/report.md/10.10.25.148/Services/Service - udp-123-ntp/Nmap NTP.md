```bash
nmap -vv --reason -Pn -T4 -sU -sV -p 123 --script="banner,(ntp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/udp_123_ntp_nmap.txt" -oX "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/xml/udp_123_ntp_nmap.xml" 10.10.25.148
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/udp_123_ntp_nmap.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/udp_123_ntp_nmap.txt):

```
# Nmap 7.92 scan initiated Thu Jul 14 21:24:47 2022 as: nmap -vv --reason -Pn -T4 -sU -sV -p 123 "--script=banner,(ntp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/udp_123_ntp_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp123/xml/udp_123_ntp_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.20s latency).
Scanned at 2022-07-14 21:24:47 IST for 11s

PORT    STATE SERVICE REASON               VERSION
123/udp open  ntp     udp-response ttl 127 NTP v3
| ntp-info: 
|_  receive time stamp: 2022-07-14T15:54:53

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:24:58 2022 -- 1 IP address (1 host up) scanned in 11.16 seconds

```
