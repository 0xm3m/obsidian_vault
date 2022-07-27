```bash
nmap -vv --reason -Pn -T4 -sV -p 53 --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/tcp_53_dns_nmap.txt" -oX "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/xml/tcp_53_dns_nmap.xml" 10.10.25.148
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/tcp_53_dns_nmap.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/tcp_53_dns_nmap.txt):

```
# Nmap 7.92 scan initiated Thu Jul 14 21:01:41 2022 as: nmap -vv --reason -Pn -T4 -sV -p 53 "--script=banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/tcp_53_dns_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp53/xml/tcp_53_dns_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.21s latency).
Scanned at 2022-07-14 21:01:42 IST for 168s

PORT   STATE SERVICE REASON          VERSION
53/tcp open  domain? syn-ack ttl 127
|_dns-nsec3-enum: Can't determine domain for host 10.10.25.148; use dns-nsec3-enum.domains script arg.
|_dns-nsec-enum: Can't determine domain for host 10.10.25.148; use dns-nsec-enum.domains script arg.

Host script results:
|_dns-brute: Can't guess domain of "10.10.25.148"; use dns-brute.domain script argument.

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:04:30 2022 -- 1 IP address (1 host up) scanned in 169.04 seconds

```
