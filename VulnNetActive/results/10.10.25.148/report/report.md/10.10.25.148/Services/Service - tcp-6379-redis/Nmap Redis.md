```bash
nmap -vv --reason -Pn -T4 -sV -p 6379 --script="banner,redis-info" -oN "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_nmap.txt" -oX "/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/xml/tcp_6379_redis_nmap.xml" 10.10.25.148
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_nmap.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_nmap.txt):

```
# Nmap 7.92 scan initiated Thu Jul 14 21:01:41 2022 as: nmap -vv --reason -Pn -T4 -sV -p 6379 --script=banner,redis-info -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/xml/tcp_6379_redis_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.20s latency).
Scanned at 2022-07-14 21:01:42 IST for 22s

PORT     STATE SERVICE REASON          VERSION
6379/tcp open  redis   syn-ack ttl 127 Redis key-value store 2.8.2402 (64 bits)
|_redis-info: ERROR: Script execution failed (use -d to debug)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:02:04 2022 -- 1 IP address (1 host up) scanned in 23.32 seconds

```
