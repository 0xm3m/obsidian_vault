```bash
dig -p 53 -x 10.10.25.148 @10.10.25.148
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_reverse-lookup.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/udp53/udp_53_dns_reverse-lookup.txt):

```

; <<>> DiG 9.18.4-2-Debian <<>> -p 53 -x 10.10.25.148 @10.10.25.148
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 51051
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;148.25.10.10.in-addr.arpa.	IN	PTR

;; Query time: 4468 msec
;; SERVER: 10.10.25.148#53(10.10.25.148) (UDP)
;; WHEN: Thu Jul 14 21:24:56 IST 2022
;; MSG SIZE  rcvd: 54



```
