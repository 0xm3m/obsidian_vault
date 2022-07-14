```bash
redis-cli -p 6379 -h 10.10.25.148 INFO
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_info.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_info.txt):

```
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a45a9622ff23b7
redis_mode:standalone
os:Windows
arch_bits:64
multiplexing_api:winsock_IOCP
process_id:4012
run_id:1ef9e1c143a06bb357ed47542d7ec503892adc80
tcp_port:6379
uptime_in_seconds:1269
uptime_in_days:0
hz:10
lru_clock:13645533
config_file:

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:952800
used_memory_human:930.47K
used_memory_rss:901792
used_memory_peak:952800
used_memory_peak_human:930.47K
used_memory_lua:36864
mem_fragmentation_ratio:0.95
mem_allocator:dlmalloc-2.8

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1657811432
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
total_connections_received:2
total_commands_processed:1
instantaneous_ops_per_sec:0
total_net_input_bytes:28
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
used_cpu_sys:0.08
used_cpu_user:0.09
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace


```
```bash
redis-cli -p 6379 -h 10.10.25.148 CONFIG GET '*'
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_config.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_config.txt):

```
dbfilename
dump.rdb
requirepass

masterauth

unixsocket

logfile

pidfile
/var/run/redis.pid
maxmemory
0
maxmemory-samples
3
timeout
0
tcp-keepalive
0
auto-aof-rewrite-percentage
100
auto-aof-rewrite-min-size
67108864
hash-max-ziplist-entries
512
hash-max-ziplist-value
64
list-max-ziplist-entries
512
list-max-ziplist-value
64
set-max-intset-entries
512
zset-max-ziplist-entries
128
zset-max-ziplist-value
64
hll-sparse-max-bytes
3000
lua-time-limit
5000
slowlog-log-slower-than
10000
latency-monitor-threshold
0
slowlog-max-len
128
port
6379
tcp-backlog
511
databases
16
repl-ping-slave-period
10
repl-timeout
60
repl-backlog-size
1048576
repl-backlog-ttl
3600
maxclients
10000
watchdog-period
0
slave-priority
100
min-slaves-to-write
0
min-slaves-max-lag
10
hz
10
repl-diskless-sync-delay
5
no-appendfsync-on-rewrite
no
slave-serve-stale-data
yes
slave-read-only
yes
stop-writes-on-bgsave-error
yes
daemonize
no
rdbcompression
yes
rdbchecksum
yes
activerehashing
yes
repl-disable-tcp-nodelay
no
repl-diskless-sync
no
aof-rewrite-incremental-fsync
yes
aof-load-truncated
yes
appendonly
no
dir
C:\Users\enterprise-security\Downloads\Redis-x64-2.8.2402
maxmemory-policy
volatile-lru
appendfsync
everysec
save
jd 3600 jd 300 jd 60
loglevel
notice
client-output-buffer-limit
normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60
unixsocketperm
0
slaveof

notify-keyspace-events

bind



```
```bash
redis-cli -p 6379 -h 10.10.25.148 CLIENT LIST
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_client-list.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp6379/tcp_6379_redis_client-list.txt):

```
id=5 addr=10.11.77.75:45952 fd=10 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=client


```
