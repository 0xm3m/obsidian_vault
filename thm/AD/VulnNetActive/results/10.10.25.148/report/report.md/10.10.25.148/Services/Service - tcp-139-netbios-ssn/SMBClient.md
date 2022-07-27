```bash
smbclient -L //10.10.25.148 -N -I 10.10.25.148 2>&1
```

[/root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp139/smbclient.txt](file:///root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/tcp139/smbclient.txt):

```
do_connect: Connection to 10.10.25.148 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available


```
