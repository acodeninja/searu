---
model: haiku
---

# nmap — port & service discovery (T1046)

Enumerate the open TCP services on one in-scope host. Reconnaissance, Active tier — allow-listing
T1046 in the ROE is enough; no authoriser needed.

`<target>` is a **host or IP, not a URL** (`10.0.0.5`, not `http://10.0.0.5:5000`). Run the default
connect + version scan:

    searu run nmap --technique T1046 --target <target>

Widen or narrow the ports with nmap's own flags after `--` (e.g. `-- -p-`, `-- --top-ports 2000`,
`-- -p 22,80,443`). Then read what it recorded:

    searu observations --kind service    # host:port + service/version per open port

Report the open services and their versions — they pick the next tool and the weakness to look for.
A SYN scan (`-sS`) or OS detection (`-O`) needs a privileged container that is not yet available; do
not pass them. Do not paste raw nmap output. See `searu tool advice nmap` for detail.
