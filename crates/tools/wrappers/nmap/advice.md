# nmap — port & service discovery (T1046)

Map the open TCP services on an in-scope host so later phases know what to probe. Active tier — the
ROE need only allow-list `T1046`; no authoriser is required.

The target is a **host or IP, never a URL** — pass `example.com` or `10.0.0.5`, not
`http://example.com:5000`. Scope still resolves a URL's host, but nmap itself wants a bare host.

Run — the default is a TCP connect + version scan (`-sT -sV`), grepable output parsed into service
observations:

    searu run nmap --technique T1046 --target 10.0.0.5

Narrow or widen with nmap's own flags after `--`:

    searu run nmap --technique T1046 --target 10.0.0.5 -- -p 22,80,443
    searu run nmap --technique T1046 --target 10.0.0.5 -- -p- --top-ports 2000
    searu run nmap --technique T1046 --target 10.0.0.5 -- -sC

Read what was found:

    searu observations --kind service    # one line per open port: host:port + service/version

Notes:

- **Connect scan only.** `-sT` needs no privileges and runs in the container as-is. A SYN scan
  (`-sS`), OS detection (`-O`) and other raw-socket modes need a privileged container (the escape
  hatch is not yet built) — do not pass them; they will fail.
- A closed or filtered port records nothing. An empty result means "nothing open in the scanned
  range", not "host down" — widen the port range before concluding.
- Version detection (`-sV`) is on by default so each service carries its product/version in the
  observation detail; that is what recon downstream keys on.
