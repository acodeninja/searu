# Tool catalogue

A roadmap of candidate tools for future `searu` wrappers, compiled from a research pass over the
**Kali**, **Parrot**, and **BlackArch** package/tool lists (plus well-known ecosystem tooling for the
source-code and analysis domains, which the distros under-cover). Completeness within scope is the
goal; overlapping functionality is deliberately kept.

## Scope

Two buckets. **(a) Active tooling** for the domains searu targets — network, web-application, and
source-code analysis. **(b) Complementary tools that chain off what an engagement yields** — the test
is *does it turn a gathered artefact or datum into a further finding or foothold?* — covering offensive
chains (a dump → John/Hashcat), and static analysis of collected **logs**, **databases** and
**binaries**.

**Excluded** (never touch that loop): wireless/802.11, RF/SDR/hardware, disk/memory-imaging DFIR of
seized media, live-malware dynamic/sandbox detonation, social-engineering, anonymity/OPSEC,
steganography, and GUI-only apps with no headless mode.

## Legend

- **source** — which list carries it: `kali`, `parrot`, `blackarch`, or `ecosystem` (well-known but
  not packaged in those distros).
- **fit** — how it maps to searu's containerised model: `container` (clean headless non-interactive
  run), `session` (needs the interactive/reverse-shell session subsystem, M7), `gui-daemon` (GUI or
  service; note any headless mode), `excluded` (listed for completeness but won't fit — reason given).
- **wrapped** — `searu` (one of the 6 shipped wrappers), `old` (present in the `old-version/` Python
  toolkit's manifests), or blank (candidate).

Tools are placed in a single primary category; long tails of near-identical micro-tools are grouped
into one row (each still named) to keep the list navigable.

---

## 1. Network reconnaissance & scanning

### 1.1 Host discovery & port/service scanning

| tool                                          | function                                               | source                | fit       | wrapped             |
|-----------------------------------------------|--------------------------------------------------------|-----------------------|-----------|---------------------|
| nmap                                          | port scan, service/version + OS detection, NSE scripts | kali,parrot,blackarch | container | searu               |
| masscan                                       | asynchronous internet-scale TCP scanner                | kali,parrot,blackarch | container | (needs NET_RAW)     |
| rustscan                                      | very fast port scanner that pipes into nmap            | kali,blackarch        | container |                     |
| naabu                                         | fast Go SYN/CONNECT port scanner                       | kali,blackarch        | container |                     |
| zmap                                          | single-packet stateless internet-wide scanner          | kali,blackarch        | container |                     |
| unicornscan                                   | asynchronous stateless TCP/UDP scanner                 | kali,blackarch        | container |                     |
| sctpscan                                      | SCTP port/association scanner (telecom)                | blackarch             | container |                     |
| zgrab2 / zmapgrab                             | application-layer banner/handshake grabbers            | blackarch             | container |                     |
| amap                                          | application protocol/service version detection         | kali,blackarch        | container |                     |
| grabbb / nerva / scannerl                     | fast banner/service fingerprinters                     | blackarch             | container |                     |
| dmitry                                        | deepmagic host info (whois, ports, subdomains)         | kali,parrot,blackarch | container |                     |
| netdiscover / arp-scan                        | active/passive ARP host discovery                      | kali,parrot,blackarch | container | (needs host net)    |
| fping                                         | parallel ICMP host-liveness sweep                      | kali,parrot,blackarch | container |                     |
| hping3 / nping / nemesis / packit / hexinject | packet crafting & probing                              | kali,parrot,blackarch | container |                     |
| autorecon / reconnoitre / lhf / legion        | recon/enum orchestrators                               | kali,blackarch        | container | legion=gui excluded |

### 1.2 DNS & subdomain enumeration

| tool                                              | function                                       | source                | fit       | wrapped   |
|---------------------------------------------------|------------------------------------------------|-----------------------|-----------|-----------|
| dnsx                                              | fast multipurpose DNS toolkit                  | kali,blackarch        | container | old       |
| massdns / zdns                                    | high-performance bulk DNS resolvers            | kali,blackarch        | container |           |
| dnsenum / dnsrecon / dnsmap / fierce              | DNS enum, AXFR, subdomain brute                | kali,parrot,blackarch | container |           |
| dnswalk / dnstracer / dnsdiag / fpdns             | zone/delegation audit & server fingerprint     | kali,blackarch        | container |           |
| dnsvalidator                                      | curate working resolver lists                  | kali,blackarch        | container |           |
| dnstwist                                          | domain permutation / typosquat detection       | kali,blackarch        | container |           |
| subfinder                                         | passive subdomain discovery                    | kali,blackarch        | container | old       |
| amass                                             | in-depth subdomain/asset enumeration & mapping | kali,parrot,blackarch | container |           |
| sublist3r / assetfinder / findomain / subbrute    | subdomain enumeration                          | kali,blackarch        | container |           |
| puredns / shuffledns                              | massdns-wrapped brute with wildcard filtering  | blackarch             | container |           |
| dnscan / knock(py) / aiodnsbrute / dnsspider      | wordlist subdomain scanners                    | blackarch             | container |           |
| altdns                                            | subdomain permutation generator                | blackarch             | container |           |
| github-subdomains / subscraper / ccrawldns / bbot | passive subdomain sources / ASM                | blackarch             | container |           |
| ct-exposer / cero / certgraph / certgraph         | subdomains from CT logs & TLS SANs             | blackarch             | container |           |
| chaos-client                                      | ProjectDiscovery Chaos DNS dataset client      | ecosystem             | container | (API key) |
| asnmap                                            | ASN → CIDR range mapping                       | kali,blackarch        | container |           |

### 1.3 Service enumeration (SMB / SNMP / LDAP / NFS / SMTP)

| tool                                         | function                                     | source                | fit       | wrapped |
|----------------------------------------------|----------------------------------------------|-----------------------|-----------|---------|
| enum4linux / enum4linux-ng                   | SMB/RPC/LDAP enumeration wrapper             | kali,parrot,blackarch | container |         |
| smbmap                                       | SMB share enumeration + access/exec          | kali,parrot,blackarch | container |         |
| smbclient / smbclient-ng / rpcclient         | interactive SMB/RPC clients (`-c` one-shot)  | kali,parrot,blackarch | session   |         |
| nbtscan / nbtscan-unixwiz / nbtool           | NetBIOS name scanners                        | kali,parrot,blackarch | container |         |
| smbspider / enum-shares / polenum            | share-content search & password policy       | blackarch,kali        | container |         |
| onesixtyone / snmpwalk / snmp-check          | SNMP community brute & enumeration           | kali,parrot,blackarch | container |         |
| braa / snmpenum / snmpscan / snmpattack      | mass/parallel SNMP query & abuse             | kali,blackarch        | container |         |
| ldapsearch / windapsearch / ldeep            | LDAP / AD directory enumeration              | kali,blackarch        | container |         |
| ldapdomaindump / goddi / activedirectoryenum | dump AD objects (HTML/JSON)                  | kali,blackarch        | container |         |
| ldapconsole / dcdetector / adenum            | ad-hoc LDAP queries & DC discovery           | blackarch             | container |         |
| showmount / rpcinfo                          | NFS export & RPC/portmap enumeration         | kali,parrot           | container |         |
| nfsshell                                     | interactive NFS share access/abuse           | blackarch             | session   |         |
| smtp-user-enum / smtpscan / smtpmap          | SMTP user enum & server fingerprint          | kali,parrot,blackarch | container |         |
| ike-scan                                     | IKE/IPsec VPN endpoint discovery/fingerprint | kali,parrot,blackarch | container |         |
| ftpmap                                       | FTP server software/version fingerprint      | blackarch             | container |         |

### 1.4 TLS/SSL enumeration

| tool                                         | function                                   | source                | fit       | wrapped           |
|----------------------------------------------|--------------------------------------------|-----------------------|-----------|-------------------|
| testssl.sh                                   | thorough TLS cipher/protocol/flaw checker  | kali,parrot,blackarch | container | old               |
| sslscan / sslscan2                           | enumerate SSL/TLS ciphers, protocols, cert | kali,parrot,blackarch | container |                   |
| sslyze                                       | fast scriptable TLS configuration analyzer | kali,parrot,blackarch | container |                   |
| tlsx                                         | bulk TLS grabber / cert-cipher harvest     | kali,blackarch        | container | old               |
| cipherscan / tls-prober / tls-fingerprinting | ciphersuite report & stack fingerprint     | blackarch             | container |                   |
| o-saft                                       | OWASP deep TLS/cert audit                  | kali,blackarch        | container |                   |
| massbleed                                    | mass SSL vuln (Heartbleed etc.) sweep      | blackarch             | container |                   |
| ssldump                                      | passive SSL/TLS session decoder            | kali                  | container | (needs interface) |

### 1.5 OS / topology / passive fingerprinting

| tool                                                          | function                             | source                | fit                  | wrapped                      |
|---------------------------------------------------------------|--------------------------------------|-----------------------|----------------------|------------------------------|
| p0f / fl0p / prads                                            | passive OS/link/asset fingerprinting | kali,blackarch        | container/gui-daemon |                              |
| xprobe2 / sinfp / thcrut                                      | active OS/ICMP fingerprinting        | kali,blackarch        | container            |                              |
| traceroute / tcptraceroute / lft / intrace / 0trace / scamper | hop-path & topology mapping          | kali,parrot,blackarch | container            |                              |
| networkmap / netmap / lanmap2 / nextnet                       | reachable-network mapping            | blackarch             | container            |                              |
| ivre / zeek / skydive / p0f                                   | recon frameworks & traffic analysers | kali,blackarch        | gui-daemon           | headless CLI paths           |
| shodan / theharvester / spiderfoot / recon-ng                 | external OSINT recon (API/console)   | kali,parrot,blackarch | container            | spiderfoot/recon-ng headless |

---

## 2. Network attack & post-exploitation

### 2.1 Poisoning, relay & MITM

| tool                                                   | function                                        | source                | fit       | wrapped |
|--------------------------------------------------------|-------------------------------------------------|-----------------------|-----------|---------|
| responder                                              | LLMNR/NBT-NS/mDNS poisoner + rogue auth capture | kali,parrot,blackarch | session   |         |
| mitm6                                                  | IPv6/DHCPv6/WPAD takeover for NTLM relay        | kali,blackarch        | container |         |
| bettercap                                              | modular network attack/MITM framework           | kali,parrot,blackarch | session   |         |
| ettercap / dsniff (arpspoof, dnsspoof) / macof         | ARP/DNS poisoning & credential sniffing         | kali,parrot,blackarch | container |         |
| net-creds / creds / creak / hharp / kickthemout        | MITM credential harvest & ARP abuse             | parrot,blackarch      | container |         |
| sslsplit / sslsniff / sslstrip / striptls              | TLS MITM & HTTPS stripping                      | kali,parrot,blackarch | container |         |
| seth / pyrdp / sshmitm                                 | RDP/SSH MITM credential capture                 | parrot,blackarch      | container |         |
| dnschef / fakedns / dns-reverse-proxy                  | DNS spoof/redirect for pentesters               | kali,parrot,blackarch | container |         |
| yersinia / dtp-spoof / eigrp-tools / cdpsnarf / nacker | L2 / routing-protocol attacks                   | kali,parrot,blackarch | container |         |

### 2.2 Active Directory / Kerberos / SMB attack

| tool                                                   | function                                       | source                | fit               | wrapped          |
|--------------------------------------------------------|------------------------------------------------|-----------------------|-------------------|------------------|
| netexec (nxc) / crackmapexec                           | SMB/WinRM/LDAP/MSSQL exec, spray, enum         | kali,parrot,blackarch | container         |                  |
| impacket (suite)                                       | protocol classes + scripts (below)             | kali,parrot,blackarch | container         |                  |
| impacket-secretsdump                                   | remote SAM/LSA/NTDS hash extraction            | kali,blackarch        | container         |                  |
| impacket-psexec/smbexec/wmiexec/dcomexec/atexec        | remote command-exec shells                     | kali,blackarch        | session           |                  |
| impacket-ntlmrelayx                                    | multi-protocol NTLM relay (SMB/LDAP/HTTP/ADCS) | kali,blackarch        | container         |                  |
| impacket-GetNPUsers/GetUserSPNs                        | AS-REP roast / Kerberoast                      | kali,blackarch        | container         |                  |
| impacket-getTGT/getST/ticketer/goldenPac               | Kerberos ticket request & forgery              | kali,blackarch        | container         |                  |
| impacket-mssqlclient/smbclient                         | interactive MSSQL/SMB clients                  | kali,blackarch        | session           |                  |
| impacket-addcomputer/dacledit/owneredit/findDelegation | AD object/ACL abuse                            | kali,blackarch        | container         |                  |
| evil-winrm                                             | WinRM post-exploitation shell                  | kali,parrot,blackarch | session           |                  |
| kerbrute                                               | Kerberos user enum + password spray            | kali,blackarch        | container         |                  |
| certipy                                                | AD CS (ADCS) enumeration & ESC1-11 abuse       | kali,blackarch        | container         |                  |
| coercer / petitpotam / krbrelayx / pkinittools         | auth coercion & Kerberos relay                 | kali,parrot,blackarch | container         |                  |
| bloodhound                                             | AD attack-path graph analysis                  | kali,parrot,blackarch | gui-daemon        | Neo4j+UI         |
| bloodhound.py / sharphound / azurehound                | AD/Azure data collectors                       | kali,blackarch        | container         |                  |
| bloodyad / aclpwn / adaptix-c2 / adenum / adassault    | AD privesc & ACL exploitation                  | parrot,blackarch      | container/session |                  |
| sprayhound / spraykatz / zackattack / keimpx           | AD spray, lsass dump, relay, cred reuse        | blackarch             | container         |                  |
| mimikatz                                               | Windows credential/ticket extraction           | kali,parrot,blackarch | container         | (run on Windows) |
| powersploit / nishang / beroot / wesng                 | PowerShell post-ex & privesc suggesters        | kali,parrot,blackarch | container         |                  |
| samdump2 / creddump7 / bkhive / chntpw                 | offline Windows hash/secret extraction         | kali,blackarch        | container         |                  |

### 2.3 Sniffing & packet capture

| tool                                     | function                               | source                | fit        | wrapped    |
|------------------------------------------|----------------------------------------|-----------------------|------------|------------|
| netsniff-ng / junkie / above             | high-performance sniffers/analysers    | kali,blackarch        | container  |            |
| tcpflow / tcpreplay / bittwist           | stream reassembly & traffic replay/gen | kali,parrot,blackarch | container  |            |
| httpry / passivedns / dnswatch / ssldump | protocol-specific sniffers/loggers     | parrot,blackarch      | container  |            |
| ostinato                                 | packet/traffic generator               | blackarch             | gui-daemon | CLI/py API |

### 2.4 C2, shells & payloads

| tool                                                 | function                               | source                | fit       | wrapped                     |
|------------------------------------------------------|----------------------------------------|-----------------------|-----------|-----------------------------|
| sliver / villain / covenant / merlin / koadic / pupy | C2 / implant frameworks                | kali,blackarch        | session   |                             |
| empire / powershell-empire                           | PowerShell/Python C2                   | kali,parrot           | session   | starkiller=gui excluded     |
| pwncat / pwncat-cs / rspet / girsh                   | reverse/bind shell handlers & upgrades | kali,blackarch        | session   |                             |
| weevely / webacoo / phpsploit / novahot / laudanum   | web-shell generators/handlers          | kali,parrot,blackarch | session   |                             |
| msfvenom / msfpc / veil / shellter / shellnoob       | payload generation & AV evasion        | kali,parrot,blackarch | container |                             |
| metasploit-framework                                 | exploitation + post-ex framework       | kali,parrot,blackarch | excluded  | per-module scope ungateable |
| armitage / starkiller                                | GUI front-ends (msf / Empire)          | kali,blackarch        | excluded  | GUI-only                    |

---

## 3. Web reconnaissance & content discovery

### 3.1 URL / endpoint / asset discovery

| tool                                             | function                                   | source         | fit       | wrapped |
|--------------------------------------------------|--------------------------------------------|----------------|-----------|---------|
| httpx                                            | fast multipurpose HTTP probe/toolkit       | kali,blackarch | container | searu   |
| httprobe / meg / proxify-style probes            | liveness probing & bulk path fetch         | blackarch      | container |         |
| gau / waybackurls / waymore / urx                | known-URL mining (Wayback/CommonCrawl/OTX) | kali,blackarch | container |         |
| urlfinder                                        | high-speed passive URL discovery           | ecosystem      | container | old     |
| katana                                           | next-gen crawling & spidering framework    | kali,blackarch | container | searu   |
| hakrawler / gospider / gocolly / cariddi         | fast crawlers / endpoint & secret harvest  | kali,blackarch | container |         |
| evine / dcrawl / crawlic / ycrawler / finalrecon | crawlers & all-in-one web recon            | blackarch      | container |         |

### 3.2 Directory / content / vhost discovery

| tool                                                                                                                                       | function                               | source         | fit       | wrapped |
|--------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------|----------------|-----------|---------|
| ffuf                                                                                                                                       | fast web fuzzer (dirs, vhosts, params) | kali,blackarch | container | searu   |
| feroxbuster                                                                                                                                | fast recursive content discovery       | kali,blackarch | container | old     |
| gobuster                                                                                                                                   | directory/file/DNS/vhost brute-forcer  | kali,blackarch | container | old     |
| dirsearch / dirb / dirbuster / dirbuster-ng                                                                                                | directory/file brute-forcers           | kali,blackarch | container |         |
| wfuzz                                                                                                                                      | web fuzzer for content/param discovery | kali           | container |         |
| dirble / dirstalk / rustbuster / webborer / cansina / opendoor / lulzbuster / konan / cybercrowl / h2buster / webrute / waldo / dirscraper | directory-brute variants               | blackarch      | container |         |
| snallygaster                                                                                                                               | scan for secret/leaked files on HTTP   | blackarch      | container |         |
| necromant / laf / cangibrina                                                                                                               | hidden-vhost & admin-panel finders     | blackarch      | container |         |

### 3.3 Parameter & JavaScript discovery

| tool                                         | function                                    | source         | fit       | wrapped |
|----------------------------------------------|---------------------------------------------|----------------|-----------|---------|
| arjun                                        | HTTP parameter discovery                    | kali,blackarch | container | old     |
| paramspider / parameth / parampampam / x8    | parameter mining & brute                    | blackarch      | container |         |
| linkfinder / jsparser / subjs / getjs        | endpoint/JS-URL extraction                  | blackarch      | container |         |
| secretfinder / jsearch / pinkerton / cariddi | secrets-in-JS discovery                     | blackarch      | container |         |
| sourcemapper / jstillery                     | JS sourcemap reconstruction & deobfuscation | blackarch      | container |         |

### 3.4 Technology & WAF fingerprinting

| tool                                                                  | function                       | source         | fit       | wrapped |
|-----------------------------------------------------------------------|--------------------------------|----------------|-----------|---------|
| whatweb                                                               | web technology fingerprinter   | kali,blackarch | container | old     |
| webanalyze / webtech / detectem / wig / fingerprinter                 | tech & version detection       | blackarch      | container |         |
| cms-explorer / blindelephant / davscan / httprint / htrosbif / mwebfp | CMS & server fingerprinting    | blackarch      | container |         |
| wafw00f                                                               | WAF identification/fingerprint | kali,blackarch | container | old     |
| whatwaf / identywaf / wafdetect                                       | WAF detection (+ bypass hints) | blackarch      | container |         |

### 3.5 Screenshotting & visual recon

| tool                                        | function                              | source         | fit       | wrapped |
|---------------------------------------------|---------------------------------------|----------------|-----------|---------|
| gowitness                                   | headless-Chrome website screenshotter | kali,blackarch | container |         |
| eyewitness / aquatone / witnessme / scrying | bulk screenshots + reporting          | kali,blackarch | container |         |
| peepingtom / jast / cutycapt / rawr         | screenshot & resource enumeration     | blackarch      | container |         |

### 3.6 Source / repo disclosure

| tool                                         | function                       | source    | fit       | wrapped |
|----------------------------------------------|--------------------------------|-----------|-----------|---------|
| gittools / gitdump / goop-dump / dvcs-ripper | dump exposed .git/SVN/HG repos | blackarch | container |         |

---

## 4. Web vulnerability scanning & exploitation

### 4.1 Generic scanners & frameworks

| tool                                                                                | function                             | source                | fit       | wrapped |
|-------------------------------------------------------------------------------------|--------------------------------------|-----------------------|-----------|---------|
| nuclei                                                                              | template-based vulnerability scanner | kali,parrot,blackarch | container | old     |
| nikto                                                                               | web server vulnerability scanner     | kali,parrot,blackarch | container | old     |
| wapiti / skipfish / arachni / w3af / golismero                                      | black-box web app scanners           | kali,parrot,blackarch | container |         |
| owtf / jok3r / websploit / tidos-framework                                          | web pentest automation frameworks    | parrot,blackarch      | container |         |
| jaeles / taipan / sitadel / striker / vulnx / yawast / vanguard                     | signature/scan Swiss-army tools      | blackarch             | container |         |
| rapidscan / grabber / pyfiscan / webpwn3r / d-tect / w13scan / webxploiter / bbscan | misc web scanners                    | blackarch             | container |         |

### 4.2 SQL injection

| tool                                                                   | function                                   | source                | fit        | wrapped |
|------------------------------------------------------------------------|--------------------------------------------|-----------------------|------------|---------|
| sqlmap                                                                 | automated SQLi detection & exploitation    | kali,parrot,blackarch | container  | searu   |
| ghauri                                                                 | advanced automated SQLi                    | blackarch             | container  |         |
| sqlninja                                                               | MS-SQL injection & takeover                | kali                  | container  |         |
| jsql-injection                                                         | Java SQLi tool (CLI + GUI)                 | kali,blackarch        | gui-daemon |         |
| bbqsql / bsqlbf / bsqlinjector / blisqy                                | blind SQLi exploitation                    | blackarch             | container  |         |
| albatar / themole / dsss / scanqli / sqid / multiinjector / darkmysqli | SQLi scan/exploit variants                 | blackarch             | container  |         |
| nosqlmap / nosqli / nosqli-user-pass-enum                              | NoSQL/MongoDB injection                    | blackarch,parrot      | container  |         |
| hqlmap / n1qlmap                                                       | HQL / N1QL injection                       | blackarch             | container  |         |
| atlas                                                                  | suggest sqlmap tamper scripts (WAF bypass) | blackarch             | container  |         |

### 4.3 Cross-site scripting (XSS)

| tool                                                                                                    | function                              | source                | fit        | wrapped |
|---------------------------------------------------------------------------------------------------------|---------------------------------------|-----------------------|------------|---------|
| dalfox                                                                                                  | fast automated XSS scanner/utility    | blackarch,parrot      | container  | old     |
| xsstrike                                                                                                | advanced XSS detection & exploitation | blackarch,parrot      | container  |         |
| xsser                                                                                                   | XSS detection/exploitation (CLI+GUI)  | kali,parrot,blackarch | gui-daemon |         |
| brutexss / xsscrapy / xsssniper / xsspy / xsscon / dsxs / anti-xss / xssya / xsss / xss-freak / xssless | XSS scan/brute/payload variants       | blackarch             | container  |         |
| snuck                                                                                                   | automatic XSS filter bypass           | blackarch             | container  |         |
| mosquito / jshell / httppwnly                                                                           | XSS post-exploitation                 | blackarch             | container  |         |

### 4.4 Command injection / SSTI / XXE / XPath

| tool                                      | function                       | source                | fit       | wrapped |
|-------------------------------------------|--------------------------------|-----------------------|-----------|---------|
| commix                                    | automated OS command injection | kali,parrot,blackarch | container | searu   |
| mando.me / smplshllctrlr / hcraft         | web command-injection helpers  | blackarch             | container |         |
| tplmap / sstimap / tinja                  | SSTI detection & exploitation  | blackarch,parrot      | container |         |
| xxeinjector / xxexploiter / otori / docem | XXE exploitation & payloads    | blackarch             | container |         |
| xcat / xxxpwn / xxxpwn-smart              | XPath injection exploitation   | blackarch             | container |         |

### 4.5 LFI / RFI / path traversal

| tool                                                          | function                    | source                | fit       | wrapped |
|---------------------------------------------------------------|-----------------------------|-----------------------|-----------|---------|
| fimap / kadimus / lfimap / liffy                              | LFI/RFI scan & exploitation | kali,parrot,blackarch | container |         |
| lfisuite / lfi-fuzzploit / lfifreak / lfi-autopwn / crabstick | LFI-to-shell variants       | blackarch             | container |         |
| dotdotpwn / fdsploit / dsfs / morxtraversal                   | directory-traversal fuzzers | kali,blackarch        | container |         |

### 4.6 SSRF / deserialization / CORS / CRLF / smuggling / cache

| tool                                                    | function                                     | source              | fit       | wrapped |
|---------------------------------------------------------|----------------------------------------------|---------------------|-----------|---------|
| ssrfmap / extended-ssrf-search / lorsrf / see-surf      | SSRF fuzz & parameter discovery              | blackarch,parrot    | container |         |
| gopherus                                                | gopher payloads for SSRF→RCE                 | blackarch,parrot    | container |         |
| ssrf-sheriff / interactsh-client                        | OOB/SSRF callback servers                    | blackarch,ecosystem | session   |         |
| ysoserial / phpggc / jdeserialize / serializationdumper | (de)serialization gadget payloads            | blackarch           | container |         |
| corsy / corscanner                                      | CORS misconfiguration scanners               | blackarch           | container |         |
| crlfuzz / injectus / recollapse                         | CRLF, open-redirect & validation-bypass fuzz | blackarch           | container |         |
| smuggler / smuggler-py / http2smugl / h2csmuggler       | HTTP request smuggling / desync              | blackarch           | container |         |
| fockcache                                               | web cache poisoning via headers              | blackarch           | container |         |

### 4.7 CMS scanners

| tool                                                                                                          | function                         | source                | fit       | wrapped |
|---------------------------------------------------------------------------------------------------------------|----------------------------------|-----------------------|-----------|---------|
| wpscan                                                                                                        | WordPress security scanner       | kali,parrot,blackarch | container |         |
| wpseku / wordpresscan / wpforce / wpprobe / plecost / vane / xmlrpc-bruteforcer / wordpress-exploit-framework | WordPress scan/attack variants   | blackarch             | container |         |
| joomscan / joomlavs / joomlascan / juumla / jooforce / jomplug                                                | Joomla scanners                  | kali,parrot,blackarch | container |         |
| droopescan / drupwn / drupalscan / dpscan / drupal-module-enum                                                | Drupal scanners                  | blackarch,parrot      | container |         |
| cmsmap / cmseek / cmsscan / cmsfuzz / cms-few / comission                                                     | multi-CMS scanners               | parrot,blackarch      | container |         |
| typo3scan / vbscan / spipscan / plown / c5scan / mooscan / flunym0us                                          | other-CMS/LMS scanners           | blackarch             | container |         |
| sparty / jira-scan / domi-owned                                                                               | SharePoint / Jira / Domino tools | blackarch             | container |         |

### 4.8 JWT / GraphQL / API / WebSocket

| tool                                                                        | function                                | source              | fit       | wrapped   |
|-----------------------------------------------------------------------------|-----------------------------------------|---------------------|-----------|-----------|
| jwt_tool                                                                    | JWT test/tamper/forge/crack             | kali,blackarch      | container | old       |
| jwt-hack / myjwt / jwt-cracker / jwtcat                                     | JWT attack/brute variants               | blackarch           | container |           |
| badsecrets / flask-unsign / flask-session-cookie-manager / rabid / eos      | framework-secret & cookie attacks       | blackarch           | container |           |
| graphw00f                                                                   | GraphQL engine fingerprint              | blackarch           | container | old       |
| graphql-cop                                                                 | GraphQL security/misconfig audit        | ecosystem           | container | old       |
| graphqlmap / graphql-path-enum / clairvoyance / crackql / inql / graphinder | GraphQL discovery & attack              | blackarch,ecosystem | container |           |
| sj                                                                          | audit exposed Swagger/OpenAPI endpoints | blackarch           | container | old       |
| kiterunner                                                                  | contextual API content discovery        | blackarch           | container |           |
| schemathesis                                                                | property-based OpenAPI/GraphQL fuzzing  | ecosystem           | container | old       |
| restler-fuzzer                                                              | stateful REST API fuzzer                | blackarch           | container |           |
| astra                                                                       | automated REST API security testing     | blackarch           | container |           |
| grpc-pentest-suite / grpcurl                                                | gRPC pentest & interaction              | blackarch,ecosystem | container |           |
| wsfuzzer / stews / wssip / wsrepl                                           | SOAP/WebSocket fuzz & manipulation      | blackarch,ecosystem | container | wssip=gui |

### 4.9 File-upload, auth bypass & misc

| tool                                                                       | function                                 | source         | fit           | wrapped |
|----------------------------------------------------------------------------|------------------------------------------|----------------|---------------|---------|
| fuxploider / uppwn / filegps                                               | file-upload flaw detection & shell guess | blackarch      | container     |         |
| log4j-scan / log4j-bypass                                                  | Log4Shell scanners                       | blackarch      | container     |         |
| xsrfprobe / csrftester                                                     | CSRF audit & exploitation                | blackarch      | container/gui |         |
| ppfuzz / ppmap                                                             | prototype-pollution scan/exploit         | blackarch      | container     |         |
| dontgo403 / ipsourcebypass                                                 | 40x & IP-restriction bypass              | blackarch      | container     |         |
| wafninja / wafpass / xwaf / lightbulb / payloadmask / abuse-ssl-bypass-waf | WAF bypass tooling                       | blackarch      | container     |         |
| davtest / cadaver / metoscan                                               | WebDAV test/client & HTTP-method scan    | kali,blackarch | container     |         |
| jexboss / jboss-autopwn / htexploit / chankro                              | app-server exploitation & bypass         | blackarch      | container     |         |
| h2t                                                                        | suggest missing security headers         | blackarch      | container     |         |

### 4.10 Intercepting proxies & fuzzers (headless)

| tool                                                               | function                                              | source                | fit                | wrapped                |
|--------------------------------------------------------------------|-------------------------------------------------------|-----------------------|--------------------|------------------------|
| zaproxy                                                            | OWASP ZAP scanner/proxy (`-daemon`, zap-cli)          | kali,parrot,blackarch | gui-daemon         | old                    |
| mitmproxy / mitmdump                                               | scriptable intercepting proxy (headless via mitmdump) | kali,blackarch        | container          |                        |
| caido-cli                                                          | intercepting proxy CLI (replay/fuzz)                  | blackarch             | container          |                        |
| proxenet / pappy-proxy / spike-proxy / hetty                       | console/scriptable web proxies                        | blackarch             | session/gui-daemon |                        |
| burpsuite / paros                                                  | integrated web attack platforms                       | kali,parrot,blackarch | excluded           | GUI-only (no headless) |
| powerfuzzer / jbrofuzz / easyfuzzer / filebuster / monsoon / htcap | web fuzzers                                           | blackarch             | container          |                        |

---

## 5. Source-code & artefact analysis

### 5.1 SAST (static application security testing)

| tool                                                                    | function                                        | source                   | fit        | wrapped          |
|-------------------------------------------------------------------------|-------------------------------------------------|--------------------------|------------|------------------|
| semgrep                                                                 | multi-language pattern SAST with taint tracking | blackarch,ecosystem      | container  |                  |
| opengrep                                                                | LGPL semgrep fork (taint/interprocedural free)  | ecosystem                | container  | old              |
| bandit                                                                  | Python SAST                                     | ecosystem                | container  |                  |
| brakeman                                                                | Ruby on Rails SAST                              | blackarch,ecosystem      | container  |                  |
| gosec / govulncheck                                                     | Go SAST & vuln check                            | ecosystem                | container  |                  |
| nodejsscan / njsscan                                                    | Node.js SAST                                    | blackarch,ecosystem      | container  |                  |
| phpcs-security-audit / phpstan / psalm                                  | PHP SAST (taint via psalm)                      | ecosystem                | container  |                  |
| flawfinder / cppcheck / rats / pscan / bof-detector                     | C/C++ SAST                                      | kali,blackarch,ecosystem | container  |                  |
| spotbugs / find-sec-bugs / pmd                                          | Java/JVM bytecode SAST                          | blackarch,ecosystem      | container  |                  |
| slither / mythril                                                       | Solidity / EVM smart-contract analysis          | blackarch,ecosystem      | container  |                  |
| graudit / insider / horusec / devskim / yasca / mosca / zarn / wpbullet | multi-language SAST & aggregators               | blackarch,ecosystem      | container  |                  |
| codeql                                                                  | semantic code-query SAST engine                 | ecosystem                | gui-daemon | OSS-only licence |
| sonarqube / sonar-scanner                                               | server-based code-quality + SAST                | blackarch,ecosystem      | gui-daemon | client+server    |
| bearer / dawnscanner / php-malware-finder / spaf                        | privacy/Ruby/PHP static analysis                | blackarch,ecosystem      | container  |                  |
| cflow / devaudit                                                        | call-graph & dev security auditing              | blackarch                | container  |                  |

### 5.2 Software-composition / dependency analysis

| tool                                                                    | function                                | source              | fit        | wrapped |
|-------------------------------------------------------------------------|-----------------------------------------|---------------------|------------|---------|
| grype                                                                   | container/filesystem/SBOM vuln scanner  | ecosystem           | container  | old     |
| trivy                                                                   | all-in-one vuln/SBOM/secret/IaC scanner | ecosystem           | container  | old     |
| osv-scanner / osv-detector                                              | scan deps against Google OSV            | ecosystem           | container  | old     |
| dependency-check                                                        | OWASP SCA against NVD                   | blackarch,ecosystem | container  |         |
| dep-scan                                                                | OWASP dep-scan SCA + reachability       | ecosystem           | container  |         |
| snyk (cli)                                                              | SAST+SCA+container+IaC (auth token)     | blackarch,ecosystem | container  |         |
| retire.js / safety / pip-audit / npm-audit / yarn-audit / bundler-audit | ecosystem dependency audits             | ecosystem           | container  |         |
| nancy / cargo-audit / cargo-deny / local-php-security-checker           | Go/Rust/PHP dep advisories              | ecosystem,blackarch | container  |         |
| guarddog                                                                | malicious PyPI/npm package heuristics   | ecosystem           | container  |         |
| ossf-scorecard                                                          | OSS project security-posture scoring    | ecosystem           | container  |         |
| dependency-track / dependabot / renovate                                | continuous SCA platforms/bots           | ecosystem           | gui-daemon |         |

### 5.3 Secret scanning

| tool                                                                           | function                                        | source              | fit       | wrapped |
|--------------------------------------------------------------------------------|-------------------------------------------------|---------------------|-----------|---------|
| trufflehog                                                                     | git/filesystem secret scanner with verification | blackarch,ecosystem | container | old     |
| gitleaks                                                                       | fast Go secret scanner                          | ecosystem           | container | old     |
| detect-secrets                                                                 | baseline-oriented secret scanner                | blackarch,ecosystem | container |         |
| ggshield / git-secrets / ripsecrets                                            | secret scanning / pre-commit                    | ecosystem           | container |         |
| noseyparker / kingfisher / whispers / tell-me-your-secrets / gitrob / githound | secret detection in history/repos               | blackarch,ecosystem | container |         |

### 5.4 IaC / container / Kubernetes / SBOM

| tool                                                                | function                                    | source              | fit                  | wrapped    |
|---------------------------------------------------------------------|---------------------------------------------|---------------------|----------------------|------------|
| checkov                                                             | IaC + misconfig scanner (Terraform/K8s/CFN) | blackarch,ecosystem | container            | old        |
| hadolint                                                            | Dockerfile linter / best-practice           | ecosystem           | container            | old        |
| tfsec / terrascan / kics / conftest                                 | Terraform / multi-IaC policy scanners       | ecosystem           | container            |            |
| dockle / clair                                                      | container image lint & vuln scan            | ecosystem           | container/gui-daemon |            |
| kube-bench / kube-hunter / kubescape / kubeaudit / polaris / datree | Kubernetes benchmark & misconfig            | ecosystem           | container            |            |
| syft / cdxgen / sbom-tool / sbomqs                                  | SBOM generation & quality                   | ecosystem           | container            | old (syft) |
| scancode-toolkit / licensee / fossology                             | licence/provenance analysis                 | ecosystem           | container/gui-daemon |            |

---

## 6. Password & hash cracking + wordlists

### 6.1 Offline hash cracking

| tool                                                                         | function                                       | source                | fit       | wrapped         |
|------------------------------------------------------------------------------|------------------------------------------------|-----------------------|-----------|-----------------|
| john (John the Ripper)                                                       | multi-format offline hash cracker (+ `*2john`) | kali,parrot,blackarch | container | old             |
| hashcat                                                                      | GPU/CPU offline hash cracker                   | kali,parrot,blackarch | container | old (needs GPU) |
| hashcat-utils                                                                | candidate/wordlist manipulation helpers        | kali,blackarch        | container |                 |
| rainbowcrack / rcracki-mt / ophcrack(-cli)                                   | time-memory (rainbow-table) cracking           | kali,blackarch        | container | ophcrack gui    |
| mdcrack / fang / pybozocrack / morxcrack / jbrute / phrasendrescher          | algorithm-specific crackers                    | blackarch             | container |                 |
| pwcrack / bob-the-butcher / doozer / crackhorn / mybff / pipeline / f-scrack | cracking frameworks/brute                      | blackarch             | container |                 |
| cryptohazemultiforcer / passgan / omen                                       | GPU/ML/Markov candidate cracking               | blackarch             | container |                 |

### 6.2 Online / service brute forcing

| tool                                                                                    | function                                 | source                | fit       | wrapped |
|-----------------------------------------------------------------------------------------|------------------------------------------|-----------------------|-----------|---------|
| hydra (thc-hydra)                                                                       | online brute forcer, 50+ protocols       | kali,parrot,blackarch | container | old     |
| medusa / ncrack / patator / crowbar                                                     | parallel modular login brute forcers     | kali,parrot,blackarch | container |         |
| brutespray                                                                              | brute from nmap output via medusa/ncrack | kali,blackarch        | container |         |
| SSH brute: against, beleth, brutessh, sshatter, sshtrix, shreder, hostbox-ssh, sshprank | SSH login crackers                       | blackarch             | container |         |
| RDP brute: rdesktop-brute, rdpassspray                                                  | RDP brute/spray                          | blackarch             | container |         |
| Web brute: iisbruteforcer, htpwdscan, morxbrute, lodowep, owabf, wmat, device-pharmer   | HTTP/webmail brute                       | blackarch             | container |         |
| WordPress brute: wpbf, wpbrute-rpc, wordbrutepress                                      | WP login/XML-RPC brute                   | blackarch             | container |         |
| levye / mkbrutus / thc-pptp-bruter                                                      | multi-protocol / MikroTik / PPTP brute   | blackarch,kali        | container |         |
| onesixtyone / snmp-brute / cisco-auditing-tool / cisco-ocs / enabler                    | SNMP & Cisco default-cred brute          | kali,blackarch        | container |         |
| acccheck / smbbf / ridenum / ldap-brute                                                 | SMB/RID/LDAP brute                       | blackarch             | container |         |
| ftp-scanner / tftp-bruteforce / sipvicious(svcrack)                                     | FTP/TFTP/SIP brute                       | kali,blackarch        | container |         |
| dbpwaudit / sqlpat / sqldict / sidguesser                                               | database password auditing               | kali,blackarch        | container |         |
| sucrack / rootbrute                                                                     | local su/root brute (privesc check)      | kali,blackarch        | container |         |
| depant / dpeparser                                                                      | default-password checks & DB             | blackarch             | container |         |

### 6.3 Hash identification

| tool                             | function                             | source                | fit       | wrapped |
|----------------------------------|--------------------------------------|-----------------------|-----------|---------|
| hashid / hash-identifier         | identify hash type                   | kali,parrot,blackarch | container |         |
| name-that-hash / haiti / hashtag | hash ID with john/hashcat mode hints | kali,blackarch        | container |         |

### 6.4 Wordlist generation & analysis

| tool                                                           | function                                        | source                | fit        | wrapped |
|----------------------------------------------------------------|-------------------------------------------------|-----------------------|------------|---------|
| crunch                                                         | wordlist generation by charset/pattern          | kali,parrot,blackarch | container  |         |
| cewl / CeWLeR / wyd / twofi                                    | site/document/OSINT wordlist scraping           | kali,blackarch        | container  |         |
| cupp / compp / pydictor                                        | targeted profile wordlist generation            | kali,parrot,blackarch | container  |         |
| rsmangler                                                      | wordlist mangling/permutation                   | kali,blackarch        | container  |         |
| maskprocessor / statsprocessor / princeprocessor / kwprocessor | hashcat candidate generators                    | kali,blackarch        | container  |         |
| pack (maskgen/policygen/statsgen/rulegen)                      | password analysis & rule/mask building          | kali,blackarch        | container  |         |
| mentalist                                                      | rule/wordlist generator (GUI; exports headless) | kali,blackarch        | gui-daemon |         |
| wordlistctl                                                    | fetch/search 6300+ wordlist archives            | blackarch             | container  |         |
| seclists                                                       | curated wordlist/payload collection (data)      | kali,blackarch        | container  | old     |
| pipal                                                          | password-list statistics/patterns               | kali,blackarch        | container  |         |

### 6.5 Credential spraying & dumping (chain)

| tool                                                                                             | function                                | source         | fit       | wrapped |
|--------------------------------------------------------------------------------------------------|-----------------------------------------|----------------|-----------|---------|
| keimpx                                                                                           | verify credentials across SMB network   | blackarch      | container |         |
| talon / sprayhound                                                                               | AD Kerberos/LDAP spraying               | blackarch      | container |         |
| o365spray / o365enum / adfspray / spray365 / trevorspray / spraycharles / credmaster / gomapenum | O365/Azure/ADFS spray & enum            | blackarch      | container |         |
| passing-the-hash / gpp-decrypt / gpocrack                                                        | pass-the-hash & GPP credential recovery | kali,blackarch | container |         |

### 6.6 Archive / file / crypto crackers

| tool                                                                               | function                                  | source         | fit       | wrapped |
|------------------------------------------------------------------------------------|-------------------------------------------|----------------|-----------|---------|
| fcrackzip / rarcrack / obevilion / pkcrack / bkcrack                               | archive password/known-plaintext cracking | kali,blackarch | container |         |
| pdfcrack / crackpkcs12 / pemcrack / pemcracker                                     | PDF / PKCS#12 / PEM key cracking          | kali,blackarch | container |         |
| truecrack / bruteforce-luks / skul / bruteforce-salted-openssl / bruteforce-wallet | volume/OpenSSL/wallet brute               | kali,blackarch | container |         |
| ssh-privkey-crack / khc                                                            | SSH private-key passphrase & known_hosts  | blackarch      | container |         |
| Cisco/BGP: cisco5crack, cisco7crack, bgp-md5crack                                  | network-device secret recovery            | blackarch      | container |         |
| sipcrack / chapcrack / eapmd5pass / vncrack                                        | protocol-capture credential cracking      | kali,blackarch | container |         |
| ikeforce / ikecrack / thc-pptp-bruter / ipmipwn                                    | VPN/IKE/IPMI credential attacks           | blackarch      | container |         |
| php-mt-seed / flask-unsign / jwtcat                                                | token/seed cracking (chain)               | blackarch      | container |         |

---

## 7. Supporting infrastructure

### 7.1 Proxies & request tooling

| tool                                         | function                                   | source                   | fit                  | wrapped |
|----------------------------------------------|--------------------------------------------|--------------------------|----------------------|---------|
| mitmproxy / mitmdump                         | scriptable intercepting proxy (headless)   | kali,blackarch           | container            |         |
| proxify                                      | CLI HTTP/SOCKS capture/filter/replay proxy | kali,blackarch           | container            |         |
| hyperfox / tcpwatch / hetty                  | traffic-recording proxies                  | blackarch,ecosystem      | container/gui-daemon |         |
| proxychains-ng / graftcp / pr0cks / redsocks | force TCP through proxy chains             | kali,blackarch           | container            |         |
| curl / httpie / xh / curlie / hurl / wuzz    | scriptable HTTP request clients            | kali,ecosystem           | container            |         |
| websocat / websocketd / grpcurl              | WebSocket & gRPC clients/servers           | kali,blackarch,ecosystem | container/session    |         |
| updog / simplehttpserver                     | ad-hoc file-serving HTTP(S) servers        | kali,ecosystem           | container            |         |

### 7.2 Listeners, shells & OOB

| tool                                          | function                                    | source         | fit     | wrapped |
|-----------------------------------------------|---------------------------------------------|----------------|---------|---------|
| netcat / ncat / socat                         | ad-hoc listeners, relays, encrypted tunnels | kali,blackarch | session |         |
| pwncat / pwncat-cs / rustcat / girsh / rlwrap | reverse/bind shell handlers & upgrades      | kali,ecosystem | session |         |
| interactsh (client/server) / dnsobserver      | OOB interaction servers (blind vuln)        | kali,ecosystem | session |         |
| responder / dnschef                           | rogue capture/redirect listeners            | kali,ecosystem | session |         |

### 7.3 Tunnelling & pivoting

| tool                                                        | function                                      | source                   | fit                | wrapped           |
|-------------------------------------------------------------|-----------------------------------------------|--------------------------|--------------------|-------------------|
| chisel                                                      | HTTP-transported TCP/UDP tunnel (SSH-secured) | kali,ecosystem           | session            |                   |
| ligolo-ng / ligolo-mp                                       | userland TUN pivoting                         | kali,blackarch           | session            |                   |
| sshuttle                                                    | transparent TCP+DNS-over-SSH VPN              | kali,ecosystem           | session            |                   |
| gost / frp / nps / revsocks / ssf / 3proxy                  | multi-protocol tunnel/relay servers           | kali,ecosystem,blackarch | session/gui-daemon |                   |
| rpivot / pivotsuite / stowaway / firecat / pwnat            | pentest pivoting/tunnelling                   | parrot,blackarch         | session            |                   |
| iodine / dnscat2 / dns2tcp                                  | IP/TCP-over-DNS tunnels                       | kali,blackarch           | session            |                   |
| ptunnel(-ng) / icmp tunnels                                 | TCP-over-ICMP tunnels                         | kali,blackarch           | session            |                   |
| stunnel4 / proxytunnel / httptunnel / wstunnel / websockify | TLS/HTTP/WebSocket tunnels                    | kali,blackarch,ecosystem | session/gui-daemon |                   |
| tunna / reGeorg / neo-reGeorg / pystinger / regeorg         | tunnel TCP over a web shell                   | blackarch,ecosystem      | session            |                   |
| ngrok / cloudflared / turner                                | hosted/OOB ingress redirectors                | ecosystem,blackarch      | session            | third-party trust |
| dnsteal / dnsfilexfer / det                                 | data exfiltration over DNS/multi-channel      | blackarch                | session            |                   |

### 7.4 TLS / certificate tooling

| tool              | function                                         | source    | fit       | wrapped |
|-------------------|--------------------------------------------------|-----------|-----------|---------|
| openssl (cli)     | crypto/TLS Swiss-army (s_client/s_server, certs) | kali      | container |         |
| step-cli / mkcert | issue/inspect certs, JWT/OAuth tokens            | ecosystem | container |         |

---

## 8. Log & database analysis

### 8.1 Log analysis

| tool                                              | function                                          | source                | fit       | wrapped       |
|---------------------------------------------------|---------------------------------------------------|-----------------------|-----------|---------------|
| goaccess                                          | real-time web-server log analyzer (terminal/HTML) | kali,parrot,blackarch | container |               |
| lnav                                              | log navigator; auto-format, SQL-query, timeline   | kali,ecosystem        | container | headless `-n` |
| chainsaw / hayabusa / zircolite / APT-Hunter      | Sigma-based Windows event-log hunting             | ecosystem             | container |               |
| evtx_dump / python-evtx / grokevt / evtkit / lfle | parse/recover Windows event logs                  | blackarch,ecosystem   | container |               |
| logdissect / scalp / lorg / angle-grinder         | parse/filter/analyse log streams                  | ecosystem             | container |               |
| sigma / sigmac                                    | detection-rule format + backend converter         | kali,ecosystem        | container |               |

### 8.2 Database inspection & schema

| tool                              | function                                 | source                | fit                  | wrapped |
|-----------------------------------|------------------------------------------|-----------------------|----------------------|---------|
| schemaspy / schemacrawler / tbls  | schema discovery + ER-diagram generation | ecosystem             | container            |         |
| sql-metadata / sqlparse           | parse SQL for tables/columns/joins       | ecosystem             | container            |         |
| mycli / pgcli / litecli / sqlite3 | headless DB clients (`-e`/`-c`)          | kali,ecosystem        | container            |         |
| mdbtools / pgdbf / mysql2sqlite   | convert/inspect Access/XBase/MySQL dumps | kali,parrot,blackarch | container            |         |
| sqlite-forensic / undark / fqlite | recover deleted SQLite records           | ecosystem             | container/gui-daemon |         |

### 8.3 Data triage & parsing

| tool                       | function                                    | source                          | fit        | wrapped |
|----------------------------|---------------------------------------------|---------------------------------|------------|---------|
| jq / yq                    | JSON / YAML-XML-TOML processors             | kali,parrot,blackarch,ecosystem | container  |         |
| csvkit / miller (mlr)      | CSV/TSV/JSON conversion & querying          | kali,ecosystem                  | container  |         |
| q / textql / dsq / octosql | SQL over CSV/JSON/logs/files                | ecosystem                       | container  |         |
| ripgrep / ripgrep-all      | fast recursive search over data/archives    | kali,ecosystem                  | container  |         |
| visidata                   | interactive terminal tabular-data multitool | ecosystem                       | gui-daemon | TUI     |

---

## 9. Binary & artefact static analysis

### 9.1 Disassembly & decompilation

| tool                                     | function                                             | source                   | fit        | wrapped       |
|------------------------------------------|------------------------------------------------------|--------------------------|------------|---------------|
| ghidra                                   | disassembler/decompiler; `analyzeHeadless` scripting | kali,blackarch           | gui-daemon | headless mode |
| radare2 / rizin                          | scriptable RE frameworks (disasm, xrefs, parse)      | kali,parrot,blackarch    | container  | cutter=gui    |
| retdec                                   | retargetable machine-code → C/LLVM decompiler        | blackarch,ecosystem      | container  |               |
| angr / angrop / triton / barf / bindead  | symbolic execution & binary analysis                 | kali,blackarch,ecosystem | container  |               |
| jadx / apktool / dex2jar                 | Android APK/DEX decompile & decode                   | kali,parrot,blackarch    | container  |               |
| binaryninja / ida-free / hopper / cutter | GUI reversing platforms                              | blackarch                | excluded   | GUI-only      |

### 9.2 Triage & extraction

| tool                                                 | function                                               | source                          | fit       | wrapped |
|------------------------------------------------------|--------------------------------------------------------|---------------------------------|-----------|---------|
| binwalk / unblob / firmware-mod-kit                  | firmware/container signature ID & extraction           | kali,parrot,blackarch,ecosystem | container |         |
| strings / floss / stringsifter / gostringsr2         | string extraction, deobfuscation, ranking              | kali,blackarch,ecosystem        | container |         |
| capa                                                 | identify capabilities/ATT&CK behaviours in executables | ecosystem                       | container |         |
| yara                                                 | pattern-match binaries against static rules            | kali,parrot,blackarch           | container |         |
| checksec                                             | report binary hardening (RELRO/NX/PIE/canary)          | kali,blackarch                  | container |         |
| readelf / objdump / nm / pev / elfparser / dissector | ELF/PE structure inspection                            | kali,parrot,blackarch           | container |         |
| detect-it-easy (diec) / packerid / exescan / cminer  | file-type/packer identification                        | blackarch,ecosystem             | container |         |
| upx / pyinstxtractor / innounp                       | unpack executables/installers                          | kali,blackarch,ecosystem        | container |         |
| xortool / bgrep / seccomp-tools / oledump            | key recovery, byte search, seccomp/OLE analysis        | kali,blackarch,ecosystem        | container |         |
| ghidriff / bindiff / syms2elf                        | binary diffing & symbol porting                        | blackarch,ecosystem             | container |         |

### 9.3 Exploit-dev helpers

| tool                                                 | function                                   | source                          | fit       | wrapped |
|------------------------------------------------------|--------------------------------------------|---------------------------------|-----------|---------|
| pwntools                                             | exploit-dev toolkit (ELF/ROP/shellcode)    | kali,blackarch                  | container |         |
| ROPgadget / ropper / rp++ / xrop / ropeme / roputils | ROP gadget finders/builders                | kali,blackarch                  | container |         |
| one_gadget / libc-database                           | libc one-shot gadgets & offset DB          | ecosystem,blackarch             | container |         |
| gdb / pwndbg / gef / edb                             | interactive debuggers (static inspect too) | kali,parrot,blackarch,ecosystem | session   |         |
| udis86 (udcli) / cstool                              | command-line disassemblers                 | kali,blackarch                  | container |         |

---

## Excluded / out-of-scope classes

Deliberately **not** catalogued (they never turn engagement loot into a further finding or foothold):
wireless/802.11 (aircrack-ng, kismet, wifite, reaver, bettercap-wifi, pyrit, asleap…), RF/SDR & hardware
(gnuradio, hackrf, proxmark3…), disk/memory-imaging DFIR of seized media (autopsy, sleuthkit,
volatility, foremost, bulk_extractor, bios_memimage, aeskeyfind…), live-malware dynamic/sandbox
analysis (cuckoo, capev2…), social-engineering (SET, gophish, beef-xss, evilginx, consumer-account
brute like ibrute/instashell/tweetshell), anonymity/OPSEC (tor, torsocks, i2p, proxychains-as-anonymity,
trevorproxy), and steganography (steghide, stegseek, zsteg…). GUI-only tools with no headless mode are
listed above but tagged `excluded` (burpsuite, paros, cutter, ida-free, hopper, binaryninja, zenmap,
legion, johnny, hydra-gtk, starkiller). Metasploit is listed but `excluded` — per-module scope is
ungateable under searu's authorisation model.

## Next steps

Pick wrappers straight from this list. Near-term candidates that fit `container` cleanly and fill gaps
in the current six (commix, ffuf, httpx, katana, nmap, sqlmap): **nuclei**, **dalfox**, **wpscan**,
**feroxbuster**/**gobuster**, **subfinder**/**dnsx**, **sslyze**/**testssl.sh**, **whatweb**,
**wafw00f**, **trivy**/**grype**, **semgrep**/**opengrep**, **trufflehog**/**gitleaks**, **hydra**,
**john**/**hashcat** — many already vetted in `old-version/`.
