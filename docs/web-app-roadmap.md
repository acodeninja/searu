# Web-application wrapper roadmap — the next 50 tools

A prioritised list of the next 50 tools to wrap for **web-application assessment**, selected from
[tool-catalogue.md](tool-catalogue.md). searu ships 6 wrappers today (commix, ffuf, httpx, katana,
nmap, sqlmap); this is the order in which to close the gaps.

## Scope & method

Scope is the **full web-app engagement chain** — recon → discovery → vulnerability scanning →
exploitation → crack/analyse — weighted to the web layer. Prioritisation drivers, in order:

1. **Gap** — fills a capability the current 6 lack (no vuln scanner, CMS, XSS, TLS, auth-brute,
   secret/SAST, GraphQL/API).
2. **Impact** — breadth of coverage per tool (nuclei alone covers thousands of checks).
3. **Fit** — `container` tools first (integrate now); the two that need a headless-GUI mode
   (`zaproxy`) or the M7 session subsystem (`interactsh`) are ranked lower and flagged.
4. **Vetted** — already present in the `old-version/` toolkit (lower risk/effort) → `vetted = old`.
5. **Coverage** — spread across every phase of the workflow.

Each tool becomes a wrapper crate: its per-phase `uses()` manifest plus an ATT&CK technique/tier
binding chosen at wrap time (scanners → `T1595`/Active, exploit tools → `T1190`/Exploitation, auth
brute → `T1110`, secret/loot → `T1552`). Columns below: **phase** (searu section), **fit**, **cov**
(headline OWASP/CWE), **vetted**.

## Tier 1 — P0 (1–15): integrate first

Biggest gaps, mostly `old`-vetted, all `container`.

| # | tool | capability | phase | fit | cov | vetted |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | nuclei | templated vuln/CVE/misconfig/exposure scanning — the biggest single win | initial-access | container | broad | old |
| 2 | wpscan | WordPress core/plugin/theme/user vuln scan (huge install base) | initial-access | container | CVE | |
| 3 | nikto | web-server misconfig & known-file scanner | initial-access | container | broad | old |
| 4 | whatweb | technology/stack fingerprint | recon | container | — | old |
| 5 | wafw00f | WAF detection (informs tactics) | recon | container | — | old |
| 6 | feroxbuster | recursive content/route discovery | discovery | container | disc | old |
| 7 | gobuster | directory/vhost/DNS brute-forcing | discovery | container | disc | old |
| 8 | arjun | hidden HTTP parameter discovery | discovery | container | disc | old |
| 9 | dalfox | XSS detection & verification | initial-access | container | CWE-79 | old |
| 10 | subfinder | subdomain enumeration (attack surface) | recon | container | — | old |
| 11 | dnsx | DNS resolution/brute toolkit | recon | container | — | old |
| 12 | testssl.sh | TLS/SSL config & flaw audit | recon | container | CWE-326/327 | old |
| 13 | jwt_tool | JWT tamper/forge/crack | initial-access | container | CWE-347 | old |
| 14 | hydra | online auth brute (web forms/basic/services) | initial-access | container | CWE-307 | old |
| 15 | ghauri | SQLi detection/exploit (coverage beside sqlmap) | initial-access | container | CWE-89 | |

## Tier 2 — P1 (16–35): strong coverage

All `container` bar zaproxy.

| # | tool | capability | phase | fit | cov | vetted |
| --- | --- | --- | --- | --- | --- | --- |
| 16 | zaproxy | active web scan + spider (headless `-daemon`/automation) | initial-access | gui-daemon | broad | old — *headless wiring* |
| 17 | gau | historical URL mining (Wayback/CommonCrawl/OTX) | recon | container | disc | |
| 18 | gospider | web crawler (complements katana) | recon | container | disc | |
| 19 | gowitness | headless screenshots for surface triage | recon | container | — | |
| 20 | dirsearch | content discovery (alt engine/wordlists) | discovery | container | disc | |
| 21 | wfuzz | general web fuzzing | discovery | container | disc | |
| 22 | x8 | hidden parameter brute (active) | discovery | container | disc | |
| 23 | linkfinder | endpoints extracted from JS | discovery | container | disc | |
| 24 | secretfinder | secrets/keys in JS | discovery | container | CWE-798 | |
| 25 | tlsx | bulk TLS/cert data (surface) | recon | container | — | old |
| 26 | joomscan | Joomla vulnerability scanner | initial-access | container | CVE | |
| 27 | droopescan | Drupal/Silverstripe scanner | initial-access | container | CVE | |
| 28 | graphw00f | GraphQL engine fingerprint | recon | container | — | old |
| 29 | graphql-cop | GraphQL misconfig/security audit | initial-access | container | API | old |
| 30 | inql | GraphQL introspection & attack | initial-access | container | API | |
| 31 | schemathesis | OpenAPI/GraphQL property-based fuzzing | initial-access | container | API | old |
| 32 | kiterunner | API route/content discovery | discovery | container | API | |
| 33 | sstimap | SSTI detection/exploit (tplmap successor) | initial-access | container | CWE-1336/94 | |
| 34 | ssrfmap | SSRF exploitation | initial-access | container | CWE-918 | |
| 35 | xxeinjector | XXE exploitation | initial-access | container | CWE-611 | |

## Tier 3 — P2 (36–50): breadth, chain & analysis

Two non-`container` tools (zaproxy is in P1; here interactsh), flagged.

| # | tool | capability | phase | fit | cov | vetted |
| --- | --- | --- | --- | --- | --- | --- |
| 36 | dotdotpwn | path-traversal fuzzer (complements ffuf) | initial-access | container | CWE-22 | |
| 37 | crlfuzz | CRLF injection + open redirect | initial-access | container | CWE-93/601 | |
| 38 | corsy | CORS misconfiguration | initial-access | container | CWE-942 | |
| 39 | smuggler | HTTP request smuggling / desync | initial-access | container | CWE-444 | |
| 40 | fuxploider | file-upload vulnerability detection | initial-access | container | CWE-434 | |
| 41 | gittools | dump exposed `.git` → source disclosure | discovery | container | CWE-527/540 | |
| 42 | trufflehog | secret scanning (responses / retrieved source) | analysis | container | CWE-798 | old |
| 43 | semgrep (opengrep) | SAST on source pulled from the target | analysis | container | broad | old |
| 44 | retire.js | vulnerable JS library detection | discovery | container | CWE-1104 | |
| 45 | hashcat | offline crack of dumped hashes (chain) | analysis | container | CWE-916 | old |
| 46 | john | offline crack + `*2john` extractors (chain) | analysis | container | — | old |
| 47 | schemaspy | ER-diagram/inspect a dumped or reachable DB | analysis | container | — | |
| 48 | goaccess | web-server log analysis (post-foothold) | analysis | container | — | |
| 49 | mitmdump (mitmproxy) | scriptable intercept/replay of web traffic | supporting | container | — | |
| 50 | interactsh | OOB / blind-vuln detection (SSRF, blind SQLi/CMDi) | supporting | session | CWE-918 | *needs M7 session* |

## First-10 batch

The fastest ROI — all `container`, mostly `old`-vetted, no new subsystem needed:
**nuclei (1), nikto (3), whatweb (4), wafw00f (5), feroxbuster (6), gobuster (7), arjun (8),
dalfox (9), jwt_tool (13), ghauri (15).** Do `wpscan` (2) right after (needs a Ruby image) and
`zaproxy` (16) once its headless daemon is wired.

**Shipped:** nuclei, whatweb, wafw00f, feroxbuster, gobuster, arjun, nikto, dalfox, ghauri — nine
wrappers, one commit each, every one with a live integration test run against its lab. **jwt_tool is
deferred:** its input is a token string, not a host/URL, so it does not fit `searu run <tool>
--target <t>` — it needs a separate decision on how a token-input tool maps to the target/scope model.

## Analysis batch (source-tree tools)

Shipped after the first-10 batch: the **analysis phase**, which resolved the deferred non-host-input
question with a workspace-confined `src:<path>` target model (product-plan decision 12), all bound to
`T1593.003`/Passive and served under a new `Phase::Analysis`. Twelve wrappers, one commit each, every
one with a live test that scans a planted vulnerable fixture: **semgrep (43), trufflehog (42)** from
this list, plus **gitleaks, bandit, gosec, brakeman, njsscan** (SAST + secrets) and **grype, trivy,
osv-scanner, checkov, hadolint** (SCA + IaC) drawn from `tool-catalogue.md` §5.

## Recon batch (attack surface)

Shipped after the analysis batch: the **reconnaissance phase**, filling the front-of-chain gap. Five
wrappers, one commit each, all emitting `Observation`s (not findings) under `Phase::Reconnaissance` on
the existing `T1590`/`T1593` (Passive) and `T1595` (Active) tiers — **no scope-model change** (the
domain-target form already matched). **subfinder (10)** subdomain enum, **dnsx (11)** DNS resolution,
**gospider (18)** web crawl, **gau (17)** historical-URL mining, **tlsx (25)** TLS/cert surface. This
round also stood up a **shared multi-vuln lab — OWASP Juice Shop** (`examples/rules-of-engagement.
juice-shop.json`) — a hermetic, content-rich crawl target now and the exploitation lab for later
rounds. **gowitness (19)** is deferred: screenshots need a writable output mount (a new capability).

## Web-exploitation batch

Shipped after the recon batch: six URL-target exploit tools on the sqlmap/commix pattern (`-u <target>`
+ flags after `--`, emitting `Finding`s under `Phase::InitialAccess`), all on the existing tiers —
**no domain change**. Detection → `T1595`/Active: **corsy (38)** CORS, **crlfuzz (37)** CRLF.
Exploitation → `T1190` (authoriser required): **dotdotpwn (36)** path traversal, **sstimap (33)** SSTI,
**fuxploider (40)** file upload; and **hydra (14)** auth brute (`T1110`, cracked credential stored as
loot). Real end-to-end lab tests where one fits — dotdotpwn→cwe-22, corsy→Juice Shop CORS,
hydra→Juice Shop login — and smoke tests (dalfox precedent) for the classes without a lab. **Deferred:**
SSRF (**ssrfmap**) and XXE (**xxeinjector**) take a captured-request *file* and need an OOB listener — a
new **request-file input mount** plus OOB infrastructure; **gittools/git-dumper (41)** needs a
**writable output mount** (the gowitness gap). Those form a later capability + OOB round.

## Coverage

recon 10 · discovery 11 · web vuln/exploit 20 · auth/crack 3 · analysis 4 · supporting 2 = **50**.
~22 are `old`-vetted (low risk). Only two are not pure `container`: `zaproxy` (headless-GUI, #16) and
`interactsh` (M7 session subsystem, #50) — both ranked to reflect the extra integration cost.

Once approved, wrap from the top — the first-10 batch — one ATDD slice per tool, each a new crate
bound to its ATT&CK cell with its `uses()` manifest and a `T1046`-style tier binding.
