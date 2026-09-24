# PHP

A server-rendered PHP application (bespoke or a framework such as Laravel/Symfony). The surface is
server-side: form and query parameters, file paths, and includes — often with revealing error output.

## Confirm it

`tech`/`server` observations naming PHP, an `X-Powered-By: PHP/<version>` header, `PHPSESSID` cookies,
`.php` paths. **Fingerprint the exact version** by provoking an error: request a malformed parameter or a
non-existent method so a warning/notice prints the version and file path, or read the default
`/phpinfo.php` if exposed — the version steers which known-CVE checks apply.

## Enumerate the surface

- Content-discovery for `.php` endpoints, backups (`.php~`, `.php.bak`, `.inc`), and config
  (`.env`, `config.php`) — see `sections/discovery.md`.
- Enumerate parameters on each script (`arjun`) and note any that name a file/path (include/download).
- For a framework, fingerprint it (Laravel `X-Powered-By`/`laravel_session`, Symfony profiler) and enable
  its debug/error page if reachable — it leaks routes, env and versions.

## Weakness classes it tends to expose

- **SQL injection** on form/query parameters — `sqlmap`/`ghauri` on the parameter
  (`specialists/T1190-sqlmap.md`).
- **LFI/RFI & path traversal** — a parameter that names a file; test `../` and PHP wrappers
  (`php://filter` to read source, `data://`/`phar://` where enabled).
- **Type-juggling auth bypass** — loose `==` comparisons and `strcmp` on arrays; a magic-hash or array
  parameter can bypass a check.
- **Unrestricted file upload** — an upload that accepts a `.php`/`.phtml` (or a bypassed content-type);
  see `specialists/T1190-fuxploider.md`, and test SPA/JS upload forms by hand.
- **SSTI** in a template engine (Twig/Blade) — a value rendered into a template; `sstimap`.
- **Vulnerable components** — map the fingerprinted version to known CVEs (`nuclei`/`nikto`), and scan a
  recovered `composer.lock` with `osv-scanner`/`grype` via `--target src:<path>`.
