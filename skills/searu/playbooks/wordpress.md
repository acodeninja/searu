# WordPress

A PHP CMS whose risk is dominated by third-party plugins and themes, plus a well-known core surface
(`wp-admin`, `wp-json`, `xmlrpc.php`). Most real findings are known-CVE issues in an out-of-date plugin.

## Confirm it

`tech`/`server` observations naming WordPress, `/wp-content/`, `/wp-includes/` asset paths, a `wp-json`
REST root, a generator `<meta>` tag, and `/wp-login.php`. The generator/readme often leaks the core
version.

## Enumerate the surface

- **Core version** from `/readme.html`, the generator meta, or asset `?ver=` query strings.
- **Plugins & themes and their versions** from `/wp-content/plugins/<slug>/` and each plugin's
  `readme.txt` (`Stable tag:`), plus enqueued asset `?ver=` — this is the primary work list.
- **Users** via the REST API (`/wp-json/wp/v2/users`) and author archives (`/?author=<n>` redirects to
  the login name) — feeds credential attacks.
- **Exposed endpoints**: `xmlrpc.php` (amplified brute force / SSRF via `pingback`), `wp-json` routes,
  `wp-cron.php`.

## Weakness classes it tends to expose

- **Vulnerable components / known CVEs** — the dominant class: map each plugin/theme+version to known
  vulnerabilities (`nuclei`/`nikto`), the highest-yield path (`specialists/T1595-nuclei.md`).
- **Broken authentication** — brute force `wp-login.php`/`xmlrpc.php` for a discovered user with `hydra`
  (`specialists/T1110-hydra.md`); crack recovered hashes with `crack --rules`.
- **SQL injection / other input flaws** in a vulnerable plugin's parameters — `sqlmap` on the parameter.
- **Unrestricted upload / RCE** via a vulnerable plugin or a writable theme editor once authenticated.
- **User/data exposure** through over-permissive REST routes — confirm with `authz`.
