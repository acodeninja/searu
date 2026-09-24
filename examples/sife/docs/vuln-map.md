# Sife — intentional vulnerability map

Internal reference only. This file is **not** served by the application. It records the deliberate
weaknesses planted in Sife, where each lives, and how to reach it. Line references are indicative.

## Seed accounts

| Email | Password | Role |
| --- | --- | --- |
| `admin@sife.io` | `password1` | admin |
| `ops@sife.io` | `letmein` | agent |
| `tara@sife.io` | `sunshine` | agent |
| `alice@northwind.example` | `123456` | customer |
| `bob@globex.example` | `qwerty` | customer |
| `carol@initech.example` | `hunter2` | customer |
| `dave@umbrella.example` | `dragon` | customer |

Passwords are stored as **unsalted MD5** (`api/src/auth/hashing.js`).

## Authentication & session

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-89 / CWE-287 | SQL injection in login → auth bypass | `repositories/userRepository.js` `findByCredentials` | `POST /rest/user/login` with `email = ' OR 1=1 -- ` |
| CWE-347 | JWT accepts `alg:none` | `auth/jwt.js` `verifyToken` | Forge `{"alg":"none"}` token with `role:"admin"` |
| CWE-798 / CWE-321 | Weak, guessable, leaked HMAC secret (`sife-signing-key`) | `config.js`, leaked in `/downloads/.env.bak` | Crack HS256 / sign arbitrary tokens |
| CWE-1275 | Session cookie has no `HttpOnly`/`Secure`/`SameSite` | `auth/session.js` | Inspect `sife.sid` |
| CWE-539 | "Remember me" persistent cookie carries a decodable identity | `auth/session.js` `issueRemember` | Login `{remember:true}` → `sife.remember` (Max-Age 1y, base64 `id:email`) |
| CWE-208 | Non-constant-time comparison of the API key | `repositories/userRepository.js` `findByApiToken`, `routes/v1.js` | `GET /api/v1/export` with a leaked `X-Api-Key` |
| CWE-384 | Forgeable session token (`base64("uid:<id>")`), not rotated on login | `auth/session.js` | Set `sife.sid` to any user id |
| CWE-307 / CWE-770 | No rate limiting / lockout on login | `routes/auth.js` | `hydra` against `/rest/user/login` |
| CWE-204 | Account enumeration via response discrepancy | `services/recoveryService.js`, `routes/users.js` | `reset-request` returns a token for a known email, `{sent:true}` for an unknown one; register 409s on an existing email |
| CWE-522 | Bearer token stored in `localStorage` | `web/src/api.ts` | Exfiltrate via XSS |
| CWE-613 | JWT/session never expire (no `exp`) | `auth/jwt.js` | Replay any old token indefinitely |
| CWE-640 / CWE-330 | Predictable password-reset token (derived from id + MD5 of email) | `services/recoveryService.js` | `POST /rest/user/reset` with a forged token |
| CWE-598 | Reset token carried in the GET link URL | `services/recoveryService.js` | Token leaks via history/referer/logs |
| CWE-644 | Reset link built from the request `Host` header | `services/recoveryService.js` | Send `Host: attacker` → poisoned reset link |
| CWE-620 / CWE-639 | Password change needs no current password, any id | `routes/users.js` `PUT /users/:id/password` | Reset another user's password |
| CWE-338 | API token minted with `Math.random()` | `services/authService.js` `register` | Predict/enumerate issued tokens |

## Access control

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-639 | IDOR on tickets (no ownership check) | `routes/tickets.js`, `services/ticketService.js` `getTicket` | `GET /api/tickets/{id}` for any id |
| CWE-639 / CWE-200 | IDOR on users leaks password hash + API token | `routes/users.js` `GET /users/:id` | `GET /api/users/{id}` |
| CWE-212 | Public status leaks internal incident notes (field not stripped) | `repositories/statusRepository.js`, `services/statusService.js` | `GET /api/status` → `internal_notes` |
| CWE-639 | Reaction endpoint leaks private incident titles (IDOR oracle) | `services/incidentService.js` | `GET /api/incidents/{id}/reactions` |
| CWE-862 | Broken function-level auth: any user lists all incidents incl. private | `routes/incidents.js` `GET /incidents` | Authenticated `GET /api/incidents` |
| CWE-602 / CWE-285 | Admin settings restricted only in the SPA; server has no role check | `routes/admin.js` (`requireAuth` only) | `GET /api/admin/settings` with a customer token leaks the signing/share keys |
| CWE-915 | Mass assignment of `role` on register/profile | `services/authService.js` `register` | `POST /api/users/register` with `"role":"admin"` |
| CWE-863 / CWE-807 | Authorisation decision trusts a spoofable header | `middleware/authenticate.js` (`x-sife-role`) | `curl -H 'X-Sife-Role: admin' /api/users` |
| CWE-306 | Missing auth on a critical function (post to public timeline) | `routes/incidents.js` `POST /incidents/:id/updates` | Unauthenticated status-update injection |
| CWE-345 | Inbound webhook signature never verified | `routes/webhooks.js`, `services/webhookService.js` | `POST /api/webhooks/monitor` unsigned → change component health |
| CWE-348 / CWE-290 | Access decision trusts `X-Forwarded-For` (spoofable) | `routes/internal.js` | `GET /api/internal/metrics` with `X-Forwarded-For: 127.0.0.1` |
| CWE-841 | No approval workflow on account credits | `services/billingService.js` `refund` | `POST /api/billing/refund {"amount":9999}` self-approves |
| CWE-1284 | No bounds on billing quantities (amount/seats) | `services/billingService.js` | `POST /api/billing/refund {"amount":-100000}` |
| CWE-362 / CWE-367 | Race / TOCTOU in coupon redemption (non-atomic check-then-act) | `services/billingService.js` `redeem`, `repositories/couponRepository.js` | Fire concurrent `POST /api/billing/redeem {"code":"WELCOME50"}` → double-spend |

## Injection

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-89 | Unauth SQLi (UNION/blind/error) in reaction tally | `repositories/reactionRepository.js` | `GET /api/incidents/{id}/reactions` — id is concatenated |
| CWE-89 | Unauth SQLi in public incident search | `repositories/incidentRepository.js` `searchPublic` | `GET /api/incidents/search?q=` |
| CWE-89 | SQLi in ticket search / sort | `repositories/ticketRepository.js` `search` | `GET /api/tickets?search=&sort=` |
| CWE-943 | NoSQL operator injection | `services/kbService.js` | `POST /api/kb/search` with `{"title":{"$ne":null}}` |
| CWE-78 | OS command injection | `services/monitorService.js` `ping` | `POST /api/monitors/ping` `{"host":"127.0.0.1; id"}` |
| CWE-1336 / CWE-94 | SSTI (EJS) | `services/reportService.js` | `GET /api/reports/preview?template=<%= 7*7 %>` |
| CWE-611 | XXE (external entities enabled) | `services/importService.js` | `POST /api/incidents/import` with a `SYSTEM` entity |
| CWE-502 | Insecure deserialization (RCE) | `services/preferenceService.js` | `sife.prefs` cookie with a `node-serialize` function payload |
| CWE-95 | Eval injection (RCE) via metric expression | `services/reportService.js` `compute` (`new Function`) | `GET /api/reports/compute?expr=process.env.JWT_SECRET` |
| CWE-776 | XML entity-expansion amplification (`huge` enabled) | `services/importService.js` | `POST /api/incidents/import` with nested entities |
| CWE-91 | XML injection in the generated RSS feed (no escaping) | `services/feedService.js` | Seed an update via `POST /api/incidents/:id/updates`, read `GET /api/status.rss` |
| CWE-643 | XPath injection over the service catalogue | `services/catalogueService.js` | `GET /api/catalogue/search?q=') or contains(name,'` leaks internal services |
| CWE-88 | Argument injection into `curl` (execFile, user tokens) | `services/monitorService.js` `connectivityCheck` | `POST /api/monitors/connectivity {"target":"-o /app/public/x.txt file:///etc/hostname"}` |
| CWE-93 | Email header injection in teammate invites | `services/teamService.js` | `POST /api/team/invite` with `\r\nBcc:` in `name`; read `GET /api/team/outbox` |
| CWE-829 / CWE-494 | Status config imported from a URL, no allow-list or integrity check | `services/configImportService.js`, `routes/admin.js` | `POST /api/admin/import-config {"url":"http://.../evil.json"}` |
| CWE-353 | Third-party analytics `<script>` loaded without SRI/`integrity` | `web/index.html` | `GET /index.html` — external script, no `integrity=` |
| CWE-1022 | Reverse tabnabbing: incident source link is `target="_blank"` without `rel="noopener"` | `web/src/pages/StatusPage.tsx` | Rendered status page / JS bundle |
| CWE-1321 | Prototype pollution via `lodash.merge` | `services/authService.js` `register` | `POST /api/users/register` with `"__proto__"` |
| CWE-79 | Stored XSS in incident bodies, ticket replies (Markdown), reaction emoji | React `dangerouslySetInnerHTML` in `StatusPage`, `TicketDetail`, `Reactions` | Post markup; renders raw |
| CWE-79 | Reflected DOM XSS in search term | `web/src/pages/Search.tsx` | `/search?q=<img src=x onerror=…>` |
| CWE-79 | Stored XSS via uploaded HTML/SVG served inline | `routes/attachments.js`, `/uploads` static | Upload `.html`, open `/uploads/<file>` |
| CWE-1236 | CSV / formula injection in ticket export | `services/exportService.js` | Ticket subject `=HYPERLINK(...)` → `GET /api/tickets/export.csv` |
| CWE-1333 / CWE-400 | ReDoS via catastrophic email regex | `services/subscriberService.js` | `POST /api/subscribers` with `aaaa…aaaa!` |
| CWE-472 / CWE-840 | Web parameter tampering: client sets plan/price | `services/billingService.js` | `POST /api/billing/subscribe {"plan":"enterprise","amount":0}` |

## Files, SSRF & redirects

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-22 | Path traversal / LFI | `services/attachmentService.js` `readByPath` | `GET /api/attachments?path=../../../../etc/passwd` |
| CWE-73 | External control of a file name → arbitrary write | `services/reportStoreService.js` | `POST /api/reports/save {"name":"../public/rfd.html","content":"<script>…"}` then `GET /rfd.html` |
| CWE-434 | Unrestricted file upload | `routes/attachments.js` | `POST /api/tickets/{id}/attachments` any type |
| CWE-918 | SSRF | `services/monitorService.js` `probe` | `POST /api/monitors/probe` `{"url":"http://internal/…"}` |
| CWE-601 | Open redirect (naive substring allow-list) | `routes/redirect.js` | `GET /api/out?to=https://sife.io.evil.example` |
| CWE-548 / CWE-732 | Directory listing + world-readable `/uploads`, `/downloads` | `app.js` (`serve-index`) | Browse `/downloads/` |
| CWE-538 / CWE-540 | Leaked secrets & source: `.env.bak`, DB backup, deploy key, source maps | `/downloads/*`, Vite `sourcemap: true` | Fetch the files / `*.js.map` |
| CWE-916 / CWE-759 | Weak, unsalted password hashing (MD5) | `auth/hashing.js` | Crack leaked hashes |
| CWE-312 | Third-party API keys stored & returned in cleartext (and readable by any user) | `services/integrationService.js` | `GET /api/integrations` |
| CWE-295 | Outbound probe disables TLS certificate validation | `services/monitorService.js` (`rejectUnauthorized: false`) | `POST /api/monitors/probe {"url":"https://expired.badssl.com/"}` |
| CWE-327 / CWE-326 | Share tokens use AES-ECB with a hardcoded key | `services/shareService.js`, `config.js` (`shareKey`, leaked in `.env.bak`) | Forge a token for any ticket id; `GET /api/shared/<token>` |
| CWE-329 / CWE-323 | Export encryption uses AES-CBC with a fixed all-zero IV | `services/exportCryptoService.js`, `config.js` (`exportKey`) | `POST /api/exports/encrypt` twice with the same data → identical ciphertext |
| CWE-256 | Security-question answer stored in cleartext | `repositories/userRepository.js`, `services/recoveryService.js` | `GET /api/users/:id` shows `security_answer`; `POST /rest/user/security-recover` |
| CWE-778 | Insufficient logging: only login is audited | `services/auditService.js` | Password change / refund / config import produce no audit entry |
| CWE-532 | Credentials written to the service log | `services/auditService.js` | `docker compose logs api` shows `password=…` |
| CWE-117 | Unsanitised email forges audit-log lines | `services/auditService.js`, `routes/audit.js` | Login with a newline in the email; read `GET /api/audit` |

## Configuration & transport

| CWE | Weakness | Location |
| --- | --- | --- |
| CWE-942 | CORS reflects `Origin` with `Allow-Credentials: true` | `middleware/cors.js` |
| CWE-1021 / CWE-693 | No `X-Frame-Options`, CSP, or HSTS | `app.js` (headers absent) |
| CWE-352 | No CSRF protection on cookie-authenticated mutations | all mutating routes |
| CWE-209 / CWE-756 | Verbose error handler leaks stack traces | `middleware/errors.js` |
| CWE-497 / CWE-215 / CWE-200 | Error responses attach a `debug` block dumping `process.env` (incl. `JWT_SECRET`), system and request info | `middleware/errors.js` |
| CWE-319 | Cleartext transport — HTTP only, no TLS | app served over plain HTTP |
| CWE-311 | Sensitive data (PII, password hashes, tokens) returned unencrypted | `routes/users.js`, backups |
| CWE-525 / CWE-524 | No `Cache-Control: no-store` on authenticated responses | `app.js` (headers absent) |
| CWE-1035 | Known-vulnerable dependencies (`lodash@4.17.4`, `marked@0.3.6`, …) | `api/package.json` + `package-lock.json` (readable via traversal) |
