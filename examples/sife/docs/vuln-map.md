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
| CWE-384 | Forgeable session token (`base64("uid:<id>")`), not rotated on login | `auth/session.js` | Set `sife.sid` to any user id |
| CWE-307 / CWE-770 | No rate limiting / lockout on login | `routes/auth.js` | `hydra` against `/rest/user/login` |
| CWE-522 | Bearer token stored in `localStorage` | `web/src/api.ts` | Exfiltrate via XSS |

## Access control

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-639 | IDOR on tickets (no ownership check) | `routes/tickets.js`, `services/ticketService.js` `getTicket` | `GET /api/tickets/{id}` for any id |
| CWE-639 / CWE-200 | IDOR on users leaks password hash + API token | `routes/users.js` `GET /users/:id` | `GET /api/users/{id}` |
| CWE-639 | Reaction endpoint leaks private incident titles (IDOR oracle) | `services/incidentService.js` | `GET /api/incidents/{id}/reactions` |
| CWE-862 | Broken function-level auth: any user lists all incidents incl. private | `routes/incidents.js` `GET /incidents` | Authenticated `GET /api/incidents` |
| CWE-915 | Mass assignment of `role` on register/profile | `services/authService.js` `register` | `POST /api/users/register` with `"role":"admin"` |

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
| CWE-1321 | Prototype pollution via `lodash.merge` | `services/authService.js` `register` | `POST /api/users/register` with `"__proto__"` |
| CWE-79 | Stored XSS in incident bodies, ticket replies (Markdown), reaction emoji | React `dangerouslySetInnerHTML` in `StatusPage`, `TicketDetail`, `Reactions` | Post markup; renders raw |
| CWE-79 | Reflected DOM XSS in search term | `web/src/pages/Search.tsx` | `/search?q=<img src=x onerror=…>` |
| CWE-79 | Stored XSS via uploaded HTML/SVG served inline | `routes/attachments.js`, `/uploads` static | Upload `.html`, open `/uploads/<file>` |

## Files, SSRF & redirects

| CWE | Weakness | Location | Reach |
| --- | --- | --- | --- |
| CWE-22 | Path traversal / LFI | `services/attachmentService.js` `readByPath` | `GET /api/attachments?path=../../../../etc/passwd` |
| CWE-434 | Unrestricted file upload | `routes/attachments.js` | `POST /api/tickets/{id}/attachments` any type |
| CWE-918 | SSRF | `services/monitorService.js` `probe` | `POST /api/monitors/probe` `{"url":"http://internal/…"}` |
| CWE-601 | Open redirect (naive substring allow-list) | `routes/redirect.js` | `GET /api/out?to=https://sife.io.evil.example` |
| CWE-548 / CWE-732 | Directory listing + world-readable `/uploads`, `/downloads` | `app.js` (`serve-index`) | Browse `/downloads/` |
| CWE-538 / CWE-540 | Leaked secrets & source: `.env.bak`, DB backup, deploy key, source maps | `/downloads/*`, Vite `sourcemap: true` | Fetch the files / `*.js.map` |
| CWE-916 / CWE-759 | Weak, unsalted password hashing (MD5) | `auth/hashing.js` | Crack leaked hashes |

## Configuration & transport

| CWE | Weakness | Location |
| --- | --- | --- |
| CWE-942 | CORS reflects `Origin` with `Allow-Credentials: true` | `middleware/cors.js` |
| CWE-1021 / CWE-693 | No `X-Frame-Options`, CSP, or HSTS | `app.js` (headers absent) |
| CWE-352 | No CSRF protection on cookie-authenticated mutations | all mutating routes |
| CWE-209 / CWE-756 | Verbose error handler leaks stack traces | `middleware/errors.js` |
| CWE-1035 | Known-vulnerable dependencies (`lodash@4.17.4`, `marked@0.3.6`, …) | `api/package.json` + `package-lock.json` (readable via traversal) |
