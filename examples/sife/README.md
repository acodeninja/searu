# Sife

**Status pages and support, together.** Sife pairs a public status page with a private support
desk, so your customers always know what is happening — and can reach you when it matters.

- Public status page with component health, an incident timeline, and one-tap reactions.
- A support desk with tickets, threaded replies and file attachments.
- A knowledge base, status-monitor probes, and reusable incident report templates.

## Architecture

A single-page React application served alongside a JSON API from one origin.

| Part   | Stack                                                                                  |
|--------|----------------------------------------------------------------------------------------|
| `web/` | React 18 + Vite + TypeScript                                                           |
| `api/` | Node 22, Express, Postgres (relational data) and MongoDB (knowledge base, subscribers) |

The API serves the built SPA and exposes:

- `/rest/user/*` — authentication (bearer token and session cookie)
- `/api/*` — status, incidents, tickets, users, attachments, monitors, reports, knowledge base

## Running locally

```sh
docker compose up --build
```

The application is then available at <http://localhost:8080>. Postgres and MongoDB run as
compose services and are seeded automatically on first boot.

For front-end development with hot-reload, run the API in Docker and the SPA with Vite:

```sh
cd web && npm install && npm run dev   # proxies /api and /rest to the API on :8080
```

## ⚠️ Intentionally vulnerable

Sife is a **deliberately insecure** practice target for authorised security testing (it is used to
exercise the `searu` toolkit). It ships with realistic but exploitable flaws and with dependencies
pinned to known-vulnerable versions on purpose. **Never deploy it, expose it to a network you do
not control, or load real data into it.** The catalogue of intentional weaknesses lives in
[`docs/vuln-map.md`](docs/vuln-map.md) and is not served by the application.

Seed accounts (all with deliberately weak passwords) are listed in that document.
