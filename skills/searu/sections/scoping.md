# Scoping & rules of engagement

Every engagement starts here. Nothing touches a target until an authorised rules-of-engagement file
exists at `./pentest/rules-of-engagement.json` and `searu` accepts it.

## Interview first

You are talking to the operator now; gather what the ROE needs before any traffic. Establish:

- **Targets** — the exact hosts, IPs, CIDRs or URLs in scope, and any exclusions.
- **Authorisation** — who signed off (name and email) if exploitation is wanted, and whether
  destructive techniques are permitted.
- **Techniques** — which ATT&CK techniques are allowed; browse them with `searu attack list` and
  `searu attack show <Txxxx>`.

Two judgements the file cannot make for you:

- **Third-party hosting is out of scope until named.** A target on a managed platform (Vercel,
  Netlify, Cloudflare, Heroku, Fly.io, GitHub Pages, a managed SaaS API) belongs to the provider,
  not the client — ask explicitly before including it.
- **Hedged scope language means ask, not assume.** "Don't hammer it" / "go easy on X" is ambiguity
  to resolve with the operator, never a quiet grant of scope.

## Write and check the ROE

Write `./pentest/rules-of-engagement.json`. Shape:

```json
{
  "scope": { "targets": [ { "type": "ip", "value": "127.0.0.1", "port": 5000 } ] },
  "allowed_techniques": ["T1595", "T1190", "T1059"],
  "authorisation": { "exploitation_authorised_by": { "name": "…", "email": "…" } }
}
```

Target `type` is one of `domain` / `ip` / `cidr` / `url` (optional `port`); non-host kinds `file`,
`person`, `osint-domain` never grant network scope. Add `"destructive_authorised": true` under
`authorisation` only if destructive techniques are signed off.

A `url` target is pinned to its port, so a host-level technique that needs a bare host (e.g. T1046
with nmap, which takes a host, never a URL) is refused against it. When you scope a `url` — especially
a loopback one like `http://localhost:3000/` — **ask the operator** whether to also add the URL's host
as a `host`/`ip` entry, and for a loopback URL both `localhost` and `127.0.0.1`, so host-level scans
can run. Add them explicitly; searu never widens scope on its own. (`searu run` prints this hint when a
host-only target is refused only on the port.)

Then validate it:

```
searu validate-roe --roe ./pentest/rules-of-engagement.json
```

Fix anything it reports (unknown ATT&CK IDs, unreadable file) before moving on. Scope and
authorisation are enforced by `searu` on every run — a target that is not in scope *now* is refused
before any network call.

## Deny uncontrolled egress

Before any tool runs, close the network side-doors so every target-facing action must go through
`searu` — including inside spawned specialists:

```
searu harden
```

This writes a project-scoped `.claude/settings.json` (merged with any existing settings, idempotent):
a settings-level `PreToolUse` hook running `searu scope-hook` and a `permissions.deny` over `WebFetch`,
`WebSearch`, MCP tools and the target-reaching Bash programs (`docker`, `curl`, `wget`, `nc`, `ncat`,
`socat`). Unlike a skill-frontmatter hook, this reaches a spawned specialist — the enforced layer that
makes every target-facing action go through `searu run`.
