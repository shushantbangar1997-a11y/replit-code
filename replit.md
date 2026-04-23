# StreamFix Hub — Digital Streaming Support

## Overview
A streaming support website with a self-hosted cloaking engine, lead capture system, and secure admin panel. Presents as an independent streaming technical support service. Runs Google Ads to generate leads while cloaking Google's review bots to a safe Amazon Prime page and blocking competitor click fraud.

## Architecture
- **Runtime**: Node.js with Express
- **Entry**: `index.js` — all routes and server logic in one file
- **Static files**: `public/` — HTML pages served directly
- **Data storage**: `data/` — JSON flat files (no database)
  - `data/settings.json` — cloaking on/off, money URL, safe URL, blocked IPs, allowed countries
  - `data/logs.json` — rolling log of last 500 cloaking decisions
  - `data/leads.json` — rolling log of last 500 lead (code submission) events

## Key Routes
| Route | Description |
|---|---|
| `/` | Homepage (index.html) |
| `/prime`, `/activate`, `/peacock` | Cloaker entry points — trigger fingerprint check |
| `/amazon-activate` | Code submission landing page (real users) |
| `/amazon-prime` | Safe landing page shown to bots/reviewers |
| `/safe` | Alias safe landing page |
| `/offer` | Offer landing page |
| `/api/cloak` | Self-hosted cloaking engine (POST) |
| `/api/track/lead` | Lead capture endpoint (public POST) |
| `/admin/login` | Admin login page |
| `/admin` | Admin dashboard (auth required) |
| `/admin/logout` | Clears session |
| `/admin/settings` | Saves money/safe URLs (POST, auth required) |
| `/admin/toggle` | Toggles cloaking on/off (POST, auth required) |
| `/admin/blocked-ips` | Saves permanently blocked IPs |
| `/admin/allowed-countries` | Saves allowed country filter |
| `/admin/clear-logs` | Clears decision log |
| `/admin/clear-leads` | Clears leads log |
| `/admin/clear-frequency` | Resets in-memory repeat-click tracker |

## Cloaking Engine
The `/api/cloak` endpoint:
1. Checks user-agent against a 30+ entry bot blocklist
2. Checks `navigator.webdriver` flag, screen resolution, plugin count
3. Calls ip-api.com free API to detect proxies/VPNs/datacenter IPs
4. Enforces repeat-click blocking (same IP within 24h window)
5. Enforces country allowlist if configured
6. Returns `{ decision: "allow"|"block", url: "..." }` and logs the decision

## Lead Capture
The `/api/track/lead` endpoint:
- **code_submit**: fires from `amazon-activate.html` when a visitor submits their TV code. Captures IP, geo, UTM params, gclid, screen, timezone. Stored in `data/leads.json`.
- **call_click**: fires when the visitor clicks the call button in the success popup. Marks the most recent matching submission (same IP, within 30 min) as `called: true` with a `calledAt` timestamp.
- Both fire-and-forget from the frontend — zero UX impact.

## Admin Panel
- Accessible at `/admin`, protected by session-based auth (bcrypt, 8h cookie)
- Password set via `ADMIN_PASSWORD` environment variable (required — no hardcoded fallback)
- Session secret from `SESSION_SECRET` environment variable (required)
- Dashboard sections: Cloaking toggle, Traffic stats, Top countries, Block reasons, URL settings, Blocked IPs, Country filter, **Leads table**, Decision log

## Environment Variables
| Variable | Purpose |
|---|---|
| `PORT` | Server port (default 5000) |
| `SESSION_SECRET` | Express session signing secret (required) |
| `ADMIN_PASSWORD` | Admin panel password — hashed with bcrypt on startup (required) |

## Dependencies
- `express` — web framework
- `express-session` — session management
- `bcryptjs` — password hashing

## Deployment
- Deployed to Railway.com
- Domain: activatemytvcode.com
- `ADMIN_PASSWORD` and `SESSION_SECRET` must be set as Railway environment variables
- Railway uses ephemeral filesystem — `data/` files reset on each deploy
