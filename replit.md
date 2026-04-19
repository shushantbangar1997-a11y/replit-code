# Digital Streaming Services

## Overview
A streaming support website with a self-hosted cloaking engine and secure admin panel. The site presents as an independent streaming technical support service, with a cloaking layer that filters real users from bots/reviewers.

## Architecture
- **Runtime**: Node.js with Express
- **Entry**: `index.js` — all routes and server logic in one file
- **Static files**: `public/` — HTML pages served directly
- **Data storage**: `data/` — JSON flat files (no database)
  - `data/settings.json` — cloaking on/off, money URL, safe URL
  - `data/logs.json` — rolling log of last 500 cloaking decisions

## Key Routes
| Route | Description |
|---|---|
| `/` | Homepage (index.html) |
| `/peacock` | Cloaker entry point — triggers fingerprint check |
| `/safe` | Safe landing page shown to bots/reviewers |
| `/offer` | Offer landing page shown to real users |
| `/api/cloak` | Self-hosted cloaking engine (POST) |
| `/admin/login` | Admin login page |
| `/admin` | Admin dashboard (auth required) |
| `/admin/logout` | Clears session |
| `/admin/settings` | Saves money/safe URLs (POST, auth required) |
| `/admin/toggle` | Toggles cloaking on/off (POST, auth required) |

## Cloaking Engine
The `/api/cloak` endpoint:
1. Checks user-agent against a 30+ entry bot blocklist
2. Checks `navigator.webdriver` flag
3. Calls ip-api.com free API to detect proxies/VPNs/datacenter IPs
4. Returns `{ decision: "allow"|"block", url: "..." }` and logs the decision

## Admin Panel
- Accessible at `/admin`, protected by session-based auth
- Password set via `ADMIN_PASSWORD` environment variable (default: `admin123`)
- Session secret from `SESSION_SECRET` environment variable
- Dashboard shows: cloaking toggle, URL settings, today's stats, last 100 decision log entries

## Environment Variables
| Variable | Purpose | Default |
|---|---|---|
| `PORT` | Server port | 5000 |
| `SESSION_SECRET` | Express session signing secret | hardcoded fallback |
| `ADMIN_PASSWORD` | Admin panel password (plaintext, hashed on startup) | `admin123` |

## Dependencies
- `express` — web framework
- `express-session` — session management
- `bcryptjs` — password hashing

## Important Notes
- Change `ADMIN_PASSWORD` env var before deploying to production
- The legacy `/api/cloakify` route redirects to `/api/cloak` for backward compatibility
- Bot detection uses regex patterns; new patterns can be added to `BOT_PATTERNS` array in `index.js`
