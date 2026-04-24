const express = require('express');
const path = require('path');
const https = require('https');
const http  = require('http');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 5000;

// ─── Admin path (secret, non-guessable URL prefix) ────────────────────────────
// Set ADMIN_PATH env var to override the default slug. No leading/trailing slashes.
var _ADMIN_PATH_RAW = (process.env.ADMIN_PATH || '').replace(/^\/+|\/+$/g, '');
var ADMIN_PATH = /^[a-zA-Z0-9_-]{4,}$/.test(_ADMIN_PATH_RAW) ? _ADMIN_PATH_RAW : 'manage-zx7q2';
if (_ADMIN_PATH_RAW && _ADMIN_PATH_RAW !== ADMIN_PATH) {
  console.warn('[WARN] ADMIN_PATH value "' + _ADMIN_PATH_RAW + '" is invalid (must be 4+ alphanumeric/-/_ chars). Using default.');
}

// ─── Data file paths (JSON fallback for local dev without DB) ─────────────────
const SETTINGS_FILE   = path.join(__dirname, 'data', 'settings.json');
const LOGS_FILE       = path.join(__dirname, 'data', 'logs.json');
const LEADS_FILE      = path.join(__dirname, 'data', 'leads.json');
const SITES_FILE      = path.join(__dirname, 'data', 'sites.json');
const ADMIN_HASH_FILE = path.join(__dirname, 'data', 'admin_hash');
const MAX_LOG_ENTRIES  = 10000;
const MAX_LEAD_ENTRIES = 5000;

const EventEmitter = require('events');
const logEmitter = new EventEmitter();
logEmitter.setMaxListeners(200);

var SETTINGS_DEFAULTS = {
  moneyUrl: '', safeUrl: '/safe', enabled: true, blockedIps: [], allowedCountries: [],
  vpnBlocking: true, proxyBlocking: true, botUaBlocking: true,
  repeatClickBlocking: true, ispBlocking: true, countryBlockingEnabled: true,
  suspiciousIspKeywords: [],
  blockedIpsMeta: {}
};

// ─── In-memory caches ─────────────────────────────────────────────────────────
var _cacheLogs     = null;   // Array, most-recent first
var _cacheLeads    = null;   // Array, most-recent first
var _cacheSites    = null;   // Array
var _cacheSettings = null;   // Object
var _dbPool        = null;
var _useDb         = false;

// ─── DB helpers ───────────────────────────────────────────────────────────────
function dbq(sql, params) {
  if (!_dbPool) return Promise.reject(new Error('No DB pool'));
  return _dbPool.query(sql, params || []);
}

function logRowToObj(row) {
  return {
    ts: row.ts ? new Date(row.ts).toISOString() : '',
    ip: row.ip || '', siteId: row.site_id || '', country: row.country || '',
    city: row.city || '', region: row.region || '', isp: row.isp || '',
    org: row.org || '', ua: row.ua || '', screen: row.screen || '',
    plugins: row.plugins != null ? row.plugins : 0,
    tz: row.tz || '', wd: !!row.wd, proxy: !!row.proxy, hosting: !!row.hosting,
    decision: row.decision || '', reason: row.reason || ''
  };
}

function leadRowToObj(row) {
  var base = {
    ts: row.ts ? new Date(row.ts).toISOString() : '',
    ip: row.ip || '', siteId: row.site_id || '', type: row.type || '',
    country: row.country || '', city: row.city || '', region: row.region || '',
    code: row.code || '', utm_source: row.utm_source || '',
    utm_campaign: row.utm_campaign || '', utm_medium: row.utm_medium || '',
    gclid: row.gclid || '', tz: row.tz || '', screen: row.screen || '',
    called: !!row.called,
    calledAt: row.called_at ? new Date(row.called_at).toISOString() : undefined,
    isp: row.isp || '', org: row.org || ''
  };
  if (row.extra && typeof row.extra === 'object') Object.assign(base, row.extra);
  return base;
}

function dbWriteLog(entry) {
  if (!_useDb || !_dbPool) return;
  dbq(
    'INSERT INTO cloaker_logs(ts,ip,site_id,country,city,region,isp,org,ua,screen,plugins,tz,wd,proxy,hosting,decision,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)',
    [entry.ts||new Date().toISOString(), entry.ip||'', entry.siteId||'', entry.country||'',
     entry.city||'', entry.region||'', entry.isp||'', entry.org||'',
     (entry.ua||'').slice(0,500), entry.screen||'', entry.plugins||0,
     entry.tz||'', !!entry.wd, !!entry.proxy, !!entry.hosting,
     entry.decision||'', entry.reason||'']
  ).catch(function(e) { console.error('DB log write error:', e.message); });
}

function dbWriteLead(entry) {
  if (!_useDb || !_dbPool) return;
  var extra = {};
  ['plugins','wd','proxy','hosting','ua'].forEach(function(k) { if (entry[k] !== undefined) extra[k] = entry[k]; });
  dbq(
    'INSERT INTO cloaker_leads(ts,ip,site_id,type,country,city,region,code,utm_source,utm_campaign,utm_medium,gclid,tz,screen,called,isp,org,extra) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)',
    [entry.ts||new Date().toISOString(), entry.ip||'', entry.siteId||'', entry.type||'',
     entry.country||'', entry.city||'', entry.region||'', entry.code||'',
     entry.utm_source||'', entry.utm_campaign||'', entry.utm_medium||'',
     entry.gclid||'', entry.tz||'', entry.screen||'', !!entry.called,
     entry.isp||'', entry.org||'', Object.keys(extra).length ? extra : null]
  ).catch(function(e) { console.error('DB lead write error:', e.message); });
}

function dbSaveSettings(data) {
  if (!_useDb || !_dbPool) return;
  dbq(
    "INSERT INTO cloaker_kv(key,value,updated_at) VALUES('settings',$1,NOW()) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()",
    [JSON.stringify(data)]
  ).catch(function(e) { console.error('DB settings write error:', e.message); });
}

function dbSaveSites(sites) {
  if (!_useDb || !_dbPool) return;
  dbq(
    "INSERT INTO cloaker_kv(key,value,updated_at) VALUES('sites',$1,NOW()) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()",
    [JSON.stringify(sites)]
  ).catch(function(e) { console.error('DB sites write error:', e.message); });
}

// ─── DB initialisation (called once at startup) ───────────────────────────────
async function initDb() {
  var dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) { console.log('No DATABASE_URL — using JSON files'); return; }

  try {
    _dbPool = new Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false }, max: 10 });
    await _dbPool.query('SELECT 1'); // connectivity test

    // Create tables
    await _dbPool.query(`
      CREATE TABLE IF NOT EXISTS cloaker_logs (
        id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL,
        ip VARCHAR(50), site_id VARCHAR(100), country VARCHAR(10),
        city VARCHAR(100), region VARCHAR(100), isp VARCHAR(255), org VARCHAR(255),
        ua TEXT, screen VARCHAR(30), plugins INT, tz VARCHAR(100),
        wd BOOLEAN DEFAULT FALSE, proxy BOOLEAN DEFAULT FALSE, hosting BOOLEAN DEFAULT FALSE,
        decision VARCHAR(10), reason VARCHAR(60)
      );
      CREATE TABLE IF NOT EXISTS cloaker_leads (
        id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ, ip VARCHAR(50),
        site_id VARCHAR(100), type VARCHAR(50), country VARCHAR(10),
        city VARCHAR(100), region VARCHAR(100), code VARCHAR(200),
        utm_source VARCHAR(255), utm_campaign VARCHAR(255), utm_medium VARCHAR(255),
        gclid TEXT, tz VARCHAR(100), screen VARCHAR(30),
        called BOOLEAN DEFAULT FALSE, called_at TIMESTAMPTZ,
        isp VARCHAR(255), org VARCHAR(255), extra JSONB
      );
      CREATE TABLE IF NOT EXISTS cloaker_kv (
        key VARCHAR(100) PRIMARY KEY, value JSONB NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_cl_ts   ON cloaker_logs(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_cl_site ON cloaker_logs(site_id);
      CREATE INDEX IF NOT EXISTS idx_ld_ts   ON cloaker_leads(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_ld_site ON cloaker_leads(site_id);
    `);

    _useDb = true;
    console.log('PostgreSQL connected — loading data into memory…');

    // ── Load logs ──────────────────────────────────────────────────────────────
    var lRes = await _dbPool.query('SELECT * FROM cloaker_logs ORDER BY ts DESC LIMIT $1', [MAX_LOG_ENTRIES]);
    if (lRes.rows.length > 0) {
      _cacheLogs = lRes.rows.map(logRowToObj);
      console.log('Loaded ' + _cacheLogs.length + ' logs from DB');
    } else {
      // Migrate from JSON file
      try {
        var jLogs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
        if (jLogs.length > 0) {
          console.log('Migrating ' + jLogs.length + ' logs from JSON → DB…');
          for (var i = jLogs.length - 1; i >= 0; i--) { dbWriteLog(jLogs[i]); }
          _cacheLogs = jLogs.slice(0, MAX_LOG_ENTRIES);
          console.log('Migration queued');
        } else { _cacheLogs = []; }
      } catch(e) { _cacheLogs = []; }
    }

    // ── Load leads ─────────────────────────────────────────────────────────────
    var ldRes = await _dbPool.query('SELECT * FROM cloaker_leads ORDER BY ts DESC LIMIT $1', [MAX_LEAD_ENTRIES]);
    if (ldRes.rows.length > 0) {
      _cacheLeads = ldRes.rows.map(leadRowToObj);
      console.log('Loaded ' + _cacheLeads.length + ' leads from DB');
    } else {
      try {
        var jLeads = JSON.parse(fs.readFileSync(LEADS_FILE, 'utf8'));
        if (jLeads.length > 0) {
          console.log('Migrating ' + jLeads.length + ' leads from JSON → DB…');
          for (var j = jLeads.length - 1; j >= 0; j--) { dbWriteLead(jLeads[j]); }
          _cacheLeads = jLeads.slice(0, MAX_LEAD_ENTRIES);
        } else { _cacheLeads = []; }
      } catch(e) { _cacheLeads = []; }
    }

    // ── Load settings ──────────────────────────────────────────────────────────
    var sRes = await _dbPool.query("SELECT value FROM cloaker_kv WHERE key='settings'");
    if (sRes.rows.length > 0) {
      _cacheSettings = Object.assign({}, SETTINGS_DEFAULTS, sRes.rows[0].value);
    } else {
      try {
        var jSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
        _cacheSettings = Object.assign({}, SETTINGS_DEFAULTS, jSettings);
        dbSaveSettings(_cacheSettings);
      } catch(e) { _cacheSettings = Object.assign({}, SETTINGS_DEFAULTS); }
    }

    // ── Load sites ─────────────────────────────────────────────────────────────
    var stRes = await _dbPool.query("SELECT value FROM cloaker_kv WHERE key='sites'");
    if (stRes.rows.length > 0) {
      _cacheSites = stRes.rows[0].value;
    } else {
      try {
        var jSites = JSON.parse(fs.readFileSync(SITES_FILE, 'utf8'));
        _cacheSites = jSites;
        dbSaveSites(_cacheSites);
      } catch(e) { _cacheSites = null; }
    }

    console.log('DB ready ✓');
  } catch (e) {
    console.error('DB init error — falling back to JSON:', e.message);
    _useDb = false;
    _dbPool = null;
  }
}

// ─── Settings helpers ─────────────────────────────────────────────────────────
function readSettings() {
  if (_cacheSettings !== null) return Object.assign({}, _cacheSettings);
  try {
    var raw = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    return Object.assign({}, SETTINGS_DEFAULTS, raw);
  } catch (e) { return Object.assign({}, SETTINGS_DEFAULTS); }
}

function writeSettings(data) {
  _cacheSettings = Object.assign({}, data);
  dbSaveSettings(data);
  try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2)); } catch(e) {}
}

// ─── Log helpers ──────────────────────────────────────────────────────────────
function readLogs() {
  if (_cacheLogs !== null) return _cacheLogs;
  try { return JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8')); } catch (e) { return []; }
}

function appendLog(entry) {
  if (_cacheLogs === null) _cacheLogs = readLogs();
  _cacheLogs.unshift(entry);
  if (_cacheLogs.length > MAX_LOG_ENTRIES) _cacheLogs = _cacheLogs.slice(0, MAX_LOG_ENTRIES);
  dbWriteLog(entry);
  try { fs.writeFileSync(LOGS_FILE, JSON.stringify(_cacheLogs.slice(0, 500), null, 2)); } catch(e) {}
  logEmitter.emit('newLog', entry);
  var today = new Date().toISOString().slice(0, 10);
  var tLogs = _cacheLogs.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  var tA = tLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var tB = tLogs.filter(function(l) { return l.decision === 'block'; }).length;
  logEmitter.emit('statsUpdate', { todayTotal: tA + tB, todayAllow: tA, todayBlock: tB });
}

// ─── Leads helpers ────────────────────────────────────────────────────────────
function readLeads() {
  if (_cacheLeads !== null) return _cacheLeads;
  try { return JSON.parse(fs.readFileSync(LEADS_FILE, 'utf8')); } catch (e) { return []; }
}

function appendLead(entry) {
  if (_cacheLeads === null) _cacheLeads = readLeads();
  _cacheLeads.unshift(entry);
  if (_cacheLeads.length > MAX_LEAD_ENTRIES) _cacheLeads = _cacheLeads.slice(0, MAX_LEAD_ENTRIES);
  dbWriteLead(entry);
  try { fs.writeFileSync(LEADS_FILE, JSON.stringify(_cacheLeads.slice(0, 500), null, 2)); } catch(e) {}
  logEmitter.emit('newLead', entry);
}

function markLeadCalled(siteId, ip, code) {
  if (_cacheLeads === null) _cacheLeads = readLeads();
  var cutoff = Date.now() - 30 * 60 * 1000;
  var found = false;
  for (var i = 0; i < _cacheLeads.length; i++) {
    var l = _cacheLeads[i];
    if (l.type === 'code_submit' && l.siteId === siteId && l.ip === ip && new Date(l.ts).getTime() > cutoff) {
      _cacheLeads[i].called = true;
      _cacheLeads[i].calledAt = new Date().toISOString();
      found = true;
      if (_useDb && _dbPool) {
        dbq('UPDATE cloaker_leads SET called=TRUE, called_at=NOW() WHERE id=(SELECT id FROM cloaker_leads WHERE site_id=$1 AND ip=$2 AND type=$3 AND ts>$4 ORDER BY ts DESC LIMIT 1)',
          [siteId, ip, 'code_submit', new Date(cutoff).toISOString()]
        ).catch(function(e) { console.error('DB markCalled error:', e.message); });
      }
      break;
    }
  }
  if (!found) {
    var newEntry = { type: 'call_click', ts: new Date().toISOString(), siteId: siteId, ip: ip, code: code || '', called: true };
    _cacheLeads.unshift(newEntry);
    if (_cacheLeads.length > MAX_LEAD_ENTRIES) _cacheLeads = _cacheLeads.slice(0, MAX_LEAD_ENTRIES);
    dbWriteLead(newEntry);
  }
  try { fs.writeFileSync(LEADS_FILE, JSON.stringify(_cacheLeads.slice(0, 500), null, 2)); } catch(e) {}
}

// ─── Sites helpers ────────────────────────────────────────────────────────────
function readSites() {
  if (_cacheSites !== null) return _cacheSites;
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
  _cacheSites = sites;
  dbSaveSites(sites);
  try { fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2)); } catch(e) {}
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
    allowedCountries: site.isDefault ? (global.allowedCountries || []) : (Array.isArray(site.allowedCountries) ? site.allowedCountries : []),
    // Global security feature flags — always read from settings.json regardless of site
    vpnBlocking:             global.vpnBlocking             !== false,
    proxyBlocking:           global.proxyBlocking           !== false,
    botUaBlocking:           global.botUaBlocking           !== false,
    repeatClickBlocking:     global.repeatClickBlocking     !== false,
    ispBlocking:             global.ispBlocking             !== false,
    countryBlockingEnabled:  global.countryBlockingEnabled  !== false,
    suspiciousIspKeywords:   Array.isArray(global.suspiciousIspKeywords) ? global.suspiciousIspKeywords : [],
    blockedIpsMeta:          (global.blockedIpsMeta && typeof global.blockedIpsMeta === 'object') ? global.blockedIpsMeta : {}
  };
}

// ─── GitHub auto-inject helper ────────────────────────────────────────────────
function buildCloakScript(hubUrl, apiKey) {
  return '<script>\n'
    + '(function(){var _h=\'' + hubUrl + '\',_k=\'' + apiKey + '\';\n'
    + 'try{fetch(_h+\'/api/v1/pixel\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Client-ID\':_k},\n'
    + 'body:JSON.stringify({ua:navigator.userAgent,sw:screen.width,sh:screen.height,\n'
    + 'wd:!!navigator.webdriver,pl:(navigator.plugins||[]).length,\n'
    + 'tz:Intl.DateTimeFormat().resolvedOptions().timeZone})}).then(function(r){return r.json()})\n'
    + '.then(function(d){if(d&&d.url)window.location.replace(d.url)}).catch(function(){})}catch(e){}\n'
    + '})();\n'
    + '</script>';
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
        'User-Agent': 'Mozilla/5.0 (compatible; web-agent/1.0)',
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

      // Remove existing injection if present (handles both legacy comment-wrapped and current bare script)
      var re = /(?:<!-- StreamFix-Hub-Start -->[\s\S]*?<!-- StreamFix-Hub-End -->|<!--t:s-->[\s\S]*?<!--t:e-->|<script>\n\(function\(\)\{var _h='[^']+',_k='[^']+';[\s\S]*?\}\)\(\);\n<\/script>)/g;
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
        message: 'chore: update analytics snippet',
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
  // Prefer persisted hash from previous change-password call
  try {
    var saved = fs.readFileSync(ADMIN_HASH_FILE, 'utf8').trim();
    if (saved && saved.startsWith('$2')) { ADMIN_PASSWORD_HASH = saved; return; }
  } catch(e) {}
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

function isSuspiciousISP(isp, org, extraKeywords) {
  var combined = ((isp || '') + ' ' + (org || '')).toLowerCase();
  var allKeywords = SUSPICIOUS_ISP.concat(Array.isArray(extraKeywords) ? extraKeywords : []);
  return allKeywords.some(function(k) { return k && combined.indexOf(k.toLowerCase()) !== -1; });
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
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
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
  res.status(404).send('Not found');
}

// ─── Public routes ────────────────────────────────────────────────────────────
app.get('/', function(req, res) {
  try {
    var html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    html = html.replace('__ADMIN_LOGIN_PATH__', '/' + ADMIN_PATH + '/login');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    res.status(500).send('Error');
  }
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
app.post('/api/v1/pixel', async function(req, res) {
  var siteKey      = req.headers['x-client-id'] || req.body.siteKey || '';
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
      country: 'XX', city: '', region: '', isp: '', org: '',
      ua: ua.slice(0, 200), screen: screenStr, plugins: pl,
      tz: tz, wd: wd, proxy: false, hosting: false,
      decision: 'block', reason: reason
    };
    appendLog(entry);
    return res.json({ decision: 'block', url: safeUrl });
  }

  // Cloaking disabled → always allow
  if (!settings.enabled) {
    appendLog({
      ts: new Date().toISOString(), ip: realIP, siteId: siteId,
      country: 'XX', city: '', region: '', isp: '', org: '',
      ua: ua.slice(0, 200), screen: screenStr, plugins: pl,
      tz: tz, wd: wd, proxy: false, hosting: false,
      decision: 'allow', reason: 'disabled'
    });
    return res.json({ decision: 'allow', url: moneyUrl });
  }

  // 1. Manual IP blocklist — checked first so it always wins with reason manual-block
  var blockedIps = Array.isArray(settings.blockedIps) ? settings.blockedIps : [];
  if (blockedIps.indexOf(realIP) !== -1) return fastBlock('manual-block');

  // 2. Repeat-click frequency check — only for IPs not on the manual list
  if (settings.repeatClickBlocking !== false && checkFrequency(realIP)) return fastBlock('repeat-click');

  // 3. Bot User-Agent check
  if (settings.botUaBlocking !== false && isBot(ua)) return fastBlock('bot-ua');

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
  if (settings.countryBlockingEnabled !== false && allowedCountries.length > 0) {
    var visitorCC = (ipData.country || 'XX').toUpperCase();
    var allowed = allowedCountries.some(function(cc) { return cc.toUpperCase() === visitorCC; });
    if (!allowed) {
      decision = 'block';
      reason   = 'country-block';
    }
  }

  // 9. Suspicious ISP/org check
  if (settings.ispBlocking !== false && decision === 'allow' && isSuspiciousISP(ipData.isp, ipData.org, settings.suspiciousIspKeywords)) {
    decision = 'block';
    reason   = 'suspicious-isp';
  }

  // 10. Proxy / hosting check
  if (decision === 'allow') {
    if (settings.vpnBlocking !== false && ipData.proxy) {
      decision = 'block'; reason = 'proxy-vpn';
    } else if (settings.proxyBlocking !== false && ipData.hosting) {
      decision = 'block'; reason = 'datacenter';
    }
  }

  appendLog({
    ts: new Date().toISOString(),
    ip: realIP,
    siteId: siteId,
    country: ipData.country || 'XX',
    city: ipData.city || '',
    region: ipData.regionName || '',
    isp: ipData.isp || '',
    org: ipData.org || '',
    ua: ua.slice(0, 200),
    screen: screenStr,
    plugins: pl,
    tz: tz,
    wd: wd,
    proxy: ipData.proxy || false,
    hosting: ipData.hosting || false,
    decision: decision,
    reason: reason
  });

  res.json({ decision: decision, url: decision === 'allow' ? moneyUrl : safeUrl });
});

// ─── Legacy redirect ───────────────────────────────────────────────────────────
app.post('/api/cloakify', function(req, res) {
  res.redirect(307, '/api/v1/pixel');
});

// ─── Lead capture (public — fires silently from amazon-activate page) ─────────
app.post('/api/v1/event', async function(req, res) {
  res.json({ ok: true }); // respond immediately, never block the client
  try {
    var siteKey = req.headers['x-client-id'] || req.body.siteKey || '';
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

// ─── Old /admin paths → 404 (keep undiscoverable) ────────────────────────────
app.all('/admin', function(req, res) { res.status(404).send('Not found'); });
app.all('/admin/login', function(req, res) { res.status(404).send('Not found'); });

// ─── Admin login ──────────────────────────────────────────────────────────────
app.get('/' + ADMIN_PATH + '/login', function(req, res) {
  if (req.session && req.session.adminAuth) return res.redirect('/' + ADMIN_PATH);
  var error = req.query.error ? '<p class="error">Invalid credentials. Try again.</p>' : '';
  res.send(adminLoginPage(error));
});

app.post('/' + ADMIN_PATH + '/login', function(req, res) {
  var password = req.body.password || '';
  if (bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    req.session.adminAuth = true;
    return res.redirect('/' + ADMIN_PATH);
  }
  res.redirect('/' + ADMIN_PATH + '/login?error=1');
});

// ─── Admin logout ─────────────────────────────────────────────────────────────
app.get('/' + ADMIN_PATH + '/logout', function(req, res) {
  req.session.destroy(function() { res.redirect('/' + ADMIN_PATH + '/login'); });
});

// ─── Admin dashboard ──────────────────────────────────────────────────────────
var LOG_PAGE_SIZE  = 100;
var LEAD_PAGE_SIZE = 50;

app.get('/' + ADMIN_PATH, requireAdmin, function(req, res) {
  var globalSettings = readSettings();
  var sites      = readSites();
  var siteFilter = req.query.site || '';
  var siteCreated = req.query.siteCreated === '1';
  var rangeParam = ['7d','30d','90d','custom'].includes(req.query.range) ? req.query.range : '24h';
  var rangeFrom  = (req.query.from  || '').replace(/[^0-9\-]/g, '').slice(0, 10);
  var rangeTo    = (req.query.to    || '').replace(/[^0-9\-]/g, '').slice(0, 10);

  // Find selected site object (null = All Sites)
  var selectedSite = siteFilter ? sites.find(function(s) { return s.id === siteFilter; }) : null;

  // Per-site view: use site-specific URL/enabled/blocked values for display, but keep globalSettings intact
  var settings = globalSettings;
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
    displayTz: req.session.displayTz || 'UTC',
    tzAutoDetected: !!req.session.tzAutoDetected,
    globalSettings: globalSettings,
    range: rangeParam,
    rangeFrom: rangeFrom,
    rangeTo: rangeTo
  }));
});

// ─── Admin SSE events ─────────────────────────────────────────────────────────
app.get('/' + ADMIN_PATH + '/events', requireAdmin, function(req, res) {
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
  function onStatsUpdate(payload) {
    res.write('data: ' + JSON.stringify({ type: 'statsUpdate', todayTotal: payload.todayTotal, todayAllow: payload.todayAllow, todayBlock: payload.todayBlock }) + '\n\n');
  }

  logEmitter.on('newLog', onLog);
  logEmitter.on('newLead', onLead);
  logEmitter.on('siteStatus', onSiteStatus);
  logEmitter.on('statsUpdate', onStatsUpdate);

  var keepAlive = setInterval(function() {
    res.write(': ping\n\n');
  }, 25000);

  req.on('close', function() {
    logEmitter.removeListener('newLog', onLog);
    logEmitter.removeListener('newLead', onLead);
    logEmitter.removeListener('siteStatus', onSiteStatus);
    logEmitter.removeListener('statsUpdate', onStatsUpdate);
    clearInterval(keepAlive);
  });
});

// ─── Admin settings save (URLs) ───────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/settings', requireAdmin, function(req, res) {
  var settings = readSettings();
  settings.moneyUrl = (req.body.moneyUrl || '').trim();
  settings.safeUrl  = (req.body.safeUrl  || '/safe').trim();
  writeSettings(settings);
  res.redirect('/' + ADMIN_PATH);
});

// ─── Railway token setup ──────────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/settings/railway-token', requireAdmin, function(req, res) {
  var token = (req.body.railwayToken || '').trim();
  setRailwayToken(token); // stores in .local/railway_token (env var takes priority)
  res.redirect('/' + ADMIN_PATH + '#settings');
});

// ─── Admin toggle cloaking ────────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/toggle', requireAdmin, async function(req, res) {
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
  res.redirect('/' + ADMIN_PATH);
});

// ─── Admin clear logs ─────────────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/clear-logs', requireAdmin, function(req, res) {
  _cacheLogs = [];
  if (_useDb && _dbPool) {
    _dbPool.query('DELETE FROM cloaker_logs').catch(function(e) { console.error('DB clear-logs:', e.message); });
  }
  try { fs.writeFileSync(LOGS_FILE, '[]'); } catch(e) {}
  res.redirect('/' + ADMIN_PATH);
});

// ─── Admin clear leads ────────────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/clear-leads', requireAdmin, function(req, res) {
  _cacheLeads = [];
  if (_useDb && _dbPool) {
    _dbPool.query('DELETE FROM cloaker_leads').catch(function(e) { console.error('DB clear-leads:', e.message); });
  }
  try { fs.writeFileSync(LEADS_FILE, '[]'); } catch(e) {}
  res.redirect('/' + ADMIN_PATH);
});

// ─── Admin save blocked IPs ───────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/blocked-ips', requireAdmin, function(req, res) {
  var settings = readSettings();
  var raw = (req.body.blockedIps || '').trim();
  settings.blockedIps = raw
    .split(/[\n,]+/)
    .map(function(s) { return s.trim(); })
    .filter(function(s) { return s.length > 0; });
  writeSettings(settings);
  res.redirect('/' + ADMIN_PATH);
});

// ─── Admin save allowed countries ────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/allowed-countries', requireAdmin, function(req, res) {
  var settings = readSettings();
  var raw = (req.body.allowedCountries || '').trim();
  settings.allowedCountries = raw
    .split(/[\n,\s]+/)
    .map(function(s) { return s.trim().toUpperCase(); })
    .filter(function(s) { return s.length === 2; });
  writeSettings(settings);
  res.redirect('/' + ADMIN_PATH);
});

// ─── Admin export blocked IPs for Google Ads ──────────────────────────────────
app.get('/' + ADMIN_PATH + '/blocked-ips-export', requireAdmin, function(req, res) {
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

app.post('/' + ADMIN_PATH + '/clear-frequency', requireAdmin, function(req, res) {
  clearFrequencyStore();
  res.redirect('/' + ADMIN_PATH);
});

app.post('/' + ADMIN_PATH + '/set-timezone', requireAdmin, function(req, res) {
  var tz = (req.body.tz || 'UTC').trim();
  try { new Intl.DateTimeFormat('en', { timeZone: tz }); } catch(e) {
    return res.json({ ok: false, error: 'Invalid timezone' });
  }
  req.session.displayTz = tz;
  if (req.body.source === 'auto') req.session.tzAutoDetected = true;
  res.json({ ok: true, tz: tz });
});

function isValidIp(ip) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return ip.split('.').every(function(p) { return parseInt(p, 10) <= 255; });
  }
  return /^[\da-fA-F:]{2,39}$/.test(ip) && ip.includes(':');
}

app.post('/' + ADMIN_PATH + '/block-ip-ajax', requireAdmin, function(req, res) {
  var ip     = (req.body.ip || '').trim();
  var siteId = (req.body.siteId || 'default').trim();
  if (!ip) return res.json({ ok: false, error: 'No IP' });
  if (!isValidIp(ip)) return res.json({ ok: false, error: 'Invalid IP address' });
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
    if (!cfg.blockedIps.includes(ip)) {
      cfg.blockedIps.push(ip);
      if (!cfg.blockedIpsMeta || typeof cfg.blockedIpsMeta !== 'object') cfg.blockedIpsMeta = {};
      cfg.blockedIpsMeta[ip] = { at: new Date().toISOString(), reason: 'manual' };
      writeSettings(cfg);
    }
  }
  res.json({ ok: true, ip: ip });
});

// ─── Admin unblock IP (AJAX) ──────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/unblock-ip-ajax', requireAdmin, function(req, res) {
  var ip     = (req.body.ip || '').trim();
  var siteId = (req.body.siteId || 'default').trim();
  if (!ip) return res.json({ ok: false, error: 'No IP' });
  if (!isValidIp(ip)) return res.json({ ok: false, error: 'Invalid IP address' });
  if (siteId && siteId !== 'default') {
    var ss = readSites();
    var idx = ss.findIndex(function(s) { return s.id === siteId; });
    if (idx !== -1 && Array.isArray(ss[idx].blockedIps)) {
      ss[idx].blockedIps = ss[idx].blockedIps.filter(function(i) { return i !== ip; });
      writeSites(ss);
    }
  } else {
    var cfg = readSettings();
    if (Array.isArray(cfg.blockedIps)) {
      cfg.blockedIps = cfg.blockedIps.filter(function(i) { return i !== ip; });
      if (cfg.blockedIpsMeta) delete cfg.blockedIpsMeta[ip];
      writeSettings(cfg);
    }
  }
  res.json({ ok: true, ip: ip });
});

// ─── Admin change password ────────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/change-password', requireAdmin, function(req, res) {
  var currentPwd = req.body.currentPassword || '';
  var newPwd     = req.body.newPassword     || '';
  var confirmPwd = req.body.confirmPassword || '';
  if (!bcrypt.compareSync(currentPwd, ADMIN_PASSWORD_HASH)) {
    return res.json({ ok: false, error: 'Current password is incorrect' });
  }
  if (newPwd.length < 8) {
    return res.json({ ok: false, error: 'New password must be at least 8 characters' });
  }
  if (newPwd !== confirmPwd) {
    return res.json({ ok: false, error: 'New passwords do not match' });
  }
  ADMIN_PASSWORD_HASH = bcrypt.hashSync(newPwd, 10);
  try { fs.writeFileSync(ADMIN_HASH_FILE, ADMIN_PASSWORD_HASH, { mode: 0o600 }); } catch(e) {}
  res.json({ ok: true });
});

// ─── Admin save feature toggles + ISP keywords ────────────────────────────────
app.post('/' + ADMIN_PATH + '/settings/features', requireAdmin, function(req, res) {
  var cfg = readSettings();
  function boolField(name) {
    var v = req.body[name];
    if (Array.isArray(v)) return v.includes('true') || v.includes('on');
    return v === 'true' || v === 'on';
  }
  cfg.vpnBlocking          = boolField('vpnBlocking');
  cfg.proxyBlocking        = boolField('proxyBlocking');
  cfg.botUaBlocking        = boolField('botUaBlocking');
  cfg.repeatClickBlocking  = boolField('repeatClickBlocking');
  cfg.ispBlocking          = boolField('ispBlocking');
  cfg.countryBlockingEnabled = boolField('countryBlockingEnabled');
  var kw = (req.body.suspiciousIspKeywords || '').split(/[\n,]+/).map(function(s) { return s.trim().toLowerCase(); }).filter(Boolean);
  cfg.suspiciousIspKeywords = kw;
  writeSettings(cfg);
  res.redirect('/' + ADMIN_PATH + '?stab=security#settings');
});

// ─── Admin sites management ───────────────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/sites', requireAdmin, async function(req, res) {
  var name      = (req.body.name || '').trim();
  var domain    = (req.body.domain || '').trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
  var githubRepo = (req.body.githubRepo || '').trim();
  var moneyUrl  = (req.body.moneyUrl || '').trim();
  if (!name) return res.redirect('/' + ADMIN_PATH + '?siteErr=name');

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

  res.redirect('/' + ADMIN_PATH + '?site=' + id + '&siteCreated=1');
});

app.post('/' + ADMIN_PATH + '/sites/:id/settings', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx === -1) return res.redirect('/' + ADMIN_PATH);

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

  // Only update security lists when those fields are explicitly included in the form submission
  if (req.body.blockedIps !== undefined) {
    site.blockedIps = String(req.body.blockedIps).split(/[\n,]+/).map(function(s) { return s.trim(); }).filter(Boolean);
  }
  if (req.body.allowedCountries !== undefined) {
    site.allowedCountries = String(req.body.allowedCountries).split(/[\n,\s]+/).map(function(s) { return s.trim().toUpperCase(); }).filter(function(s) { return s.length === 2; });
  }
  sites[idx] = site;
  writeSites(sites);

  // For the default site, settings.json is the authoritative source for cloaking decisions,
  // so mirror any URL/security field updates there to keep getSiteSettings() consistent.
  if (site.isDefault) {
    var gs = readSettings();
    if (req.body.moneyUrl !== undefined) gs.moneyUrl = site.moneyUrl;
    if (req.body.safeUrl  !== undefined) gs.safeUrl  = site.safeUrl;
    if (req.body.blockedIps !== undefined) gs.blockedIps = site.blockedIps;
    if (req.body.allowedCountries !== undefined) gs.allowedCountries = site.allowedCountries;
    writeSettings(gs);
  }

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
  res.redirect('/' + ADMIN_PATH + qs);
});

app.post('/' + ADMIN_PATH + '/sites/:id/regenerate-key', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx === -1) return res.redirect('/' + ADMIN_PATH);

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
  res.redirect('/' + ADMIN_PATH + qs);
});

app.post('/' + ADMIN_PATH + '/sites/:id/delete', requireAdmin, function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === id; });
  if (!site || site.isDefault) return res.redirect('/' + ADMIN_PATH); // protect default
  writeSites(sites.filter(function(s) { return s.id !== id; }));
  res.redirect('/' + ADMIN_PATH);
});

// ─── Manual re-inject (admin AJAX) ───────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/sites/:id/inject', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var site = sites.find(function(s) { return s.id === id; });
  if (!site) return res.json({ ok: false, reason: 'site-not-found' });
  var hubUrl = 'https://' + (process.env.REPLIT_DEV_DOMAIN || req.headers.host || 'localhost');
  try {
    var result = await githubInject(site, hubUrl);
    return res.json(result);
  } catch (e) {
    return res.json({ ok: false, reason: 'error', message: e.message });
  }
});

// ─── Lead called toggle (admin AJAX) ─────────────────────────────────────────
app.post('/' + ADMIN_PATH + '/lead-toggle', requireAdmin, function(req, res) {
  var ts     = (req.body.ts     || '').trim();
  var siteId = (req.body.siteId || '').trim();
  var ip     = (req.body.ip     || '').trim();
  if (!ts) return res.json({ ok: false, reason: 'no-ts' });
  var leads = readLeads();
  // Match by composite key (ts + siteId + ip) for precision; fall back to ts-only for older records
  var idx = leads.findIndex(function(l) {
    return l.ts === ts && ((!siteId && !ip) || (l.siteId === siteId && l.ip === ip));
  });
  if (idx === -1) idx = leads.findIndex(function(l) { return l.ts === ts; });
  if (idx === -1) return res.json({ ok: false, reason: 'not-found' });
  leads[idx].called = !leads[idx].called;
  if (leads[idx].called) leads[idx].calledAt = new Date().toISOString();
  else delete leads[idx].calledAt;
  if (_cacheLeads !== null) _cacheLeads = leads;
  if (_useDb && _dbPool) {
    var toggleTs = leads[idx].ts;
    if (leads[idx].called) {
      _dbPool.query('UPDATE cloaker_leads SET called=TRUE,called_at=NOW() WHERE id=(SELECT id FROM cloaker_leads WHERE ts=$1 AND site_id=$2 AND ip=$3 ORDER BY id DESC LIMIT 1)',
        [toggleTs, leads[idx].siteId || '', leads[idx].ip || '']
      ).catch(function(e) { console.error('DB toggle-lead error:', e.message); });
    } else {
      _dbPool.query('UPDATE cloaker_leads SET called=FALSE,called_at=NULL WHERE id=(SELECT id FROM cloaker_leads WHERE ts=$1 AND site_id=$2 AND ip=$3 ORDER BY id DESC LIMIT 1)',
        [toggleTs, leads[idx].siteId || '', leads[idx].ip || '']
      ).catch(function(e) { console.error('DB toggle-lead error:', e.message); });
    }
  }
  try { fs.writeFileSync(LEADS_FILE, JSON.stringify(leads.slice(0, 500), null, 2)); } catch(e) {}
  res.json({ ok: true, called: leads[idx].called });
});

app.post('/' + ADMIN_PATH + '/sites/:id/toggle', requireAdmin, async function(req, res) {
  var id = req.params.id;
  var sites = readSites();
  var idx = sites.findIndex(function(s) { return s.id === id; });
  if (idx !== -1) {
    sites[idx].enabled = !sites[idx].enabled;
    writeSites(sites);
    // For the default site, settings.json is the authoritative enabled source for cloaking
    if (sites[idx].isDefault) {
      var gs = readSettings();
      gs.enabled = sites[idx].enabled;
      writeSettings(gs);
    }
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
  res.redirect('/' + ADMIN_PATH + qs);
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

function scheduleStartupReInject() {
  if (!process.env.GITHUB_TOKEN) return;
  var hubDomain = process.env.REPLIT_DEV_DOMAIN || process.env.RAILWAY_PUBLIC_DOMAIN || null;
  if (!hubDomain) return;
  var hubUrl = 'https://' + hubDomain;
  setTimeout(async function() {
    var sites = readSites();
    var toReInject = sites.filter(function(s) {
      return s.githubRepo && s.injectedFiles && s.injectedFiles.length;
    });
    if (!toReInject.length) return;
    console.log('Auto re-injecting ' + toReInject.length + ' site(s) with updated analytics snippet...');
    for (var i = 0; i < toReInject.length; i++) {
      try {
        var r = await githubInject(toReInject[i], hubUrl);
        if (r.ok) console.log('Re-injected:', toReInject[i].id, r.injected);
        else console.log('Re-inject skipped:', toReInject[i].id, r.reason);
      } catch (e) {
        console.error('Re-inject error for', toReInject[i].id, e.message);
      }
    }
  }, 8000);
}

initDb().then(function() {
  app.listen(PORT, '0.0.0.0', function() {
    console.log('Server running on port ' + PORT);
    scheduleStartupReInject();
  });
}).catch(function(e) {
  console.error('initDb failed, starting without DB:', e.message);
  app.listen(PORT, '0.0.0.0', function() {
    console.log('Server running on port ' + PORT + ' (no DB)');
    scheduleStartupReInject();
  });
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
<title>Sign In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#f9fafb;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#111827}
.card{background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;padding:44px 40px;width:100%;max-width:400px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 24px rgba(0,0,0,.06)}
.logo-row{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.logo-box{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#2563eb);display:flex;align-items:center;justify-content:center;box-shadow:0 1px 4px rgba(59,130,246,.4)}
.logo-box svg{width:22px;height:22px}
.brand-name{font-size:1.2rem;font-weight:800;color:#111827;letter-spacing:-.5px}
.brand-tag{font-size:.65rem;color:#9ca3af;margin-top:1px}
h1{font-size:.9rem;font-weight:600;color:#4b5563;margin-bottom:22px}
label{display:block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-bottom:6px}
input[type=password]{width:100%;padding:11px 14px;background:#f9fafb;border:1px solid #d1d5db;border-radius:9px;color:#111827;font-size:.9rem;outline:none;transition:border .2s,box-shadow .2s;font-family:inherit}
input[type=password]:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.12)}
button{width:100%;margin-top:18px;padding:13px;background:#3b82f6;color:#fff;border:none;border-radius:9px;font-size:.95rem;font-weight:700;cursor:pointer;transition:background .2s;font-family:inherit}
button:hover{background:#2563eb}
.error{color:#dc2626;font-size:.82rem;margin-top:12px;text-align:center;background:rgba(220,38,38,.05);border:1px solid rgba(220,38,38,.15);padding:8px 12px;border-radius:7px}
</style>
</head>
<body>
<div class="card">
  <div class="logo-row">
    <div class="logo-box">
      <svg viewBox="0 0 50 39" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M16.4992 2H37.5808L22.0816 24.9729H1L16.4992 2Z" fill="white"/>
        <path d="M17.4224 27.102L11.4192 36H33.5008L49 13.0271H32.7024L23.2064 27.102H17.4224Z" fill="white"/>
      </svg>
    </div>
    <div>
      <div class="brand-name">Portal</div>
      <div class="brand-tag">Management Console</div>
    </div>
  </div>
  <h1>Sign in to your dashboard</h1>
  <form method="POST" action="/${ADMIN_PATH}/login">
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
  var tzAutoDetected  = opts.tzAutoDetected || false;
  var globalSettings  = opts.globalSettings || settings;
  var range        = opts.range || '24h';
  var rangeFrom    = opts.rangeFrom || '';
  var rangeTo      = opts.rangeTo || '';
  var now = new Date();
  var today = now.toISOString().slice(0, 10);
  var timeStr = now.toUTCString().slice(17, 25);

  // ── Range cutoff ────────────────────────────────────────────────────────────
  var rangeDays = { '24h': 0, '7d': 7, '30d': 30, '90d': 90 }[range] || 0;
  var rangeCutoff = '';
  if (rangeDays > 0) {
    var cutD = new Date(now.getTime() - rangeDays * 24 * 60 * 60 * 1000);
    rangeCutoff = cutD.toISOString().slice(0, 10);
  }

  // ── Stats ─────────────────────────────────────────────────────────────────
  var todayLogs;
  if (range === 'custom' && rangeFrom && rangeTo) {
    var rfrom = rangeFrom <= rangeTo ? rangeFrom : rangeTo;
    var rto   = rangeFrom <= rangeTo ? rangeTo   : rangeFrom;
    todayLogs = statsLogs.filter(function(l) {
      if (!l.ts) return false;
      var d = l.ts.slice(0, 10);
      return d >= rfrom && d <= rto;
    });
  } else if (rangeDays === 0) {
    todayLogs = statsLogs.filter(function(l) { return l.ts && l.ts.startsWith(today); });
  } else {
    todayLogs = statsLogs.filter(function(l) { return l.ts && l.ts.slice(0,10) >= rangeCutoff; });
  }
  var todayAllow   = todayLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var todayBlock   = todayLogs.filter(function(l) { return l.decision === 'block'; }).length;
  var todayTotal   = todayAllow + todayBlock;
  var allAllow     = statsLogs.filter(function(l) { return l.decision === 'allow'; }).length;
  var allBlock     = statsLogs.filter(function(l) { return l.decision === 'block'; }).length;
  var allTotal     = allAllow + allBlock;
  var blockRate    = allTotal > 0 ? Math.round(allBlock / allTotal * 100) : 0;

  // ── Top countries ─────────────────────────────────────────────────────────
  var countryStats = {};
  todayLogs.forEach(function(l) {
    var cc = l.country || 'XX';
    if (!countryStats[cc]) countryStats[cc] = { hits: 0, allow: 0, block: 0 };
    countryStats[cc].hits++;
    if (l.decision === 'allow') countryStats[cc].allow++;
    else countryStats[cc].block++;
  });
  var flags = { US:'🇺🇸',GB:'🇬🇧',CA:'🇨🇦',AU:'🇦🇺',IN:'🇮🇳',DE:'🇩🇪',FR:'🇫🇷',PH:'🇵🇭',MX:'🇲🇽',BR:'🇧🇷',NL:'🇳🇱',SG:'🇸🇬',JP:'🇯🇵',NG:'🇳🇬',PK:'🇵🇰',ZA:'🇿🇦',XX:'🌐' };
  var topCountries = Object.keys(countryStats)
    .sort(function(a,b){ return countryStats[b].hits - countryStats[a].hits; })
    .slice(0, 8);
  var countryRows = topCountries.length ? (
    '<table style="width:100%;border-collapse:collapse;font-size:.73rem">'
    + '<thead><tr>'
    + '<th style="text-align:left;padding:5px 6px;color:var(--text3);font-size:.63rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700">Country</th>'
    + '<th style="text-align:right;padding:5px 6px;color:var(--text3);font-size:.63rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700">Hits</th>'
    + '<th style="text-align:right;padding:5px 6px;color:var(--text3);font-size:.63rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700">Allow</th>'
    + '<th style="text-align:right;padding:5px 6px;color:var(--text3);font-size:.63rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700">Block</th>'
    + '<th style="text-align:right;padding:5px 6px;color:var(--text3);font-size:.63rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700">Rate</th>'
    + '</tr></thead><tbody>'
    + topCountries.map(function(cc) {
        var s = countryStats[cc];
        var flag = flags[cc] || '🌐';
        var rate = s.hits > 0 ? Math.round(s.block / s.hits * 100) : 0;
        return '<tr style="border-top:1px solid var(--border)">'
          + '<td style="padding:6px 6px;display:flex;align-items:center;gap:6px"><span style="font-size:.88rem">' + flag + '</span><span style="color:var(--text2);font-family:\'SF Mono\',monospace">' + escHtml(cc) + '</span></td>'
          + '<td style="padding:6px 6px;text-align:right;color:var(--text);font-weight:600">' + s.hits + '</td>'
          + '<td style="padding:6px 6px;text-align:right;color:var(--green)">' + s.allow + '</td>'
          + '<td style="padding:6px 6px;text-align:right;color:var(--red)">' + s.block + '</td>'
          + '<td style="padding:6px 6px;text-align:right;color:var(--text3)">' + rate + '%</td>'
          + '</tr>';
      }).join('')
    + '</tbody></table>'
  ) : '<p style="font-size:.8rem;color:var(--text3);padding:16px 0;text-align:center">No geo data</p>';

  // ── Block reasons (including new ones) ────────────────────────────────────
  var reasonCounts = {};
  todayLogs.filter(function(l){ return l.decision === 'block'; }).forEach(function(l) {
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
  var blockedIpsList    = Array.isArray(globalSettings.blockedIps) ? globalSettings.blockedIps : [];
  var blockedIpsMeta    = (globalSettings.blockedIpsMeta && typeof globalSettings.blockedIpsMeta === 'object') ? globalSettings.blockedIpsMeta : {};
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

  // ── Risk score (0–100) ────────────────────────────────────────────────────
  function calcScore(l) {
    if (l.decision !== 'block') {
      // Allowed: score 5–20 based on minor signals
      var s = 5;
      if (l.wd) s += 10;
      if (!l.screen || l.screen === '0x0') s += 8;
      if (l.plugins === 0) s += 5;
      return Math.min(s, 25);
    }
    var scoreMap = {
      'repeat-click': 40, 'country-block': 45, 'manual-block': 50,
      'suspicious-isp': 60, 'bot-ua': 68, 'no-screen': 65,
      'no-plugins-desktop': 65, 'headless-screen': 75, 'webdriver': 75,
      'datacenter': 80, 'proxy-vpn': 88
    };
    return scoreMap[l.reason] || 50;
  }
  function scoreBadge(score) {
    var cls = score < 30 ? 'score-low' : score < 65 ? 'score-mid' : 'score-high';
    return '<span class="score-badge ' + cls + '">' + score + '</span>';
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
  var logRows = logs.map(function(l, li) {
    var dec     = l.decision === 'allow' ? 'allow' : 'block';
    var ts      = fmtTs(l.ts);
    var flag    = flagEmoji(l.country);
    var sId     = l.siteId || 'default';
    var detailId = 'lrd-' + li;
    var score   = calcScore(l);
    var rowNum  = li < 9 ? '0' + (li + 1) : String(li + 1);

    // ── Device detection from UA ──────────────────────────────────────────────
    var uaStr = l.ua || '';
    var devType, devIcon;
    if (/iPhone|iPod|(android.*mobile)|BlackBerry|IEMobile|WPDesktop/i.test(uaStr)) {
      devType = 'Mobile';
      devIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
    } else if (/iPad|tablet|Kindle|PlayBook|(android(?!.*mobile))/i.test(uaStr)) {
      devType = 'Tablet';
      devIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
    } else {
      devType = 'Desktop';
      devIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><polyline points="8 21 12 17 16 21"/></svg>';
    }

    // ── Browser detection from UA ─────────────────────────────────────────────
    var browser;
    if (/Googlebot|bingbot|YandexBot|DuckDuckBot|Baiduspider|facebookexternalhit|Twitterbot|crawler|spider|bot/i.test(uaStr)) {
      browser = 'Bot / Crawler';
    } else if (/Edg\//i.test(uaStr)) {
      browser = 'Edge';
    } else if (/OPR\/|Opera/i.test(uaStr)) {
      browser = 'Opera';
    } else if (/Chrome\/[0-9]/i.test(uaStr) && !/Chromium/i.test(uaStr)) {
      browser = 'Chrome';
    } else if (/Safari\/[0-9]/i.test(uaStr) && !/Chrome/i.test(uaStr)) {
      browser = 'Safari';
    } else if (/Firefox\/[0-9]/i.test(uaStr)) {
      browser = 'Firefox';
    } else if (/MSIE|Trident\//i.test(uaStr)) {
      browser = 'Internet Explorer';
    } else {
      browser = 'Unknown';
    }

    // ── OS detection from UA ──────────────────────────────────────────────────
    var os;
    if (/Windows NT 10/i.test(uaStr))       os = 'Windows 10/11';
    else if (/Windows NT 6\.3/i.test(uaStr)) os = 'Windows 8.1';
    else if (/Windows NT 6\.1/i.test(uaStr)) os = 'Windows 7';
    else if (/Windows/i.test(uaStr))         os = 'Windows';
    else if (/iPhone OS 1[0-9]/i.test(uaStr)) os = 'iOS ' + (uaStr.match(/iPhone OS (\d+)/i)||['','?'])[1];
    else if (/iPhone|iPod/i.test(uaStr))     os = 'iOS';
    else if (/iPad/i.test(uaStr))            os = 'iPadOS';
    else if (/Mac OS X/i.test(uaStr))        os = 'macOS';
    else if (/Android (\d+)/i.test(uaStr))   os = 'Android ' + (uaStr.match(/Android (\d+)/i)||['','?'])[1];
    else if (/Linux/i.test(uaStr))           os = 'Linux';
    else os = 'Unknown';

    // ── Score bars ────────────────────────────────────────────────────────────
    var filledBars = Math.round(score / 100 * 10);
    var barHeights = [8,10,12,13,14,13,15,16,18,20];
    var scoreBarsHtml = '';
    for (var b = 0; b < 10; b++) {
      var h = barHeights[b] || 14;
      scoreBarsHtml += '<div class="lsb ' + (b < filledBars ? 'lsb-' + dec : 'lsb-empty') + '" style="height:' + h + 'px"></div>';
    }

    // ── Decision icon ─────────────────────────────────────────────────────────
    var decIconHtml = dec === 'allow'
      ? '<div class="log-dec-icon log-dec-allow"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>'
      : '<div class="log-dec-icon log-dec-block"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></div>';

    // ── Location ──────────────────────────────────────────────────────────────
    var cityStr = l.city ? escHtml(l.city) + (l.region ? ', ' + escHtml(l.region) : '') : escHtml(l.country || 'Unknown');
    var locHtml = '<div class="lc-location">'
      + '<div class="lc-location-top"><span class="lc-flag">' + flag + '</span><span class="lc-city">' + cityStr + '</span></div>'
      + '<span class="lc-cc">' + escHtml(l.country || 'XX') + '</span>'
      + '</div>';

    // ── Device column ─────────────────────────────────────────────────────────
    var screenStr = (!l.screen || l.screen === '0x0') ? '—' : escHtml(l.screen);
    var deviceHtml = '<div class="lc-device">'
      + '<div class="lc-device-type">' + devIcon + ' ' + devType + '</div>'
      + '<span class="lc-screen">' + screenStr + '</span>'
      + '</div>';

    // ── Quick-block ───────────────────────────────────────────────────────────
    var quickBlockBtn = '<button class="quick-block-btn" data-ip="' + escHtml(l.ip || '') + '" data-site="' + escHtml(sId) + '" onclick="event.stopPropagation();quickBlockIp(this)" title="Block this IP">&#9940;</button>';

    // ── Detail panel items ────────────────────────────────────────────────────
    function ldcItem(label, value, extra) {
      return '<div class="ldc-item">'
        + '<div class="ldc-label">' + label + '</div>'
        + '<div class="ldc-value' + (extra ? ' ' + extra : '') + '">' + value + '</div>'
        + '</div>';
    }
    function boolBadge(val) {
      return val ? '<span class="ldc-badge-yes">Yes</span>' : '<span class="ldc-badge-no">No</span>';
    }

    var fullLoc = [l.city, l.region, l.country].filter(Boolean).join(', ') || 'Unknown';
    var pluginCount = l.plugins !== undefined ? String(l.plugins) : '—';
    var wdVal = l.wd !== undefined ? boolBadge(l.wd) : '<span style="color:var(--text3)">—</span>';
    var proxyVal = l.proxy !== undefined ? boolBadge(l.proxy) : '<span style="color:var(--text3)">—</span>';
    var hostVal = l.hosting !== undefined ? boolBadge(l.hosting) : '<span style="color:var(--text3)">—</span>';

    var detailHtml = '<div class="log-detail-card" id="' + detailId + '" style="display:none">'
      + '<div class="ldc-grid">'
      + ldcItem('IP Address',     escHtml(l.ip || '—'))
      + ldcItem('Full Location',  escHtml(fullLoc))
      + ldcItem('ISP',            escHtml(l.isp || '—'))
      + ldcItem('Organization',   escHtml(l.org || '—'))
      + ldcItem('Device',         devType + ' · ' + os)
      + ldcItem('Screen',         screenStr + (screenStr !== '—' ? '' : ' (no screen reported)'))
      + ldcItem('Browser',        browser)
      + ldcItem('Visitor TZ',     escHtml((l.tz || '').slice(0, 40) || '—'))
      + ldcItem('Plugins',        pluginCount + (pluginCount === '0' ? ' (suspicious — bots often report 0)' : ''))
      + ldcItem('WebDriver Flag', wdVal)
      + ldcItem('Proxy / VPN',    proxyVal)
      + ldcItem('Datacenter IP',  hostVal)
      + ldcItem('Risk Score',     String(score) + ' / 100')
      + ldcItem('Reason',         escHtml(l.reason || '—'))
      + ldcItem('Site',           escHtml(sId))
      + ldcItem('User Agent',     escHtml((l.ua || '—').slice(0, 300)), 'ldc-ua')
      + '</div>'
      + '</div>';

    return '<div class="log-card log-card-' + dec + '" data-decision="' + dec + '" data-detail="' + detailId + '">'
      + '<div class="log-card-grad log-grad-' + dec + '"></div>'
      + '<div class="log-card-inner lc-grid" onclick="toggleLogRow(\'' + detailId + '\')" title="Click to expand full details">'
      +   '<div class="lc-num">' + rowNum + '</div>'
      +   '<div class="lc-dec">' + decIconHtml + '<span class="dec-' + dec + '">' + (dec === 'allow' ? 'Allow' : 'Block') + '</span></div>'
      +   '<div class="lc-ip">' + escHtml(l.ip || '—') + '</div>'
      +   locHtml
      +   deviceHtml
      +   '<div class="lc-score-wrap"><div class="lc-score-bars">' + scoreBarsHtml + '</div><span class="lc-score-val">' + score + '</span></div>'
      +   '<div class="lc-isp" title="' + escHtml(l.isp || '') + '">' + escHtml((l.isp || '—').slice(0, 30)) + '</div>'
      +   '<div class="lc-ts">' + escHtml(ts) + '</div>'
      +   '<div class="lc-reason">' + reasonPill(l.reason) + '</div>'
      +   '<div class="lc-actions">' + quickBlockBtn + '</div>'
      + '</div>'
      + detailHtml
      + '</div>';
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
    var safeTs  = escHtml(l.ts || '');
    var calledToggle = l.called
      ? '<button class="lead-toggle-btn called" data-ts="' + safeTs + '" data-site="' + escHtml(l.siteId || '') + '" data-ip="' + escHtml(l.ip || '') + '" onclick="toggleLeadCalled(this)" title="Mark as not called">✓ Called</button>'
      : '<button class="lead-toggle-btn" data-ts="' + safeTs + '" data-site="' + escHtml(l.siteId || '') + '" data-ip="' + escHtml(l.ip || '') + '" onclick="toggleLeadCalled(this)" title="Mark as called">○ Pending</button>';
    return '<tr>'
      + '<td class="t-mono t-ts">' + escHtml(ts) + '</td>'
      + '<td class="t-mono">' + escHtml(l.ip || '') + '</td>'
      + '<td><span class="t-flag">' + flag + '</span> ' + escHtml(l.country || 'XX') + '</td>'
      + '<td>' + escHtml(l.city || '') + '</td>'
      + '<td class="t-mono" style="color:#3b82f6;font-weight:700">' + escHtml(l.code || '') + '</td>'
      + '<td>' + adSource(l) + '</td>'
      + '<td class="t-mono">' + escHtml((l.tz || '').slice(0, 30)) + '</td>'
      + '<td>' + calledToggle + '</td>'
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
      return '/' + ADMIN_PATH + '?' + params;
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
    var snip = '<script>\n'
      + '(function(){var _h=\'' + hubUrl + '\',_k=\'' + s.apiKey + '\';\n'
      + 'try{fetch(_h+\'/api/v1/pixel\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\',\'X-Client-ID\':_k},\n'
      + 'body:JSON.stringify({ua:navigator.userAgent,sw:screen.width,sh:screen.height,\n'
      + 'wd:!!navigator.webdriver,pl:(navigator.plugins||[]).length,\n'
      + 'tz:Intl.DateTimeFormat().resolvedOptions().timeZone})}).then(function(r){return r.json()})\n'
      + '.then(function(d){if(d&&d.url)window.location.replace(d.url)}).catch(function(){})}catch(e){}\n'
      + '})();\n'
      + '<\/script>';
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
    var pct  = todayBlock > 0 ? Math.round(cnt / todayBlock * 100) : 0;
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
      +   '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/toggle" class="inline">'
      +     '<label class="ts-wrap"><input type="checkbox" class="ts-input" ' + (isEnabled ? 'checked' : '') + ' onchange="this.closest(\'form\').submit()"><span class="ts-track"></span>'
      +     '<span class="ts-label" style="font-size:0.75rem">' + (isEnabled ? 'Active' : 'Paused') + '</span></label>'
      +   '</form>'
      +   '<div class="sl-actions">'
      +     '<button class="sl-settings" onclick="toggleSlRow(this,\'slx-' + sid + '\')">\u2699 Settings</button>'
      +     (hasGithubToken && s.githubRepo
          ? '<button class="btn-ghost btn-sm reinject-btn" onclick="reInjectSite(\'' + sid + '\',this)" title="Re-push cloaking script to GitHub repo">\u2B06 Re-inject</button>'
          : '')
      +     (s.isDefault ? '' :
      +       '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/regenerate-key" class="inline" onsubmit="return confirm(\'Rotate API key? Old key stops immediately.\')">'
      +         '<button type="submit" class="btn-ghost btn-sm">\u21BB Rotate</button>'
      +       '</form>'
      +       '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/delete" class="inline" onsubmit="return confirm(\'Delete ' + escHtml(s.name) + '? Cannot be undone.\')">'
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
      +     '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/settings">'
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
      +     '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/settings">'
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
      +     '<form method="POST" action="/' + ADMIN_PATH + '/sites/' + sid + '/settings">'
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
:root{--bg:#f9fafb;--bg2:#ffffff;--bg3:#f3f4f6;--card:#ffffff;--border:#e5e7eb;--border2:#d1d5db;--pri:#3b82f6;--pri-h:#2563eb;--pri-l:#60a5fa;--text:#111827;--text2:#4b5563;--text3:#9ca3af;--green:#16a34a;--red:#dc2626;--amber:#d97706;--blue:#2563eb;--sidebar:256px;--topbar:60px;--shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.06)}
body.dark{--bg:#030712;--bg2:#111827;--bg3:#1f2937;--card:#111827;--border:#1f2937;--border2:#374151;--pri:#3b82f6;--pri-h:#2563eb;--pri-l:#93c5fd;--text:#f9fafb;--text2:#d1d5db;--text3:#6b7280;--green:#4ade80;--red:#f87171;--amber:#fbbf24;--blue:#60a5fa;--shadow:0 1px 3px rgba(0,0,0,.4),0 1px 2px rgba(0,0,0,.3)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;overflow:hidden;height:100vh}
/* Layout */
.f-app{display:flex;height:100vh;overflow:hidden}
.f-sidebar{width:var(--sidebar);min-width:var(--sidebar);background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;height:100vh;overflow-y:auto;z-index:200;transition:width .22s,min-width .22s,transform .3s;flex-shrink:0}
.f-sidebar.collapsed{width:64px;min-width:64px}
.f-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;overflow:hidden}
.f-topbar{height:var(--topbar);background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;padding:0 20px;flex-shrink:0}
.f-content{flex:1;overflow-y:auto;padding:24px;background:var(--bg)}
/* Sidebar brand */
.sb-brand{padding:14px 12px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);overflow:hidden;flex-shrink:0;cursor:pointer;transition:background .15s;border-radius:6px 6px 0 0}
.sb-brand:hover{background:var(--bg3)}
.sb-logo-box{width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#2563eb);display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 1px 4px rgba(59,130,246,.35)}
.sb-logo-box svg{width:20px;height:20px}
.sb-brand-text{overflow:hidden;flex:1;min-width:0}
.sb-name{font-size:0.88rem;font-weight:700;color:var(--text);letter-spacing:-0.3px;white-space:nowrap}
.sb-tagline{font-size:0.7rem;color:var(--text3);margin-top:1px;white-space:nowrap}
.f-sidebar.collapsed .sb-brand-text,.f-sidebar.collapsed .sb-brand-chevron{display:none}
.f-sidebar.collapsed .sb-brand{justify-content:center;padding:12px 8px}
/* Nav */
.sb-nav{flex:1;padding:8px 6px;display:flex;flex-direction:column;gap:2px;overflow:hidden}
.sb-link{display:flex;align-items:center;gap:0;padding:0;border-radius:6px;font-size:0.82rem;color:var(--text2);text-decoration:none;cursor:pointer;border:none;background:none;width:100%;transition:background .15s,color .15s;text-align:left;white-space:nowrap;overflow:hidden;position:relative;height:44px;border-left:2px solid transparent}
.sb-link:hover{background:var(--bg3);color:var(--text)}
.sb-link.active{background:rgba(59,130,246,.1);color:var(--pri-h);font-weight:600;border-left-color:var(--pri)}
body.dark .sb-link.active{background:rgba(59,130,246,.18);color:var(--pri-l)}
.sb-icon{display:flex;align-items:center;justify-content:center;width:48px;height:44px;flex-shrink:0}
.sb-icon svg{width:16px;height:16px}
.sb-link-lbl{overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0;padding-right:8px}
.sb-cnt{background:var(--pri);color:#fff;font-size:0.6rem;font-weight:700;padding:1px 7px;border-radius:10px;flex-shrink:0;margin-right:10px}
.f-sidebar.collapsed .sb-link-lbl,.f-sidebar.collapsed .sb-cnt{display:none}
.f-sidebar.collapsed .sb-link{justify-content:center;border-left-color:transparent!important;border-radius:6px}
.f-sidebar.collapsed .sb-link.active{background:rgba(59,130,246,.12);color:var(--pri)}
.f-sidebar.collapsed .sb-icon{width:100%}
.f-sidebar.collapsed .sb-link:hover::after{content:attr(title);position:absolute;left:calc(100% + 8px);top:50%;transform:translateY(-50%);background:var(--bg2);border:1px solid var(--border2);color:var(--text);font-size:.72rem;padding:5px 10px;border-radius:7px;white-space:nowrap;z-index:1000;pointer-events:none;box-shadow:var(--shadow)}
/* Account section divider */
.sb-section-lbl{font-size:0.67rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;padding:8px 14px 4px;white-space:nowrap;overflow:hidden}
.f-sidebar.collapsed .sb-section-lbl{display:none}
.sb-divider{height:1px;background:var(--border);margin:8px 6px}
/* Site selector */
.sb-site-wrap{padding:6px 6px 4px;overflow:hidden}
.sb-site-lbl{font-size:0.62rem;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;display:block;font-weight:600;white-space:nowrap;padding:0 4px}
.sb-site-sel{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:7px;color:var(--text);font-size:0.77rem;padding:6px 9px;outline:none;cursor:pointer}
.sb-site-sel:focus{border-color:var(--pri)}
.f-sidebar.collapsed .sb-site-wrap{display:none}
/* Bottom controls */
.sb-bottom{padding:4px 6px 0;border-top:1px solid var(--border);flex-shrink:0}
.sb-ctrl{display:flex;align-items:center;gap:0;padding:0;border-radius:6px;font-size:0.82rem;color:var(--text2);cursor:pointer;border:none;background:none;width:100%;transition:background .15s,color .15s;text-align:left;overflow:hidden;white-space:nowrap;height:44px;border-left:2px solid transparent}
.sb-ctrl:hover{background:var(--bg3);color:var(--text)}
.sb-ctrl svg{width:16px;height:16px;flex-shrink:0}
.sb-ctrl .sb-icon{width:48px;height:44px;flex-shrink:0}
.sb-ctrl-lbl{overflow:hidden;text-overflow:ellipsis;flex:1}
.f-sidebar.collapsed .sb-ctrl{justify-content:center;border-radius:6px}
.f-sidebar.collapsed .sb-ctrl .sb-icon{width:100%}
.f-sidebar.collapsed .sb-ctrl-lbl{display:none}
.sb-ctrl.logout:hover{background:rgba(220,38,38,.08);color:var(--red)}
/* Collapse toggle at very bottom */
.sb-collapse-btn{display:flex;align-items:center;width:100%;border:none;background:none;border-top:1px solid var(--border);cursor:pointer;padding:0;transition:background .15s;color:var(--text2);margin-top:4px}
.sb-collapse-btn:hover{background:var(--bg3)}
.sb-collapse-inner{display:flex;align-items:center;padding:10px 6px;width:100%}
.sb-collapse-icon{width:40px;height:24px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sb-collapse-icon svg{width:16px;height:16px;transition:transform .3s;color:var(--text3)}
.f-sidebar:not(.collapsed) .sb-collapse-icon svg{transform:rotate(180deg)}
.sb-collapse-lbl{font-size:0.82rem;font-weight:500;color:var(--text2)}
.f-sidebar.collapsed .sb-collapse-lbl{display:none}
.f-sidebar.collapsed .sb-collapse-inner{justify-content:center}
.f-sidebar.collapsed .sb-collapse-icon{width:100%}
/* Topbar */
.f-hamburger{display:none;background:none;border:none;color:var(--text2);cursor:pointer;padding:5px;border-radius:6px;font-size:1.1rem;align-items:center;justify-content:center}
.f-topbar-left{flex:1;min-width:0}
.f-topbar-title{font-size:1rem;font-weight:700;color:var(--text);line-height:1.2}
.f-breadcrumb{font-size:0.78rem;color:var(--text3);margin-top:1px}
.f-topbar-right{display:flex;align-items:center;gap:6px}
.f-clock{font-size:0.72rem;color:var(--text3);font-family:'SF Mono',Menlo,monospace;background:var(--bg3);padding:4px 9px;border-radius:6px;white-space:nowrap;border:1px solid var(--border)}
.f-tz-badge{font-size:0.67rem;color:var(--pri);background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.18);border-radius:6px;padding:3px 7px;cursor:pointer;white-space:nowrap;font-weight:600}
.f-tz-badge:hover{background:rgba(59,130,246,.15)}
.tb-icon-btn{display:flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:8px;border:1px solid var(--border);background:var(--bg2);color:var(--text2);cursor:pointer;transition:all .15s;position:relative;flex-shrink:0}
.tb-icon-btn:hover{background:var(--bg3);color:var(--text)}
.tb-icon-btn svg{width:18px;height:18px}
.tb-notif-dot{position:absolute;top:-3px;right:-3px;width:10px;height:10px;background:var(--red);border-radius:50%;border:2px solid var(--bg2)}
/* Sections */
.f-section{display:none}.f-section.active{display:block}
/* Notifications */
.notif-wrap{position:relative}
.notif-btn{background:none;border:none;cursor:pointer;padding:6px;border-radius:7px;color:var(--text2);display:flex;align-items:center;justify-content:center;transition:background .15s;position:relative}
.notif-btn:hover{background:var(--bg3);color:var(--text)}
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
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;transition:box-shadow .2s,border-color .2s;box-shadow:var(--shadow)}
.kpi:hover{box-shadow:0 4px 12px rgba(0,0,0,.1);border-color:var(--border2)}
body.dark .kpi:hover{box-shadow:0 4px 12px rgba(0,0,0,.4)}
.kpi-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.kpi-icon-box{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.kpi-icon-box svg{width:18px;height:18px}
.kpi-trend{width:16px;height:16px;color:var(--green);flex-shrink:0}
.kpi-label{font-size:0.76rem;font-weight:500;color:var(--text2);margin-bottom:4px}
.kpi-val{font-size:1.7rem;font-weight:800;color:var(--text);line-height:1;font-variant-numeric:tabular-nums}
.kpi-sub{font-size:0.72rem;color:var(--text3);margin-top:6px}
/* KPI icon box colour variants */
.kpi-ib-blue{background:rgba(59,130,246,.1)}.kpi-ib-blue svg{color:var(--pri)}
.kpi-ib-green{background:rgba(22,163,74,.1)}.kpi-ib-green svg{color:var(--green)}
.kpi-ib-purple{background:rgba(147,51,234,.1)}.kpi-ib-purple svg{color:#7c3aed}
.kpi-ib-orange{background:rgba(234,88,12,.1)}.kpi-ib-orange svg{color:#ea580c}
body.dark .kpi-ib-blue{background:rgba(59,130,246,.15)}.kpi-ib-blue svg{color:var(--pri-l)}
body.dark .kpi-ib-green{background:rgba(74,222,128,.12)}.kpi-ib-green svg{color:var(--green)}
body.dark .kpi-ib-purple{background:rgba(167,139,250,.12)}.kpi-ib-purple svg{color:#a78bfa}
body.dark .kpi-ib-orange{background:rgba(251,146,60,.12)}.kpi-ib-orange svg{color:#fb923c}
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
.lt-row:hover{background:var(--bg3)}
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
tbody tr:hover{background:var(--bg3)}
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
/* ── Click Log card-list (server-management-table theme) ──────────────── */
.lc-wrap{border-radius:14px;border:1px solid var(--border);background:var(--card);overflow:hidden}
/* grid: No | Dec | IP | Location | Device | Score | ISP | Time | Reason | Act */
.lc-grid{display:grid;grid-template-columns:36px 128px 100px 150px 108px 128px minmax(55px,1fr) 110px 118px 36px;gap:10px;align-items:center}
.lc-headers{padding:9px 16px 7px;font-size:.6rem;text-transform:uppercase;letter-spacing:.65px;font-weight:700;color:var(--text3)}
.log-card-list{display:flex;flex-direction:column;gap:7px;padding:10px 10px 12px}
.log-card{position:relative;border-radius:11px;border:1px solid var(--border);background:var(--bg3);overflow:hidden;transition:transform .15s ease,box-shadow .15s ease}
.log-card:hover{transform:translateY(-1px);box-shadow:0 4px 14px rgba(0,0,0,.07)}
body.dark .log-card:hover{box-shadow:0 4px 14px rgba(0,0,0,.28)}
.log-card-grad{position:absolute;inset:0;pointer-events:none;background-size:30% 100%;background-position:right;background-repeat:no-repeat}
.log-grad-allow{background-image:linear-gradient(to left,rgba(34,197,94,.09),transparent)}
.log-grad-block{background-image:linear-gradient(to left,rgba(239,68,68,.09),transparent)}
.log-card-inner{position:relative;padding:12px 16px;cursor:pointer}
.lc-num{font-size:1.05rem;font-weight:800;color:var(--text3);font-family:'SF Mono',Menlo,monospace;line-height:1}
.lc-dec{display:flex;align-items:center;gap:7px;white-space:nowrap}
.log-dec-icon{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.log-dec-allow{background:linear-gradient(135deg,#22c55e,#16a34a)}
.log-dec-block{background:linear-gradient(135deg,#ef4444,#dc2626)}
.lc-ip{font-family:'SF Mono',Menlo,monospace;font-size:.71rem;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lc-location{display:flex;flex-direction:column;gap:1px;min-width:0}
.lc-location-top{display:flex;align-items:center;gap:4px}
.lc-flag{font-size:.95rem;line-height:1;flex-shrink:0}
.lc-city{font-size:.73rem;color:var(--text);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lc-cc{font-size:.66rem;color:var(--text3)}
.lc-device{display:flex;flex-direction:column;gap:2px;min-width:0}
.lc-device-type{display:flex;align-items:center;gap:4px;font-size:.72rem;color:var(--text2);font-weight:500}
.lc-device-type svg{flex-shrink:0;opacity:.7}
.lc-screen{font-size:.66rem;font-family:'SF Mono',Menlo,monospace;color:var(--text3)}
.lc-score-wrap{display:flex;align-items:center;gap:5px}
.lc-score-bars{display:flex;gap:3px;align-items:flex-end}
.lsb{width:5px;border-radius:2px;transition:background .3s}
.lsb-allow{background:rgba(59,130,246,.65)}
.lsb-block{background:rgba(239,68,68,.65)}
.lsb-empty{background:var(--border2)}
.lc-score-val{font-size:.69rem;font-family:'SF Mono',Menlo,monospace;color:var(--text2);min-width:20px}
.lc-isp{font-size:.71rem;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lc-ts{font-size:.66rem;font-family:'SF Mono',Menlo,monospace;color:var(--text3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lc-reason{overflow:hidden;min-width:0}.lc-reason .rpill{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.lc-actions{display:flex;justify-content:center}
/* Updated decision badge sizing to match reference */
.dec-allow{display:inline-flex;align-items:center;padding:3px 9px;border-radius:7px;background:rgba(34,197,94,.1);color:var(--green);font-weight:600;font-size:.66rem;text-transform:uppercase;border:1px solid rgba(34,197,94,.25);white-space:nowrap}
.dec-block{display:inline-flex;align-items:center;padding:3px 9px;border-radius:7px;background:rgba(239,68,68,.1);color:var(--red);font-weight:600;font-size:.66rem;text-transform:uppercase;border:1px solid rgba(239,68,68,.25);white-space:nowrap}
/* Log detail panel (inside card) — rich 2-column grid */
.log-detail-card{background:var(--bg2);border-top:1px solid var(--border);padding:12px 16px}
.ldc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px 24px}
.ldc-item{display:flex;flex-direction:column;gap:2px}
.ldc-label{font-size:.59rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700;color:var(--text3)}
.ldc-value{font-size:.72rem;color:var(--text2);font-family:'SF Mono',Menlo,monospace;word-break:break-all;line-height:1.4}
.ldc-value.ldc-ua{font-family:inherit;font-size:.71rem}
.ldc-badge-yes{display:inline-flex;align-items:center;padding:1px 7px;border-radius:5px;background:rgba(239,68,68,.1);color:var(--red);font-size:.65rem;font-weight:700;border:1px solid rgba(239,68,68,.2)}
.ldc-badge-no{display:inline-flex;align-items:center;padding:1px 7px;border-radius:5px;background:rgba(34,197,94,.1);color:var(--green);font-size:.65rem;font-weight:700;border:1px solid rgba(34,197,94,.2)}
.ldd-lbl{color:var(--text3);font-weight:700;text-transform:uppercase;font-size:.62rem;letter-spacing:.5px}
.ldd-val{color:var(--text2);font-family:'SF Mono',Menlo,monospace;font-size:.67rem}
/* Lead called toggle */
.lead-toggle-btn{background:rgba(255,255,255,.04);border:1px solid var(--border2);border-radius:20px;padding:2px 10px;font-size:.65rem;font-weight:600;cursor:pointer;color:var(--text3);transition:all .15s;white-space:nowrap}
.lead-toggle-btn:hover{border-color:var(--green);color:var(--green)}
.lead-toggle-btn.called{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3);color:var(--green)}
.lead-toggle-btn.called:hover{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.3);color:var(--red)}
/* Hotkeys panel */
.hk-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 20px}
.hk-row{display:flex;align-items:center;gap:8px;font-size:.77rem;color:var(--text2)}
.hk-key{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:22px;padding:0 7px;background:var(--bg3);border:1px solid var(--border2);border-bottom:2px solid var(--border2);border-radius:5px;font-family:'SF Mono',Menlo,monospace;font-size:.72rem;color:var(--pri);font-weight:700}
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
.sl-settings:hover,.sl-settings.open{border-color:var(--pri);color:var(--pri);background:rgba(59,130,246,.08)}
.sl-expand{display:none;margin-top:10px;border-top:1px solid var(--border);padding-top:14px}
.sl-expand.open{display:block}
.sl-tabs{display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap}
.sl-tab{background:none;border:1px solid var(--border);border-radius:7px;padding:4px 11px;color:var(--text2);font-size:.73rem;cursor:pointer;transition:all .15s}
.sl-tab.active,.sl-tab:hover{border-color:var(--pri);color:var(--pri);background:rgba(59,130,246,.08)}
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
.stab.active{color:var(--pri);border-bottom-color:var(--pri)}
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
/* Score badge */
.score-badge{display:inline-block;min-width:36px;text-align:center;padding:2px 7px;border-radius:6px;font-size:.7rem;font-weight:700;font-variant-numeric:tabular-nums}
.score-low{background:rgba(63,185,80,.12);color:var(--green)}
.score-mid{background:rgba(210,153,34,.12);color:var(--amber)}
.score-high{background:rgba(248,81,73,.12);color:var(--red)}
/* Time range filter */
.tr-filter{display:flex;gap:3px;flex-wrap:wrap}
.tr-btn{background:none;border:1px solid var(--border2);border-radius:6px;padding:3px 10px;font-size:.72rem;color:var(--text2);cursor:pointer;transition:all .15s;font-family:inherit}
.tr-btn:hover{border-color:var(--pri);color:var(--pri)}
.tr-btn.active{background:var(--pri);border-color:var(--pri);color:#fff}
/* Live indicator */
.live-pill{display:inline-flex;align-items:center;gap:5px;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.2);border-radius:20px;padding:3px 9px;font-size:.68rem;font-weight:700;color:var(--green)}
.live-pill-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.4s infinite;flex-shrink:0}
/* Click Log header bar */
.cl-header-bar{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.cl-hitcnt{font-size:.78rem;color:var(--text3)}
/* Country table */
.cc-row{display:flex;align-items:center;gap:8px;padding:5px 0}
.cc-flag{font-size:.9rem;width:20px}
.cc-code{font-size:.72rem;font-family:'SF Mono',Menlo,monospace;color:var(--text2);width:24px}
.cc-bar-wrap{flex:1;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
.cc-bar{height:100%;background:var(--pri);border-radius:3px}
.cc-cnt{font-size:.69rem;color:var(--text3);width:28px;text-align:right}
/* Overlay + mobile */
.f-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:150}
@media(max-width:960px){.kpi-grid{grid-template-columns:repeat(2,1fr)}.dash-mid{grid-template-columns:1fr}.dash-bot{grid-template-columns:1fr}}
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
<script>
(function(){var t=localStorage.getItem('filterTheme');if(t==='dark')document.body.classList.add('dark');})();
</script>
<div class="f-app" id="fApp">

  <!-- ═══ SIDEBAR ═══ -->
  <aside class="f-sidebar" id="fSidebar">

    <!-- Brand -->
    <div class="sb-brand">
      <div class="sb-logo-box">
        <svg viewBox="0 0 50 39" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M16.4992 2H37.5808L22.0816 24.9729H1L16.4992 2Z" fill="white"/>
          <path d="M17.4224 27.102L11.4192 36H33.5008L49 13.0271H32.7024L23.2064 27.102H17.4224Z" fill="white"/>
        </svg>
      </div>
      <div class="sb-brand-text">
        <div class="sb-name">FILTER</div>
        <div class="sb-tagline">Traffic Management</div>
      </div>
      <svg class="sb-brand-chevron" style="width:14px;height:14px;color:var(--text3);flex-shrink:0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
    </div>

    <!-- Nav -->
    <nav class="sb-nav">
      <button class="sb-link active" data-section="dashboard" title="Dashboard" onclick="navTo('dashboard',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg></span>
        <span class="sb-link-lbl">Dashboard</span>
      </button>
      <button class="sb-link" data-section="sites" title="Sites" onclick="navTo('sites',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg></span>
        <span class="sb-link-lbl">Sites</span>
        <span class="sb-cnt">${sites.length}</span>
      </button>
      <button class="sb-link" data-section="logs" title="Click Log" onclick="navTo('logs',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg></span>
        <span class="sb-link-lbl">Click Log</span>
        <span class="sb-cnt">${logTotal}</span>
      </button>
      <button class="sb-link" data-section="leads" title="Leads" onclick="navTo('leads',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
        <span class="sb-link-lbl">Leads</span>
        <span class="sb-cnt">${leadTotal}</span>
      </button>
      <button class="sb-link" data-section="blocked-ips" title="Blocked IPs" onclick="navTo('blocked-ips',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
        <span class="sb-link-lbl">Blocked IPs</span>
        <span class="sb-cnt">${blockedIpsList.length}</span>
      </button>

      <!-- Account section -->
      <div class="sb-divider"></div>
      <div class="sb-section-lbl">Account</div>
      <button class="sb-link" data-section="settings" title="Settings" onclick="navTo('settings',this)">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></span>
        <span class="sb-link-lbl">Settings</span>
      </button>
      <a class="sb-link" href="/${ADMIN_PATH}?stab=security#settings" title="Features">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg></span>
        <span class="sb-link-lbl">Features</span>
      </a>
    </nav>

    <!-- Site selector -->
    <div class="sb-site-wrap">
      <span class="sb-site-lbl">Viewing Site</span>
      <select class="sb-site-sel" onchange="changeSite(this.value)">
        <option value="" ${!siteFilter ? 'selected' : ''}>All Sites</option>
        ${siteOptHtml}
      </select>
    </div>

    <!-- Bottom controls -->
    <div class="sb-bottom">
      <a class="sb-ctrl logout" href="/${ADMIN_PATH}/logout" title="Log out">
        <span class="sb-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg></span>
        <span class="sb-ctrl-lbl">Log out</span>
      </a>
    </div>

    <!-- ChevronsRight collapse toggle -->
    <button class="sb-collapse-btn" id="collapseBtn" title="Toggle sidebar" onclick="toggleCollapse()">
      <div class="sb-collapse-inner">
        <div class="sb-collapse-icon">
          <svg id="collapseIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/></svg>
        </div>
        <span class="sb-collapse-lbl">Hide</span>
      </div>
    </button>
  </aside>

  <!-- Mobile overlay -->
  <div class="f-overlay" id="fOverlay" onclick="closeSidebar()"></div>

  <!-- ═══ MAIN ═══ -->
  <main class="f-main">

    <!-- Topbar -->
    <div class="f-topbar">
      <button class="f-hamburger" onclick="toggleSidebar()">☰</button>
      <div class="f-topbar-left">
        <div class="f-topbar-title" id="fBreadcrumb">Dashboard</div>
        <div class="f-breadcrumb">Traffic management &amp; monitoring</div>
      </div>
      <div class="f-topbar-right">
        <span class="f-clock" id="fClock">--:--:--</span>
        <span class="f-tz-badge" onclick="navTo('settings',document.querySelector('[data-section=settings]'));setTimeout(function(){switchTab(document.querySelector('.stab[data-tab=tz]'),'stab-tz')},100)" title="Change display timezone">${escHtml(displayTz)}</span>

        <!-- Notification bell -->
        <div class="notif-wrap">
          <button class="tb-icon-btn notif-btn" onclick="toggleNotif()" title="Notifications" style="border:1px solid var(--border)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
            <span class="notif-badge" id="notifBadge">0</span>
          </button>
          <div class="notif-dropdown" id="notifDropdown">
            <div class="notif-hdr"><span>Live Alerts</span><button class="notif-clear" onclick="clearNotifs()">Clear all</button></div>
            <div class="notif-list" id="notifList"><div class="notif-empty">No alerts yet</div></div>
          </div>
        </div>

        <!-- Theme toggle -->
        <button class="tb-icon-btn" id="themeToggleBtn" onclick="toggleTheme()" title="Toggle theme">
          <svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        </button>

        <!-- User avatar -->
        <button class="tb-icon-btn" title="Logged in as admin">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </button>
      </div>
    </div>

    <!-- Content -->
    <div class="f-content">

      <!-- ── DASHBOARD ─────────────────────────────────── -->
      <div class="f-section active" id="sec-dashboard">
        <div class="sec-header mb16">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <div>
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
                <div class="sec-title">Command Center</div>
                <span class="live-pill"><span class="live-pill-dot"></span>Live</span>
              </div>
              <div class="sec-sub">Traffic health &amp; detection overview &nbsp;·&nbsp; ${siteFilter ? escHtml(selectedSite ? selectedSite.name : siteFilter) : 'All sites'}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <div class="tr-filter" id="trFilter">
              <button class="tr-btn${range === '24h' ? ' active' : ''}" data-range="24h" onclick="setTimeRange(this)">24h</button>
              <button class="tr-btn${range === '7d' ? ' active' : ''}" data-range="7d" onclick="setTimeRange(this)">7d</button>
              <button class="tr-btn${range === '30d' ? ' active' : ''}" data-range="30d" onclick="setTimeRange(this)">30d</button>
              <button class="tr-btn${range === '90d' ? ' active' : ''}" data-range="90d" onclick="setTimeRange(this)">90d</button>
              <button class="tr-btn${range === 'custom' ? ' active' : ''}" onclick="toggleCustomRange()">Custom ▾</button>
            </div>
            <div id="customRangeBox" style="display:${range === 'custom' ? 'flex' : 'none'};align-items:center;gap:6px;margin-top:6px;flex-wrap:wrap">
              <input type="date" id="crFrom" class="filter-input" style="padding:4px 8px;font-size:.75rem" value="${escHtml(rangeFrom)}">
              <span style="color:var(--text3);font-size:.8rem">to</span>
              <input type="date" id="crTo" class="filter-input" style="padding:4px 8px;font-size:.75rem" value="${escHtml(rangeTo)}">
              <button class="btn-ghost btn-sm" onclick="applyCustomRange()">Apply</button>
            </div>
            ${siteCreated ? '<div class="rpill rpill-green">✓ Site created</div>' : ''}
          </div>
        </div>

        <!-- KPI row — 4 cards -->
        <div class="kpi-grid">
          <div class="kpi">
            <div class="kpi-header">
              <div class="kpi-icon-box kpi-ib-blue">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              </div>
              <svg class="kpi-trend" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
            </div>
            <div class="kpi-label">Total Hits</div>
            <div class="kpi-val" id="kpiTotal">${todayTotal}</div>
            <div class="kpi-sub">all traffic in range</div>
          </div>
          <div class="kpi">
            <div class="kpi-header">
              <div class="kpi-icon-box kpi-ib-orange">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              </div>
              <svg class="kpi-trend" style="color:var(--red)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/></svg>
            </div>
            <div class="kpi-label">Block Rate</div>
            <div class="kpi-val" id="kpiBlock">${blockRateToday + '%'}</div>
            <div class="kpi-sub" id="kpiBlockPct">${todayBlock} blocked</div>
          </div>
          <div class="kpi">
            <div class="kpi-header">
              <div class="kpi-icon-box kpi-ib-purple">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
              </div>
              <svg class="kpi-trend" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
            </div>
            <div class="kpi-label">Avg Risk Score</div>
            <div class="kpi-val" id="kpiAllow">${todayTotal === 0 ? '—' : Math.round(todayBlock / todayTotal * 100)}</div>
            <div class="kpi-sub" id="kpiAllowPct">${todayAllow} allowed</div>
          </div>
          <div class="kpi">
            <div class="kpi-header">
              <div class="kpi-icon-box kpi-ib-green">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
              </div>
              <svg class="kpi-trend" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
            </div>
            <div class="kpi-label">Active Sites</div>
            <div class="kpi-val" id="kpiSites">${sites.filter(function(s){return s.enabled !== false;}).length}</div>
            <div class="kpi-sub">of ${sites.length} total</div>
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
                <div class="donut-pct" style="color:var(--red)" id="donutPct">${blockRateToday}%</div>
                <div class="donut-lbl">blocked</div>
              </div>
            </div>
            <div class="chart-legend">
              <div class="leg-item"><span class="leg-dot" style="background:var(--green)"></span>Allow (${todayAllow})</div>
              <div class="leg-item"><span class="leg-dot" style="background:var(--red)"></span>Block (${todayBlock})</div>
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
              &nbsp;<a href="/${ADMIN_PATH}/blocked-ips-export" style="color:var(--pri-l)">Export →</a>
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
            <form method="POST" action="/${ADMIN_PATH}/toggle">
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
        <div class="sec-header mb12">
          <div>
            <div class="sec-title">Click Log</div>
            <div class="sec-sub">Real-time and historical traffic across all campaigns</div>
          </div>
          <a href="/${ADMIN_PATH}/blocked-ips-export" class="btn-ghost btn-sm">⬇ Export Blocked IPs</a>
        </div>

        <div class="cl-header-bar">
          <span class="live-pill"><span class="live-pill-dot"></span>Live</span>
          <span class="cl-hitcnt">${logTotal} hits</span>
          <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
            <input type="text" class="filter-input" id="logSearch" placeholder="Filter IP or country…" oninput="filterLogs()" style="min-width:150px">
            <select class="filter-select" id="logDecFilter" onchange="filterLogs()">
              <option value="">All decisions</option>
              <option value="allow">Allow only</option>
              <option value="block">Block only</option>
            </select>
          </div>
        </div>

        <div class="lc-wrap">
          <div class="lc-headers lc-grid">
            <div>No</div>
            <div>Decision</div>
            <div>IP Address</div>
            <div>Location</div>
            <div>Device · Screen</div>
            <div>Risk Score</div>
            <div>ISP</div>
            <div>Time</div>
            <div>Reason</div>
            <div></div>
          </div>
          <div class="log-card-list" id="logsBody">
            ${logRows || '<div class="empty-state" style="padding:40px 0;text-align:center">No hits found</div>'}
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

      <!-- ── BLOCKED IPs ───────────────────────────────── -->
      <div class="f-section" id="sec-blocked-ips">
        <div class="sec-header">
          <div>
            <div class="sec-title">Blocked IPs</div>
            <div class="sec-sub">${blockedIpsList.length} IPs manually blocked &nbsp;·&nbsp; <a href="/${ADMIN_PATH}/blocked-ips-export" style="color:var(--pri-l)">Export for Google Ads →</a></div>
          </div>
          <div class="flex-gap8">
            <input type="text" id="manualBlockIpInput" placeholder="Enter IP to block…" style="background:var(--bg2);border:1px solid var(--border2);border-radius:7px;color:var(--text);font-size:.82rem;padding:7px 12px;outline:none;width:190px" onkeydown="if(event.key==='Enter')manualBlockIpBtn()">
            <button class="btn-pri" onclick="manualBlockIpBtn()">+ Block IP</button>
          </div>
        </div>

        <div class="f-card" style="padding:0">
          <div class="f-table-wrap">
            <table id="blockedIpsTable">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Date Blocked (${escHtml(displayTz)})</th>
                  <th>Reason</th>
                  <th></th>
                </tr>
              </thead>
              <tbody id="blockedIpsBody">
                ${blockedIpsList.length === 0
                  ? '<tr><td colspan="4" class="empty-state">No manually blocked IPs. Blocked IPs from fingerprint checks appear in Traffic Logs.</td></tr>'
                  : blockedIpsList.map(function(ip) {
                      var meta = blockedIpsMeta[ip] || {};
                      var dateStr = meta.at ? new Date(meta.at).toLocaleString('en-US', {timeZone: displayTz, month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit'}) : '—';
                      var reason  = meta.reason || 'manual';
                      return '<tr id="bip-' + escHtml(ip.replace(/\./g,'_').replace(/:/g,'_')) + '">'
                        + '<td class="t-mono t-ip">' + escHtml(ip) + '</td>'
                        + '<td style="font-size:.78rem;color:var(--text2)">' + escHtml(dateStr) + '</td>'
                        + '<td><span class="pill pill-grey">' + escHtml(reason) + '</span></td>'
                        + '<td style="text-align:right"><button class="btn-danger btn-sm unblock-ip-btn" data-ip="' + escHtml(ip) + '" data-site="default">Unblock</button></td>'
                        + '</tr>';
                    }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ── SETTINGS ──────────────────────────────────── -->
      <div class="f-section" id="sec-settings">
        <div class="sec-header mb16">
          <div><div class="sec-title">Settings</div><div class="sec-sub">Configure cloaking rules, security, and integrations</div></div>
        </div>

        <div class="stabs">
          <button class="stab active" data-tab="engine" onclick="switchTab(this,'stab-engine')">⚡ Engine</button>
          <button class="stab" data-tab="security" onclick="switchTab(this,'stab-security')">🔒 Security</button>
          <button class="stab" data-tab="ips" onclick="switchTab(this,'stab-ips')">🛡 Blocked IPs</button>
          <button class="stab" data-tab="countries" onclick="switchTab(this,'stab-countries')">🌍 Countries</button>
          <button class="stab" data-tab="integrations" onclick="switchTab(this,'stab-integrations')">🔗 Integrations</button>
          <button class="stab" data-tab="tz" onclick="switchTab(this,'stab-tz')">🕐 Timezone</button>
          <button class="stab" data-tab="password" onclick="switchTab(this,'stab-password')">🔑 Password</button>
          <button class="stab" data-tab="danger" onclick="switchTab(this,'stab-danger')">⚠ Danger Zone</button>
        </div>

        <!-- Security toggles tab -->
        <div class="stab-content" id="stab-security">
          <div class="f-card mb16">
            <div class="f-card-title">Detection Modules</div>
            <p class="hint mb16">Toggle individual detection checks. Disabled checks are skipped; all visitors still pass through active checks.</p>
            <form method="POST" action="/${ADMIN_PATH}/settings/features">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px">
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="vpnBlocking" value="false">
                    <input type="checkbox" class="ts-input" name="vpnBlocking" value="true" ${globalSettings.vpnBlocking !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">VPN / Proxy Blocking</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Block visitors on detected VPN or anonymous proxies.</p>
                </div>
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="proxyBlocking" value="false">
                    <input type="checkbox" class="ts-input" name="proxyBlocking" value="true" ${globalSettings.proxyBlocking !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">Datacenter / Hosting Blocking</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Block visitors on datacenter / cloud IP ranges.</p>
                </div>
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="botUaBlocking" value="false">
                    <input type="checkbox" class="ts-input" name="botUaBlocking" value="true" ${globalSettings.botUaBlocking !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">Bot User-Agent Detection</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Block well-known crawlers, scrapers, and headless browsers.</p>
                </div>
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="repeatClickBlocking" value="false">
                    <input type="checkbox" class="ts-input" name="repeatClickBlocking" value="true" ${globalSettings.repeatClickBlocking !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">Repeat-Click Blocking</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Block IPs that visit more than once within 24 hours.</p>
                </div>
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="ispBlocking" value="false">
                    <input type="checkbox" class="ts-input" name="ispBlocking" value="true" ${globalSettings.ispBlocking !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">Suspicious ISP Blocking</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Block traffic from known tech-company and cloud ISPs.</p>
                </div>
                <div>
                  <label class="ts-wrap" style="margin-bottom:12px;cursor:pointer">
                    <input type="hidden" name="countryBlockingEnabled" value="false">
                    <input type="checkbox" class="ts-input" name="countryBlockingEnabled" value="true" ${globalSettings.countryBlockingEnabled !== false ? 'checked' : ''} onchange="this.previousSibling.disabled=this.checked">
                    <span class="ts-track"></span>
                    <span class="ts-label" style="font-size:.83rem;font-weight:600">Country / Geo Blocking</span>
                  </label>
                  <p class="hint" style="margin-left:50px">Enforce the allowed-countries list (Settings → Countries tab). Disable to bypass geo-filter globally.</p>
                </div>
              </div>
              <div class="form-row">
                <label>Custom ISP Keyword Blocklist <span class="hint" style="display:inline">(one per line — appended to the built-in list)</span></label>
                <textarea name="suspiciousIspKeywords" rows="5" placeholder="e.g.&#10;comcast&#10;spectrum&#10;verizon">${escHtml((Array.isArray(globalSettings.suspiciousIspKeywords) ? globalSettings.suspiciousIspKeywords : []).join('\n'))}</textarea>
              </div>
              <button type="submit" class="btn-pri mt12">Save Security Settings</button>
            </form>
          </div>
        </div>

        <!-- Password tab -->
        <div class="stab-content" id="stab-password">
          <div class="f-card" style="max-width:460px">
            <div class="f-card-title">Change Admin Password</div>
            <p class="hint mb16">Password must be at least 8 characters.</p>
            <div class="form-row">
              <label>Current Password</label>
              <input type="password" id="pwCurrent" autocomplete="current-password" placeholder="Enter current password">
            </div>
            <div class="form-row">
              <label>New Password</label>
              <input type="password" id="pwNew" autocomplete="new-password" placeholder="At least 8 characters">
            </div>
            <div class="form-row">
              <label>Confirm New Password</label>
              <input type="password" id="pwConfirm" autocomplete="new-password" placeholder="Repeat new password">
            </div>
            <div id="pwMsg" style="font-size:.78rem;margin-bottom:10px;display:none"></div>
            <button class="btn-pri mt8" onclick="changePassword()">Update Password</button>
          </div>
        </div>

        <!-- Engine tab -->
        <div class="stab-content active" id="stab-engine">
          <div class="f-card mb16">
            <div class="f-card-title">Cloaking Engine</div>
            <div class="flex-gap8 mb16">
              <form method="POST" action="/${ADMIN_PATH}/toggle">
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
            <form method="POST" action="/${ADMIN_PATH}/settings">
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
              <a href="/${ADMIN_PATH}/blocked-ips-export" class="btn-ghost btn-sm">⬇ Export for Google Ads</a>
            </div>
            <p class="hint mb12">These IPs are always blocked, regardless of geo or fingerprint checks. ${exportCount} unique IPs ready for export.</p>
            <form method="POST" action="/${ADMIN_PATH}/blocked-ips">
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
            <form method="POST" action="/${ADMIN_PATH}/allowed-countries">
              <div class="form-row">
                <label>Allowed countries</label>
                <input type="text" name="allowedCountries" value="${escHtml(allowedCountriesList.join(', '))}" placeholder="US CA GB AU IN — blank means allow all">
              </div>
              <div class="flex-gap8 mt12">
                <button type="submit" class="btn-pri">Save Filter</button>
                ${allowedCountriesList.length > 0 ? '<form method="POST" action="/' + ADMIN_PATH + '/allowed-countries" class="inline"><input type="hidden" name="allowedCountries" value=""><button type="submit" class="btn-danger" onclick="return confirm(\'Remove country filter?\')">Remove Filter</button></form>' : ''}
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
            <form method="POST" action="/${ADMIN_PATH}/settings/railway-token">
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
                <form method="POST" action="/${ADMIN_PATH}/clear-logs">
                  <button type="submit" class="btn-danger" onclick="return confirm('Delete all ${logTotal} traffic log records? Cannot be undone.')">Clear Logs</button>
                </form>
              </div>
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(239,68,68,.15)">
                <div>
                  <div style="font-size:.82rem;font-weight:600">Clear Leads</div>
                  <div class="hint">${leadTotal} lead records will be deleted</div>
                </div>
                <form method="POST" action="/${ADMIN_PATH}/clear-leads">
                  <button type="submit" class="btn-danger" onclick="return confirm('Delete all ${leadTotal} lead records? Cannot be undone.')">Clear Leads</button>
                </form>
              </div>
              <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0">
                <div>
                  <div style="font-size:.82rem;font-weight:600">Reset Frequency Tracker</div>
                  <div class="hint">${freqStoreSize} entries in memory store</div>
                </div>
                <form method="POST" action="/${ADMIN_PATH}/clear-frequency">
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

<!-- ── HOTKEYS PANEL ───────────────────────────────── -->
<div class="f-modal" id="hotkeysModal">
  <div class="f-modal-box" style="max-width:440px">
    <div class="f-modal-hdr">
      <span class="f-modal-title">⌨ Keyboard Shortcuts</span>
      <button class="f-modal-close" onclick="closeModal('hotkeysModal')">✕</button>
    </div>
    <div class="hk-grid">
      <div class="hk-row"><span class="hk-key">1</span> Dashboard</div>
      <div class="hk-row"><span class="hk-key">2</span> Sites</div>
      <div class="hk-row"><span class="hk-key">3</span> Click Log</div>
      <div class="hk-row"><span class="hk-key">4</span> Leads</div>
      <div class="hk-row"><span class="hk-key">5</span> Settings</div>
      <div class="hk-row"><span class="hk-key">?</span> This panel</div>
      <div class="hk-row"><span class="hk-key">Esc</span> Close modals</div>
      <div class="hk-row"><span class="hk-key">N</span> Notifications</div>
    </div>
  </div>
</div>

<!-- ── ADD SITE MODAL ──────────────────────────────── -->
<div class="f-modal" id="addSiteModal">
  <div class="f-modal-box">
    <div class="f-modal-hdr">
      <span class="f-modal-title">+ Add New Site</span>
      <button class="f-modal-close" onclick="closeModal('addSiteModal')">✕</button>
    </div>
    <form method="POST" action="/${ADMIN_PATH}/sites">
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
var sectionMap = { dashboard:'Command Center', sites:'Sites', logs:'Click Log', leads:'Leads', 'blocked-ips':'Blocked IPs', settings:'Settings' };
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
document.addEventListener('DOMContentLoaded', function() {
  initSection();
  // Auto-open specific settings sub-tab via ?stab= query param (e.g., after feature-settings save)
  (function() {
    var stab = new URLSearchParams(location.search).get('stab');
    if (stab) {
      var btn = document.querySelector('.stab[data-tab="' + stab + '"]');
      if (btn) switchTab(btn, 'stab-' + stab);
    }
  })();
  // Auto-detect browser timezone on first admin session load (step 10)
  // Only runs when timezone hasn't been auto-detected yet (tzAutoDetected = false)
  (function() {
    if (${JSON.stringify(tzAutoDetected)}) return; // already set this session
    try {
      var detected = Intl.DateTimeFormat().resolvedOptions().timeZone;
      var current  = ${JSON.stringify(displayTz)};
      if (detected && detected !== current) {
        fetch('/${ADMIN_PATH}/set-timezone', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({tz: detected, source: 'auto'})
        }).then(function(r){return r.json();}).then(function(d){
          if (d.ok) location.reload();
        }).catch(function(){});
      }
    } catch(e) {}
  })();
});

// ── Theme toggle ─────────────────────────────────────────────────────────────
function toggleTheme() {
  var isDark = document.body.classList.toggle('dark');
  localStorage.setItem('filterTheme', isDark ? 'dark' : 'light');
  var icon = document.getElementById('themeIcon');
  if (icon) {
    if (isDark) {
      icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
    } else {
      icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
    }
  }
}
(function() {
  var isDark = document.body.classList.contains('dark');
  var icon = document.getElementById('themeIcon');
  if (icon && isDark) {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
  }
})();

// ── Sidebar collapse ──────────────────────────────────────────────────────────
function toggleCollapse() {
  var sb = document.getElementById('fSidebar');
  var collapsed = sb.classList.toggle('collapsed');
  localStorage.setItem('filterCollapsed', collapsed ? '1' : '');
  var lbl = document.getElementById('collapseLabel');
  if (lbl) lbl.textContent = collapsed ? 'Show' : 'Hide';
}
(function() {
  if (localStorage.getItem('filterCollapsed') === '1') {
    var sb = document.getElementById('fSidebar');
    if (sb) sb.classList.add('collapsed');
    var lbl = document.getElementById('collapseLabel');
    if (lbl) lbl.textContent = 'Show';
  }
})();

// ── Time range filter ─────────────────────────────────────────────────────────
function setTimeRange(btn) {
  var range = btn.dataset.range;
  var params = new URLSearchParams(window.location.search);
  params.set('range', range);
  params.delete('from');
  params.delete('to');
  params.delete('logPage');
  params.delete('leadPage');
  window.location.search = params.toString();
}

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
  var params = new URLSearchParams(window.location.search);
  if (val) { params.set('site', val); } else { params.delete('site'); }
  params.delete('logPage');
  params.delete('leadPage');
  var hash = window.location.hash || '#dashboard';
  window.location.href = '/${ADMIN_PATH}?' + params.toString() + hash;
}

// ── Custom date range picker toggle ────────────────────────────────────────────
function toggleCustomRange() {
  var box = document.getElementById('customRangeBox');
  if (box) { box.style.display = box.style.display === 'none' ? 'flex' : 'none'; }
}
function applyCustomRange() {
  var from = document.getElementById('crFrom').value;
  var to   = document.getElementById('crTo').value;
  if (!from || !to) return;
  var params = new URLSearchParams(window.location.search);
  params.set('range', 'custom');
  params.set('from', from);
  params.set('to', to);
  params.delete('logPage');
  params.delete('leadPage');
  window.location.search = params.toString();
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
  fetch('/${ADMIN_PATH}/set-timezone', {
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

// ── Re-inject cloaking script into GitHub repo ────────────────────────────────
function reInjectSite(siteId, btn) {
  var orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '\u2026Pushing';
  fetch('/${ADMIN_PATH}/sites/' + encodeURIComponent(siteId) + '/inject', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' }
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.ok) {
      btn.textContent = '\u2713 Pushed';
      var files = (d.injected || []).join(', ');
      showToast('Script injected into: ' + (files || 'repo'), 'success');
      var row = document.querySelector('[data-site-id="' + siteId + '"]');
      if (row) {
        row.dataset.deployStatus = 'pushed';
        var badge = row.querySelector('.db-live,.db-pushed,.db-pending,.db-failed,.db-rotated');
        if (badge) { badge.className = 'db-pushed'; badge.textContent = 'GitHub \u2713'; }
      }
    } else {
      btn.textContent = '\u2717 Failed';
      var reasons = {
        'no-token': 'GitHub token not set',
        'no-repo': 'No repo configured for this site',
        'invalid-repo': 'Invalid GitHub repo URL',
        'repo-not-found': 'Repo not found (check token permissions)',
        'no-html-files': 'No HTML files found in repo',
        'inject-failed': 'GitHub rejected the file update',
        'site-not-found': 'Site not found'
      };
      var errMsg = (d.reason === 'error' && d.message) ? d.message : (reasons[d.reason] || d.reason || 'Unknown error');
      showToast('Re-inject failed: ' + errMsg, 'error');
    }
  }).catch(function() {
    btn.textContent = '\u2717 Failed';
    showToast('Network error — could not reach server', 'error');
  }).finally(function() {
    setTimeout(function() { btn.textContent = orig; btn.disabled = false; }, 2200);
  });
}

// ── Quick block IP ────────────────────────────────────────────────────────────
function quickBlockIp(btn) {
  var ip = btn.dataset.ip;
  var site = btn.dataset.site;
  if (!ip || btn.classList.contains('blocked')) return;
  if (!confirm('Block IP ' + ip + ' immediately?')) return;
  fetch('/${ADMIN_PATH}/block-ip-ajax', {
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

// ── Unblock IP (called by event delegation on .unblock-ip-btn) ────────────────
function unblockIp(ip, siteId, btn) {
  if (!confirm('Remove ' + ip + ' from the block list?')) return;
  fetch('/${ADMIN_PATH}/unblock-ip-ajax', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, siteId: siteId || 'default' })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.ok) {
      var row = btn.closest('tr');
      if (row) row.remove();
      showToast('IP ' + ip + ' unblocked', 'success');
      var body = document.getElementById('blockedIpsBody');
      if (body && body.querySelectorAll('tr').length === 0) {
        var emptyRow = body.insertRow();
        var emptyCell = emptyRow.insertCell();
        emptyCell.colSpan = 4;
        emptyCell.className = 'empty-state';
        emptyCell.textContent = 'No manually blocked IPs.';
      }
    } else showToast(d.error || 'Failed to unblock IP', 'error');
  }).catch(function(){ showToast('Network error', 'error'); });
}
// Event delegation for unblock buttons (avoids inline JS with interpolated IP strings)
document.addEventListener('click', function(e) {
  var btn = e.target.closest('.unblock-ip-btn');
  if (!btn) return;
  var ip   = btn.dataset.ip   || '';
  var site = btn.dataset.site || 'default';
  unblockIp(ip, site, btn);
});

// ── Manual block IP from Blocked IPs page ─────────────────────────────────────
function manualBlockIpBtn() {
  var input = document.getElementById('manualBlockIpInput');
  var ip = (input ? input.value : '').trim();
  if (!ip) return showToast('Enter an IP address first', 'error');
  fetch('/${ADMIN_PATH}/block-ip-ajax', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, siteId: 'default' })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.ok) {
      var body = document.getElementById('blockedIpsBody');
      if (body) {
        var empty = body.querySelector('td[colspan]');
        if (empty) empty.closest('tr').remove();
        // Build row using safe DOM methods (no innerHTML with user-supplied values)
        var now = new Date().toLocaleString('en-US', {month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit'});
        var row = body.insertRow(0);
        row.id = 'bip-' + ip.replace(/[^a-zA-Z0-9]/g,'_');
        var td1 = row.insertCell(); td1.className = 't-mono t-ip'; td1.textContent = ip;
        var td2 = row.insertCell(); td2.style.cssText = 'font-size:.78rem;color:var(--text2)'; td2.textContent = now;
        var td3 = row.insertCell();
        var pill = document.createElement('span'); pill.className = 'pill pill-grey'; pill.textContent = 'manual'; td3.appendChild(pill);
        var td4 = row.insertCell(); td4.style.textAlign = 'right';
        var ubtn = document.createElement('button');
        ubtn.className = 'btn-danger btn-sm unblock-ip-btn';
        ubtn.dataset.ip   = ip;
        ubtn.dataset.site = 'default';
        ubtn.textContent  = 'Unblock';
        td4.appendChild(ubtn);
      }
      if (input) input.value = '';
      showToast('IP ' + ip + ' blocked', 'success');
    } else showToast(d.error || 'Failed to block IP', 'error');
  }).catch(function(){ showToast('Network error', 'error'); });
}

// ── Change password ───────────────────────────────────────────────────────────
function changePassword() {
  var cur  = document.getElementById('pwCurrent').value;
  var nw   = document.getElementById('pwNew').value;
  var conf = document.getElementById('pwConfirm').value;
  var msg  = document.getElementById('pwMsg');
  fetch('/${ADMIN_PATH}/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: cur, newPassword: nw, confirmPassword: conf })
  }).then(function(r){ return r.json(); }).then(function(d) {
    if (d.ok) {
      if (msg) { msg.style.display='block'; msg.style.color='var(--green)'; msg.textContent='Password updated successfully.'; }
      document.getElementById('pwCurrent').value = '';
      document.getElementById('pwNew').value = '';
      document.getElementById('pwConfirm').value = '';
      showToast('Password updated', 'success');
    } else {
      if (msg) { msg.style.display='block'; msg.style.color='var(--red)'; msg.textContent=d.error || 'Failed to update password'; }
      showToast(d.error || 'Failed to update password', 'error');
    }
  }).catch(function(){ showToast('Network error', 'error'); });
}

// ── Log table filter ─────────────────────────────────────────────────────────
function filterLogs() {
  var search = (document.getElementById('logSearch').value || '').toLowerCase();
  var dec    = (document.getElementById('logDecFilter').value || '').toLowerCase();
  var cards  = document.querySelectorAll('#logsBody .log-card');
  cards.forEach(function(card) {
    var text = card.textContent.toLowerCase();
    var matchSearch = !search || text.includes(search);
    var matchDec = !dec || card.dataset.decision === dec;
    var show = matchSearch && matchDec;
    card.style.display = show ? '' : 'none';
    // Collapse detail panel when hiding a card
    if (!show) {
      var detailId = card.dataset.detail;
      if (detailId) {
        var detail = document.getElementById(detailId);
        if (detail) detail.style.display = 'none';
      }
    }
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
    var allow = ${todayAllow}, block = ${todayBlock}, total = allow + block;
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

  function countActive() {
    var cutoff = Date.now() - 3 * 60 * 1000;
    return Object.values(activeTimes).filter(function(t){ return t > cutoff; }).length;
  }
  function updateCount() {
    var n = countActive();
    if (activeEl) activeEl.textContent = n;
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
  var es = new EventSource('/${ADMIN_PATH}/events');
  es.onmessage = function(e) {
    var payload, entry;
    try { payload = JSON.parse(e.data); } catch(x) { return; }

    // Handle KPI stats refresh (only overwrite when viewing 24h — other ranges show server-rendered values)
    if (payload.type === 'statsUpdate') {
      var curRange = (new URLSearchParams(window.location.search)).get('range') || '24h';
      if (curRange === '24h') {
        var elT = document.getElementById('kpiTotal');
        var elA = document.getElementById('kpiAllow');
        var elB = document.getElementById('kpiBlock');
        var elAP = document.getElementById('kpiAllowPct');
        var elBP = document.getElementById('kpiBlockPct');
        var tot = payload.todayTotal || 0;
        var blk = payload.todayBlock || 0;
        var alw = payload.todayAllow || 0;
        var blockRate = tot > 0 ? Math.round(blk / tot * 100) : 0;
        if (elT) elT.textContent = tot;
        if (elB) elB.textContent = blockRate + '%';
        if (elA) elA.textContent = tot === 0 ? '—' : blockRate;
        if (elBP) elBP.textContent = blk + ' blocked';
        if (elAP) elAP.textContent = alw + ' allowed';
      }
      return;
    }

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
  if (e.key === '?' || e.key === '/') { openModal('hotkeysModal'); }
  if (e.key === 'n' || e.key === 'N') { toggleNotif(); }
});

// ── Log row expand ────────────────────────────────────────────────────────────
function toggleLogRow(id) {
  var row = document.getElementById(id);
  if (!row) return;
  var isOpen = row.style.display !== 'none';
  row.style.display = isOpen ? 'none' : '';
}

// ── Lead called toggle ────────────────────────────────────────────────────────
function toggleLeadCalled(btn) {
  var ts = btn.dataset.ts;
  if (!ts || btn.disabled) return;
  btn.disabled = true;
  fetch('/${ADMIN_PATH}/lead-toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ts: ts, siteId: btn.dataset.site || '', ip: btn.dataset.ip || '' })
  }).then(function(r){ return r.json(); }).then(function(d) {
    btn.disabled = false;
    if (d.ok) {
      if (d.called) {
        btn.textContent = '✓ Called';
        btn.classList.add('called');
        btn.title = 'Mark as not called';
      } else {
        btn.textContent = '○ Pending';
        btn.classList.remove('called');
        btn.title = 'Mark as called';
      }
    } else { showToast('Failed to update lead', 'error'); }
  }).catch(function(){ btn.disabled = false; showToast('Network error', 'error'); });
}

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
      var blob = new Blob([csv.join('\\n')], { type: 'text/csv' });
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
