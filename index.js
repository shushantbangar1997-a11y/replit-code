const express = require('express');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 5000;

// Serve static files from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Homepage
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
