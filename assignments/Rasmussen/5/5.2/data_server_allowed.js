const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3001;

http.createServer((req, res) => {
  if (req.url === '/') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
  } else if (req.url === '/data.json') {
    fs.readFile(path.join(__dirname, 'data.json'), 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading data.json');
        return;
      }

      let jsonData;
      try {
        jsonData = JSON.parse(data);
      } catch (parseError) {
        res.writeHead(500);
        res.end('Error parsing data.json');
        return;
      }
      // Set the custom headers using the parsed data
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-CS533f24-drums': jsonData.drums,
        'X-CS533f24-comedy': jsonData.comedy,
        'X-CS533f24-music': jsonData.music,
        'X-CS533f24-videogames': jsonData.videogame, // Note 'videogame' singular
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Expose-Headers': 'X-CS533f24-drums, X-CS533f24-comedy, X-CS533f24-music, X-CS533f24-videogames'
      });
      // Send the raw data (string) as the response body
      res.end(data);
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
}).listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
