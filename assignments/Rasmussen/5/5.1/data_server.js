const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4201;

http.createServer((req, res) => {
  if (req.url === '/data.json') {
    fs.readFile(path.join(__dirname, 'data.json'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading data.json');
        return;
      }
      // Note: No CORS headers are set here, the client can't access the data
      // res.writeHead(200, { 'Content-Type': 'application/json' });

      // With CORS headers set, the client can access the data
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*', // Allow all origins
      });

      res.end(data);
    });
  }
}).listen(PORT, () => {
  console.log(`Data Server running at http://localhost:${PORT}`);
});
