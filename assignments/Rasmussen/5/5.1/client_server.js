const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4200;

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
  }
}).listen(PORT, () => {
  console.log(`Client Server running at http://localhost:${PORT}`);
});
