const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;

http.createServer((req, res) => {
  if (req.url === '/') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
        return;
      }

      // Note: No Content-Security-Policy headers are set here, the client can embed another page
      res.writeHead(200, { 'Content-Type': 'text/html' });

      // With Content-Security-Policy headers set, the client cannot embed another page
      // res.writeHead(200, {
      //   'Content-Type': 'text/html',
      //   'Content-Security-Policy': "frame-src 'none'" // This will block all frame sources
      //   // 'Content-Security-Policy': "frame-src 'self'" // This will only allow the same origin to be embedded
      // });
      res.end(data);
    });
  }
}).listen(PORT, () => {
  console.log(`Client Server running at http://localhost:${PORT}`);
});
