const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve allow-embed.html (no CSP header)
app.get('/allow', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'allow-embed.html'));
});

// Serve prohibit-embed.html with stronger CSP and X-Frame-Options
app.get('/prohibit', (req, res) => {
    console.log("Setting CSP and X-Frame-Options headers to block embedding.");
    res.set('Content-Security-Policy', "frame-ancestors 'none'; default-src 'none';");
    res.set('X-Frame-Options', 'DENY');
    res.sendFile(path.join(__dirname, 'public', 'prohibit-embed.html'));
});

// Default route for other files
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

