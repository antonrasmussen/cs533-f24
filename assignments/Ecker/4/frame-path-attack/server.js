const express = require('express');
const path = require('path');

const app = express();
const PORT = 4000;

// Serve the parent page
app.get('/parent', (req, res) => {
    console.log("Parent request cookies:", req.headers.cookie);
    res.sendFile(path.join(__dirname, 'parent.html'));
});

app.get('/iframe', (req, res) => {
    console.log("Iframe request cookies:", req.headers.cookie);
    res.cookie('sensitiveCookie', 'superSecretValue', {
        path: '/'  // Accessible across all paths
    });
    res.sendFile(path.join(__dirname, 'iframe.html'));
});

// Start the Express server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
