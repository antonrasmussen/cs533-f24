// File: alice.js
const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Serve the HTML file
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
    console.log(`Alice running on http://localhost:${PORT}`);
});
