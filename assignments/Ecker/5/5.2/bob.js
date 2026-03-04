// File: bob.js
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 4000;

// Updated custom headers
const customHeaders = {
    "X-CS533f24-Artist": "Bad Religion",
    "X-CS533f24-TV-Series": "Barney Miller",
    "X-CS533f24-Book-Series": "Perry Mason",
    "X-CS533f24-Game-Series": "Half-Life"
};

// No CORS: Headers are blocked
app.get('/no-cors-headers', (req, res) => {
    console.log("Endpoint '/no-cors-headers' was called.");
    res.set(customHeaders);
    res.json({ message: "Custom headers set, but blocked by CORS" });
});

// With CORS: Headers are exposed
app.use(cors({ exposedHeaders: Object.keys(customHeaders) }));
app.get('/with-cors-headers', (req, res) => {
    console.log("Endpoint '/with-cors-headers' was called.");
    res.set(customHeaders);
    res.json({ message: "Custom headers set and exposed via CORS" });
});

app.listen(PORT, () => {
    console.log(`Bob server running at http://localhost:${PORT}`);
});

