// File: bob.js
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 4000;

// Data to be included in responses
const favoriteThings = {
    artist: "Bad Religion",
    tvSeries: "Barney Miller",
    bookSeries: "Perry Mason",
    gameSeries: "Half-Life",
};

// No CORS: Blocked response
app.get('/no-cors', (req, res) => {
    res.json({
        favoriteThings,
    });
});

// With CORS: Allowed response
app.use(cors());
app.get('/with-cors', (req, res) => {
    res.json({
        favoriteThings,
    });
});

app.listen(PORT, () => {
    console.log(`Bob server running on http://localhost:${PORT}`);
});

