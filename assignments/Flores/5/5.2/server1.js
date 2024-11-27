const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors'); // Include CORS middleware
const app = express();
const PORT = 4000;

// Toggle CORS dynamically with an environment variable
const ENABLE_CORS = process.env.ENABLE_CORS === 'true';

// Apply middleware based on the CORS toggle
if (ENABLE_CORS) {
    app.use(cors({
        origin: 'http://localhost:3000',
        exposedHeaders: [
            'X-CS533f24-JohnnyCash',
            'X-CS533f24-KarateKid',
            'X-CS533f24-KaijuNo8',
            'X-CS533f24-Gladiator'
        ]
    }));
    console.log('CORS is ENABLED');
} else {
    // Middleware to block cross-origin requests
    app.use((req, res, next) => {
        const origin = req.headers.origin;
        const allowedOrigin = `http://localhost:${PORT}`;
        if (origin && origin !== allowedOrigin) {
            res.status(403).send('Cross-origin requests are not allowed.');
        } else {
            next();
        }
    });
    console.log('CORS is DISABLED');
}

// JSON response with favorite items and custom headers for CORS testing
app.get('/favorites', (req, res) => {
    console.log('Processing /favorites request');

    // Set custom debug header
    res.setHeader('X-Debug', 'CORS-Test');

    // Add the four custom headers
    res.setHeader('X-CS533f24-JohnnyCash', 'Johnny Cash Info');
    res.setHeader('X-CS533f24-KarateKid', 'Karate Kid Info');
    res.setHeader('X-CS533f24-KaijuNo8', 'Kaiju No. 8 Info');
    res.setHeader('X-CS533f24-Gladiator', 'Gladiator Info');

    res.json({
        "favorites": [
            "Johnny Cash",
            "Karate Kid",
            "Kaiju No. 8",
            "Gladiator"
        ]
    });
});

// Additional endpoints serving HTML content
app.get('/Johnnycash', (req, res) => {
    res.cookie('favorite_artist', 'Johnny Cash');
    res.send(`
        <html>
            <body>
                <h1>Johnny Cash</h1>
                <p>Best known as a country music icon, Cash's music spans rock, blues, folk, and gospel.</p>
            </body>
        </html>
    `);
});

app.get('/karate-kid.html', (req, res) => {
    res.cookie('favorite_show', 'KarateKid');
    res.send(`
        <html>
            <body>
                <h1>Karate Kid Series</h1>
                <p>This series teaches timeless lessons on discipline and perseverance.</p>
            </body>
        </html>
    `);
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
    console.log(`CORS is currently ${ENABLE_CORS ? 'ENABLED' : 'DISABLED'}`);
});

