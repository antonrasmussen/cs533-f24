const express = require('express');
const path = require('path');
const app = express();
const PORT = 3000;

// Serve static files from the 5.1 directory
app.use(express.static(path.join(__dirname)));

// Start Server 2
app.listen(PORT, () => {
    console.log(`Server 2 is running at http://localhost:${PORT}`);
});
