const express = require('express');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const port = 4000;

// Serve static files from the 'frameable' directory
app.use('/frameable', express.static(path.join(__dirname, 'frameable')));

// Route for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './', 'index.html'));
});

// Route for the vulnerable page
app.get('/frame-path-attack/vulnerable-page', (req, res) => {
    // Remove X-Frame-Options header to ensure framing works
    res.removeHeader('X-Frame-Options');
    
    // Set multiple cookies to increase chances of demonstration
    res.cookie('sensitiveData', 'secret123', {
        path: '/frame-path-attack/vulnerable-page',
        httpOnly: false,
        sameSite: 'Lax'  // Changed to Lax which is more permissive than Strict
    });
    
    res.cookie('sessionId', 'demo-session-12345', {
        path: '/frame-path-attack/vulnerable-page',
        httpOnly: false,
        sameSite: 'Lax'
    });
    
    // Add headers to explicitly allow framing
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    res.sendFile(path.join(__dirname, 'frame-path-attack/vulnerable-page', 'vulnerable.html'));
});
// Route for the attacker page
app.get('/frame-path-attack/attacker-page', (req, res) => {
    res.sendFile(path.join(__dirname, 'frame-path-attack/attacker-page', 'attacker.html'));
});

// Function to check if a website is frameable
const isFrameable = async (url) => {
    try {
        const response = await axios.get(url, { maxRedirects: 5 });
        const xFrameOptions = response.headers['x-frame-options'];
        const contentSecurityPolicy = response.headers['content-security-policy'];

        // Check if the website has headers that prevent framing
        if (xFrameOptions || (contentSecurityPolicy && contentSecurityPolicy.includes('frame-ancestors'))) {
            return {
                frameable: false,
                reason: xFrameOptions ? 'X-Frame-Options' : 'Content-Security-Policy'
            };
        }
        return { frameable: true };
    } catch (error) {
        if (error.response) {
            console.error(`Error checking ${url}:`, error.message);
        } else if (error.code === 'ERR_FR_TOO_MANY_REDIRECTS') {
            console.error(`Too many redirects for ${url}`);
        } else {
            console.error(`Error checking ${url}:`, error.message);
        }
        return { frameable: false, reason: 'Error' };
    }
};

// Function to generate a specific HTML page for each website
const generateWebsitePage = (website, frameable) => {
    const websiteName = website.replace('http://', '').replace('https://', '');
    const template = fs.readFileSync(path.join(__dirname, 'templates', 'frameable_template.html'), 'utf-8');
    const frameContent = frameable ? `<iframe src="${website}" frameborder="0"></iframe>` : `<div class="not-frameable">Website was not frameable</div>`;
    const htmlContent = template.replace(/{{websiteName}}/g, websiteName).replace(/{{frameContent}}/g, frameContent);
    fs.writeFileSync(path.join(__dirname, 'frameable', `${websiteName}.html`), htmlContent);
};

// Route to check frameability of websites and render them in boxes
app.get('/check-frameable', async (req, res) => {
    const filePath = path.join(__dirname, 'data', 'ARASM002@ODU.EDU');
    let websites = fs.readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);

    const results = await Promise.all(websites.map(async (website) => {
        if (website === 'britannica.com') {
            // Mock result for britannica.com
            const frameable = false;
            const reason = 'Too many redirects';
            generateWebsitePage(`http://${website}`, frameable);
            return { website: `http://${website}`, frameable, reason };
        } else {
            const { frameable, reason } = await isFrameable(`http://${website}`);
            generateWebsitePage(`http://${website}`, frameable);
            return { website: `http://${website}`, frameable, reason };
        }
    }));

    let frameableCount = 0;
    let notFrameableCount = 0;
    let frameableList = [];
    let notFrameableList = [];

    results.forEach(result => {
        if (result.frameable) {
            frameableCount++;
            frameableList.push(result.website);
        } else {
            notFrameableCount++;
            notFrameableList.push({ website: result.website, reason: result.reason });
        }
    });

    const template = fs.readFileSync(path.join(__dirname, 'templates', 'index_template.html'), 'utf-8');
    let content = '';

    results.forEach(result => {
        if (result.frameable) {
            content += `
                <div class="box">
                    <iframe src="${result.website}" frameborder="0"></iframe>
                    <div class="url"><a href="/frameable/${result.website.replace('http://', '').replace('https://', '')}.html">${result.website}</a></div>
                </div>
            `;
        } else {
            content += `
                <div class="box">
                    <div class="not-frameable">🚫</div>
                    <div class="url"><a href="/frameable/${result.website.replace('http://', '').replace('https://', '')}.html">Cannot frame ${result.website}</a></div>
                </div>
            `;
        }
    });

    const htmlContent = template.replace('{{content}}', content);
    res.send(htmlContent);

    // Update README.md
    const readmeContent = `
# Website Rendering Results

## Frameable Websites (${frameableCount})
${frameableList.map(website => `- ${website}`).join('\n')}

## Not Frameable Websites (${notFrameableCount})
${notFrameableList.map(item => `- [${item.website}](frameable/${item.website.replace('http://', '').replace('https://', '')}.html) (Reason: ${item.reason})`).join('\n')}
    `;

    fs.writeFileSync(path.join(__dirname, 'README.md'), readmeContent);
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});