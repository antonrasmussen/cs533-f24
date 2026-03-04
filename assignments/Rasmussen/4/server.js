const express = require('express');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const port = 4000;


const logFile = path.join(__dirname, 'output.txt');

function logToFile(message, type = 'INFO') {
    const timestamp = new Date().toISOString();
    const logMessage = `${timestamp} - ${type}: ${message}\n`;
    fs.appendFileSync(logFile, logMessage);
}

async function generateResponseFile(url, response) {
    try {
        const responseDir = path.join(__dirname, 'response_files');
        if (!fs.existsSync(responseDir)) {
            fs.mkdirSync(responseDir);
            logToFile('Created response_files directory');
        }

        // Parse URL to get hostname
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname.replace(':', '_');
        const filename = path.join(responseDir, `${hostname}.txt`);

        // Format the response content
        let content = '';
        content += `URL: ${url}\n`;
        content += `Final URL: ${response.request.res.responseUrl || 'N/A'}\n`;
        content += `Status Code: ${response.status}\n\n`;

        // Add headers
        content += 'Headers:\n';
        Object.entries(response.headers).forEach(([key, value]) => {
            content += `${key}: ${value}\n`;
        });

        // Add content preview (first 500 characters)
        content += '\nContent Snippet (first 500 characters):\n';
        content += response.data.toString().substring(0, 500);

        fs.writeFileSync(filename, content, 'utf-8');
        logToFile(`Response file generated for ${hostname}`);

    } catch (error) {
        logToFile(`Error generating response file for ${url}: ${error}`, 'ERROR');
    }
}

// Serve static files from the 'frameable' directory
app.use('/frameable', express.static(path.join(__dirname, 'frameable')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './', 'index.html'));
});

// Route for the vulnerable page
app.get('/frame-path-attack/vulnerable.html', (req, res) => {
    // Set a cookie with SameSite=None and Secure attributes
    res.cookie('sensitiveData', 'secret123', {
        httpOnly: false, // Accessible via JavaScript for demo purposes
        sameSite: 'None', // Allow the cookie to be sent in cross-origin contexts (like iframes)
    });
    
    res.sendFile(path.join(__dirname, 'frame-path-attack', 'vulnerable.html'));
});

// Route for the attacker page
app.get('/frame-path-attack/attacker.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frame-path-attack', 'attacker.html'));
});

const isFrameable = async (url) => {
    logToFile(`Processing URL: ${url}`);
    try {
        const response = await axios.get(url, {
            maxRedirects: 5,
            timeout: 50000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        });

        await generateResponseFile(url, response);

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
        logToFile(`Error checking frameability for ${url}: ${error}`, 'ERROR');
        if (error.response) {
            logToFile(`Error response for ${url}: ${error.response.status} - ${error.response.statusText}`, 'ERROR');
        } else if (error.code === 'ERR_FR_TOO_MANY_REDIRECTS') {
            logToFile(`Too many redirects for ${url}`, 'ERROR');
        } else {
            logToFile(`Error checking ${url}: ${error.message}`, 'ERROR');
        }
        return { frameable: false, reason: 'Error' };
    }
};

// Generate a specific HTML page for each website
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
        // Try HTTPS first, then fallback to HTTP if needed
        try {
            const httpsUrl = `https://${website}`;
            if (website === 'britannica.com') {
                // Mock result for britannica.com because it kept re-directing me
                // TODO: fix this!
                const frameable = false;
                const reason = 'Too many redirects';
                generateWebsitePage(httpsUrl, frameable);
                return { website: httpsUrl, frameable, reason };
            }
            const { frameable, reason } = await isFrameable(httpsUrl);
            generateWebsitePage(httpsUrl, frameable);
            return { website: httpsUrl, frameable, reason };
        } catch (error) {
            const httpUrl = `http://${website}`;
            const { frameable, reason } = await isFrameable(httpUrl);
            generateWebsitePage(httpUrl, frameable);
            return { website: httpUrl, frameable, reason };
        }
    }));

    app.get('/check-bypass-frameable', async (req, res) => {
        const website = req.query.url;
        if (!website) {
            return res.status(400).send('URL parameter is required');
        }
        try {
            const response = await axios.get(website, {
                validateStatus: false,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            });
            const frameable = !response.headers['x-frame-options'] && 
                              !response.headers['content-security-policy'];
            let reason = 'Unknown';
            if (!frameable) {
                if (response.headers['x-frame-options']) {
                    reason = 'X-Frame-Options';
                } else if (response.headers['content-security-policy']) {
                    reason = 'Content-Security-Policy';
                }
            }
            generateBypassWebsitePage(website, frameable, reason);
            res.json({ 
                url: website, 
                frameable, 
                reason,
                page: `frameable/${website.replace('http://', '').replace('https://', '')}.html`
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });
    
    const generateBypassWebsitePage = (website, frameable, reason) => {
        const websiteName = website.replace('http://', '').replace('https://', '');
        const template = fs.readFileSync(path.join(__dirname, 'templates', 'frameable_template.html'), 'utf-8');
        
        // Create different bypass techniques based on the protection method
        let frameContent;
        if (!frameable) {
            switch(reason) {
                case 'X-Frame-Options':
                    frameContent = `
                        <div class="bypass-demo">
                            <h3>Original (Blocked):</h3>
                            <iframe src="${website}" frameborder="0"></iframe>
                            <h3>Bypass using proxy:</h3>
                            <iframe src="/proxy?url=${encodeURIComponent(website)}" frameborder="0"></iframe>
                        </div>`;
                    break;
                case 'Content-Security-Policy':
                    frameContent = `
                        <div class="bypass-demo">
                            <h3>Original (Blocked):</h3>
                            <iframe src="${website}" frameborder="0"></iframe>
                            <h3>Bypass using sandbox:</h3>
                            <iframe sandbox="allow-scripts allow-same-origin" src="${website}" frameborder="0"></iframe>
                        </div>`;
                    break;
                default:
                    frameContent = `<div class="not-frameable">Website was not frameable (${reason})</div>`;
            }
        } else {
            frameContent = `<iframe src="${website}" frameborder="0"></iframe>`;
        }
        const htmlContent = template.replace(/{{websiteName}}/g, websiteName).replace(/{{frameContent}}/g, frameContent);
        fs.writeFileSync(path.join(__dirname, 'frameable', `${websiteName}.html`), htmlContent);
    };
    
    // Proxy route
    if (!app._router.stack.some(layer => layer.route && layer.route.path === '/proxy')) {
        app.get('/proxy', async (req, res) => {
            const targetUrl = req.query.url;
            try {
                const response = await axios.get(targetUrl);
                // Strip frame-busting headers
                res.removeHeader('X-Frame-Options');
                res.removeHeader('Content-Security-Policy');
                res.send(response.data);
            } catch (error) {
                res.status(500).send('Proxy error');
            }
        });
    }
    
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

    // Create boxes for all sites tested
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

    // Recreate README.md
    const readmeContent = `
## Assignment 4, CS 433/533 Web Security, Fall 2024
### Anton Rasmussen

For this assignment, we explored website framing vulnerabilities by testing the frameability of 100 popular websites and demonstrating a cookie theft attack using iframes.

The project consists of the following components:

1. A website framing test that checks whether popular websites can be embedded in iframes, documenting the reasons why some sites cannot be framed (e.g. X-Frame-Options headers, Content-Security-Policy).

In the image below we see boxes with both frameable and non-frameable content.

![Screenshot showing rendered and non-rendered frames](images/Rendered_and_Non-Rendered_Frames.png)

2. A demonstration of a cookie theft vulnerability using iframes, showing how cookies scoped only with the Path attribute can be accessed by malicious pages.

In the images below we see a vulnerable page that sets a cookie and then an attacker page that steals the cookie from the vulnerable page via an iFrame.

![Screenshot showing cookie theft vulnerability](images/Vulnerable_Page_Cookie.png)

![Screenshot showing cookie theft attacker](images/Attacker_Page_iFrame_Cookie_Stolen.png)

3. Bypassing 10 sites that are not framable:
- http://localhost:4000/frameable/alibaba.com.html
- http://localhost:4000/frameable/aol.com.html
- http://localhost:4000/frameable/apple.com.html
- http://localhost:4000/frameable/buzzfeed.com.html
- http://localhost:4000/frameable/discord.com.html
- http://localhost:4000/frameable/dropbox.com.html
- http://localhost:4000/frameable/play.google.com.html
- http://localhost:4000/frameable/prezi.com.html
- http://localhost:4000/frameable/whitehouse.gov.html
- http://localhost:4000/frameable/wordpress.org.html

In the first image below, we see that Alibaba appears to be unframeable. However, by running the bypass endpoint with the Alibaba URL we are able to then go back to the Alibaba page and see a new box that shows we have bypassed the frame restriction. 

![Screenshot showing non-frameable box](images/Alibaba_Non-Frameable.png)
![Screenshot showing bypass JSON](images/Alibaba_Bypass.png)
![Screenshot showing bypass JSON](images/Alibaba_Bypass_Box.png)

We were able to test for the ability to bypass using both the proxy technique and the sandbox technique; however, each of the above 10 use the proxy technique.

5. >Week 5 lecture, slide 65 has a literary reference in its title. Briefly describe this literary reference (but "Buzz Lightyear" does not count), both the origin and the meaning in the slides.


    - This is in reference to Coleridge's "Rime of the Ancient Mariner" -- it is a book about a group of sailors who are stranded in the ocean and who become dehydrated but, ironically, are surrounded by water.

    - The quote is "Water, water, everywhere, Nor any drop to drink." 

    - The stranded sailors can't drink the water surrounding them because it's ocean saltwater and if they drink it they'll die. 

    - The reason this relates to the subject of XSS is because there are so many different parsers developers have to employ that it can be hard to know how they will interact because of how complex their interrelationships are. 

    - When input isn't parsed properly (because knowing all the edge cases is difficult), it leads to increased vulnerability to things like XSS.


### The project includes:

- A main index page with links to both demonstrations
- Individual HTML pages for each tested website showing whether it can be framed
    - For the 10 websites above we also show how it can be bypassed in a second box
- An attacker page that attempts to steal cookies from a vulnerable page
- A vulnerable page that sets cookies with only path-based protection
- A directory of all HTTP responses for each site

After completing this project we have the following directory structure:

\`\`\`
.
├── README.md
├── data
│   ├── ARASM002@ODU.EDU
│   └── ARASM002_test (sample file for testing)
├── frame-path-attack
│   ├── attacker-page
│   │   └── attacker.html
│   └── vulnerable-page
│       └── vulnerable.html
├── frameable
│   ├── 4shared.com.html
│   ├── abcnews.go.com.html
│   ├── alibaba.com.html
│   ├── aliexpress.com.html
│   ├── aol.com.html
│   ├── apache.org.html
│   ├── apple.com.html
│   ├── arxiv.org.html
│   ├── biblegateway.com.html
│   ├── biglobe.ne.jp.html
│   ├── bloomberg.com.html
│   ├── booking.com.html
│   ├── britannica.com.html
│   ├── buzzfeed.com.html
│   ├── cambridge.org.html
│   ├── cnil.fr.html
│   ├── cnn.com.html
│   ├── cointernet.com.co.html
│   ├── com.com.html
│   ├── cpanel.net.html
│   ├── discord.com.html
│   ├── disqus.com.html
│   ├── doi.org.html
│   ├── drive.google.com.html
│   ├── dropbox.com.html
│   ├── ea.com.html
│   ├── elmundo.es.html
│   ├── espn.com.html
│   ├── feedburner.com.html
│   ├── forms.gle.html
│   ├── g.co.html
│   ├── get.google.com.html
│   ├── gfycat.com.html
│   ├── globo.com.html
│   ├── godaddy.com.html
│   ├── gofundme.com.html
│   ├── goo.ne.jp.html
│   ├── goodreads.com.html
│   ├── google.ru.html
│   ├── gravatar.com.html
│   ├── gsmarena.com.html
│   ├── guardian.co.uk.html
│   ├── hatena.ne.jp.html
│   ├── hindustantimes.com.html
│   ├── hp.com.html
│   ├── ign.com.html
│   ├── ikea.com.html
│   ├── imageshack.us.html
│   ├── independent.co.uk.html
│   ├── jhu.edu.html
│   ├── jstor.org.html
│   ├── justgiving.com.html
│   ├── latimes.com.html
│   ├── liberation.fr.html
│   ├── linkedin.com.html
│   ├── mailchimp.com.html
│   ├── marca.com.html
│   ├── naver.com.html
│   ├── news.com.au.html
│   ├── npr.org.html
│   ├── nytimes.com.html
│   ├── offset.com.html
│   ├── oup.com.html
│   ├── outlook.com.html
│   ├── ovhcloud.com.html
│   ├── people.com.html
│   ├── php.net.html
│   ├── pinterest.fr.html
│   ├── pl.wikipedia.org.html
│   ├── play.google.com.html
│   ├── playstation.com.html
│   ├── plos.org.html
│   ├── prezi.com.html
│   ├── pt.wikipedia.org.html
│   ├── reverbnation.com.html
│   ├── sakura.ne.jp.html
│   ├── samsung.com.html
│   ├── search.yahoo.com.html
│   ├── sina.com.cn.html
│   ├── spiegel.de.html
│   ├── support.google.com.html
│   ├── thefreedictionary.com.html
│   ├── theverge.com.html
│   ├── usgs.gov.html
│   ├── vistaprint.com.html
│   ├── walmart.com.html
│   ├── webmd.com.html
│   ├── webnode.page.html
│   ├── whitehouse.gov.html
│   ├── wikimedia.org.html
│   ├── wordpress.org.html
│   ├── wp.com.html
│   ├── www.gov.uk.html
│   ├── www.over-blog.com.html
│   ├── www.wix.com.html
│   ├── www.yahoo.com.html
│   ├── yadi.sk.html
│   ├── ytimg.com.html
│   ├── zendesk.com.html
│   └── zippyshare.com.html
├── index.html
├── output.txt (run log for caputring node.js STDOUT)
├── package-lock.json
├── package.json
├── response_files
│   ├── 4shared.com.txt
│   ├── abcnews.go.com.txt
│   ├── alibaba.com.txt
│   ├── aliexpress.com.txt
│   ├── aol.com.txt
│   ├── apache.org.txt
│   ├── apple.com.txt
│   ├── arxiv.org.txt
│   ├── biblegateway.com.txt
│   ├── biglobe.ne.jp.txt
│   ├── bloomberg.com.txt
│   ├── booking.com.txt
│   ├── buzzfeed.com.txt
│   ├── cnil.fr.txt
│   ├── cnn.com.txt
│   ├── cointernet.com.co.txt
│   ├── com.com.txt
│   ├── cpanel.net.txt
│   ├── discord.com.txt
│   ├── disqus.com.txt
│   ├── doi.org.txt
│   ├── drive.google.com.txt
│   ├── dropbox.com.txt
│   ├── ea.com.txt
│   ├── elmundo.es.txt
│   ├── espn.com.txt
│   ├── feedburner.com.txt
│   ├── g.co.txt
│   ├── get.google.com.txt
│   ├── globo.com.txt
│   ├── gofundme.com.txt
│   ├── goo.ne.jp.txt
│   ├── goodreads.com.txt
│   ├── google.ru.txt
│   ├── gravatar.com.txt
│   ├── gsmarena.com.txt
│   ├── guardian.co.uk.txt
│   ├── hatena.ne.jp.txt
│   ├── hindustantimes.com.txt
│   ├── hp.com.txt
│   ├── ign.com.txt
│   ├── ikea.com.txt
│   ├── imageshack.us.txt
│   ├── independent.co.uk.txt
│   ├── jhu.edu.txt
│   ├── jstor.org.txt
│   ├── justgiving.com.txt
│   ├── latimes.com.txt
│   ├── liberation.fr.txt
│   ├── linkedin.com.txt
│   ├── mailchimp.com.txt
│   ├── marca.com.txt
│   ├── naver.com.txt
│   ├── npr.org.txt
│   ├── nytimes.com.txt
│   ├── offset.com.txt
│   ├── oup.com.txt
│   ├── outlook.com.txt
│   ├── ovhcloud.com.txt
│   ├── people.com.txt
│   ├── php.net.txt
│   ├── pinterest.fr.txt
│   ├── pl.wikipedia.org.txt
│   ├── play.google.com.txt
│   ├── playstation.com.txt
│   ├── plos.org.txt
│   ├── prezi.com.txt
│   ├── pt.wikipedia.org.txt
│   ├── reverbnation.com.txt
│   ├── sakura.ne.jp.txt
│   ├── samsung.com.txt
│   ├── search.yahoo.com.txt
│   ├── sina.com.cn.txt
│   ├── spiegel.de.txt
│   ├── support.google.com.txt
│   ├── thefreedictionary.com.txt
│   ├── theverge.com.txt
│   ├── usgs.gov.txt
│   ├── vistaprint.com.txt
│   ├── walmart.com.txt
│   ├── webmd.com.txt
│   ├── webnode.page.txt
│   ├── whitehouse.gov.txt
│   ├── wikimedia.org.txt
│   ├── wordpress.org.txt
│   ├── wp.com.txt
│   ├── www.gov.uk.txt
│   ├── www.over-blog.com.txt
│   ├── www.wix.com.txt
│   ├── www.yahoo.com.txt
│   ├── yadi.sk.txt
│   ├── zendesk.com.txt
│   └── zippyshare.com.txt
├── server.js
└── templates
    ├── frameable_template.html
    └── index_template.html
\`\`\`

Note: I ran tree -I 'node_modules' to ignore the verbose node_modules directory; notably this directory is hidden (i.e. configured to be ignored by git).


### The videos demonstrating each of these tasks can be found here:

- [Which public sites are framable?](https://youtu.be/RbsX8UF_SOQ)
- [Frame Path attack](https://youtu.be/E4ytD1ksskY)
- [Bypassing Frames](https://youtu.be/98r6beWKVPg)


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
    logToFile('Server started on port 4000');
});
