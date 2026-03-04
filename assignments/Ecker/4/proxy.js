const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
const PORT = 3000;

// Fetch and serve the HTML with modified headers
app.get('/iframe-page', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).send('URL parameter is required');
  }

  try {
    // Fetch the HTML content
    const response = await axios.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    });

    // Load HTML into Cheerio for manipulation
    const $ = cheerio.load(response.data);

    // Rewrite all internal links and resources to go through the proxy
    $('a').each((i, el) => {
      const href = $(el).attr('href');
      if (href && href.startsWith('/')) {
        $(el).attr('href', `/proxy-content?url=${encodeURIComponent(new URL(href, targetUrl))}`);
      }
    });

    $('img, script, link').each((i, el) => {
      const src = $(el).attr('src') || $(el).attr('href');
      if (src && src.startsWith('/')) {
        const attr = $(el).attr('src') ? 'src' : 'href';
        $(el).attr(attr, `/proxy-content?url=${encodeURIComponent(new URL(src, targetUrl))}`);
      }
    });

    // Send modified HTML with an iframe
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Iframe Proxy Page</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f3f4f6;
          }
          .container {
            margin: 20px auto;
            padding: 20px;
            width: 80%;
            max-width: 800px;
            border: 1px solid #ddd;
            background-color: #fff;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          }
          h1 {
            font-size: 1.5em;
            color: #333;
          }
          .iframe-container {
            border: 1px solid #ccc;
            padding: 10px;
            background-color: #f9f9f9;
          }
          iframe {
            width: 100%;
            max-width: 600px;
            height: 400px;
            border: 1px solid #aaa;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Testing URL: <a href="${targetUrl}" target="_blank">${targetUrl}</a></h1>
          <div class="iframe-container">
            <iframe src="/proxy-content?url=${encodeURIComponent(targetUrl)}" frameborder="0" allowfullscreen></iframe>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('Error fetching the URL');
  }
});

// Proxy route for other resources (CSS, JS, images)
app.get('/proxy-content', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).send('URL parameter is required');
  }

  try {
    const response = await axios.get(targetUrl, {
      responseType: 'arraybuffer', // Use arraybuffer for binary data (images)
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    });
    // Set correct content type
    res.set('Content-Type', response.headers['content-type']);
    res.send(response.data);
  } catch (error) {
    res.status(500).send('Error fetching the resource');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
