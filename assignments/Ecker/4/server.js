const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

// Function to ensure URLs are absolute
function ensureAbsoluteURL(url) {
  url = url.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return 'https://' + url;
  }
  return url;
}

// Read URLs from urls.txt
const urls = fs.readFileSync('urls.txt', 'utf-8').split('\n').filter(Boolean);

// Map URLs to absolute URLs
const absoluteUrls = urls.map(ensureAbsoluteURL);

// Directory to store HTML files
const framableDir = path.join(__dirname, 'framable');

// Ensure the directory exists
if (!fs.existsSync(framableDir)) {
  fs.mkdirSync(framableDir, { recursive: true });
}

// Function to generate HTML content
function generateHTML(url, index) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Page ${index}</title>
    </head>
    <body>
      <h2>Testing URL: ${url}</h2>
      <iframe src="${url}" width="100%" height="600px"></iframe>
    </body>
    </html>
  `;
}

// Create HTML files with absolute URLs
absoluteUrls.forEach((url, index) => {
  const htmlContent = generateHTML(url, index + 1);
  fs.writeFileSync(
    path.join(framableDir, `page${index + 1}.html`),
    htmlContent,
    'utf-8'
  );
});

// Generate index.html
function generateIndexPage(urls) {
  let links = urls
    .map(
      (url, index) =>
        `<li><a href="page${index + 1}.html">Page ${index + 1}</a> - ${url}</li>`
    )
    .join('');
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Iframe Tester Index</title>
    </head>
    <body>
      <h1>Iframe Tester</h1>
      <ul>${links}</ul>
    </body>
    </html>
  `;
}

const indexContent = generateIndexPage(absoluteUrls);
fs.writeFileSync(path.join(framableDir, 'index.html'), indexContent, 'utf-8');

// Serve static files
app.use('/', express.static(framableDir));

app.listen(3001, () => {
  console.log('Server is running at http://localhost:3001');
});
