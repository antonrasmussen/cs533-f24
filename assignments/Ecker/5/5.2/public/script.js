// File: public/script.js

// Helper function to filter custom headers
function extractCustomHeaders(headers) {
    return headers.filter(([key]) => key.startsWith("x-cs533f24"));
}

// Fetch headers from /no-cors-headers (Blocked)
async function fetchNoCORSHeaders() {
    try {
        const res = await fetch('http://localhost:4000/no-cors-headers');
        const data = await res.json();
        const headers = extractCustomHeaders(Array.from(res.headers.entries()));
        document.getElementById('blocked-headers').innerText = 
            `Response: ${JSON.stringify(data)}\nCustom Headers: ${JSON.stringify(headers)}`;
    } catch (err) {
        document.getElementById('blocked-headers').innerText = `Blocked: ${err}`;
    }
}

// Fetch headers from /with-cors-headers (Allowed)
async function fetchWithCORSHeaders() {
    try {
        const res = await fetch('http://localhost:4000/with-cors-headers');
        const data = await res.json();
        const headers = extractCustomHeaders(Array.from(res.headers.entries()));
        document.getElementById('allowed-headers').innerText = 
            `Response: ${JSON.stringify(data)}\nCustom Headers: ${JSON.stringify(headers)}`;
    } catch (err) {
        document.getElementById('allowed-headers').innerText = `Error: ${err}`;
    }
}

