// File: public/script.js

// Function to fetch data from /no-cors endpoint
async function fetchWithoutCORS() {
    try {
        const res = await fetch('http://localhost:4000/no-cors');
        const data = await res.json();
        document.getElementById('no-cors').innerText = JSON.stringify(data);
    } catch (err) {
        document.getElementById('no-cors').innerText = `Blocked: ${err}`;
    }
}

// Function to fetch data from /with-cors endpoint
async function fetchWithCORS() {
    try {
        const res = await fetch('http://localhost:4000/with-cors');
        const data = await res.json();
        document.getElementById('with-cors').innerText = JSON.stringify(data);
    } catch (err) {
        document.getElementById('with-cors').innerText = `Error: ${err}`;
    }
}

