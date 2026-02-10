async function setCookie() {
    const res = await fetch('/api/cookie/set');
    const data = await res.json();
    document.getElementById('cookie-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function getCookie() {
    const res = await fetch('/api/cookie/get');
    const data = await res.json();
    document.getElementById('cookie-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function setSession() {
    const res = await fetch('/api/session/set');
    const data = await res.json();
    document.getElementById('session-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function getSession() {
    const res = await fetch('/api/session/get');
    const data = await res.json();
    document.getElementById('session-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

let storedToken = localStorage.getItem('jwt_token') || '';

async function loginToken() {
    const res = await fetch('/api/token/login', { method: 'POST' });
    const data = await res.json();
    storedToken = data.token;
    localStorage.setItem('jwt_token', storedToken);
    document.getElementById('token-result').innerHTML = `<pre>Token stored in localStorage: \n${storedToken}</pre>`;
}

async function getProfile() {
    const res = await fetch('/api/token/profile', {
        headers: {
            'Authorization': `Bearer ${storedToken}`
        }
    });
    const data = await res.json();
    document.getElementById('token-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

// --- Opaque Token Functions ---
let storedOpaqueToken = '';

async function loginOpaque() {
    const res = await fetch('/api/opaque/login', { method: 'POST' });
    const data = await res.json();
    storedOpaqueToken = data.token;
    document.getElementById('opaque-result').innerHTML = `<pre>Opaque Token: \n${storedOpaqueToken}</pre>`;
}

async function getOpaqueProfile() {
    const res = await fetch('/api/opaque/profile', {
        headers: {
            'Authorization': `Bearer ${storedOpaqueToken}`
        }
    });
    const data = await res.json();
    document.getElementById('opaque-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function revokeOpaque() {
    const res = await fetch('/api/opaque/revoke', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${storedOpaqueToken}`
        }
    });
    const data = await res.json();
    document.getElementById('opaque-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

// --- PASETO Functions ---
let storedPasetoToken = '';

async function loginPaseto() {
    const res = await fetch('/api/paseto/login', { method: 'POST' });
    const data = await res.json();
    storedPasetoToken = data.token;
    document.getElementById('paseto-result').innerHTML = `<pre>PASETO Token: \n${storedPasetoToken}</pre>`;
}

async function getPasetoProfile() {
    const res = await fetch('/api/paseto/profile', {
        headers: {
            'Authorization': `Bearer ${storedPasetoToken}`
        }
    });
    const data = await res.json();
    document.getElementById('paseto-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function revokePaseto() {
    const res = await fetch('/api/paseto/revoke', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${storedPasetoToken}`
        }
    });
    const data = await res.json();
    document.getElementById('paseto-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function revokeToken() {
    const res = await fetch('/api/token/revoke', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${storedToken}`
        }
    });
    const data = await res.json();
    document.getElementById('token-result').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}
