const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';

// 模拟 Token 黑名单（生产环境建议使用 Redis）
const tokenBlacklist = new Set();
const pasetoBlacklist = new Set(); // 新增 PASETO 黑名单

// 模拟 Opaque Token 存储（生产环境建议使用 Redis）
const opaqueTokenStore = new Map();
const crypto = require('crypto');

// PASETO 密钥 (必须是 32 字节)
const PASETO_KEY = crypto.randomBytes(32);

// --- PASETO 模拟实现 (由于 Node 12 兼容性问题，我们手动实现一个符合 PASETO 理念的加密 Token) ---
const PASETO_SIM = {
    encrypt: (payload, key) => {
        const header = 'v1.local.';
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        // 格式：header + nonce + ciphertext + tag (全部 base64url)
        const token = header + Buffer.concat([nonce, ciphertext, tag]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        return token;
    },
    decrypt: (token, key) => {
        if (!token.startsWith('v1.local.')) throw new Error('Invalid token header');
        const raw = Buffer.from(token.slice(9).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const nonce = raw.slice(0, 12);
        const tag = raw.slice(raw.length - 16);
        const ciphertext = raw.slice(12, raw.length - 16);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return JSON.parse(decrypted.toString('utf8'));
    }
};

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: 'session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // 1 minute
}));

// --- 1. Cookie Demo ---
app.get('/api/cookie/set', (req, res) => {
    res.cookie('user_cookie', 'cookie_value_123', { maxAge: 900000, httpOnly: true });
    res.json({ message: 'Cookie has been set' });
});

app.get('/api/cookie/get', (req, res) => {
    const userCookie = req.cookies.user_cookie;
    res.json({ cookie: userCookie || 'No cookie found' });
});

// --- 2. Session Demo ---
app.get('/api/session/set', (req, res) => {
    req.session.user = { id: 1, name: 'SessionUser' };
    res.json({ 
        message: 'Session has been set',
        sessionId: req.sessionID // 返回生成的 Session ID
    });
});

app.get('/api/session/get', (req, res) => {
    if (req.session.user) {
        res.json({ 
            session: req.session.user,
            sessionId: req.sessionID // 返回当前的 Session ID
        });
    } else {
        res.json({ message: 'No session found' });
    }
});

// --- 3. Token (JWT) Demo ---
app.post('/api/token/login', (req, res) => {
    const user = { id: 1, name: 'TokenUser' };
    const token = jwt.sign(user, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

app.post('/api/token/revoke', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        tokenBlacklist.add(token); // 将当前 Token 加入黑名单
        res.json({ message: 'Token has been revoked (added to blacklist)' });
    } else {
        res.json({ message: 'No token provided' });
    }
});

app.get('/api/token/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token required' });

    // 检查是否在黑名单中
    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ message: 'Token has been revoked' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        res.json({ user });
    });
});

// --- 4. Opaque Token Demo ---
app.post('/api/opaque/login', (req, res) => {
    const user = { id: 100, name: 'OpaqueUser' };
    const token = crypto.randomBytes(32).toString('hex'); // 生成一个没有任何意义的随机字符串
    
    // 将 Token 和用户信息存入服务器端的 Store
    opaqueTokenStore.set(token, user);
    
    res.json({ token });
});

app.get('/api/opaque/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Opaque Token required' });

    const user = opaqueTokenStore.get(token);
    if (!user) {
        return res.status(401).json({ message: 'Invalid or revoked Opaque Token' });
    }

    res.json({ user });
});

app.post('/api/opaque/revoke', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        opaqueTokenStore.delete(token); // 直接从服务器端删除，实现秒级撤销
        res.json({ message: 'Opaque Token has been successfully deleted/revoked' });
    } else {
        res.json({ message: 'No token provided' });
    }
});

// --- 5. PASETO Demo ---
app.post('/api/paseto/login', (req, res) => {
    const user = { id: 200, name: 'PasetoUser', role: 'admin' };
    try {
        console.log('Generating PASETO-SIM token...');
        const token = PASETO_SIM.encrypt(user, PASETO_KEY);
        console.log('Token generated:', token);
        res.json({ token });
    } catch (err) {
        console.error('PASETO Error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/paseto/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'PASETO Token required' });

    // 检查黑名单
    if (pasetoBlacklist.has(token)) {
        return res.status(401).json({ message: 'PASETO Token has been revoked' });
    }

    try {
        const payload = PASETO_SIM.decrypt(token, PASETO_KEY);
        res.json({ user: payload });
    } catch (err) {
        res.status(403).json({ message: 'Invalid or expired PASETO token', error: err.message });
    }
});

app.post('/api/paseto/revoke', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        pasetoBlacklist.add(token);
        res.json({ message: 'PASETO Token revoked successfully' });
    } else {
        res.status(400).json({ message: 'No token provided' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
