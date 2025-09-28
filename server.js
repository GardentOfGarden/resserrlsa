const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'eclipse_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        balance DECIMAL(10,2) DEFAULT 0.00,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        version TEXT DEFAULT '1.0',
        secret TEXT,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id INTEGER,
        license_key TEXT UNIQUE,
        hwid TEXT,
        hwid_locked BOOLEAN DEFAULT 0,
        expires_at DATETIME,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(app_id) REFERENCES applications(id)
    )`);

    db.run(`CREATE TABLE sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        license_id INTEGER,
        app_id INTEGER,
        token TEXT,
        session_id TEXT,
        hwid TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(license_id) REFERENCES licenses(id),
        FOREIGN KEY(app_id) REFERENCES applications(id)
    )`);

    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
        ['admin', 'admin@eclipse.com', defaultPassword]);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
}

app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.json({ success: false, message: 'All fields are required' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
        [username, email, hashedPassword], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'User already exists' });
            }
            res.json({ success: true, message: 'Registration successful' });
        });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({
            success: true,
            token: token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    });
});

app.get('/api/apps', authenticateToken, (req, res) => {
    db.all(`
        SELECT a.*, 
               (SELECT COUNT(*) FROM licenses WHERE app_id = a.id) as keys_count,
               (SELECT COUNT(*) FROM sessions WHERE app_id = a.id AND datetime(expires_at) > datetime('now')) as online_users
        FROM applications a 
        WHERE user_id = ?
    `, [req.user.id], (err, apps) => {
        if (err) {
            return res.json({ success: false, message: 'Failed to fetch apps' });
        }
        res.json({ success: true, data: apps });
    });
});

app.post('/api/apps', authenticateToken, (req, res) => {
    const { name, version } = req.body;
    
    if (!name) {
        return res.json({ success: false, message: 'App name is required' });
    }

    const secret = require('crypto').randomBytes(32).toString('hex');
    
    db.run(`INSERT INTO applications (user_id, name, version, secret) VALUES (?, ?, ?, ?)`, 
        [req.user.id, name, version || '1.0', secret], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Failed to create app' });
            }
            res.json({ success: true, message: 'Application created successfully' });
        });
});

app.get('/api/keys', authenticateToken, (req, res) => {
    const appId = req.query.app_id;
    
    db.all(`
        SELECT l.* 
        FROM licenses l 
        JOIN applications a ON l.app_id = a.id 
        WHERE a.user_id = ? AND l.app_id = ?
    `, [req.user.id, appId], (err, keys) => {
        if (err) {
            return res.json({ success: false, message: 'Failed to fetch keys' });
        }
        res.json({ success: true, data: keys });
    });
});

app.post('/api/keys', authenticateToken, (req, res) => {
    const { app_id, expires_at, hwid_locked } = req.body;
    
    if (!app_id) {
        return res.json({ success: false, message: 'app_id is required' });
    }

    const key = require('crypto').randomBytes(16).toString('hex').toUpperCase();
    
    db.run(`INSERT INTO licenses (app_id, license_key, hwid_locked, expires_at) VALUES (?, ?, ?, ?)`, 
        [app_id, key, hwid_locked || false, expires_at], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Failed to generate key' });
            }
            res.json({ success: true, key: key });
        });
});

app.post('/api/verify', (req, res) => {
    const { app_name, owner_id, version, license_key, hwid } = req.body;
    
    if (!app_name || !owner_id || !license_key || !hwid) {
        return res.json({ success: false, message: 'Missing required fields' });
    }

    db.get(`
        SELECT l.*, a.name as app_name, a.user_id as owner_id 
        FROM licenses l 
        JOIN applications a ON l.app_id = a.id 
        WHERE a.name = ? AND a.user_id = ? AND l.license_key = ?
    `, [app_name, owner_id, license_key], (err, license) => {
        if (err || !license) {
            return res.json({ success: false, message: 'Invalid license key' });
        }

        if (license.hwid_locked && license.hwid && license.hwid !== hwid) {
            return res.json({ success: false, message: 'HWID mismatch' });
        }

        if (license.expires_at && new Date(license.expires_at) < new Date()) {
            return res.json({ success: false, message: 'License expired' });
        }

        if (license.hwid_locked && !license.hwid) {
            db.run(`UPDATE licenses SET hwid = ? WHERE id = ?`, [hwid, license.id]);
        }

        const sessionId = require('crypto').randomBytes(32).toString('hex');
        db.run(`INSERT INTO sessions (license_id, app_id, session_id, hwid, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+1 hour'))`, 
            [license.id, license.app_id, sessionId, hwid]);
        
        res.json({
            success: true, 
            session_id: sessionId,
            message: 'License verified successfully'
        });
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Eclipse Auth Server running on port ${PORT}`);
});
