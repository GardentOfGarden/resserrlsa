const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'eclipse_secret_2024';

app.use(express.json());
app.use(express.static('.'));

// База данных в памяти
const db = new sqlite3.Database(':memory:');

// Инициализация БД
db.serialize(() => {
    // Таблица пользователей
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Таблица приложений
    db.run(`CREATE TABLE applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        version TEXT DEFAULT '1.0',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Таблица ключей
    db.run(`CREATE TABLE license_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id INTEGER,
        key TEXT UNIQUE,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Создаем тестового пользователя
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, ['admin', hashedPassword]);
    
    // Создаем тестовое приложение
    db.run(`INSERT INTO applications (user_id, name) VALUES (?, ?)`, [1, 'TestApp']);
});

// Middleware проверки токена
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    try {
        const user = jwt.verify(token, JWT_SECRET);
        req.user = user;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Логин
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.json({ success: false, error: 'User not found' });
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.json({ success: false, error: 'Wrong password' });
        }
        
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
        res.json({ success: true, token, user: { id: user.id, username: user.username } });
    });
});

// Получить приложения
app.get('/api/apps', authMiddleware, (req, res) => {
    db.all('SELECT * FROM applications WHERE user_id = ?', [req.user.id], (err, apps) => {
        if (err) return res.json({ success: false, error: err.message });
        res.json({ success: true, apps: apps || [] });
    });
});

// Создать приложение
app.post('/api/apps', authMiddleware, (req, res) => {
    const { name } = req.body;
    if (!name) return res.json({ success: false, error: 'Name required' });
    
    db.run('INSERT INTO applications (user_id, name) VALUES (?, ?)', [req.user.id, name], function(err) {
        if (err) return res.json({ success: false, error: err.message });
        res.json({ success: true, appId: this.lastID });
    });
});

// Получить ключи приложения
app.get('/api/apps/:appId/keys', authMiddleware, (req, res) => {
    const appId = req.params.appId;
    
    db.all('SELECT * FROM license_keys WHERE app_id = ?', [appId], (err, keys) => {
        if (err) return res.json({ success: false, error: err.message });
        res.json({ success: true, keys: keys || [] });
    });
});

// Создать ключ
app.post('/api/apps/:appId/keys', authMiddleware, (req, res) => {
    const appId = req.params.appId;
    const key = 'ECL-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    
    db.run('INSERT INTO license_keys (app_id, key) VALUES (?, ?)', [appId, key], function(err) {
        if (err) return res.json({ success: false, error: err.message });
        res.json({ success: true, key });
    });
});

// Проверка ключа
app.post('/api/verify', (req, res) => {
    const { app_name, owner_id, license_key, hwid } = req.body;
    
    db.get(`
        SELECT lk.*, a.name as app_name, a.user_id as owner_id 
        FROM license_keys lk 
        JOIN applications a ON lk.app_id = a.id 
        WHERE a.name = ? AND a.user_id = ? AND lk.key = ? AND lk.status = 'active'
    `, [app_name, owner_id, license_key], (err, key) => {
        if (err || !key) {
            return res.json({ success: false, error: 'Invalid license key' });
        }
        
        res.json({ success: true, message: 'License valid' });
    });
});

// Статические файлы
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
    console.log(`👤 Логин: admin`);
    console.log(`🔑 Пароль: admin123`);
});
