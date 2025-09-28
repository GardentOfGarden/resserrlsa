const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'eclipse_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database(':memory:');

// Инициализация базы данных
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
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

    // Создаем тестового пользователя
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
        ['admin', 'admin@eclipse.com', defaultPassword]);
});

// Middleware для проверки JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Требуется токен доступа' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Неверный токен' });
        }
        req.user = user;
        next();
    });
}

// Регистрация
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.json({ success: false, message: 'Все поля обязательны для заполнения' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
        [username, email, hashedPassword], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Пользователь уже существует' });
            }
            res.json({ success: true, message: 'Регистрация прошла успешно' });
        });
});

// Вход
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Введите логин и пароль' });
    }

    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Неверные учетные данные' });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.json({ success: false, message: 'Неверные учетные данные' });
        }

        const token = jwt.sign({ 
            id: user.id, 
            username: user.username 
        }, JWT_SECRET, { expiresIn: '24h' });
        
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

// Получить приложения пользователя
app.get('/api/apps', authenticateToken, (req, res) => {
    db.all(`
        SELECT a.*, 
               (SELECT COUNT(*) FROM licenses WHERE app_id = a.id) as keys_count
        FROM applications a 
        WHERE user_id = ?
    `, [req.user.id], (err, apps) => {
        if (err) {
            return res.json({ success: false, message: 'Ошибка при загрузке приложений' });
        }
        res.json({ success: true, data: apps || [] });
    });
});

// Создать приложение
app.post('/api/apps', authenticateToken, (req, res) => {
    const { name, version } = req.body;
    
    if (!name) {
        return res.json({ success: false, message: 'Название приложения обязательно' });
    }

    const secret = require('crypto').randomBytes(32).toString('hex');
    
    db.run(`INSERT INTO applications (user_id, name, version, secret) VALUES (?, ?, ?, ?)`, 
        [req.user.id, name, version || '1.0', secret], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Ошибка при создании приложения' });
            }
            res.json({ success: true, message: 'Приложение создано успешно' });
        });
});

// Создать лицензионный ключ
app.post('/api/keys', authenticateToken, (req, res) => {
    const { app_id } = req.body;
    
    if (!app_id) {
        return res.json({ success: false, message: 'ID приложения обязательно' });
    }

    const key = require('crypto').randomBytes(16).toString('hex').toUpperCase();
    
    db.run(`INSERT INTO licenses (app_id, license_key) VALUES (?, ?)`, 
        [app_id, key], 
        function(err) {
            if (err) {
                return res.json({ success: false, message: 'Ошибка при создании ключа' });
            }
            res.json({ success: true, key: key });
        });
});

// Верификация ключа
app.post('/api/verify', (req, res) => {
    const { app_name, owner_id, license_key, hwid } = req.body;
    
    if (!app_name || !owner_id || !license_key || !hwid) {
        return res.json({ success: false, message: 'Не все обязательные поля заполнены' });
    }

    db.get(`
        SELECT l.*, a.name as app_name, a.user_id as owner_id 
        FROM licenses l 
        JOIN applications a ON l.app_id = a.id 
        WHERE a.name = ? AND a.user_id = ? AND l.license_key = ?
    `, [app_name, owner_id, license_key], (err, license) => {
        if (err || !license) {
            return res.json({ success: false, message: 'Неверный лицензионный ключ' });
        }

        if (license.status !== 'active') {
            return res.json({ success: false, message: 'Лицензия не активна' });
        }

        if (license.expires_at && new Date(license.expires_at) < new Date()) {
            return res.json({ success: false, message: 'Срок действия лицензии истек' });
        }

        if (license.hwid_locked && license.hwid && license.hwid !== hwid) {
            return res.json({ success: false, message: 'HWID не совпадает' });
        }

        // Если HWID привязка включена, но HWID еще не установлен - устанавливаем
        if (license.hwid_locked && !license.hwid) {
            db.run(`UPDATE licenses SET hwid = ? WHERE id = ?`, [hwid, license.id]);
        }

        res.json({
            success: true, 
            message: 'Лицензия подтверждена успешно'
        });
    });
});

// Обслуживание статических файлов
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/apps.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'apps.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Eclipse Auth Server запущен на порту ${PORT}`);
    console.log(`📍 Логин: admin`);
    console.log(`📍 Пароль: admin123`);
});
