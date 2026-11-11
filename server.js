const express = require('express');
const session = require('express-session');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();

// DB 연결 (접속 정보는 .env에서)
const DB = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// 미들웨어
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));

const requireLogin = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: '로그인이 필요합니다.' });
    }
    next();
};

// 로컬 테스트용 정적 파일 (VM에서는 Nginx가 public을 제공)
app.use(express.static(path.join(__dirname, 'public')));

// DB 연결 테스트
DB.connect(err => {
    if (err) {
        console.error('MySQL 연결 실패', err);
        return;
    }
    console.log('MySQL 연결 성공');
});

// 회원가입
app.post('/api/register', async (req, res) => {
    const { userid, userpw } = req.body;
    if (!userid || !userpw) {
        return res.status(400).send('ID와 PW를 입력하세요.');
    }
    const hash = await bcrypt.hash(userpw, 10);
    const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
    DB.query(sql, [userid, hash], (err) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(409).send('이미 사용 중인 ID입니다.');
            }
            console.error('회원가입 실패:', err);
            return res.status(500).send('DB 오류');
        }
        res.redirect('/');
    });
});

// 로그인
app.post('/api/login', (req, res) => {
    const { userid, userpw } = req.body;
    const sql = 'SELECT id, username, password_hash FROM users WHERE username = ?';
    DB.query(sql, [userid], async (err, rows) => {
        if (err) {
            console.error('로그인 조회 실패:', err);
            return res.status(500).send('DB 오류');
        }
        const ok = rows.length > 0 && await bcrypt.compare(userpw, rows[0].password_hash);
        if (!ok) {
            return res.status(401).send('<h1>Login Failed</h1><p>ID 또는 PW가 잘못되었습니다.</p>');
        }
        req.session.user = { id: rows[0].id, username: rows[0].username };
        console.log('로그인 성공:', req.session.user);
        res.redirect('/welcome.html');
    });
});

// 로그인한 사용자 정보 (welcome.html에서 확인용)
app.get('/api/me', requireLogin, (req, res) => {
    res.json(req.session.user);
});

// 로그아웃
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log(`서버 실행: http://127.0.0.1:${PORT}`);
});