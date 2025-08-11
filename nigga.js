const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;
const SECRET_KEY = crypto.randomBytes(32).toString('hex'); // Gere uma chave secreta única para JWT
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('sua_senha_admin_segura', 10); // Defina uma senha admin forte e hasheie

// Configurações de segurança
app.use(cors({ origin: 'http://seu-site.com' })); // Restrinja ao domínio do seu site
app.use(bodyParser.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })); // Limite de requests para evitar ataques

// Banco de dados SQLite (simples e sem necessidade de instalação extra)
const db = new sqlite3.Database('./referencias.db', (err) => {
  if (err) {
    console.error('Erro ao conectar ao DB:', err.message);
  } else {
    console.log('Conectado ao DB.');
    // Cria tabelas se não existirem
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      referral_link TEXT UNIQUE,
      percentage REAL NOT NULL DEFAULT 0,
      balance REAL NOT NULL DEFAULT 0,
      is_referrer INTEGER NOT NULL DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      referrer_id INTEGER,
      sale_value REAL NOT NULL,
      commission REAL NOT NULL,
      date TEXT NOT NULL,
      FOREIGN KEY(referrer_id) REFERENCES users(id)
    )`);
  }
});

// Middleware de autenticação JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Middleware de autenticação Admin
const authenticateAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.sendStatus(403);
  }
};

// Endpoint para login admin (protegido)
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    const token = jwt.sign({ role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Senha incorreta' });
  }
});

// Endpoint admin: Selecionar usuário como referrer e definir %
app.post('/admin/set-referrer', authenticateJWT, authenticateAdmin, (req, res) => {
  const { username, percentage } = req.body;
  if (!username || percentage <= 0 || percentage > 100) {
    return res.status(400).json({ error: 'Dados inválidos' });
  }
  const referral_link = `https://seu-site.com/?ref=${crypto.randomBytes(16).toString('hex')}`;
  db.run(`INSERT OR REPLACE INTO users (username, referral_link, percentage, is_referrer) VALUES (?, ?, ?, 1)`,
    [username, referral_link, percentage],
    (err) => {
      if (err) return res.status(500).json({ error: 'Erro no DB' });
      res.json({ success: true, referral_link });
    }
  );
});

// Endpoint admin: Listar todos referrers
app.get('/admin/referrers', authenticateJWT, authenticateAdmin, (req, res) => {
  db.all(`SELECT username, referral_link, percentage, balance FROM users WHERE is_referrer = 1`, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro no DB' });
    res.json(rows);
  });
});

// Endpoint para usuário: Obter dados de referrer (visível só para selecionados)
app.get('/user/referral', authenticateJWT, (req, res) => {
  const { username } = req.user; // Assuma que o JWT tem o username do usuário logado
  db.get(`SELECT referral_link, percentage, balance FROM users WHERE username = ? AND is_referrer = 1`, [username], (err, row) => {
    if (err || !row) return res.status(403).json({ error: 'Acesso negado ou não é referrer' });
    res.json(row);
  });
});

// Endpoint para registrar venda via link (chamado pelo site após compra)
app.post('/register-sale', authenticateJWT, authenticateAdmin, (req, res) => { // Protegido para admin ou integração segura
  const { ref_code, sale_value } = req.body;
  if (!ref_code || sale_value <= 0) return res.status(400).json({ error: 'Dados inválidos' });
  db.get(`SELECT id, percentage FROM users WHERE referral_link LIKE '%ref=${ref_code}'`, (err, referrer) => {
    if (err || !referrer) return res.status(404).json({ error: 'Referrer não encontrado' });
    const commission = (referrer.percentage / 100) * sale_value;
    const date = new Date().toISOString();
    db.run(`INSERT INTO sales (referrer_id, sale_value, commission, date) VALUES (?, ?, ?, ?)`,
      [referrer.id, sale_value, commission, date],
      (err) => {
        if (err) return res.status(500).json({ error: 'Erro no DB' });
        db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [commission, referrer.id]);
        res.json({ success: true, commission });
      }
    );
  });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
