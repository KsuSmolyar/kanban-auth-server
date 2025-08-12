require('dotenv').config();
require('./createTables');
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

// --- Конфигурация ---
const PORT = process.env.PORT || 4000;
const DOMAIN = process.env.NODE_ENV === "production"
      ? process.env.COOKIE_DOMAIN_PROD
      : process.env.COOKIE_DOMAIN_LOCAL;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
if (!ACCESS_SECRET || !REFRESH_SECRET) {
  console.error("ERROR: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set in .env");
  process.exit(1);
}

const ACCESS_EXPIRES = '15m';
const REFRESH_EXPIRES = '7d';

// --- Подключение к базе ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false
});

// --- Приложение ---
const app = express();
app.use(helmet());
if (isProd) app.set('trust proxy', 1);

const allowedOrigins = [
  'http://localhost:5173',
  'https://ksusmolyar.github.io',
];

const corsOptions = {
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(null, false); // вместо ошибки
  },
  credentials: true,
};

app.use(cors(corsOptions));

// Обработка preflight запросов OPTIONS для всех маршрутов
// app.options('*', cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// --- Лимитер ---
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { message: "Too many requests, try again later" },
});

// --- JWT утилиты ---
const signAccess = (user) =>
  jwt.sign({ id: user.id, email: user.email }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });

const signRefresh = (user, tokenId) =>
  jwt.sign({ id: user.id, tokenId }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });

const cookieOptions = (maxAgeMs) => {
  const base = {
    httpOnly: true,
    secure: isProd,                   // в деве false, в проде true
    sameSite: 'none', // в деве lax, в проде none
    maxAge: maxAgeMs,
  };
  if (DOMAIN) {
    base.domain = DOMAIN;             // domain только в проде, если задан
  }
  return base;
};

// --- DB функции ---
async function findUserByEmail(email) {
  const res = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return res.rows[0];
}

async function findUserById(id) {
  const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return res.rows[0];
}

async function addUser(user) {
  await pool.query(
    `INSERT INTO users (id, name, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $5)`,
    [user.id, user.name, user.email, user.passwordHash, user.createdAt]
  );
}

async function addRefreshToken({ tokenId, userId, token }) {
  const hash = await bcrypt.hash(token, 10);
  const expiresAt = Date.now() + 7 * 24 * 3600 * 1000;
  const createdAt = Date.now();
  await pool.query(
    `INSERT INTO refresh_tokens (token_id, user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)`,
    [tokenId, userId, hash, expiresAt, createdAt]
  );
}

async function findRefreshRecord(tokenId) {
  const res = await pool.query('SELECT * FROM refresh_tokens WHERE token_id = $1', [tokenId]);
  return res.rows[0];
}

async function removeRefreshToken(tokenId) {
  await pool.query('DELETE FROM refresh_tokens WHERE token_id = $1', [tokenId]);
}

// --- Middleware ---
const authenticate = (req, res, next) => {
  const token = req.cookies.access;
  if (!token) return res.status(401).end();
  try {
    req.user = jwt.verify(token, ACCESS_SECRET);
    next();
  } catch {
    return res.status(401).end();
  }
};

// --- Роуты ---
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing email or password' });

    const existingUser = await findUserByEmail(email);
    if (existingUser) return res.status(409).json({ message: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = { id: uuidv4(), name: name || '', email, passwordHash: hash, createdAt: new Date().toISOString() };

    await addUser(user);

    const access = signAccess(user);
    const tokenId = uuidv4();
    const refresh = signRefresh(user, tokenId);

    await addRefreshToken({ tokenId, userId: user.id, token: refresh });

    res.cookie('access', access, cookieOptions(15 * 60 * 1000));
    res.cookie('refresh', refresh, cookieOptions(7 * 24 * 3600 * 1000));

    res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await findUserByEmail(email);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const access = signAccess(user);
    const tokenId = uuidv4();
    const refresh = signRefresh(user, tokenId);

    await addRefreshToken({ tokenId, userId: user.id, token: refresh });

    res.cookie('access', access, cookieOptions(15 * 60 * 1000));
    res.cookie('refresh', refresh, cookieOptions(7 * 24 * 3600 * 1000));

    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).end();
    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).end();
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  console.log('request cookies', req.cookies)
  try {
    const token = req.cookies.refresh;
    if (!token) return res.status(401).end();

    let payload;
    try {
      payload = jwt.verify(token, REFRESH_SECRET);
    } catch {
      return res.status(401).end();
    }

    const record = await findRefreshRecord(payload.tokenId);
    if (!record) return res.status(401).end();

    if (record.expires_at && Date.now() > Number(record.expires_at)) {
      await removeRefreshToken(payload.tokenId);
      return res.status(401).end();
    }

    const match = await bcrypt.compare(token, record.token_hash);
    if (!match) {
      await removeRefreshToken(payload.tokenId);
      return res.status(401).end();
    }

    await removeRefreshToken(payload.tokenId);

    const user = await findUserById(payload.id);
    if (!user) return res.status(401).end();

    const newTokenId = uuidv4();
    const newRefresh = signRefresh(user, newTokenId);
    await addRefreshToken({ tokenId: newTokenId, userId: user.id, token: newRefresh });

    const newAccess = signAccess(user);
    res.cookie('access', newAccess, cookieOptions(15 * 60 * 1000));
    res.cookie('refresh', newRefresh, cookieOptions(7 * 24 * 3600 * 1000));

    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).end();
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const token = req.cookies.refresh;
    if (token) {
      try {
        const payload = jwt.verify(token, REFRESH_SECRET);
        if (payload?.tokenId) {
          await removeRefreshToken(payload.tokenId);
        }
      } catch {
        // ignore
      }
    }

    res.clearCookie('access', {
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      domain: isProd && DOMAIN ? DOMAIN : undefined,
    });
    res.clearCookie('refresh', {
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      domain: isProd && DOMAIN ? DOMAIN : undefined,
    });
     res.json({ ok: true });
  } catch (err) {
      console.error(err);
      res.status(500).end();
  }
});

// --- Раздача клиента ---
// if (process.env.SERVE_CLIENT === 'true') {
//   const clientDist = path.join(__dirname, 'client', 'dist');
//   if (fs.existsSync(clientDist)) {
//     app.use(express.static(clientDist));
//     app.get('*', (_, res) => res.sendFile(path.join(clientDist, 'index.html')));
//   }
// }

app.listen(PORT,'0.0.0.0', () => {
  console.log(`Auth server started on http://localhost:${PORT} (NODE_ENV=${NODE_ENV})`);
});
