require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const DOMAIN = process.env.COOKIE_DOMAIN || undefined; // например ".your-domain.com"
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProd = NODE_ENV === 'production';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
if (!ACCESS_SECRET || !REFRESH_SECRET) {
  console.error("ERROR: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set in env");
  process.exit(1);
}

const ACCESS_EXPIRES = '15m';
const REFRESH_EXPIRES = '7d';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const REFRESH_FILE = path.join(DATA_DIR, 'refreshTokens.json');

// ensure data files exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]', 'utf8');
if (!fs.existsSync(REFRESH_FILE)) fs.writeFileSync(REFRESH_FILE, '[]', 'utf8');

const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
const writeUsers = (arr) => fs.writeFileSync(USERS_FILE, JSON.stringify(arr, null, 2), 'utf8');

const readRefreshStore = () => JSON.parse(fs.readFileSync(REFRESH_FILE, 'utf8'));
const writeRefreshStore = (arr) => fs.writeFileSync(REFRESH_FILE, JSON.stringify(arr, null, 2), 'utf8');

const app = express();

// security headers
app.use(helmet());

// allow reverse proxy (e.g. Render, Heroku) to set secure cookies correctly
if (isProd) {
  app.set('trust proxy', 1);
}

// CORS
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

// rate limiters
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per windowMs
  message: { message: "Too many requests, try again later" },
});

const signAccess = (user) => jwt.sign({ id: user.id, email: user.email }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
const signRefresh = (user, tokenId) => jwt.sign({ id: user.id, tokenId }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });

// cookie options helper
const cookieOptions = (maxAgeMs) => ({
  httpOnly: true,
  secure: isProd, // only over https in production
  sameSite: isProd ? 'none' : 'lax', // if frontend on another domain in prod, use 'none'
  domain: DOMAIN, // optional
  maxAge: maxAgeMs,
});

// helpers for refresh token store (we store hashes)
const addRefreshToken = async ({ tokenId, userId, token }) => {
  const store = readRefreshStore();
  const hash = await bcrypt.hash(token, 10);
  const expiresAt = Date.now() + 7 * 24 * 3600 * 1000;
  store.push({ tokenId, userId, tokenHash: hash, expiresAt, createdAt: Date.now() });
  writeRefreshStore(store);
};

const removeRefreshToken = (tokenId) => {
  const store = readRefreshStore();
  const filtered = store.filter(r => r.tokenId !== tokenId);
  writeRefreshStore(filtered);
};

const findRefreshRecord = (tokenId) => {
  const store = readRefreshStore();
  return store.find(r => r.tokenId === tokenId);
};

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing email or password' });

    const users = readUsers();
    if (users.find(u => u.email === email)) return res.status(409).json({ message: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = { id: uuidv4(), name: name || '', email, passwordHash: hash, createdAt: new Date().toISOString() };
    users.push(user);
    writeUsers(users);

    // create tokens
    const access = signAccess(user);
    const tokenId = uuidv4();
    const refresh = signRefresh(user, tokenId);

    // store hashed refresh
    await addRefreshToken({ tokenId, userId: user.id, token: refresh });

    // set cookies
    res.cookie('access', access, cookieOptions(15 * 60 * 1000));
    res.cookie('refresh', refresh, cookieOptions(7 * 24 * 3600 * 1000));

    res.status(201).json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
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

// auth middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.access;
  if (!token) return res.status(401).end();
  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).end();
  }
};

// /me
app.get('/api/auth/me', authenticate, (req, res) => {
  try {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).end();
    res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).end();
  }
});

// refresh (rotation)
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const token = req.cookies.refresh;
    if (!token) return res.status(401).end();

    let payload;
    try {
      payload = jwt.verify(token, REFRESH_SECRET);
    } catch (err) {
      return res.status(401).end();
    }

    const tokenId = payload.tokenId;
    const record = findRefreshRecord(tokenId);
    if (!record) {
      // possible reuse / theft -> reject
      return res.status(401).end();
    }

    // check expiry
    if (record.expiresAt && Date.now() > record.expiresAt) {
      removeRefreshToken(tokenId);
      return res.status(401).end();
    }

    // verify hash
    const match = await bcrypt.compare(token, record.tokenHash);
    if (!match) {
      // token tampered or reuse -> remove and reject
      removeRefreshToken(tokenId);
      return res.status(401).end();
    }

    // OK — rotate: remove old, create new token & record
    removeRefreshToken(tokenId);

    const users = readUsers();
    const user = users.find(u => u.id === payload.id);
    if (!user) return res.status(401).end();

    const newTokenId = uuidv4();
    const newRefresh = signRefresh(user, newTokenId);
    await addRefreshToken({ tokenId: newTokenId, userId: user.id, token: newRefresh });

    const newAccess = signAccess(user);
    res.cookie('access', newAccess, cookieOptions(15 * 60 * 1000));
    res.cookie('refresh', newRefresh, cookieOptions(7 * 24 * 3600 * 1000));

    return res.json({ id: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    return res.status(500).end();
  }
});

// logout (remove that specific refresh token if present)
app.post('/api/auth/logout', (req, res) => {
  try {
    const token = req.cookies.refresh;
    if (token) {
      try {
        const payload = jwt.verify(token, REFRESH_SECRET);
        if (payload && payload.tokenId) {
          removeRefreshToken(payload.tokenId);
        }
      } catch (e) {
        // ignore
      }
    }

    res.clearCookie('access', { domain: DOMAIN, secure: isProd, sameSite: isProd ? 'none' : 'lax' });
    res.clearCookie('refresh', { domain: DOMAIN, secure: isProd, sameSite: isProd ? 'none' : 'lax' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).end();
  }
});

// optional: static serve (if you build frontend into client/dist and deploy on same server)
if (process.env.SERVE_CLIENT === 'true') {
  const clientDist = path.join(__dirname, 'client', 'dist');
  if (fs.existsSync(clientDist)) {
    app.use(express.static(clientDist));
    app.get('*', (_, res) => res.sendFile(path.join(clientDist, 'index.html')));
  }
}

app.listen(PORT, () => {
  console.log(`Auth server started on http://localhost:${PORT} (NODE_ENV=${NODE_ENV})`);
});
