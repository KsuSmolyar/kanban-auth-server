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
const { WebSocketServer } = require('ws');

// --- Конфигурация ---
const PORT = process.env.PORT || 4000;
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
    sameSite: isProd ? 'none' : "lax", // в деве lax, в проде none
    maxAge: maxAgeMs,
  };
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

// ================= WebSocket =================
const server = require('http').createServer(app);
// const { WebSocketServer } = require('ws');
const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  console.log('Client connected via WebSocket');
  ws.send(JSON.stringify({ type: 'connected', message: 'WebSocket connected' }));

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

// Функция для отправки сообщений всем клиентам
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === client.OPEN) client.send(msg);
  });
}

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
  try {
    const token = req.cookies.refresh;
    if (!token) return res.status(401).json({ message: 'Refresh token not found' });

    let payload;
    try {
      payload = jwt.verify(token, REFRESH_SECRET);
    } catch {
      return res.status(401).json({ message: 'Failed verify refresh token' });
    }
    const record = await findRefreshRecord(payload.tokenId);

    if (!record) return res.status(401).json({ message: `Record not found`});


    if (record.expires_at && Date.now() > Number(record.expires_at)) {
      await removeRefreshToken(payload.tokenId);
      return res.status(401).json({ message: 'Refresh token is expired' });
    }

    const match = await bcrypt.compare(token, record.token_hash);
    if (!match) {
      await removeRefreshToken(payload.tokenId);
      return res.status(401).json({ message: 'Refresh token not match' })
    }

    await removeRefreshToken(payload.tokenId);

    const user = await findUserById(payload.id);
    if (!user) return res.status(401).json({ message: 'User not found' });


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
    });
    res.clearCookie('refresh', {
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
    });
     res.json({ ok: true });
  } catch (err) {
      console.error(err);
      res.status(500).end();
  }
});

// ===================== TASKS =====================

// Получить все задачи 
app.get('/api/tasks', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        t.*,
        u.name AS author_name
      FROM tasks t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Создать новую задачу
app.post('/api/tasks', authenticate, async (req, res) => {
  try {
    const { title, description, status, deadline, tags } = req.body;
    if (!title) return res.status(400).json({ message: 'Требуется title' });

    const result = await pool.query(
      `INSERT INTO tasks (title, description, status, user_id, deadline, tags)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
      [
        title,
        description || '',
        status || 'todo',
        req.user.id,
        deadline ? new Date(deadline) : null,               // конвертируем в Date
        JSON.stringify(Array.isArray(tags) ? tags : [])
      ]
    );
    const task = result.rows[0];
    broadcast({ type: 'task_created', payload: task });
    res.status(201).json(task);
  } catch (err) {
    // console.error(err);
    console.error('Ошибка при добавлении задачи:', err.message, err.stack);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Редактировать существующую задачу
app.put('/api/tasks/:id', authenticate, async (req, res) => {
  try {
    const taskId = req.params.id;
    const { title, description, status, deadline, tags } = req.body;

    if (!title) return res.status(400).json({ message: 'Требуется title' });

    // Обновляем задачу
    const result = await pool.query(
      `UPDATE tasks
       SET title = $1,
           description = $2,
           status = $3,
           deadline = $4,
           tags = $5
       WHERE id = $6
       RETURNING *`,
      [
        title,
        description || '',
        status || 'todo',
        deadline ? new Date(deadline) : null,               // конвертируем в Date
        JSON.stringify(Array.isArray(tags) ? tags : []),
        taskId
      ]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Задача не найдена' });
    }

    // Получаем актуальный список всех задач
    const updatedTask = await pool.query(
      `SELECT 
        t.*,
        u.name AS author_name
      FROM tasks t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at ASC`
    );

    broadcast({ type: "task_updated", payload: updatedTask.rows });
    res.json(updatedTask.rows);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

app.delete('/api/tasks/:id', authenticate, async(req, res) => {
  try {
    const taskId = req.params.id;

    // Проверяем, что задача существует
    const check = await pool.query(
      `SELECT * FROM tasks WHERE id = $1`,
      [taskId]
    );

    if (check.rowCount === 0) {
      return res.status(404).json({ message: 'Задача не найдена' });
    }

    // Проверка прав — удалять может автор или админ
    if (check.rows[0].author_id !== req.user.id && !req.user.is_admin) {
      return res.status(403).json({ message: 'Нет прав на удаление задачи' });
    }

    // Удаляем задачу
    await pool.query(`DELETE FROM tasks WHERE id = $1`, [taskId]);

    // Получаем актуальный список задач
    const tasks = await pool.query(
      `SELECT 
        t.id,
        t.title,
        t.description,
        t.status,
        t.author_id,
        u.name AS author_name,
        t.created_at,
        t.updated_at
      FROM tasks t
      JOIN users u ON t.author_id = u.id
      ORDER BY t.created_at ASC`
    );

    broadcast({ type: "task_deleted", payload: tasks.rows });

    res.status(200).json(tasks.rows);
  } catch (err) {
    console.error(err);
     res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
})

// ===================== COMMENTS =====================

// Получить комментарии для задачи
app.get('/api/comments/:taskId', authenticate, async (req, res) => {
  try {
    const { taskId } = req.params;
    const result = await pool.query(`
      SELECT 
        c.id,
        c.task_id,
        c.author_id,
        u.name AS user_name,
        c.content,
        c.created_at,
        c.replied_comment_id,
        parent_u.name AS replied_comment_author,
        parent_c.content AS replied_comment_content
      FROM comments c
      JOIN users u ON c.author_id = u.id
      LEFT JOIN comments parent_c ON c.replied_comment_id = parent_c.id
      LEFT JOIN users parent_u ON parent_c.author_id = parent_u.id
      WHERE c.task_id = $1
      ORDER BY c.created_at ASC
    `, [taskId]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера', error: err.message });
  }
});

// Добавить комментарий к задаче
app.post('/api/comments/:taskId', authenticate, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { content, repliedCommentId } = req.body;
    if (!content) return res.status(400).json({ message: 'Требуется content' });

    // 1. Вставляем новый комментарий
    await pool.query(
      `INSERT INTO comments (task_id, author_id, content, replied_comment_id)
       VALUES ($1, $2, $3, $4)`,
      [taskId, req.user.id, content, repliedCommentId || null]
    );

    // Достаем комментарий с данными об авторе и, если есть, о родительском комментарии
    const commentsResult = await pool.query(
      `SELECT 
        c.id,
        c.task_id,
        c.author_id,
        u.name AS user_name,
        c.content,
        c.created_at,
        c.replied_comment_id,
        parent_u.name AS replied_comment_author,
        parent_c.content AS replied_comment_content
      FROM comments c
      JOIN users u ON c.author_id = u.id
      LEFT JOIN comments parent_c ON c.replied_comment_id = parent_c.id
      LEFT JOIN users parent_u ON parent_c.author_id = parent_u.id
      WHERE c.task_id = $1
      ORDER BY c.created_at ASC
    `, [taskId]
    );

    broadcast({ type: "comment_created", payload: commentsResult.rows });
    res.status(201).json(commentsResult.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Удалить комментарий и вернуть актуальный список
app.delete('/api/comments/:taskId/:commentId', authenticate, async (req, res) => {
  try {
    const { taskId, commentId } = req.params;

    // Проверяем, что комментарий существует
    const check = await pool.query(
      `SELECT * FROM comments WHERE id = $1 AND task_id = $2`,
      [commentId, taskId]
    );

    if (check.rowCount === 0) {
      return res.status(404).json({ message: 'Комментарий не найден' });
    }

    // Проверка прав — удалять может только автор или админ
    if (check.rows[0].author_id !== req.user.id && !req.user.is_admin) {
      return res.status(403).json({ message: 'Нет прав на удаление комментария' });
    }

    // Удаляем комментарий
    await pool.query(
      `DELETE FROM comments WHERE id = $1 AND task_id = $2`,
      [commentId, taskId]
    );

    // Получаем актуальный список комментариев
    const comments = await pool.query(
      `SELECT 
        c.id,
        c.task_id,
        c.author_id,
        u.name AS user_name,
        c.content,
        c.created_at,
        c.replied_comment_id,
        parent_u.name AS replied_comment_author,
        parent_c.content AS replied_comment_content
      FROM comments c
      JOIN users u ON c.author_id = u.id
      LEFT JOIN comments parent_c ON c.replied_comment_id = parent_c.id
      LEFT JOIN users parent_u ON parent_c.author_id = parent_u.id
      WHERE c.task_id = $1
      ORDER BY c.created_at ASC`,
      [taskId]
    );

    broadcast({ type: "comment_deleted", payload: comments.rows });
    res.status(200).json(comments.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

server.listen(PORT,'0.0.0.0', () => {
  console.log(`Auth server started on http://localhost:${PORT} (NODE_ENV=${NODE_ENV})`);
});
