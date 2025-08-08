const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // сюда ставь строку подключения из Render
  ssl: {
    rejectUnauthorized: false, // важно для облачных БД (Render, Heroku и др.)
  },
});

const createTables = async () => {
  try {
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(100),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL
      );
    `);
    console.log('Таблицы успешно созданы или уже существуют');
  } catch (err) {
    console.error('Ошибка при создании таблиц:', err);
  } finally {
    await pool.end();
  }
};

createTables();
