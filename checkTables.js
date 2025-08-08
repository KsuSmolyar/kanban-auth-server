require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  try {
    const res = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public';
    `);
    console.log("Таблицы в БД:", res.rows);
  } catch (err) {
    console.error("Ошибка подключения:", err);
  } finally {
    await pool.end();
  }
})();
