require('dotenv').config(); // Load the .env file
const { Pool } = require('pg');

const pool = new Pool({
    // If there is a Cloud URL, use it. Otherwise, use local settings.
    connectionString: process.env.DATABASE_URL || `postgresql://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false // Required for most cloud databases
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};