// db.js
import pkg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Pool } = pkg;

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    require: true,
    rejectUnauthorized: false
  }
});

db.on("connect", () => console.log("✅ Pool conectado a PostgreSQL con SSL"));
db.on("error", (err) => console.error("❌ Error en pool Postgres:", err));
