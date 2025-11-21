// db.js
import { Pool } from "pg";
import dotenv from "dotenv";
dotenv.config();

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

db.on("connect", () => console.log("✅ Pool conectado a PostgreSQL"));
db.on("error", (err) => console.error("❌ Error en pool Postgres:", err));


