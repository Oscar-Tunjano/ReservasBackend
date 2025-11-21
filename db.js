// db.js
import { Pool } from "pg";
import dotenv from "dotenv";

dotenv.config();

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" 
       ? { rejectUnauthorized: false }
       : false
});

// Eventos útiles
db.on("connect", () => console.log("✅ Conectado a PostgreSQL (Pool listo)"));
db.on("error", (err) => console.error("❌ Error en el Pool de PostgreSQL:", err));


