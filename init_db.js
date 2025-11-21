// init_db.js
import { db } from "./db.js";

export default async function initDatabase() {
  try {
    console.log("⏳ Verificando/creando tablas en PostgreSQL...");

    // usuarios
    await db.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(200) NOT NULL,
        correo VARCHAR(200) UNIQUE NOT NULL,
        contrasena TEXT NOT NULL,
        role VARCHAR(50) DEFAULT 'cliente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // propiedades
    await db.query(`
      CREATE TABLE IF NOT EXISTS propiedades (
        id SERIAL PRIMARY KEY,
        titulo VARCHAR(200),
        descripcion TEXT,
        precio NUMERIC(10,2),
        ubicacion VARCHAR(200),
        imagen TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // reservas
    await db.query(`
      CREATE TABLE IF NOT EXISTS reservas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        propiedad_id INTEGER REFERENCES propiedades(id) ON DELETE CASCADE,
        fecha_inicio DATE NOT NULL,
        fecha_fin DATE NOT NULL,
        estado VARCHAR(50) DEFAULT 'pendiente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // índices (si no existen)
    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_res_prop_dates
      ON reservas (propiedad_id, fecha_inicio, fecha_fin);
    `);

    console.log("✅ Tablas verificadas/creadas correctamente.");
  } catch (err) {
    console.error("❌ Error iniciando BD:", err);
  }
}
