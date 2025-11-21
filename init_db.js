// init_db.js
import { db } from "./db.js";

export default async function initDatabase() {
  try {
    console.log("⏳ Verificando/creando tablas en PostgreSQL...");

    // ================================
    // USUARIOS
    // ================================
    await db.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(200) NOT NULL,
        correo VARCHAR(200) UNIQUE NOT NULL,
        contrasena TEXT NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'cliente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ================================
    // PROPIEDADES
    // ================================
    await db.query(`
      CREATE TABLE IF NOT EXISTS propiedades (
        id SERIAL PRIMARY KEY,
        titulo VARCHAR(200) NOT NULL,
        descripcion TEXT,
        precio NUMERIC(10,2) NOT NULL DEFAULT 0,
        ubicacion VARCHAR(200),
        imagen TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ================================
    // RESERVAS
    // ================================
    await db.query(`
      CREATE TABLE IF NOT EXISTS reservas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        propiedad_id INTEGER NOT NULL REFERENCES propiedades(id) ON DELETE CASCADE,
        fecha_inicio DATE NOT NULL,
        fecha_fin DATE NOT NULL,
        estado VARCHAR(50) NOT NULL DEFAULT 'pendiente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ================================
    // ÍNDICES
    // ================================
    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_res_prop_dates
      ON reservas (propiedad_id, fecha_inicio, fecha_fin);
    `);

    console.log("✅ Tablas verificadas/creadas correctamente.");
  } catch (err) {
    console.error("❌ Error iniciando BD:", err);
  }
}
