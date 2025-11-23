// ==============================================
// init_db.js — PostgreSQL (Render)
// Crea tablas solo si no existen (NO elimina datos)
// ==============================================

import { db } from "./db.js";

export default async function initDatabase() {
  try {
    console.log("⏳ Verificando estructura de la base de datos (Postgres)...");

    // ===============================
    // USUARIOS
    // ===============================
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

    // ===============================
    // PROPIEDADES
    // ===============================
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

    // ===============================
    // RESERVAS
    // ===============================
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

    // Índice para optimización
    await db.query(`
      CREATE INDEX IF NOT EXISTS idx_res_prop_dates
      ON reservas (propiedad_id, fecha_inicio, fecha_fin);
    `);

    // ===============================
    // CONTACTOS (formulario contacto)
    // ===============================
    await db.query(`
      CREATE TABLE IF NOT EXISTS contactos (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(200),
        correo VARCHAR(200),
        telefono VARCHAR(50),
        mensaje TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ Base de datos lista (Postgres)");
  } catch (error) {
    console.error("❌ Error inicializando base de datos:", error);
    throw error;
  }
}
