// =========================================
//  BACKEND RESERVAS — COMPLETO Y CORREGIDO
//  Render + PostgreSQL + Sesiones
// =========================================

import express from "express";
import session from "express-session";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { Pool } from "pg";

dotenv.config();
const app = express();

// ===============================
//  MIDDLEWARES BÁSICOS
// ===============================
app.use(express.json());

// =========================================
//  CABECERAS DE SEGURIDAD (Evita alerta roja en Chrome)
// =========================================
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

// =========================================
//  CORS
// =========================================
app.use(
  cors({
    origin: true,          // frontend desde cualquier dominio permitido
    credentials: true,     // enviar cookies de sesión
  })
);

app.set("trust proxy", 1);

// =========================================
//  SESIÓN (Render usa HTTPS siempre)
// =========================================
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 4, // 4 horas
    },
  })
);

// ===============================
//  CONEXIÓN A POSTGRES
// ===============================
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

db.connect()
  .then(() => console.log("✅ Conectado a PostgreSQL Render"))
  .catch((err) => console.error("❌ Error conectando a Postgres:", err));

// ===============================
//  HELPERS
// ===============================
function requireLogin(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: "Debes iniciar sesión" });
  next();
}

async function isAdmin(req) {
  return req.session.user?.role === "admin";
}

// ===============================
//  AUTH
// ===============================

// Registro usuario
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, correo, contraseña } = req.body;

    const hashed = await bcrypt.hash(contraseña, 10);

    await db.query(
      "INSERT INTO usuarios (nombre, correo, contraseña) VALUES ($1,$2,$3)",
      [nombre, correo, hashed]
    );

    res.json({ message: "Registro exitoso" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error registrando usuario" });
  }
});

// Login usuario
app.post("/api/auth/login", async (req, res) => {
  try {
    const { correo, contraseña } = req.body;

    const result = await db.query(
      "SELECT * FROM usuarios WHERE correo=$1",
      [correo]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "Usuario no existe" });

    const user = result.rows[0];
    const ok = await bcrypt.compare(contraseña, user.contraseña);

    if (!ok)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    req.session.user = {
      id: user.id,
      correo: user.correo,
      role: "cliente",
    };

    res.json({ message: "Login exitoso", user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en login" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Sesión cerrada" }));
});

// ===============================
//  PROPIEDADES
// ===============================
app.get("/api/propiedades", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM propiedades ORDER BY id ASC"
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo propiedades" });
  }
});

app.get("/api/propiedades/:id", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM propiedades WHERE id=$1",
      [req.params.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "Propiedad no encontrada" });

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo propiedad" });
  }
});

// ===============================
//  RESERVAS
// ===============================

// Crear reserva
app.post("/api/reservations", requireLogin, async (req, res) => {
  try {
    const usuario_id = req.session.user.id;
    const { propiedad_id, fecha_inicio, fecha_fin } = req.body;

    const result = await db.query(
      `INSERT INTO reservas (usuario_id, propiedad_id, fecha_inicio, fecha_fin, estado)
       VALUES ($1,$2,$3,$4,'pendiente')
       RETURNING *`,
      [usuario_id, propiedad_id, fecha_inicio, fecha_fin]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Error creando reserva" });
  }
});

// Obtener reservas del usuario
app.get("/api/reservations/user/:email", async (req, res) => {
  try {
    const u = await db.query(
      "SELECT id FROM usuarios WHERE correo = $1",
      [req.params.email]
    );

    if (u.rows.length === 0) return res.json([]);

    const result = await db.query(
      `SELECT r.id, r.fecha_inicio, r.fecha_fin, r.estado,
              p.titulo AS propiedad
       FROM reservas r
       JOIN propiedades p ON p.id = r.propiedad_id
       WHERE usuario_id = $1
       ORDER BY r.id DESC`,
      [u.rows[0].id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo reservas" });
  }
});

// Cancelar reserva
app.delete("/api/reservations/:id", requireLogin, async (req, res) => {
  try {
    await db.query("UPDATE reservas SET estado='cancelada' WHERE id=$1", [
      req.params.id,
    ]);
    res.json({ message: "Reserva cancelada" });
  } catch (err) {
    res.status(500).json({ error: "Error cancelando reserva" });
  }
});

// ===============================
//  RUTA RAÍZ
// ===============================
app.get("/", (req, res) => res.send("API Reservas OK"));

// ===============================
//  INICIAR SERVIDOR
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("🚀 Server running on port " + PORT)
);
