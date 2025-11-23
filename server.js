// ===============================================
// SERVER.JS — Backend Reservas SM (PostgreSQL)
// ===============================================

import express from "express";
import session from "express-session";
import pgSession from "connect-pg-simple";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { db } from "./db.js";
import initDatabase from "./init_db.js";

dotenv.config();
const app = express();

// ===============================================
// MIDDLEWARES
// ===============================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Necesario para cookies secure con proxy (Render)
app.set("trust proxy", 1);

// ===============================================
// CORS — Permitir frontend de Vercel
// ===============================================
const FRONTEND = process.env.FRONTEND_ORIGIN ||
  "https://www.reservatuhospedajeensantamarta.site";

app.use(
  cors({
    origin: FRONTEND,
    credentials: true,
  })
);

// ===============================================
// SESIONES — PostgreSQL
// ===============================================
const PGSessionStore = pgSession(session);

app.use(
  session({
    store: new PGSessionStore({
      pool: db,
      tableName: "sessions",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || "clave_sesion_local",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // REQUERIDO para Render
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 4, // 4 horas
    },
  })
);

// ===============================================
// HELPER — Requiere sesión iniciada
// ===============================================
function requireLogin(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: "Debes iniciar sesión" });
  next();
}

// ===============================================
// AUTH — LOGIN, REGISTRO, LOGOUT
// ===============================================

// Registro
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, correo, password } = req.body;

    if (!nombre || !correo || !password)
      return res.status(400).json({ error: "Faltan datos obligatorios" });

    const exists = await db.query("SELECT id FROM usuarios WHERE correo=$1", [
      correo,
    ]);

    if (exists.rows.length > 0)
      return res.status(409).json({ error: "Correo ya registrado" });

    const hashed = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO usuarios (nombre, correo, contrasena) VALUES ($1,$2,$3)",
      [nombre, correo, hashed]
    );

    res.json({ message: "Registro exitoso" });
  } catch (err) {
    console.error("❌ REGISTRO ERROR:", err);
    res.status(500).json({ error: "Error registrando usuario" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const correo = req.body.correo;
    const password =
      req.body.password || req.body.contrasena || req.body["contraseña"];

    if (!correo || !password)
      return res.status(400).json({ error: "Correo y contraseña requeridos" });

    const result = await db.query("SELECT * FROM usuarios WHERE correo=$1", [
      correo,
    ]);

    if (result.rows.length === 0)
      return res.status(404).json({ error: "Usuario no existe" });

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.contrasena);
    if (!ok)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    req.session.user = {
      id: user.id,
      correo: user.correo,
      role: user.role,
    };

    res.json({
      message: "Login exitoso",
      user: req.session.user,
    });
  } catch (err) {
    console.error("❌ LOGIN ERROR:", err);
    res.status(500).json({ error: "Error en login" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() =>
    res.json({ message: "Sesión cerrada correctamente" })
  );
});

// ===============================================
// PROPIEDADES
// ===============================================
app.get("/api/propiedades", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM propiedades ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ ERROR PROPIEDADES:", err);
    res.status(500).json({ error: "Error obteniendo propiedades" });
  }
});

app.get("/api/propiedades/:id", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM propiedades WHERE id=$1", [
      req.params.id,
    ]);

    if (result.rows.length === 0)
      return res.status(404).json({ error: "Propiedad no encontrada" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ ERROR PROPIEDAD:", err);
    res.status(500).json({ error: "Error obteniendo propiedad" });
  }
});

// ===============================================
// RESERVAS
// ===============================================
app.post("/api/reservas", requireLogin, async (req, res) => {
  try {
    const usuario_id = req.session.user.id;
    const { propiedad_id, fecha_inicio, fecha_fin } = req.body;

    if (!propiedad_id || !fecha_inicio || !fecha_fin)
      return res.status(400).json({ error: "Datos incompletos" });

    const result = await db.query(
      `INSERT INTO reservas (usuario_id, propiedad_id, fecha_inicio, fecha_fin, estado)
       VALUES ($1,$2,$3,$4,'pendiente') RETURNING *`,
      [usuario_id, propiedad_id, fecha_inicio, fecha_fin]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ ERROR CREANDO RESERVA:", err);
    res.status(500).json({ error: "Error creando reserva" });
  }
});

// Reservas por correo
app.get("/api/reservas/user/:correo", async (req, res) => {
  try {
    const usr = await db.query("SELECT id FROM usuarios WHERE correo=$1", [
      req.params.correo,
    ]);

    if (usr.rows.length === 0) return res.json([]);

    const result = await db.query(
      `SELECT r.id, r.fecha_inicio, r.fecha_fin, r.estado,
              p.titulo AS propiedad
       FROM reservas r
       JOIN propiedades p ON p.id = r.propiedad_id
       WHERE r.usuario_id = $1
       ORDER BY r.id DESC`,
      [usr.rows[0].id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ ERROR OBTENIENDO RESERVAS:", err);
    res.status(500).json({ error: "Error obteniendo reservas" });
  }
});

// Cancelar reserva
app.delete("/api/reservas/:id", requireLogin, async (req, res) => {
  try {
    await db.query("UPDATE reservas SET estado='cancelada' WHERE id=$1", [
      req.params.id,
    ]);
    res.json({ message: "Reserva cancelada" });
  } catch (err) {
    console.error("❌ ERROR CANCELANDO RESERVA:", err);
    res.status(500).json({ error: "Error cancelando reserva" });
  }
});

// ===============================================
// CONTACTO (Formulario Contacto HTML)
// ===============================================
app.post("/api/contact", async (req, res) => {
  try {
    const { nombre, email, telefono, mensaje } = req.body;

    if (!email || !mensaje)
      return res.status(400).json({ error: "Email y mensaje requeridos" });

    await db.query(
      "INSERT INTO contactos (nombre, correo, telefono, mensaje) VALUES ($1,$2,$3,$4)",
      [nombre || null, email, telefono || null, mensaje]
    );

    res.json({ message: "Mensaje recibido correctamente" });
  } catch (err) {
    console.error("❌ ERROR CONTACTO:", err);
    res.status(500).json({ error: "Error enviando mensaje" });
  }
});

// ===============================================
// ROOT
// ===============================================
app.get("/", (req, res) =>
  res.send("API Reservas SM — PostgreSQL — Server OK")
);

// ===============================================
// INICIAR SERVIDOR
// ===============================================
const PORT = process.env.PORT || 3000;

(async () => {
  await initDatabase();
  app.listen(PORT, () =>
    console.log("🚀 Backend escuchando en puerto:", PORT)
  );
})();
