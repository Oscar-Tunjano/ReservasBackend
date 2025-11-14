// server.js (ESM)
import express from "express";
import session from "express-session";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { Pool } from "pg";
import connectPgSimple from "connect-pg-simple"; // npm i connect-pg-simple
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const app = express();
app.use(express.json());

// Configuración CORS
const FRONTEND_URL = process.env.FRONTEND_URL || true; // si el frontend está en otro dominio ponlo aquí
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
  })
);

// Conexión Postgres
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// session store usando Postgres
const PgSession = connectPgSimple(session);
const sessionStore = new PgSession({
  pool: db,
  tableName: "session",
});

// Configuración de sesiones
app.set("trust proxy", 1); // si usas proxy (Render, Heroku)
app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 4, // 4 horas
    },
  })
);

// ======= Inicializar BD: crear tablas si no existen =======
async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(150) NOT NULL,
      correo VARCHAR(255) UNIQUE NOT NULL,
      contraseña VARCHAR(255) NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'cliente',
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS propiedades (
      id SERIAL PRIMARY KEY,
      titulo VARCHAR(255) NOT NULL,
      descripcion TEXT,
      precio NUMERIC(12,2) NOT NULL,
      ciudad VARCHAR(100),
      direccion VARCHAR(255),
      imagen VARCHAR(500),
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS reservas (
      id SERIAL PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
      propiedad_id INTEGER REFERENCES propiedades(id) ON DELETE CASCADE,
      fecha_inicio DATE NOT NULL,
      fecha_fin DATE NOT NULL,
      rooms INTEGER DEFAULT 1,
      guests INTEGER DEFAULT 1,
      notes TEXT,
      estado VARCHAR(30) DEFAULT 'pendiente',
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      usuario VARCHAR(150) UNIQUE NOT NULL,
      contraseña VARCHAR(255) NOT NULL,
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  // Opcional: crear admin inicial si se definen variables en .env
  if (process.env.ADMIN_USER && process.env.ADMIN_PASS) {
    const adminUser = process.env.ADMIN_USER;
    const adminPass = process.env.ADMIN_PASS;
    const found = await db.query("SELECT id FROM admins WHERE usuario = $1", [adminUser]);
    if (found.rows.length === 0) {
      const hash = await bcrypt.hash(adminPass, 10);
      await db.query("INSERT INTO admins (usuario, contraseña) VALUES ($1, $2)", [adminUser, hash]);
      console.log("Admin creado:", adminUser);
    }
  }
}

// Helper: middleware requireLogin
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Debes iniciar sesión" });
  next();
}
async function isAdminBySession(req) {
  if (!req.session.user) return false;
  // Si el usuario viene de tabla usuarios con role admin:
  if (req.session.user.role && req.session.user.role === "admin") return true;
  // O si viene de tabla admins (login como admin) - role 'admin' en sesión también se setea
  return req.session.user.role === "admin";
}

// Iniciar y comprobar conexión
db.connect()
  .then(async () => {
    console.log("Conectado a PostgreSQL ✔");
    await initDb();
  })
  .catch((err) => {
    console.error("Error conectando a Postgres:", err);
    process.exit(1);
  });

// ========================= RUTAS =========================

// Health
app.get("/healthz", (req, res) => res.json({ ok: true }));

// --- AUTH ---

// Register (cliente)
app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, correo, contraseña } = req.body;
    if (!nombre || !correo || !contraseña) return res.status(400).json({ error: "Datos incompletos" });

    const hash = await bcrypt.hash(contraseña, 10);
    await db.query("INSERT INTO usuarios (nombre, correo, contraseña, role) VALUES ($1,$2,$3,'cliente')", [nombre, correo, hash]);
    return res.json({ message: "Registro exitoso" });
  } catch (err) {
    console.error("Error register:", err);
    if (err.code === "23505") return res.status(400).json({ error: "Correo ya registrado" });
    res.status(500).json({ error: "Error registrando usuario" });
  }
});

// Login (cliente o admin)
app.post("/api/auth/login", async (req, res) => {
  try {
    const { correo, contraseña } = req.body;
    if (!correo || !contraseña) return res.status(400).json({ error: "Datos incompletos" });

    // 1) buscar en usuarios
    const u = await db.query("SELECT id, nombre, correo, contraseña, role FROM usuarios WHERE correo = $1", [correo]);
    if (u.rows.length > 0) {
      const user = u.rows[0];
      const ok = await bcrypt.compare(contraseña, user.contraseña);
      if (!ok) return res.status(401).json({ error: "Contraseña incorrecta" });

      req.session.user = { id: user.id, correo: user.correo, nombre: user.nombre, role: user.role || "cliente" };
      return res.json({ message: "Login exitoso", user: req.session.user });
    }

    // 2) fallback: buscar en admins (si usas tabla admins)
    const a = await db.query("SELECT id, usuario, contraseña FROM admins WHERE usuario = $1", [correo]);
    if (a.rows.length > 0) {
      const admin = a.rows[0];
      const ok = await bcrypt.compare(contraseña, admin.contraseña);
      if (!ok) return res.status(401).json({ error: "Contraseña incorrecta" });

      req.session.user = { id: admin.id, correo: admin.usuario, nombre: admin.usuario, role: "admin" };
      return res.json({ message: "Login admin exitoso", user: req.session.user });
    }

    return res.status(404).json({ error: "Usuario no encontrado" });
  } catch (err) {
    console.error("Error login:", err);
    res.status(500).json({ error: "Error en login" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Sesión cerrada" }));
});

// Me
app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autenticado" });
  res.json(req.session.user);
});

// --- PROPIEDADES ---

// Listar propiedades
app.get("/api/propiedades", async (req, res) => {
  try {
    const result = await db.query("SELECT id, titulo, descripcion, precio, ciudad, direccion, imagen FROM propiedades ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Error propiedades:", err);
    res.status(500).json({ error: "Error al listar propiedades" });
  }
});

// Obtener propiedad por id
app.get("/api/propiedades/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const r = await db.query("SELECT * FROM propiedades WHERE id = $1", [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: "Propiedad no encontrada" });
    res.json(r.rows[0]);
  } catch (err) {
    console.error("Error propiedad:", err);
    res.status(500).json({ error: "Error al obtener propiedad" });
  }
});

// Crear propiedad (solo admin)
app.post("/api/propiedades", requireLogin, async (req, res) => {
  if (!(await isAdminBySession(req))) return res.status(403).json({ error: "No autorizado" });
  try {
    const { titulo, descripcion, precio, ciudad, direccion, imagen } = req.body;
    const r = await db.query(
      `INSERT INTO propiedades (titulo, descripcion, precio, ciudad, direccion, imagen)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [titulo, descripcion, precio || 0, ciudad, direccion, imagen]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error("Error crear propiedad:", err);
    res.status(500).json({ error: "Error al crear propiedad" });
  }
});

// Editar propiedad (solo admin)
app.put("/api/propiedades/:id", requireLogin, async (req, res) => {
  if (!(await isAdminBySession(req))) return res.status(403).json({ error: "No autorizado" });
  try {
    const { id } = req.params;
    const { titulo, descripcion, precio, ciudad, direccion, imagen } = req.body;
    const r = await db.query(
      `UPDATE propiedades SET titulo=$1, descripcion=$2, precio=$3, ciudad=$4, direccion=$5, imagen=$6 WHERE id=$7 RETURNING *`,
      [titulo, descripcion, precio, ciudad, direccion, imagen, id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: "Propiedad no encontrada" });
    res.json(r.rows[0]);
  } catch (err) {
    console.error("Error editar propiedad:", err);
    res.status(500).json({ error: "Error al editar propiedad" });
  }
});

// Eliminar propiedad (solo admin)
app.delete("/api/propiedades/:id", requireLogin, async (req, res) => {
  if (!(await isAdminBySession(req))) return res.status(403).json({ error: "No autorizado" });
  try {
    const { id } = req.params;
    await db.query("DELETE FROM propiedades WHERE id = $1", [id]);
    res.json({ message: "Propiedad eliminada" });
  } catch (err) {
    console.error("Error eliminar propiedad:", err);
    res.status(500).json({ error: "Error al eliminar propiedad" });
  }
});

// --- RESERVAS ---

// Crear reserva (usa sesión si existe, si no, se puede crear por email si pasas email y existe ese usuario)
app.post("/api/reservas", requireLogin, async (req, res) => {
  // Ruta: POST /api/reservas
  // body: { propiedad_id, fecha_inicio, fecha_fin, rooms?, guests?, notes? }
  try {
    const usuario_id = req.session.user.id;
    const { propiedad_id, fecha_inicio, fecha_fin, rooms = 1, guests = 1, notes = null } = req.body;

    if (!propiedad_id || !fecha_inicio || !fecha_fin) return res.status(400).json({ error: "Datos incompletos" });

    const inicio = new Date(fecha_inicio);
    const fin = new Date(fecha_fin);
    if (isNaN(inicio) || isNaN(fin) || inicio >= fin) return res.status(400).json({ error: "Fechas inválidas" });

    // comprobar solapamiento: (fecha_inicio < fin) AND (fecha_fin > inicio)
    const overlapQ = `
      SELECT id FROM reservas
      WHERE propiedad_id = $1
        AND NOT (fecha_fin <= $2 OR fecha_inicio >= $3)
        AND estado != 'cancelada'
      LIMIT 1;
    `;
    const ov = await db.query(overlapQ, [propiedad_id, fecha_inicio, fecha_fin]);
    if (ov.rows.length > 0) return res.status(409).json({ error: "Fechas ocupadas" });

    const insert = `
      INSERT INTO reservas (usuario_id, propiedad_id, fecha_inicio, fecha_fin, rooms, guests, notes, estado)
      VALUES ($1,$2,$3,$4,$5,$6,$7,'confirmada') RETURNING *;
    `;
    const r = await db.query(insert, [usuario_id, propiedad_id, fecha_inicio, fecha_fin, rooms, guests, notes]);
    res.json({ message: "Reserva creada", reserva: r.rows[0] });
  } catch (err) {
    console.error("Error crear reserva:", err);
    res.status(500).json({ error: "Error al crear reserva" });
  }
});

// Obtener reservas del usuario (por sesión)
app.get("/api/reservas", requireLogin, async (req, res) => {
  try {
    const usuario_id = req.session.user.id;
    const q = await db.query(
      `SELECT r.id, r.fecha_inicio, r.fecha_fin, r.rooms, r.guests, r.notes, r.estado,
              p.id AS propiedad_id, p.titulo AS propiedad_titulo, p.precio, p.imagen
       FROM reservas r
       JOIN propiedades p ON p.id = r.propiedad_id
       WHERE r.usuario_id = $1
       ORDER BY r.id DESC`,
      [usuario_id]
    );
    res.json(q.rows);
  } catch (err) {
    console.error("Error listar reservas usuario:", err);
    res.status(500).json({ error: "Error al listar reservas" });
  }
});

// Obtener reservas por email (útil para frontend estático que sólo tiene email)
app.get("/api/reservas/user/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const u = await db.query("SELECT id FROM usuarios WHERE correo = $1", [email]);
    if (u.rows.length === 0) return res.json([]);
    const usuario_id = u.rows[0].id;
    const q = await db.query(
      `SELECT r.id, r.fecha_inicio, r.fecha_fin, r.rooms, r.guests, r.notes, r.estado,
              p.id AS propiedad_id, p.titulo AS propiedad_titulo, p.precio, p.imagen
       FROM reservas r
       JOIN propiedades p ON p.id = r.propiedad_id
       WHERE r.usuario_id = $1
       ORDER BY r.id DESC`,
      [usuario_id]
    );
    res.json(q.rows);
  } catch (err) {
    console.error("Error reservas por email:", err);
    res.status(500).json({ error: "Error al obtener reservas" });
  }
});

// Cancelar / borrar reserva (propietario o admin)
app.delete("/api/reservas/:id", requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.session.user.id;
    const admin = await isAdminBySession(req);

    const r = await db.query("SELECT usuario_id FROM reservas WHERE id = $1", [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: "Reserva no encontrada" });
    const ownerId = r.rows[0].usuario_id;
    if (ownerId !== userId && !admin) return res.status(403).json({ error: "No autorizado" });

    // marcaremos como cancelada
    await db.query("UPDATE reservas SET estado = 'cancelada' WHERE id = $1", [id]);
    res.json({ message: "Reserva cancelada" });
  } catch (err) {
    console.error("Error cancelar reserva:", err);
    res.status(500).json({ error: "Error al cancelar reserva" });
  }
});

// Raíz
app.get("/", (req, res) => res.send("API Reservas OK"));

// START
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
