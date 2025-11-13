require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const mysql = require("mysql2/promise");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();

// 🔥 Middlewares
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.set("trust proxy", 1);

app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // ✅ debe ser false en localhost
      sameSite: "lax",
      maxAge: 1000 * 60 * 60, // 1 hora
    },
  })
);

// Middleware: requiere login
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Debes iniciar sesión" });
  }
  next();
}

// Middleware: requiere rol admin
function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Debes iniciar sesión" });
  }
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Acceso denegado" });
  }
  next();
}

(async () => {
  const db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "ostun123",
    database: "reservas_sm",
  });

  global.db = db;

  console.log("Conectado a MySQL correctamente ✔");

  // ========== REGISTRO ==========
  app.post("/api/auth/register", async (req, res) => {
    const { email, password, full_name } = req.body;

    const hash = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, 'client')",
      [email, hash, full_name]
    );

    return res.json({ message: "Registro exitoso" });
  });

  // ========== LOGIN ==========
  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;

    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      full_name: user.full_name,
    };

    return res.json({ message: "Login exitoso", user: req.session.user });
  });

  // ========== TEST AUTENTICACIÓN ==========
  app.get("/api/me", (req, res) => {
    if (!req.session.user)
      return res.status(401).json({ error: "No autenticado" });
    res.json(req.session.user);
  });

  // ========== LISTAR ALOJAMIENTOS ==========
  app.get("/api/accommodations", async (req, res) => {
    const [rows] = await db.query("SELECT * FROM accommodations");
    res.json(rows);
  });

  // ========== CREAR RESERVA ==========
  app.post("/api/reservations", requireLogin, async (req, res) => {
    const { accommodation_id, checkin, checkout } = req.body;

    if (!accommodation_id || !checkin || !checkout) {
      return res.status(400).json({ error: "Datos incompletos" });
    }

    const code = uuidv4();

    const [existing] = await db.query(
      `SELECT id FROM reservations
       WHERE accommodation_id = ?
       AND (checkin < ? AND checkout > ?)`,
      [accommodation_id, checkout, checkin]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: "Fechas ocupadas" });
    }

    const nights =
      (new Date(checkout) - new Date(checkin)) /
      (1000 * 60 * 60 * 24);

    const [acc] = await db.query(
      "SELECT price_per_night FROM accommodations WHERE id = ?",
      [accommodation_id]
    );

    const total = nights * acc[0].price_per_night;

    await db.query(
      "INSERT INTO reservations (user_id, accommodation_id, checkin, checkout, code, total_price) VALUES (?, ?, ?, ?, ?, ?)",
      [req.session.user.id, accommodation_id, checkin, checkout, code, total]
    );

    res.json({
      message: "Reserva creada correctamente",
      code,
      nights,
      total,
    });
  });

  // ========== LISTAR RESERVAS DEL USUARIO ==========
  app.get("/api/reservations", requireLogin, async (req, res) => {
    const [rows] = await db.query(
      "SELECT * FROM reservations WHERE user_id = ?",
      [req.session.user.id]
    );
    res.json(rows);
  });

  // ========== ADMIN: LISTAR TODAS LAS RESERVAS ==========
  app.get("/api/admin/reservations", requireAdmin, async (req, res) => {
    const [rows] = await db.query(`
      SELECT r.*, u.full_name, u.email, a.title AS accommodation
      FROM reservations r
      JOIN users u ON r.user_id = u.id
      JOIN accommodations a ON r.accommodation_id = a.id
      ORDER BY r.created_at DESC
    `);

    res.json(rows);
  });

  // ========== ADMIN: LISTAR USUARIOS ==========
  app.get("/api/admin/users", requireAdmin, async (req, res) => {
    const [rows] = await db.query(`
      SELECT id, full_name, email, role, created_at
      FROM users
      ORDER BY created_at DESC
    `);

    res.json(rows);
  });

  // ========== ADMIN: LISTAR ALOJAMIENTOS ==========
  app.get("/api/admin/accommodations", requireAdmin, async (req, res) => {
    const [rows] = await db.query(`
      SELECT *
      FROM accommodations
      ORDER BY created_at DESC
    `);

    res.json(rows);
  });

  // Servidor encendido
  app.listen(3000, () => {
    console.log("Server running on port 3000 🚀");
  });
})();


