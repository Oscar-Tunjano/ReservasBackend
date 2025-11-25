// ===============================================
// SERVER.JS — Backend Reservas SM (Con JWT)
// ===============================================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db } from "./db.js";
import initDatabase from "./init_db.js";

dotenv.config();
const app = express();

// ===============================================
// CONFIGURACIÓN GLOBAL
// ===============================================
app.use(express.json());

// CORS CONFIGURADO PARA TU DOMINIO REAL
app.use(cors({
  origin: [
    "https://reservatuhospedajeensantamarta.site",
    "https://www.reservatuhospedajeensantamarta.site"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// Necesario para preflight con Authorization
app.options("*", cors());

// Inicializar BD
initDatabase();

// ===============================================
// MIDDLEWARE — Validación JWT
// ===============================================
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  
  if (!token)
    return res.status(401).json({ error: "Falta token de autenticación" });

  const realToken = token.replace("Bearer ", "");

  jwt.verify(realToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });

    req.user = decoded;
    next();
  });
};

// ===============================================
// LOGIN — Devuelve JWT
// ===============================================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db.query("SELECT * FROM usuarios WHERE email=$1", [email]);

    if (result.rows.length === 0)
      return res.status(401).json({ error: "Usuario no encontrado" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user.id, email: user.email, nombre: user.nombre },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, nombre: user.nombre });
  } catch (err) {
    console.error("❌ ERROR LOGIN:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ===============================================
// REGISTRO
// ===============================================
app.post("/api/registro", async (req, res) => {
  try {
    const { nombre, email, password } = req.body;

    const exists = await db.query(
      "SELECT * FROM usuarios WHERE email=$1",
      [email]
    );

    if (exists.rows.length > 0)
      return res.status(400).json({ error: "El correo ya está registrado" });

    const hashed = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3)",
      [nombre, email, hashed]
    );

    res.json({ success: true, message: "Usuario registrado correctamente" });
  } catch (err) {
    console.error("❌ ERROR REGISTRO:", err);
    res.status(500).json({ error: "Error registrando usuario" });
  }
});

// ===============================================
// LISTADO DE PROPIEDADES
// ===============================================
app.get("/api/propiedades", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM propiedades");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ ERROR PROPIEDADES:", err);
    res.status(500).json({ error: "Error obteniendo propiedades" });
  }
});

// ===============================================
// PROPIEDAD POR ID
// ===============================================
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
    console.error("❌ ERROR:", err);
    res.status(500).json({ error: "Error obteniendo la propiedad" });
  }
});

// ===============================================
// CREAR RESERVA (JWT requerido)
// ===============================================
app.post("/api/reservas", verifyToken, async (req, res) => {
  try {
    const { propiedad_id, fecha_inicio, fecha_fin } = req.body;

    await db.query(
      "INSERT INTO reservas (usuario_id, propiedad_id, fecha_inicio, fecha_fin) VALUES ($1, $2, $3, $4)",
      [req.user.id, propiedad_id, fecha_inicio, fecha_fin]
    );

    res.json({ success: true, message: "Reserva creada exitosamente" });
  } catch (err) {
    console.error("❌ ERROR RESERVA:", err);
    res.status(500).json({ error: "Error creando la reserva" });
  }
});

// ===============================================
// VER MIS RESERVAS
// ===============================================
app.get("/api/mis-reservas", verifyToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT r.*, p.nombre AS propiedad 
       FROM reservas r 
       JOIN propiedades p ON r.propiedad_id = p.id 
       WHERE usuario_id=$1`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ ERROR MIS RESERVAS:", err);
    res.status(500).json({ error: "Error obteniendo reservas" });
  }
});

// ===============================================
// INICIAR SERVIDOR
// ===============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Backend corriendo en puerto ${PORT}`)
);
app.get("/", (req, res) => {
  res.send("Backend de Reservas SM funcionando correctamente ✔️");
});
