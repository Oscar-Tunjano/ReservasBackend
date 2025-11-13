// ===============================
//  IMPORTACIONES
// ===============================
import express from "express";
import session from "express-session";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { Pool } from "pg";

dotenv.config();

const app = express();

// ===============================
//  CONFIGURACIONES BÁSICAS
// ===============================
app.use(express.json());
app.use(cors());

// Configuración de sesión (Render usa HTTPS, por eso secure: true si está en producción)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
    },
  })
);

// ===============================
//  CONEXIÓN A POSTGRESQL (Render)
// ===============================
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => console.log("✅ Conectado a PostgreSQL Render"))
  .catch((err) => console.error("❌ Error al conectar a PostgreSQL:", err));

// ===============================
//  RUTAS DE EJEMPLO
// ===============================

// Ruta raíz
app.get("/", (req, res) => {
  res.send("Servidor backend funcionando correctamente 🚀");
});

// Obtener todos los usuarios
app.get("/usuarios", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM usuarios");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// Crear usuario
app.post("/usuarios", async (req, res) => {
  try {
    const { nombre, correo, contraseña } = req.body;
    const hashedPassword = await bcrypt.hash(contraseña, 10);
    await db.query(
      "INSERT INTO usuarios (nombre, correo, contraseña) VALUES ($1, $2, $3)",
      [nombre, correo, hashedPassword]
    );
    res.json({ mensaje: "Usuario creado exitosamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al crear usuario" });
  }
});

// ===============================
//  SERVIDOR
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en el puerto ${PORT}`);
});


