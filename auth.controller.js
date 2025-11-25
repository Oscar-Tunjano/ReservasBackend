// auth.controller.js
const db = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

module.exports = {
    // ---------------- REGISTER -----------------
    async register(req, res) {
        const { nombre, email, password } = req.body;

        const hashed = await bcrypt.hash(password, 10);

        try {
            await db.run(
                "INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)",
                [nombre, email, hashed]
            );

            res.json({ success: true, message: "Usuario creado" });

        } catch (err) {
            res.status(500).json({ error: "Error registrando usuario" });
        }
    },

    // ---------------- LOGIN -----------------
    async login(req, res) {
        const { email, password } = req.body;

        try {
            const user = await db.get("SELECT * FROM usuarios WHERE email = ?", [email]);

            if (!user) return res.status(400).json({ error: "Usuario no existe" });

            const ok = await bcrypt.compare(password, user.password);
            if (!ok) return res.status(400).json({ error: "Contraseña incorrecta" });

            const token = jwt.sign(
                { id: user.id, nombre: user.nombre },
                process.env.JWT_SECRET || "secret_jwt_key",
                { expiresIn: "2h" }
            );

            res.cookie("token", token, {
                httpOnly: true,
                sameSite: "lax",
            });

            res.json({ success: true, message: "Login exitoso" });

        } catch (err) {
            res.status(500).json({ error: "Error en login" });
        }
    },

    // ---------------- LOGOUT -----------------
    logout(req, res) {
        res.clearCookie("token");
        res.json({ success: true, message: "Sesión cerrada" });
    }
};