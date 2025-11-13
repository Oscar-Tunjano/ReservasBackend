# Reservas SM - Backend (Entrega para SENA)

Contiene:
- db_init.sql : script para crear la base de datos y tablas.
- server.js : servidor Express con autenticación, sesiones y endpoints.
- db.js : conexión con mysql2.
- package.json : dependencias.

Siga los pasos:
1. Instalar MySQL y crear la BD: `mysql -u root -p < db_init.sql`
2. Crear archivo .env con las credenciales (puede usar .env.example)
3. `npm install`
4. `npm run dev`

Endpoints principales:
- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/logout
- GET  /api/accommodations
- POST /api/admin/accommodations (admin)
- POST /api/reservations  (crear reserva)
- GET  /api/reservations   (listar)

Use cookie jar (Postman or curl -c/-b) para mantener sesión entre peticiones.
