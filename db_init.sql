-- ===========================================
-- BASE DE DATOS RESERVAS SANTA MARTA
-- PostgreSQL — Tablas definitivas
-- ===========================================

-- ===============================
-- USUARIOS
-- ===============================
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(200) NOT NULL,
    correo VARCHAR(200) UNIQUE NOT NULL,
    contrasena TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'cliente',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===============================
-- PROPIEDADES
-- ===============================
CREATE TABLE IF NOT EXISTS propiedades (
    id SERIAL PRIMARY KEY,
    titulo VARCHAR(200),
    descripcion TEXT,
    precio NUMERIC(10,2),
    ubicacion VARCHAR(200),
    imagen TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===============================
-- RESERVAS
-- ===============================
CREATE TABLE IF NOT EXISTS reservas (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
    propiedad_id INTEGER REFERENCES propiedades(id) ON DELETE CASCADE,
    fecha_inicio DATE NOT NULL,
    fecha_fin DATE NOT NULL,
    estado VARCHAR(50) DEFAULT 'pendiente',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===============================
-- ÍNDICE PARA OPTIMIZAR BÚSQUEDAS
-- ===============================
CREATE INDEX IF NOT EXISTS idx_res_prop_dates
ON reservas (propiedad_id, fecha_inicio, fecha_fin);

-- ===============================
-- SESIONES (CONNECT-PG-SIMPLE)
-- ===============================
CREATE TABLE IF NOT EXISTS sessions (
    sid VARCHAR NOT NULL COLLATE "default",
    sess JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL
)
WITH (OIDS=FALSE);

ALTER TABLE sessions
ADD CONSTRAINT sessions_pkey PRIMARY KEY (sid);

CREATE INDEX IF NOT EXISTS idx_sessions_expire
ON sessions (expire);

