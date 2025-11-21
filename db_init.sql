-- ============================================
--  BASE DE DATOS PARA POSTGRESQL (RENDER)
--  CREA TABLAS SOLO SI NO EXISTEN
-- ============================================

-- ========================
--  USERS
-- ========================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(191) NOT NULL UNIQUE,
    password_hash VARCHAR(191) NOT NULL,
    full_name VARCHAR(191),
    role VARCHAR(20) NOT NULL DEFAULT 'client', 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
--  ACCOMMODATIONS
-- ========================
CREATE TABLE IF NOT EXISTS accommodations (
    id SERIAL PRIMARY KEY,
    title VARCHAR(191) NOT NULL,
    description TEXT,
    price_per_night NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    location VARCHAR(191),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
--  RESERVATIONS
-- ========================
CREATE TABLE IF NOT EXISTS reservations (
    id SERIAL PRIMARY KEY,
    reservation_code VARCHAR(191) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    accommodation_id INT NOT NULL,
    checkin DATE NOT NULL,
    checkout DATE NOT NULL,
    nights INT NOT NULL,
    total_amount NUMERIC(12,2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) DEFAULT 'confirmed', 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_res_user
        FOREIGN KEY (user_id) REFERENCES users(id),

    CONSTRAINT fk_res_accommodation
        FOREIGN KEY (accommodation_id) REFERENCES accommodations(id)
);

-- ========================
--  INDEX
-- ========================
CREATE INDEX IF NOT EXISTS idx_res_accom_dates
ON reservations (accommodation_id, checkin, checkou_
