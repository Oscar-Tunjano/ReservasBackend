DROP DATABASE IF EXISTS reservas_sm;
CREATE DATABASE reservas_sm
  CHARACTER SET utf8
  COLLATE utf8_general_ci;
USE reservas_sm;

-- Usuarios
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(191) NOT NULL UNIQUE,
  password_hash VARCHAR(191) NOT NULL,
  full_name VARCHAR(191),
  role ENUM('client','admin') NOT NULL DEFAULT 'client',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Alojamientos
CREATE TABLE accommodations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(191) NOT NULL,
  description TEXT,
  price_per_night DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  currency VARCHAR(10) NOT NULL DEFAULT 'USD',
  location VARCHAR(191),
  active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Reservas
CREATE TABLE reservations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  reservation_code VARCHAR(191) NOT NULL UNIQUE,
  user_id INT NOT NULL,
  accommodation_id INT NOT NULL,
  checkin DATE NOT NULL,
  checkout DATE NOT NULL,
  nights INT NOT NULL,
  total_amount DECIMAL(12,2) NOT NULL,
  currency VARCHAR(10) NOT NULL DEFAULT 'USD',
  status ENUM('confirmed','cancelled','pending') DEFAULT 'confirmed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (accommodation_id) REFERENCES accommodations(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE INDEX idx_res_accom_dates
ON reservations (accommodation_id, checkin, checkout);

