const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const SQL = `
-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  nombre VARCHAR(255) NOT NULL,
  iniciales VARCHAR(5),
  iva_porc INT DEFAULT 19,
  plan VARCHAR(50) DEFAULT 'basico',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Tabla de empresas
CREATE TABLE IF NOT EXISTS empresas (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nombre VARCHAR(255) NOT NULL,
  rut VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Tabla de clientes
CREATE TABLE IF NOT EXISTS clientes (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nombre VARCHAR(255) NOT NULL,
  rut VARCHAR(50),
  email VARCHAR(255),
  telefono VARCHAR(20),
  empresa_id INT REFERENCES empresas(id),
  tipo_venta VARCHAR(50),
  tipo_cobro VARCHAR(50),
  metodo_pago VARCHAR(50),
  monto_cuota DECIMAL(15, 2),
  cuotas_total INT DEFAULT 1,
  cuotas_pagadas INT DEFAULT 0,
  proximo_venc DATE,
  estado VARCHAR(20) DEFAULT 'pendiente',
  notas TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Tabla de pagos
CREATE TABLE IF NOT EXISTS pagos (
  id SERIAL PRIMARY KEY,
  cliente_id INT NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  monto DECIMAL(15, 2) NOT NULL,
  fecha DATE NOT NULL,
  metodo VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Crear índices
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_empresas_user_id ON empresas(user_id);
CREATE INDEX IF NOT EXISTS idx_clientes_user_id ON clientes(user_id);
CREATE INDEX IF NOT EXISTS idx_clientes_empresa_id ON clientes(empresa_id);
CREATE INDEX IF NOT EXISTS idx_pagos_cliente_id ON pagos(cliente_id);
`;

async function initDB() {
  try {
    console.log('Conectando a PostgreSQL...');
    await pool.query(SQL);
    console.log('✓ Base de datos inicializada correctamente');
    process.exit(0);
  } catch (err) {
    console.error('Error inicializando BD:', err);
    process.exit(1);
  }
}

initDB();
