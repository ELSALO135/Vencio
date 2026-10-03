-- ═══════════════════════════════════════════════════════════════════════════
-- VENCIO DATABASE SCHEMA
-- Gestión de cobranza inteligente
-- ═══════════════════════════════════════════════════════════════════════════

-- ═══════════════════════════
-- TABLAS
-- ═══════════════════════════

-- Usuarios
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  nombre VARCHAR(255) NOT NULL,
  iniciales VARCHAR(5),
  iva_porc INT DEFAULT 19,
  plan VARCHAR(50) DEFAULT 'basico',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Empresas (clientes pueden tener múltiples empresas)
CREATE TABLE empresas (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nombre VARCHAR(255) NOT NULL,
  rut VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Clientes
CREATE TABLE clientes (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nombre VARCHAR(255) NOT NULL,
  rut VARCHAR(50),
  email VARCHAR(255),
  telefono VARCHAR(20),
  empresa_id INT REFERENCES empresas(id),
  tipo_venta VARCHAR(50),           -- 'servicio', 'producto'
  tipo_cobro VARCHAR(50),           -- 'cuota', 'fijo'
  metodo_pago VARCHAR(50),          -- 'transferencia', 'tarjeta', 'efectivo'
  monto_cuota DECIMAL(15, 2),
  cuotas_total INT DEFAULT 1,
  cuotas_pagadas INT DEFAULT 0,
  proximo_venc DATE,
  estado VARCHAR(20) DEFAULT 'pendiente', -- 'pendiente', 'pagada', 'vencida'
  notas TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Pagos (historial de cada pago registrado)
CREATE TABLE pagos (
  id SERIAL PRIMARY KEY,
  cliente_id INT NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  monto DECIMAL(15, 2) NOT NULL,
  fecha DATE NOT NULL,
  metodo VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- ═══════════════════════════
-- ÍNDICES (para búsquedas rápidas)
-- ═══════════════════════════

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_empresas_user_id ON empresas(user_id);
CREATE INDEX idx_clientes_user_id ON clientes(user_id);
CREATE INDEX idx_clientes_empresa_id ON clientes(empresa_id);
CREATE INDEX idx_clientes_estado ON clientes(estado);
CREATE INDEX idx_pagos_cliente_id ON pagos(cliente_id);
CREATE INDEX idx_pagos_fecha ON pagos(fecha);

-- ═══════════════════════════
-- DATOS DE PRUEBA (Opcional)
-- ═══════════════════════════

-- Usuario de prueba (contraseña hasheada de "123456")
INSERT INTO users (email, password, nombre, iniciales, plan)
VALUES ('demo@vencio.cl', '$2a$10$fakehashedpasswordhere...', 'Demo User', 'DU', 'pro');

-- Empresa de prueba
INSERT INTO empresas (user_id, nombre, rut)
VALUES (1, 'Mi Empresa', '12345678-9');

-- Clientes de prueba
INSERT INTO clientes (
  user_id, nombre, rut, email, telefono, empresa_id,
  tipo_venta, tipo_cobro, metodo_pago, monto_cuota, cuotas_total,
  proximo_venc, estado
) VALUES
  (1, 'Juan García', '11222333-4', 'juan@email.com', '+56912345678', 1, 'servicio', 'cuota', 'transferencia', 150000, 3, '2024-03-15', 'pendiente'),
  (1, 'María López', '22333444-5', 'maria@email.com', '+56987654321', 1, 'producto', 'fijo', 'tarjeta', 250000, 1, '2024-02-28', 'pendiente'),
  (1, 'Carlos Muñoz', '33444555-6', 'carlos@email.com', NULL, 1, 'servicio', 'cuota', 'transferencia', 180000, 6, '2024-03-20', 'vencida');

-- ═══════════════════════════
-- VISTAS ÚTILES
-- ═══════════════════════════

-- Vista: Resumen de clientes por usuario
CREATE OR REPLACE VIEW v_clientes_resumen AS
SELECT
  c.id,
  c.nombre,
  c.email,
  e.nombre as empresa,
  c.monto_cuota,
  c.cuotas_pagadas,
  c.cuotas_total,
  COALESCE(c.cuotas_total - c.cuotas_pagadas, 0) as cuotas_pendientes,
  c.estado,
  c.proximo_venc,
  u.nombre as user_nombre
FROM clientes c
LEFT JOIN empresas e ON c.empresa_id = e.id
LEFT JOIN users u ON c.user_id = u.id;

-- Vista: Ingresos por cliente
CREATE OR REPLACE VIEW v_ingresos_cliente AS
SELECT
  c.id,
  c.nombre,
  COUNT(p.id) as total_pagos,
  SUM(p.monto) as monto_total_pagado,
  c.monto_cuota * c.cuotas_total as monto_total_esperado
FROM clientes c
LEFT JOIN pagos p ON c.id = p.cliente_id
GROUP BY c.id, c.nombre, c.monto_cuota, c.cuotas_total;

-- ═══════════════════════════
-- PROCEDIMIENTOS ALMACENADOS
-- ═══════════════════════════

-- Actualizar estado de clientes vencidos
CREATE OR REPLACE FUNCTION actualizar_clientes_vencidos()
RETURNS void AS $$
BEGIN
  UPDATE clientes
  SET estado = 'vencida'
  WHERE estado = 'pendiente'
  AND proximo_venc < CURRENT_DATE
  AND cuotas_pagadas < cuotas_total;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════
-- QUERIES ÚTILES PARA DESARROLLO
-- ═══════════════════════════

-- Ver todos los usuarios
-- SELECT * FROM users;

-- Ver clientes con estado
-- SELECT * FROM v_clientes_resumen WHERE user_nombre = 'Demo User';

-- Ver ingresos por cliente
-- SELECT * FROM v_ingresos_cliente;

-- Ver pagos recientes
-- SELECT p.*, c.nombre FROM pagos p
-- JOIN clientes c ON p.cliente_id = c.id
-- ORDER BY p.created_at DESC LIMIT 10;

-- Calcular total adeudado por cliente
-- SELECT
--   c.nombre,
--   (c.monto_cuota * c.cuotas_total) - COALESCE(SUM(p.monto), 0) as adeudado
-- FROM clientes c
-- LEFT JOIN pagos p ON c.id = p.cliente_id
-- GROUP BY c.id, c.nombre, c.monto_cuota, c.cuotas_total;
