require('dotenv').config();
const express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), { Pool } = require('pg'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 5000, JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error('Falta DATABASE_URL o JWT_SECRET. Revisa que el archivo se llame ".env" (con punto) y esté junto a server.js.');
  process.exit(1);
}
// Flow (pagos). Para probar sin dinero real: FLOW_API_URL=https://sandbox.flow.cl/api con credenciales de sandbox.flow.cl
const FLOW_KEY = process.env.FLOW_API_KEY, FLOW_SECRET = process.env.FLOW_API_SECRET;
const FLOW_URL = process.env.FLOW_API_URL || 'https://www.flow.cl/api';
const APP_URL = (process.env.APP_URL || 'https://vencio-production.up.railway.app').replace(/\/$/, '');
// Precios en CLP por 30 días. AJÚSTALOS a lo que quieras cobrar (Flow exige mínimo $350).
const PLANES = { Principal: 13000, Plus: 22000, Pro: 36000, Omnibus: 64000 };
// SEGURIDAD: límites reales de cada plan, validados en el servidor (el navegador no es de fiar).
// 'basico' es el plan de las cuentas nuevas o con el plan vencido. AJUSTA estos números a tu gusto.
const LIMITES_PLAN = {
  basico:    { empresas: 1,        clientes: 50,       moderadores: 0 },
  Principal: { empresas: 1,        clientes: 50,       moderadores: 0 },
  Plus:      { empresas: 2,        clientes: 200,      moderadores: 1 },
  Pro:       { empresas: 3,        clientes: 500,      moderadores: 3 },
  Omnibus:   { empresas: Infinity, clientes: Infinity, moderadores: Infinity }
};
if (!FLOW_KEY || !FLOW_SECRET) console.warn('Aviso: faltan FLOW_API_KEY / FLOW_API_SECRET, los pagos con Flow no funcionarán.');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false })); // Flow envía el token como formulario
app.use(express.static(path.join(__dirname, 'public')));

const fail = (res, e, msg) => { console.error(e); res.status(500).json({ error: msg }); };
const makeToken = u => jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try { req.userId = jwt.verify((req.headers.authorization || '').split(' ')[1], JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Sesión inválida' }); }
};
const estadoInicial = empresa => ({ empresas: [{ id: 1, nombre: empresa || 'Mi Empresa' }], clientes: [], ventas: [], notifs: [], moderadores: [] });

// Limitador simple de intentos (sin dependencias): evita adivinar contraseñas por fuerza bruta
const intentos = new Map();
const limitar = (max, ventanaMs) => (req, res, next) => {
  const k = req.ip + req.path, ahora = Date.now();
  let r = intentos.get(k);
  if (!r || ahora > r.reset) r = { n: 0, reset: ahora + ventanaMs };
  r.n++; intentos.set(k, r);
  if (r.n > max) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos e inténtalo de nuevo.' });
  next();
};
setInterval(() => { const a = Date.now(); for (const [k, v] of intentos) if (a > v.reset) intentos.delete(k); }, 600000).unref();

// ── Flow: comercios asociados y cobro automático a los clientes de cada empresa ──
// IMPORTANTE: para que el dinero llegue directo a cada empresa (en vez de a tu cuenta),
// tu cuenta Flow debe estar habilitada como "comercio integrador". Pídelo a soporte de Flow
// antes de usar esto en producción; en sandbox normalmente ya viene habilitado para pruebas.

// Crea el comercio asociado de un usuario en Flow (una vez por usuario). No bloquea el registro si falla.
const crearComercioFlow = async (userId, nombre) => {
  if (!FLOW_KEY || !FLOW_SECRET) return;
  try {
    const f = await flowCall('POST', '/merchant/create', {
      id: 'VENCIO-' + userId, name: (nombre || 'Empresa').slice(0, 60), url: APP_URL
    });
    await pool.query('UPDATE users SET flow_merchant_id=$1, flow_merchant_estado=$2 WHERE id=$3',
      [f.id || ('VENCIO-' + userId), 'activo', userId]);
  } catch (e) {
    console.error('No se pudo crear el comercio asociado en Flow:', e.message);
    await pool.query(`UPDATE users SET flow_merchant_estado='error' WHERE id=$1`, [userId]);
  }
};

// Devuelve el plan actual del usuario; si ya venció, lo baja a 'basico'
const planVigente = async userId => {
  await pool.query(`UPDATE users SET plan='basico', plan_vence=NULL WHERE id=$1 AND plan<>'basico' AND plan_vence IS NOT NULL AND plan_vence < NOW()`, [userId]);
  const u = (await pool.query('SELECT plan FROM users WHERE id=$1', [userId])).rows[0];
  return u ? u.plan : 'basico';
};

// Revisa que los datos tengan la forma esperada (los números son números, etc.). Devuelve un texto de error o null.
const esNum = n => typeof n === 'number' && Number.isFinite(n);
const esObj = o => o !== null && typeof o === 'object' && !Array.isArray(o);
const validarEstado = e => {
  for (const k of ['empresas', 'clientes', 'moderadores'])
    if (e[k].some(it => !esObj(it) || !esNum(it.id))) return 'Datos inválidos en ' + k;
  for (const c of e.clientes) {
    if (!esNum(c.montoCuota) || !esNum(c.cuotasPagadas) || !esNum(c.cuotasTotal)) return 'Un cliente tiene montos o cuotas inválidos';
    if (!['al día', 'pendiente', 'vencida'].includes(c.estado)) return 'Un cliente tiene un estado inválido';
    if (!['cuotas', 'membresia'].includes(c.tipo)) return 'Un cliente tiene un tipo de cobro inválido';
    if (!Array.isArray(c.historial) || c.historial.some(h => !esObj(h) || !esNum(h.monto))) return 'Historial de pagos inválido';
    if (!Array.isArray(c.notas) || c.notas.some(n => !esObj(n))) return 'Notas inválidas';
  }
  if (e.ventas.some(v => !esObj(v) || !esNum(v.monto) || !esNum(v.costo))) return 'Datos de ventas inválidos';
  return null;
};

// ── Flow: firma HMAC-SHA256 de los parámetros ordenados alfabéticamente ──
const flowSign = p => crypto.createHmac('sha256', FLOW_SECRET).update(Object.keys(p).sort().map(k => k + p[k]).join('')).digest('hex');
const flowCall = async (method, endpoint, params) => {
  const body = { ...params, apiKey: FLOW_KEY };
  body.s = flowSign(body);
  const qs = new URLSearchParams(body).toString();
  const r = method === 'GET'
    ? await fetch(`${FLOW_URL}${endpoint}?${qs}`)
    : await fetch(`${FLOW_URL}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: qs });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.message || 'Error al comunicarse con Flow');
  return d;
};
// Consulta a Flow el estado real del pago (nunca confiamos en lo que llega por el formulario) y activa el plan si se pagó
const procesarPago = async token => {
  const f = await flowCall('GET', '/payment/getStatus', { token });
  const estado = { 1: 'pendiente', 2: 'pagado', 3: 'rechazado', 4: 'anulado' }[f.status] || 'desconocido';
  const p = (await pool.query('SELECT * FROM pagos WHERE commerce_order=$1', [f.commerceOrder])).rows[0];
  if (!p) throw new Error('Pago no encontrado: ' + f.commerceOrder);
  if (Number(f.amount) !== p.monto) throw new Error('Monto no coincide en la orden ' + p.commerce_order);
  if (estado === 'pagado') {
    const up = await pool.query(`UPDATE pagos SET estado='pagado', flow_order=$1, pagado_at=NOW() WHERE id=$2 AND estado<>'pagado'`, [String(f.flowOrder), p.id]);
    if (up.rowCount) await pool.query(
      `UPDATE users SET plan=$1, plan_vence=GREATEST(COALESCE(plan_vence,NOW()),NOW()) + INTERVAL '30 days' WHERE id=$2`, [p.plan, p.user_id]);
  } else if (p.estado !== 'pagado') await pool.query('UPDATE pagos SET estado=$1 WHERE id=$2', [estado, p.id]);
  return estado;
};

app.post('/api/auth/register', limitar(10, 3600000), async (req, res) => {
  try {
    const { email, password, nombre, empresa } = req.body;
    if (!email || !password || !nombre) return res.status(400).json({ error: 'Nombre, correo y contraseña son obligatorios' });
    if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    const mail = email.trim().toLowerCase();
    if ((await pool.query('SELECT 1 FROM users WHERE email=$1', [mail])).rowCount)
      return res.status(400).json({ error: 'Ese correo ya está registrado' });
    const ini = nombre.split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
    const u = (await pool.query(
      'INSERT INTO users(email,password,nombre,iniciales) VALUES($1,$2,$3,$4) RETURNING id,email,nombre,iniciales',
      [mail, await bcrypt.hash(password, 10), nombre.trim(), ini])).rows[0];
    await pool.query('INSERT INTO user_data(user_id,estado) VALUES($1,$2)', [u.id, estadoInicial(empresa && empresa.trim())]);
    crearComercioFlow(u.id, empresa && empresa.trim() || nombre); // en segundo plano, no se espera
    res.status(201).json({ token: makeToken(u), user: u });
  } catch (e) { fail(res, e, 'No se pudo crear la cuenta'); }
});

app.post('/api/auth/login', limitar(10, 900000), async (req, res) => {
  try {
    const { email, password } = req.body;
    const u = (await pool.query('SELECT * FROM users WHERE email=$1', [(email || '').trim().toLowerCase()])).rows[0];
    if (!u || !(await bcrypt.compare(password || '', u.password)))
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    res.json({ token: makeToken(u), user: { id: u.id, email: u.email, nombre: u.nombre, iniciales: u.iniciales } });
  } catch (e) { fail(res, e, 'Error al iniciar sesión'); }
});

app.get('/api/auth/profile', auth, async (req, res) => {
  try {
    const u = (await pool.query('SELECT id,email,nombre,iniciales FROM users WHERE id=$1', [req.userId])).rows[0];
    u ? res.json(u) : res.status(404).json({ error: 'Usuario no encontrado' });
  } catch (e) { fail(res, e, 'Error al obtener el perfil'); }
});

// Estado completo de la cuenta (empresas, clientes, pagos, notas, moderadores, config)
app.get('/api/state', auth, async (req, res) => {
  try {
    const plan = await planVigente(req.userId);
    const r = await pool.query('SELECT estado FROM user_data WHERE user_id=$1', [req.userId]);
    const estado = r.rows[0] ? r.rows[0].estado : estadoInicial();
    estado.config = { ...(estado.config || {}), plan }; // el plan SIEMPRE viene de la base de datos
    res.json({ estado, plan });
  } catch (e) { fail(res, e, 'Error al cargar los datos'); }
});

app.put('/api/state', auth, async (req, res) => {
  try {
    const b = req.body, estado = {};
    for (const k of ['empresas', 'clientes', 'ventas', 'notifs', 'moderadores']) estado[k] = Array.isArray(b[k]) ? b[k] : [];
    const { plan: _ignorado, ...cfg } = (b.config && typeof b.config === 'object' && !Array.isArray(b.config)) ? b.config : {};
    estado.config = cfg; // el plan del navegador se ignora
    estado.notifs = estado.notifs.slice(0, 200);

    const errorForma = validarEstado(estado);
    if (errorForma) return res.status(400).json({ error: errorForma });

    // Límites del plan. Se permite guardar si el usuario está BAJANDO la cantidad (para que pueda borrar y ponerse al día).
    const plan = await planVigente(req.userId);
    const lim = LIMITES_PLAN[plan] || LIMITES_PLAN.basico;
    const actual = (await pool.query('SELECT estado FROM user_data WHERE user_id=$1', [req.userId])).rows[0];
    const prev = (actual && actual.estado) || {};
    for (const [k, max, nombre] of [['empresas', lim.empresas, 'empresa(s)'], ['clientes', lim.clientes, 'cliente(s)'], ['moderadores', lim.moderadores, 'moderador(es)']]) {
      const antes = Array.isArray(prev[k]) ? prev[k].length : 0;
      if (estado[k].length > max && estado[k].length > antes)
        return res.status(400).json({ error: `Tu plan ${plan} permite como máximo ${max} ${nombre}. Mejora tu plan para agregar más.` });
    }
    await pool.query(
      `INSERT INTO user_data(user_id,estado) VALUES($1,$2)
       ON CONFLICT(user_id) DO UPDATE SET estado=$2, updated_at=NOW()`, [req.userId, estado]);
    res.json({ ok: true });
  } catch (e) { fail(res, e, 'Error al guardar los datos'); }
});

// ── Pagos con Flow ──
// 1) El usuario elige un plan: creamos la orden en Flow y devolvemos la URL de pago
app.post('/api/pagos/iniciar', auth, async (req, res) => {
  try {
    if (!FLOW_KEY || !FLOW_SECRET) return res.status(503).json({ error: 'Los pagos aún no están configurados' });
    const plan = req.body.plan, monto = PLANES[plan];
    if (!monto) return res.status(400).json({ error: 'Plan inválido' });
    const u = (await pool.query('SELECT email FROM users WHERE id=$1', [req.userId])).rows[0];
    const orden = `VEN-${req.userId}-${Date.now()}`;
    const id = (await pool.query(
      'INSERT INTO pagos(user_id,commerce_order,plan,monto) VALUES($1,$2,$3,$4) RETURNING id', [req.userId, orden, plan, monto])).rows[0].id;
    const f = await flowCall('POST', '/payment/create', {
      commerceOrder: orden, subject: `Vencio - Plan ${plan} (30 días)`, currency: 'CLP', amount: monto, email: u.email,
      urlConfirmation: `${APP_URL}/api/pagos/confirmar`, urlReturn: `${APP_URL}/api/pagos/retorno` });
    await pool.query('UPDATE pagos SET token=$1, flow_order=$2 WHERE id=$3', [f.token, String(f.flowOrder), id]);
    res.json({ url: `${f.url}?token=${f.token}` });
  } catch (e) { fail(res, e, 'No se pudo iniciar el pago'); }
});

// 2) Webhook: Flow avisa (servidor a servidor) que el pago cambió de estado
app.post('/api/pagos/confirmar', async (req, res) => {
  try { await procesarPago(req.body.token); res.sendStatus(200); }
  catch (e) { console.error(e); res.sendStatus(500); }
});

// 3) El cliente vuelve desde Flow a Vencio (Flow lo redirige con POST)
const retorno = async (req, res) => {
  try {
    const estado = await procesarPago((req.body && req.body.token) || req.query.token);
    res.redirect(303, `/?pago=${estado === 'pagado' ? 'ok' : estado === 'pendiente' ? 'pendiente' : 'error'}`);
  } catch (e) { console.error(e); res.redirect(303, '/?pago=error'); }
};
app.post('/api/pagos/retorno', retorno);
app.get('/api/pagos/retorno', retorno);

// 4) Plan actual e historial de pagos del usuario
app.get('/api/pagos', auth, async (req, res) => {
  try {
    await planVigente(req.userId);
    const u = (await pool.query('SELECT plan,plan_vence FROM users WHERE id=$1', [req.userId])).rows[0];
    const pagos = (await pool.query(
      'SELECT plan,monto,estado,created_at,pagado_at FROM pagos WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [req.userId])).rows;
    res.json({ plan: u.plan, plan_vence: u.plan_vence, pagos });
  } catch (e) { fail(res, e, 'Error al cargar los pagos'); }
});

// ── Endpoints de cobro automático a clientes ──

// Ver / reintentar el comercio asociado del usuario logueado
app.get('/api/flow/comercio', auth, async (req, res) => {
  try {
    const u = (await pool.query('SELECT flow_merchant_id,flow_merchant_estado FROM users WHERE id=$1', [req.userId])).rows[0];
    res.json({ id: u.flow_merchant_id, estado: u.flow_merchant_estado || 'pendiente' });
  } catch (e) { fail(res, e, 'Error al consultar el comercio'); }
});
app.post('/api/flow/comercio/reintentar', auth, async (req, res) => {
  try {
    const u = (await pool.query('SELECT nombre FROM users WHERE id=$1', [req.userId])).rows[0];
    await crearComercioFlow(req.userId, u.nombre);
    const r = (await pool.query('SELECT flow_merchant_id,flow_merchant_estado FROM users WHERE id=$1', [req.userId])).rows[0];
    res.json({ id: r.flow_merchant_id, estado: r.flow_merchant_estado });
  } catch (e) { fail(res, e, 'No se pudo crear el comercio'); }
});

// Invita a un cliente (de una empresa) a registrar su tarjeta para cobro automático
app.post('/api/flow/clientes/:clienteId/invitar', auth, async (req, res) => {
  try {
    if (!FLOW_KEY || !FLOW_SECRET) return res.status(503).json({ error: 'Los pagos aún no están configurados' });
    const clienteId = Number(req.params.clienteId);
    const { nombre, email } = req.body;
    if (!nombre || !email) return res.status(400).json({ error: 'Falta el nombre o email del cliente' });

    let existente = (await pool.query(
      'SELECT flow_customer_id FROM flow_clientes WHERE user_id=$1 AND cliente_id=$2', [req.userId, clienteId])).rows[0];

    let customerId = existente && existente.flow_customer_id;
    if (!customerId) {
      const c = await flowCall('POST', '/customer/create', {
        name: nombre, email, externalId: `${req.userId}-${clienteId}`
      });
      customerId = c.customerId;
      await pool.query(
        `INSERT INTO flow_clientes(user_id,cliente_id,flow_customer_id) VALUES($1,$2,$3)
         ON CONFLICT(user_id,cliente_id) DO UPDATE SET flow_customer_id=$3`, [req.userId, clienteId, customerId]);
    }

    const r = await flowCall('POST', '/customer/register', {
      customerId, url_return: `${APP_URL}/api/flow/clientes/registro-retorno`
    });
    const urlRegistro = `${r.url}?token=${r.token}`;
    await pool.query('UPDATE flow_clientes SET token_registro=$1 WHERE user_id=$2 AND cliente_id=$3',
      [r.token, req.userId, clienteId]);
    res.json({ url: urlRegistro });
  } catch (e) { fail(res, e, 'No se pudo invitar al cliente'); }
});

// El cliente final vuelve desde Flow tras intentar registrar su tarjeta
app.get('/api/flow/clientes/registro-retorno', async (req, res) => {
  try {
    const token = req.query.token;
    if (token) {
      const st = await flowCall('GET', '/customer/getRegisterStatus', { token });
      if (st.status === 1) // 1 = registro exitoso (confirma el valor exacto en sandbox)
        await pool.query('UPDATE flow_clientes SET tarjeta_registrada=TRUE WHERE token_registro=$1', [token]);
    }
    res.redirect(303, `${APP_URL}/?registro=ok`);
  } catch (e) { console.error(e); res.redirect(303, `${APP_URL}/?registro=error`); }
});

// Consulta si un cliente ya registró su tarjeta
app.get('/api/flow/clientes/:clienteId/estado', auth, async (req, res) => {
  try {
    const r = (await pool.query(
      'SELECT tarjeta_registrada FROM flow_clientes WHERE user_id=$1 AND cliente_id=$2',
      [req.userId, Number(req.params.clienteId)])).rows[0];
    res.json({ registrado: !!(r && r.tarjeta_registrada) });
  } catch (e) { fail(res, e, 'Error al consultar el estado'); }
});

// Cobra automáticamente a un cliente que ya registró su tarjeta
app.post('/api/flow/clientes/:clienteId/cobrar', auth, async (req, res) => {
  try {
    if (!FLOW_KEY || !FLOW_SECRET) return res.status(503).json({ error: 'Los pagos aún no están configurados' });
    const clienteId = Number(req.params.clienteId);
    const monto = Number(req.body.monto), subject = String(req.body.subject || 'Cobro de membresía').slice(0, 100);
    if (!Number.isFinite(monto) || monto < 350) return res.status(400).json({ error: 'Monto inválido (mínimo $350)' });

    const fc = (await pool.query(
      'SELECT flow_customer_id,tarjeta_registrada FROM flow_clientes WHERE user_id=$1 AND cliente_id=$2',
      [req.userId, clienteId])).rows[0];
    if (!fc || !fc.tarjeta_registrada) return res.status(400).json({ error: 'Este cliente aún no registró su tarjeta' });

    const orden = `COB-${req.userId}-${clienteId}-${Date.now()}`;
    await pool.query(
      'INSERT INTO flow_cobros(user_id,cliente_id,flow_customer_id,commerce_order,monto) VALUES($1,$2,$3,$4,$5)',
      [req.userId, clienteId, fc.flow_customer_id, orden, monto]);

    const f = await flowCall('POST', '/customer/charge', {
      customerId: fc.flow_customer_id, commerceOrder: orden, subject, currency: 'CLP', amount: monto,
      urlConfirmation: `${APP_URL}/api/flow/cobros/confirmar`, urlReturn: `${APP_URL}/?cobro=ok`
    });
    await pool.query('UPDATE flow_cobros SET flow_order=$1 WHERE commerce_order=$2', [String(f.flowOrder || ''), orden]);
    res.json({ ok: true, commerceOrder: orden });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: e.message || 'No se pudo realizar el cobro' });
  }
});

// Webhook: Flow confirma el resultado del cobro automático
app.post('/api/flow/cobros/confirmar', async (req, res) => {
  try {
    const token = req.body.token;
    const f = await flowCall('GET', '/payment/getStatus', { token });
    const estado = { 1: 'pendiente', 2: 'pagado', 3: 'rechazado', 4: 'anulado' }[f.status] || 'desconocido';
    await pool.query('UPDATE flow_cobros SET estado=$1, pagado_at=CASE WHEN $1=\'pagado\' THEN NOW() ELSE pagado_at END WHERE commerce_order=$2',
      [estado, f.commerceOrder]);
    res.sendStatus(200);
  } catch (e) { console.error(e); res.sendStatus(500); }
});

// Historial de cobros automáticos de un cliente
app.get('/api/flow/clientes/:clienteId/cobros', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT commerce_order,monto,estado,created_at,pagado_at FROM flow_cobros WHERE user_id=$1 AND cliente_id=$2 ORDER BY id DESC LIMIT 20',
      [req.userId, Number(req.params.clienteId)]);
    res.json(r.rows);
  } catch (e) { fail(res, e, 'Error al cargar los cobros'); }
});

(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL,
      nombre VARCHAR(255) NOT NULL, iniciales VARCHAR(5), iva_porc INT DEFAULT 19,
      plan VARCHAR(50) DEFAULT 'basico', created_at TIMESTAMP DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS user_data(
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      estado JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMP DEFAULT NOW());
    ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_vence TIMESTAMP;
    CREATE TABLE IF NOT EXISTS pagos(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      commerce_order VARCHAR(100) UNIQUE NOT NULL, token VARCHAR(100), flow_order VARCHAR(50),
      plan VARCHAR(50) NOT NULL, monto INT NOT NULL, estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
      created_at TIMESTAMP DEFAULT NOW(), pagado_at TIMESTAMP);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flow_merchant_id VARCHAR(100);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS flow_merchant_estado VARCHAR(20) DEFAULT 'pendiente';
    -- Un cliente final (el de la empresa, no el de Vencio) registrado en Flow para cobro automático.
    -- cliente_id apunta al "id" dentro del arreglo JSON estado.clientes (no hay tabla clientes).
    CREATE TABLE IF NOT EXISTS flow_clientes(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      cliente_id INT NOT NULL, flow_customer_id VARCHAR(100) UNIQUE NOT NULL,
      tarjeta_registrada BOOLEAN NOT NULL DEFAULT FALSE, token_registro VARCHAR(200),
      created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, cliente_id));
    CREATE TABLE IF NOT EXISTS flow_cobros(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      cliente_id INT NOT NULL, flow_customer_id VARCHAR(100) NOT NULL,
      commerce_order VARCHAR(100) UNIQUE NOT NULL, monto INT NOT NULL,
      estado VARCHAR(20) NOT NULL DEFAULT 'pendiente', flow_order VARCHAR(50), error_msg TEXT,
      created_at TIMESTAMP DEFAULT NOW(), pagado_at TIMESTAMP);`);
  app.listen(PORT, () => console.log(`✓ Vencio corriendo en http://localhost:${PORT}`));
})().catch(e => { console.error('No se pudo conectar a PostgreSQL:', e.message); process.exit(1); });
