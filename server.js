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
// Mercado Pago (OAuth): cada usuario conecta su propia cuenta para traer sus ventas
const MP_CLIENT_ID = process.env.MP_CLIENT_ID, MP_CLIENT_SECRET = process.env.MP_CLIENT_SECRET;
if (!MP_CLIENT_ID || !MP_CLIENT_SECRET) console.warn('Aviso: faltan MP_CLIENT_ID / MP_CLIENT_SECRET, conectar Mercado Pago no funcionará.');
// Las credenciales de cada usuario se cifran con esta llave antes de guardarlas en la base de datos
const ENC_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const encrypt = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const e = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, e, c.getAuthTag()].map(b => b.toString('base64')).join('.'); };
const decrypt = s => { const [iv, e, tag] = s.split('.').map(b => Buffer.from(b, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(e), d.final()]).toString('utf8'); };
// Precios en CLP por 30 días. AJÚSTALOS a lo que quieras cobrar (Flow exige mínimo $350).
const PLANES = { Principal: 13000, Plus: 22000, Pro: 36000, Omnibus: 64000 };
if (!FLOW_KEY || !FLOW_SECRET) console.warn('Aviso: faltan FLOW_API_KEY / FLOW_API_SECRET, los pagos con Flow no funcionarán.');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
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

app.post('/api/auth/register', async (req, res) => {
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
    res.status(201).json({ token: makeToken(u), user: u });
  } catch (e) { fail(res, e, 'No se pudo crear la cuenta'); }
});

app.post('/api/auth/login', async (req, res) => {
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
    const r = await pool.query('SELECT estado FROM user_data WHERE user_id=$1', [req.userId]);
    res.json({ estado: r.rows[0] ? r.rows[0].estado : estadoInicial() });
  } catch (e) { fail(res, e, 'Error al cargar los datos'); }
});

app.put('/api/state', auth, async (req, res) => {
  try {
    const b = req.body, estado = {};
    for (const k of ['empresas', 'clientes', 'ventas', 'notifs', 'moderadores']) estado[k] = Array.isArray(b[k]) ? b[k] : [];
    estado.config = b.config && typeof b.config === 'object' ? b.config : {};
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
    const u = (await pool.query('SELECT plan,plan_vence FROM users WHERE id=$1', [req.userId])).rows[0];
    const pagos = (await pool.query(
      'SELECT plan,monto,estado,created_at,pagado_at FROM pagos WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [req.userId])).rows;
    res.json({ plan: u.plan, plan_vence: u.plan_vence, pagos });
  } catch (e) { fail(res, e, 'Error al cargar los pagos'); }
});

// ── Mercado Pago: conectar la cuenta del usuario y traer sus pagos ──
// 1) El usuario hace clic en "Conectar": lo mandamos a loguearse en Mercado Pago.
//    Usamos su propio JWT como "state" para saber, al volver, a qué usuario de Vencio pertenece.
app.get('/api/mp/conectar', (req, res) => {
  try {
    const userId = jwt.verify(req.query.token || '', JWT_SECRET).id;
    const qs = new URLSearchParams({
      client_id: MP_CLIENT_ID, response_type: 'code', platform_id: 'mp',
      redirect_uri: `${APP_URL}/api/mp/callback`, state: req.query.token }).toString();
    res.redirect(`https://auth.mercadopago.cl/authorization?${qs}`);
  } catch (e) { res.status(401).send('Sesión inválida, vuelve a intentarlo desde Vencio.'); }
});

// 2) Mercado Pago nos devuelve un "code": lo cambiamos por el token de acceso del usuario y lo guardamos cifrado
app.get('/api/mp/callback', async (req, res) => {
  try {
    const userId = jwt.verify(req.query.state || '', JWT_SECRET).id;
    const r = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'authorization_code',
        code: req.query.code, redirect_uri: `${APP_URL}/api/mp/callback` }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.message || 'Mercado Pago rechazó la conexión');
    await pool.query(
      `INSERT INTO mp_cuentas(user_id,mp_user_id,access_token,refresh_token,public_key,expires_at)
       VALUES($1,$2,$3,$4,$5,NOW() + ($6||' seconds')::interval)
       ON CONFLICT(user_id) DO UPDATE SET mp_user_id=$2,access_token=$3,refresh_token=$4,public_key=$5,expires_at=NOW() + ($6||' seconds')::interval`,
      [userId, d.user_id, encrypt(d.access_token), encrypt(d.refresh_token), d.public_key, d.expires_in]);
    res.redirect(303, '/?mp=ok');
  } catch (e) { console.error(e); res.redirect(303, '/?mp=error'); }
});

// Devuelve (y si hace falta renueva) el access_token ya descifrado de un usuario
const mpToken = async userId => {
  const c = (await pool.query('SELECT * FROM mp_cuentas WHERE user_id=$1', [userId])).rows[0];
  if (!c) return null;
  if (new Date(c.expires_at) > new Date()) return decrypt(c.access_token);
  const r = await fetch('https://api.mercadopago.com/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'refresh_token', refresh_token: decrypt(c.refresh_token) }) });
  const d = await r.json();
  if (!r.ok) { await pool.query('DELETE FROM mp_cuentas WHERE user_id=$1', [userId]); return null; }
  await pool.query('UPDATE mp_cuentas SET access_token=$1,refresh_token=$2,expires_at=NOW() + ($3||\' seconds\')::interval WHERE user_id=$4',
    [encrypt(d.access_token), encrypt(d.refresh_token), d.expires_in, userId]);
  return d.access_token;
};

// 3) ¿Este usuario ya conectó su Mercado Pago?
app.get('/api/mp/estado', auth, async (req, res) => {
  try { res.json({ conectado: !!(await pool.query('SELECT 1 FROM mp_cuentas WHERE user_id=$1', [req.userId])).rowCount }); }
  catch (e) { fail(res, e, 'Error al consultar Mercado Pago'); }
});

app.post('/api/mp/desconectar', auth, async (req, res) => {
  try { await pool.query('DELETE FROM mp_cuentas WHERE user_id=$1', [req.userId]); res.json({ ok: true }); }
  catch (e) { fail(res, e, 'Error al desconectar Mercado Pago'); }
});

// 4) Trae las ventas reales del usuario desde Mercado Pago (lo que alimenta los gráficos)
app.get('/api/mp/ventas', auth, async (req, res) => {
  try {
    const token = await mpToken(req.userId);
    if (!token) return res.status(404).json({ error: 'Cuenta de Mercado Pago no conectada' });
    const r = await fetch('https://api.mercadopago.com/v1/payments/search?sort=date_created&criteria=desc&limit=50', {
      headers: { Authorization: `Bearer ${token}` } });
    const d = await r.json();
    if (!r.ok) throw new Error(d.message || 'Error al traer las ventas de Mercado Pago');
    res.json({ ventas: (d.results || []).map(p => ({
      id: p.id, monto: p.transaction_amount, estado: p.status, fecha: p.date_created,
      pagador: p.payer && p.payer.email, descripcion: p.description })) });
  } catch (e) { fail(res, e, 'Error al traer las ventas de Mercado Pago'); }
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
    CREATE TABLE IF NOT EXISTS mp_cuentas(
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, mp_user_id VARCHAR(50),
      access_token TEXT NOT NULL, refresh_token TEXT NOT NULL, public_key VARCHAR(100), expires_at TIMESTAMP NOT NULL);
    CREATE TABLE IF NOT EXISTS pagos(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      commerce_order VARCHAR(100) UNIQUE NOT NULL, token VARCHAR(100), flow_order VARCHAR(50),
      plan VARCHAR(50) NOT NULL, monto INT NOT NULL, estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
      created_at TIMESTAMP DEFAULT NOW(), pagado_at TIMESTAMP);`);
  app.listen(PORT, () => console.log(`✓ Vencio corriendo en http://localhost:${PORT}`));
})().catch(e => { console.error('No se pudo conectar a PostgreSQL:', e.message); process.exit(1); });
