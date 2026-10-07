require('dotenv').config();
const express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), { Pool } = require('pg'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 5000, JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error('Falta DATABASE_URL o JWT_SECRET. Revisa que el archivo se llame ".env" (con punto) y esté junto a server.js.');
  process.exit(1);
}
const APP_URL = (process.env.APP_URL || 'https://vencio-production.up.railway.app').replace(/\/$/, '');
// Precios en CLP por 30 días. AJÚSTALOS a lo que quieras cobrar.
// Si los cambias, cámbialos también en index.html: PLANES_LP (portada) y la pantalla "Planes" de la app.
const PLANES = { Principal: 7990, Plus: 16990, Pro: 27990, Omnibus: 59990 };
// Prueba gratis: 14 días del plan Principal. Mercado Pago pide la tarjeta al activarla (no se cobra nada hasta
// el día 14) y luego cobra solo, cada 30 días, hasta que el usuario cancele. Solo se puede usar una vez por cuenta.
const DIAS_PRUEBA = 14, PLAN_PRUEBA = 'Principal';
// SEGURIDAD: límites reales de cada plan, validados en el servidor (el navegador no es de fiar).
// 'basico' es el plan de las cuentas nuevas o con el plan vencido. AJUSTA estos números a tu gusto.
const LIMITES_PLAN = {
  basico:    { empresas: 1,        clientes: 50,       moderadores: 0 },
  Principal: { empresas: 1,        clientes: 50,       moderadores: 0 },
  Plus:      { empresas: 2,        clientes: 200,      moderadores: 1 },
  Pro:       { empresas: 3,        clientes: 500,      moderadores: 3 },
  Omnibus:   { empresas: Infinity, clientes: Infinity, moderadores: Infinity }
};

// ── Mercado Pago ──
// MP_ACCESS_TOKEN: el Access Token de TU propia cuenta Vencio (el de "Credenciales de producción").
//   Se usa para cobrar los planes de Vencio y, en el modelo marketplace, para leer el estado de pagos
//   y suscripciones de las cuentas que los usuarios conectan (lo permite MP porque son de tu misma app).
// MP_CLIENT_ID / MP_CLIENT_SECRET: los de "Datos de integración" de tu app, para el OAuth de cada usuario.
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const MP_CLIENT_ID = process.env.MP_CLIENT_ID, MP_CLIENT_SECRET = process.env.MP_CLIENT_SECRET;
if (!MP_ACCESS_TOKEN) console.warn('Aviso: falta MP_ACCESS_TOKEN, el cobro de planes de Vencio no funcionará.');
if (!MP_CLIENT_ID || !MP_CLIENT_SECRET) console.warn('Aviso: faltan MP_CLIENT_ID / MP_CLIENT_SECRET, conectar Mercado Pago no funcionará.');
// Las credenciales de cada usuario (access/refresh token de su cuenta MP) se cifran antes de guardarse.
const ENC_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const encrypt = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const e = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, e, c.getAuthTag()].map(b => b.toString('base64')).join('.'); };
const decrypt = s => { const [iv, e, tag] = s.split('.').map(b => Buffer.from(b, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(e), d.final()]).toString('utf8'); };
// Llamada genérica a la API de Mercado Pago con un token dado
const mpCall = async (method, path, token, body) => {
  const r = await fetch(`https://api.mercadopago.com${path}`, {
    method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d && d.message) || 'Error al comunicarse con Mercado Pago');
  return d;
};

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '5mb', verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const fail = (res, e, msg) => { console.error(e); res.status(500).json({ error: msg }); };
const makeToken = u => jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try { req.userId = jwt.verify((req.headers.authorization || '').split(' ')[1], JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Sesión inválida' }); }
};
// ivaPorc: % de IVA con el que parte la cuenta nueva. Lo elige el usuario en el registro según su país (el
// IVA varía por país), y queda guardado en su config para que no todas las cuentas partan asumiendo Chile.
const estadoInicial = (empresa, ivaPorc) => ({
  empresas: [{ id: 1, nombre: empresa || 'Mi Empresa' }], clientes: [], ventas: [], notifs: [], moderadores: [],
  config: { ivaPorc: Number.isFinite(ivaPorc) && ivaPorc >= 0 && ivaPorc <= 100 ? ivaPorc : 19 },
});

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

app.post('/api/auth/register', limitar(10, 3600000), async (req, res) => {
  try {
    const { email, password, nombre, empresa, ivaPorc } = req.body;
    if (!email || !password || !nombre) return res.status(400).json({ error: 'Nombre, correo y contraseña son obligatorios' });
    if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    const mail = email.trim().toLowerCase();
    if ((await pool.query('SELECT 1 FROM users WHERE email=$1', [mail])).rowCount)
      return res.status(400).json({ error: 'Ese correo ya está registrado' });
    const ini = nombre.split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
    const u = (await pool.query(
      'INSERT INTO users(email,password,nombre,iniciales) VALUES($1,$2,$3,$4) RETURNING id,email,nombre,iniciales',
      [mail, await bcrypt.hash(password, 10), nombre.trim(), ini])).rows[0];
    await pool.query('INSERT INTO user_data(user_id,estado) VALUES($1,$2)',
      [u.id, estadoInicial(empresa && empresa.trim(), Number(ivaPorc))]);
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
    estado.config = { ...(estado.config || {}), plan };
    res.json({ estado, plan });
  } catch (e) { fail(res, e, 'Error al cargar los datos'); }
});

app.put('/api/state', auth, async (req, res) => {
  try {
    const b = req.body, estado = {};
    for (const k of ['empresas', 'clientes', 'ventas', 'notifs', 'moderadores']) estado[k] = Array.isArray(b[k]) ? b[k] : [];
    const { plan: _ignorado, ...cfg } = (b.config && typeof b.config === 'object' && !Array.isArray(b.config)) ? b.config : {};
    estado.config = cfg;
    estado.notifs = estado.notifs.slice(0, 200);

    const errorForma = validarEstado(estado);
    if (errorForma) return res.status(400).json({ error: errorForma });

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

// ── Pago de los PLANES de Vencio (lo que te cobra a ti el usuario), con Mercado Pago ──
// 1) El usuario elige un plan: creamos una preferencia de pago (Checkout Pro) y devolvemos el link
app.post('/api/pagos/iniciar', auth, async (req, res) => {
  try {
    if (!MP_ACCESS_TOKEN) return res.status(503).json({ error: 'Los pagos aún no están configurados' });
    const plan = req.body.plan, monto = PLANES[plan];
    if (!monto) return res.status(400).json({ error: 'Plan inválido' });
    const u = (await pool.query('SELECT email FROM users WHERE id=$1', [req.userId])).rows[0];
    const orden = `VEN-${req.userId}-${Date.now()}`;
    await pool.query('INSERT INTO pagos(user_id,commerce_order,plan,monto) VALUES($1,$2,$3,$4)', [req.userId, orden, plan, monto]);
    const pref = await mpCall('POST', '/checkout/preferences', MP_ACCESS_TOKEN, {
      items: [{ title: `Vencio - Plan ${plan} (30 días)`, quantity: 1, currency_id: 'CLP', unit_price: monto }],
      payer: { email: u.email }, external_reference: orden,
      back_urls: { success: `${APP_URL}/api/pagos/retorno`, pending: `${APP_URL}/api/pagos/retorno`, failure: `${APP_URL}/api/pagos/retorno` },
      auto_return: 'approved', notification_url: `${APP_URL}/api/pagos/confirmar` });
    res.json({ url: pref.init_point });
  } catch (e) { fail(res, e, 'No se pudo iniciar el pago'); }
});

// Marca el pago de un plan como pagado (idempotente) y le extiende la vigencia al usuario
const procesarPagoPlan = async (orden, pago) => {
  const p = (await pool.query('SELECT * FROM pagos WHERE commerce_order=$1', [orden])).rows[0];
  if (!p) return;
  if (pago.status === 'approved') {
    const up = await pool.query(`UPDATE pagos SET estado='pagado', mp_payment_id=$1, pagado_at=NOW() WHERE id=$2 AND estado<>'pagado'`, [String(pago.id), p.id]);
    if (up.rowCount) await pool.query(
      `UPDATE users SET plan=$1, plan_vence=GREATEST(COALESCE(plan_vence,NOW()),NOW()) + INTERVAL '30 days' WHERE id=$2`, [p.plan, p.user_id]);
  } else if (p.estado !== 'pagado') await pool.query('UPDATE pagos SET estado=$1 WHERE id=$2', [pago.status, p.id]);
};

// 2) Mercado Pago avisa (webhook) que un pago cambió de estado. Sirve tanto para los planes de Vencio
//    como para los cobros a clientes finales (se distingue por el prefijo del external_reference).
app.post('/api/mp/webhook', async (req, res) => {
  try {
    const tipo = req.query.type || req.query.topic || req.body.type;
    const id = req.query['data.id'] || (req.body.data && req.body.data.id) || req.query.id;
    if (!tipo || !id || !MP_ACCESS_TOKEN) return res.sendStatus(200);
    if (tipo === 'payment') {
      const pago = await mpCall('GET', `/v1/payments/${id}`, MP_ACCESS_TOKEN);
      const ref = pago.external_reference || '';
      if (ref.startsWith('VEN-')) await procesarPagoPlan(ref, pago);
      else if (ref.startsWith('COB-')) await procesarCobroCliente(ref, pago);
    } else if (tipo === 'preapproval') {
      const pre = await mpCall('GET', `/preapproval/${id}`, MP_ACCESS_TOKEN);
      const esPrueba = (await pool.query('SELECT 1 FROM vencio_suscripciones WHERE preapproval_id=$1', [pre.id])).rowCount;
      if (esPrueba) await aplicarPrueba(pre); else await procesarSuscripcion(pre);
    } else if (tipo === 'subscription_authorized_payment' || tipo === 'authorized_payment') {
      // Cobro recurrente de una suscripción (el que hace Mercado Pago solo, cada mes). Por ahora solo se usa
      // para la prueba gratis de Vencio; las membresías de los clientes finales no se suman a este historial.
      const fact = await mpCall('GET', `/authorized_payments/${id}`, MP_ACCESS_TOKEN);
      const pago = fact.payment;
      if (fact.preapproval_id && pago && pago.status === 'approved') {
        const ya = (await pool.query('SELECT 1 FROM pagos WHERE mp_payment_id=$1', [String(pago.id)])).rowCount;
        if (!ya) {
          const sus = (await pool.query('SELECT user_id FROM vencio_suscripciones WHERE preapproval_id=$1', [fact.preapproval_id])).rows[0];
          if (sus) {
            const orden = `TRIAL-renew-${pago.id}`;
            await pool.query(
              `INSERT INTO pagos(user_id,commerce_order,plan,monto,estado,mp_payment_id,pagado_at)
               VALUES($1,$2,$3,$4,'pagado',$5,NOW())`,
              [sus.user_id, orden, PLAN_PRUEBA, PLANES[PLAN_PRUEBA], String(pago.id)]);
            await pool.query(
              `UPDATE users SET plan=$1, plan_vence=GREATEST(COALESCE(plan_vence,NOW()),NOW()) + INTERVAL '30 days' WHERE id=$2`,
              [PLAN_PRUEBA, sus.user_id]);
          }
        }
      }
    }
    res.sendStatus(200);
  } catch (e) { console.error('Webhook MP:', e.message); res.sendStatus(200); }
});

// 3) El usuario vuelve desde Mercado Pago tras pagar su plan
app.get('/api/pagos/retorno', async (req, res) => {
  try {
    const orden = req.query.external_reference;
    if (orden && MP_ACCESS_TOKEN) {
      const r = await mpCall('GET', `/v1/payments/search?external_reference=${encodeURIComponent(orden)}&sort=date_created&criteria=desc`, MP_ACCESS_TOKEN);
      const pago = r.results && r.results[0];
      if (pago) await procesarPagoPlan(orden, pago);
    }
    const estado = req.query.status === 'approved' ? 'ok' : req.query.status === 'pending' || req.query.status === 'in_process' ? 'pendiente' : 'error';
    res.redirect(303, `/?pago=${estado}`);
  } catch (e) { console.error(e); res.redirect(303, '/?pago=error'); }
});

// 4) Plan actual e historial de pagos del usuario
app.get('/api/pagos', auth, async (req, res) => {
  try {
    await planVigente(req.userId);
    const u = (await pool.query('SELECT plan,plan_vence,trial_usado FROM users WHERE id=$1', [req.userId])).rows[0];
    const pagos = (await pool.query(
      'SELECT plan,monto,estado,created_at,pagado_at FROM pagos WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [req.userId])).rows;
    const sus = (await pool.query('SELECT estado FROM vencio_suscripciones WHERE user_id=$1', [req.userId])).rows[0];
    res.json({ plan: u.plan, plan_vence: u.plan_vence, pagos, trial_usado: u.trial_usado, prueba_estado: sus ? sus.estado : null });
  } catch (e) { fail(res, e, 'Error al cargar los pagos'); }
});

// ── Prueba gratis de 14 días (plan Principal), con cobro automático real al vencer ──
// 1) El usuario activa la prueba: se crea una SUSCRIPCIÓN en Mercado Pago (preapproval) con "free_trial" de 14
//    días. Mercado Pago pide la tarjeta ahora pero no cobra nada hasta que el período gratis termine.
app.post('/api/pagos/prueba', auth, async (req, res) => {
  try {
    if (!MP_ACCESS_TOKEN) return res.status(503).json({ error: 'Los pagos aún no están configurados' });
    const u = (await pool.query('SELECT email,trial_usado FROM users WHERE id=$1', [req.userId])).rows[0];
    if (u.trial_usado) return res.status(400).json({ error: 'Ya usaste tu prueba gratis de 14 días' });
    const pre = await mpCall('POST', '/preapproval', MP_ACCESS_TOKEN, {
      reason: `Vencio - Plan ${PLAN_PRUEBA} (prueba ${DIAS_PRUEBA} días)`, external_reference: `TRIAL-${req.userId}`,
      payer_email: u.email, back_url: `${APP_URL}/api/pagos/retorno-prueba`, status: 'pending',
      auto_recurring: {
        frequency: 1, frequency_type: 'months', transaction_amount: PLANES[PLAN_PRUEBA], currency_id: 'CLP',
        free_trial: { frequency: DIAS_PRUEBA, frequency_type: 'days' } } });
    await pool.query(
      `INSERT INTO vencio_suscripciones(user_id,preapproval_id,estado) VALUES($1,$2,'pending')
       ON CONFLICT(user_id) DO UPDATE SET preapproval_id=$2, estado='pending'`, [req.userId, pre.id]);
    res.json({ url: pre.init_point });
  } catch (e) { fail(res, e, 'No se pudo activar la prueba gratis'); }
});

// Aplica el resultado de la suscripción de prueba (lo usan el webhook y el retorno, de forma idempotente).
// Solo activa el plan Principal la PRIMERA vez que la suscripción queda autorizada (trial_usado evita que una
// reautorización posterior, o un reintento de Mercado Pago, vuelva a extender el período gratis).
const aplicarPrueba = async pre => {
  const up = await pool.query('UPDATE vencio_suscripciones SET estado=$1 WHERE preapproval_id=$2 RETURNING user_id',
    [pre.status, pre.id]);
  if (!up.rowCount) return;
  if (pre.status === 'authorized') await pool.query(
    `UPDATE users SET plan=$1, plan_vence=NOW() + ($2||' days')::interval, trial_usado=TRUE
     WHERE id=$3 AND trial_usado=FALSE`, [PLAN_PRUEBA, DIAS_PRUEBA, up.rows[0].user_id]);
};

// 2) El usuario vuelve desde Mercado Pago tras autorizar (o cancelar) la tarjeta de la prueba
app.get('/api/pagos/retorno-prueba', async (req, res) => {
  try {
    const id = req.query.preapproval_id;
    if (id && MP_ACCESS_TOKEN) await aplicarPrueba(await mpCall('GET', `/preapproval/${id}`, MP_ACCESS_TOKEN));
    res.redirect(303, `/?prueba=${id ? 'ok' : 'error'}`);
  } catch (e) { console.error(e); res.redirect(303, '/?prueba=error'); }
});

// 3) Cancelar la suscripción de la prueba ANTES de que Mercado Pago cobre al día 14 (o más adelante, para que
//    no se renueve el mes siguiente). El acceso al plan Principal se mantiene hasta la fecha ya pagada/gratis.
app.post('/api/pagos/prueba/cancelar', auth, async (req, res) => {
  try {
    const r = (await pool.query('SELECT preapproval_id FROM vencio_suscripciones WHERE user_id=$1', [req.userId])).rows[0];
    if (!r) return res.status(404).json({ error: 'No tienes una suscripción de prueba activa' });
    if (MP_ACCESS_TOKEN) await mpCall('PUT', `/preapproval/${r.preapproval_id}`, MP_ACCESS_TOKEN, { status: 'cancelled' }).catch(() => {});
    await pool.query("UPDATE vencio_suscripciones SET estado='cancelled' WHERE user_id=$1", [req.userId]);
    res.json({ ok: true });
  } catch (e) { fail(res, e, 'No se pudo cancelar la prueba'); }
});

// ── WooCommerce / Shopify: traer clientes automáticamente a Vencio ──
const wooApi = async (ig, method, path, params = {}) => {
  const base = ig.dominio.replace(/\/$/, '');
  const qs = new URLSearchParams({ ...params, consumer_key: ig.cred1, consumer_secret: ig.cred2 }).toString();
  const r = await fetch(`${base}/wp-json/wc/v3${path}?${qs}`, { method });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d && (d.message || d.error)) || 'Error al conectar con WooCommerce');
  return d;
};
const shopifyApi = async (ig, method, path, body) => {
  const r = await fetch(`https://${ig.dominio}/admin/api/2024-01${path}`, {
    method, headers: { 'X-Shopify-Access-Token': ig.cred1, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d && d.errors && JSON.stringify(d.errors)) || 'Error al conectar con Shopify');
  return d;
};
const verificarFirmaWoo = (req, secret) => {
  const firma = req.get('X-WC-Webhook-Signature');
  if (!firma || !req.rawBody) return false;
  const esperada = crypto.createHmac('sha256', secret).update(req.rawBody).digest('base64');
  try { return crypto.timingSafeEqual(Buffer.from(firma), Buffer.from(esperada)); } catch { return false; }
};
const verificarFirmaShopify = (req, secret) => {
  const firma = req.get('X-Shopify-Hmac-Sha256');
  if (!firma || !req.rawBody) return false;
  const esperada = crypto.createHmac('sha256', secret).update(req.rawBody).digest('base64');
  try { return crypto.timingSafeEqual(Buffer.from(firma), Buffer.from(esperada)); } catch { return false; }
};

const upsertClienteExterno = async (userId, empresaId, origen, externalId, datos) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query('SELECT estado FROM user_data WHERE user_id=$1 FOR UPDATE', [userId]);
    const estado = (r.rows[0] && r.rows[0].estado) || estadoInicial();
    estado.clientes = Array.isArray(estado.clientes) ? estado.clientes : [];
    let c = estado.clientes.find(x => x.origen === origen && x.externalId === externalId);
    if (c) {
      c.nombre = datos.nombre || c.nombre; c.email = datos.email || c.email; c.telefono = datos.telefono || c.telefono;
    } else {
      const nextId = estado.clientes.reduce((m, x) => Math.max(m, x.id || 0), 0) + 1;
      c = {
        id: nextId, empresa: empresaId, nombre: datos.nombre || '(sin nombre)', email: datos.email || '',
        telefono: datos.telefono || '', rut: '', tipo: 'membresia', montoCuota: 0, cuotasPagadas: 0, cuotasTotal: 0,
        metodoPago: '—', estado: 'pendiente', proximoVenc: null, historial: [], notas: [],
        origen, externalId
      };
      estado.clientes.push(c);
    }
    await client.query(
      `INSERT INTO user_data(user_id,estado) VALUES($1,$2)
       ON CONFLICT(user_id) DO UPDATE SET estado=$2, updated_at=NOW()`, [userId, estado]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
};

// Pedidos/ventas traídos de WooCommerce y Shopify (para las gráficas). Van en una tabla aparte
// (no en el JSON de estado) porque hay que sumarlos y agruparlos por fecha.
// Solo estos estados cuentan como venta en las gráficas (no pendientes, cancelados ni reembolsados del todo).
const ESTADOS_VENTA = ['completed', 'processing', 'paid', 'partially_paid', 'partially_refunded'];
const comoUTC = f => !f ? new Date().toISOString() : (/(Z|[+-]\d\d:?\d\d)$/.test(f) ? f : f + 'Z');
const datosPedidoWoo = p => ({
  monto: Number(p.total) || 0, moneda: p.currency || 'CLP', estado: String(p.status || ''),
  clienteNombre: `${p.billing?.first_name || ''} ${p.billing?.last_name || ''}`.trim(), fecha: comoUTC(p.date_created_gmt || p.date_created)
});
const datosPedidoShopify = p => ({
  monto: Number(p.total_price) || 0, moneda: p.currency || 'CLP', estado: String(p.financial_status || ''),
  clienteNombre: `${p.customer?.first_name || ''} ${p.customer?.last_name || ''}`.trim(), fecha: comoUTC(p.created_at)
});
const upsertVentaExterna = async (ig, externalId, d) => {
  await pool.query(
    `INSERT INTO ventas_tienda(integracion_id,user_id,empresa_id,external_id,monto,moneda,estado,cliente_nombre,fecha_pedido)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT(integracion_id,external_id) DO UPDATE SET monto=$5,moneda=$6,estado=$7,cliente_nombre=$8`,
    [ig.id, ig.user_id, ig.empresa_id, externalId, d.monto, d.moneda, d.estado, d.clienteNombre, d.fecha]);
};

app.get('/api/integraciones', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id,empresa_id,tipo,nombre,dominio,activa,ultima_sync,
              (webhook_id_remoto IS NOT NULL) AS webhook_activo
       FROM integraciones_tienda WHERE user_id=$1 ORDER BY id DESC`, [req.userId]);
    res.json(r.rows);
  } catch (e) { fail(res, e, 'Error al cargar las integraciones'); }
});

app.post('/api/integraciones', auth, async (req, res) => {
  try {
    const { tipo, empresaId, nombre, dominio } = req.body;
    let { cred1, cred2 } = req.body;
    if (!['woocommerce', 'shopify'].includes(tipo)) return res.status(400).json({ error: 'Tipo de tienda inválido' });
    if (!empresaId || !nombre || !dominio || !cred1 || !cred2) return res.status(400).json({ error: 'Faltan datos de conexión' });

    const dom = String(dominio).trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    const ig = { dominio: tipo === 'woocommerce' ? `https://${dom}` : dom, cred1: String(cred1).trim(), cred2: String(cred2).trim() };

    if (tipo === 'woocommerce') await wooApi(ig, 'GET', '/customers', { per_page: 1 });
    else await shopifyApi(ig, 'GET', '/shop.json');

    const webhookSecret = tipo === 'woocommerce' ? crypto.randomBytes(24).toString('hex') : null;
    const row = (await pool.query(
      `INSERT INTO integraciones_tienda(user_id,empresa_id,tipo,nombre,dominio,cred1,cred2,webhook_secret)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [req.userId, empresaId, tipo, nombre, ig.dominio, ig.cred1, ig.cred2, webhookSecret])).rows[0];

    let webhookOk = false, avisoWebhook = null;
    try {
      if (tipo === 'woocommerce') {
        const base = ig.dominio.replace(/\/$/, '');
        const qs = new URLSearchParams({ consumer_key: ig.cred1, consumer_secret: ig.cred2 }).toString();
        const r1 = await fetch(`${base}/wp-json/wc/v3/webhooks?${qs}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Vencio - clientes creados', topic: 'customer.created',
            delivery_url: `${APP_URL}/api/webhooks/woocommerce/${row.id}`, secret: webhookSecret })
        });
        const d1 = await r1.json();
        if (r1.ok) { await pool.query('UPDATE integraciones_tienda SET webhook_id_remoto=$1 WHERE id=$2', [String(d1.id), row.id]); webhookOk = true; }
      } else {
        const d1 = await shopifyApi(ig, 'POST', '/webhooks.json', {
          webhook: { topic: 'customers/create', address: `${APP_URL}/api/webhooks/shopify/${row.id}`, format: 'json' }
        });
        if (d1.webhook) { await pool.query('UPDATE integraciones_tienda SET webhook_id_remoto=$1 WHERE id=$2', [String(d1.webhook.id), row.id]); webhookOk = true; }
      }
    } catch (e) { avisoWebhook = 'Se conectó la tienda, pero no se pudo activar la sincronización automática: ' + e.message + '. Puedes usar "Sincronizar ahora" mientras tanto.'; }

    // Webhooks de pedidos (aparte de los de clientes, para que si uno falla el otro igual quede). Avisan al crear y al actualizar.
    try {
      const idsPed = [];
      if (tipo === 'woocommerce') {
        const base = ig.dominio.replace(/\/$/, '');
        const qs = new URLSearchParams({ consumer_key: ig.cred1, consumer_secret: ig.cred2 }).toString();
        for (const [nombreHook, topic] of [['Vencio - pedidos creados', 'order.created'], ['Vencio - pedidos actualizados', 'order.updated']]) {
          const rp = await fetch(`${base}/wp-json/wc/v3/webhooks?${qs}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: nombreHook, topic, delivery_url: `${APP_URL}/api/webhooks/woocommerce-pedido/${row.id}`, secret: webhookSecret })
          });
          const dp = await rp.json();
          if (rp.ok) idsPed.push(String(dp.id));
        }
      } else {
        for (const topic of ['orders/create', 'orders/updated']) {
          const dp = await shopifyApi(ig, 'POST', '/webhooks.json', {
            webhook: { topic, address: `${APP_URL}/api/webhooks/shopify-pedido/${row.id}`, format: 'json' }
          });
          if (dp.webhook) idsPed.push(String(dp.webhook.id));
        }
      }
      if (idsPed.length) await pool.query('UPDATE integraciones_tienda SET webhook_pedidos_remoto=$1 WHERE id=$2', [idsPed.join(','), row.id]);
    } catch (e) { avisoWebhook = (avisoWebhook ? avisoWebhook + ' ' : '') + 'No se pudo activar la sincronización automática de pedidos: ' + e.message + '.'; }

    res.status(201).json({ id: row.id, webhookActivo: webhookOk, aviso: avisoWebhook });
  } catch (e) { res.status(400).json({ error: 'No se pudo conectar la tienda: ' + e.message }); }
});

app.post('/api/integraciones/:id/sincronizar', auth, async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1 AND user_id=$2', [req.params.id, req.userId])).rows[0];
    if (!ig) return res.status(404).json({ error: 'Integración no encontrada' });

    let importados = 0;
    if (ig.tipo === 'woocommerce') {
      for (let pagina = 1; pagina <= 5; pagina++) {
        const clientes = await wooApi(ig, 'GET', '/customers', { per_page: 50, page: pagina });
        if (!Array.isArray(clientes) || !clientes.length) break;
        for (const c of clientes) {
          await upsertClienteExterno(req.userId, ig.empresa_id, 'woocommerce', String(c.id), {
            nombre: `${c.first_name || ''} ${c.last_name || ''}`.trim() || c.username, email: c.email, telefono: c.billing?.phone || ''
          });
          importados++;
        }
        if (clientes.length < 50) break;
      }
    } else {
      let pageInfo = null;
      for (let pagina = 1; pagina <= 5; pagina++) {
        const path = pageInfo ? `/customers.json?limit=50&page_info=${pageInfo}` : '/customers.json?limit=50';
        const d = await shopifyApi(ig, 'GET', path);
        const clientes = d.customers || [];
        if (!clientes.length) break;
        for (const c of clientes) {
          await upsertClienteExterno(req.userId, ig.empresa_id, 'shopify', String(c.id), {
            nombre: `${c.first_name || ''} ${c.last_name || ''}`.trim(), email: c.email, telefono: c.phone || ''
          });
          importados++;
        }
        break;
      }
    }
    // Pedidos/ventas (para las gráficas). Si falla (p. ej. la llave no tiene permiso de pedidos) no se pierde lo de clientes.
    let pedidos = 0, avisoPedidos = null;
    try {
      if (ig.tipo === 'woocommerce') {
        for (let pagina = 1; pagina <= 5; pagina++) {
          const lista = await wooApi(ig, 'GET', '/orders', { per_page: 50, page: pagina });
          if (!Array.isArray(lista) || !lista.length) break;
          for (const p of lista) { await upsertVentaExterna(ig, String(p.id), datosPedidoWoo(p)); pedidos++; }
          if (lista.length < 50) break;
        }
      } else {
        const d = await shopifyApi(ig, 'GET', '/orders.json?status=any&limit=250');
        for (const p of (d.orders || [])) { await upsertVentaExterna(ig, String(p.id), datosPedidoShopify(p)); pedidos++; }
      }
    } catch (e) { avisoPedidos = 'No se pudieron traer los pedidos: ' + e.message; }
    await pool.query('UPDATE integraciones_tienda SET ultima_sync=NOW() WHERE id=$1', [ig.id]);
    res.json({ importados, pedidos, avisoPedidos });
  } catch (e) { res.status(400).json({ error: 'No se pudo sincronizar: ' + e.message }); }
});

// Ventas por día de TODAS las tiendas conectadas de una empresa, para graficar.
// ?dias=30 controla cuántos días hacia atrás (por defecto 30, máximo 180). Los días se cuentan en hora de Chile.
app.get('/api/empresas/:empresaId/ventas-resumen', auth, async (req, res) => {
  try {
    const dias = Math.min(Math.max(parseInt(req.query.dias, 10) || 30, 1), 180);
    const r = await pool.query(
      `SELECT to_char(date_trunc('day', fecha_pedido AT TIME ZONE 'America/Santiago'), 'YYYY-MM-DD') AS dia,
              SUM(monto) AS total, COUNT(*) AS pedidos
       FROM ventas_tienda
       WHERE user_id=$1 AND empresa_id=$2 AND estado = ANY($3) AND fecha_pedido >= NOW() - ($4 || ' days')::interval
       GROUP BY dia ORDER BY dia`,
      [req.userId, Number(req.params.empresaId), ESTADOS_VENTA, dias]);
    res.json(r.rows.map(x => ({ dia: x.dia, total: Number(x.total), pedidos: Number(x.pedidos) })));
  } catch (e) { fail(res, e, 'Error al calcular el resumen de ventas'); }
});

app.delete('/api/integraciones/:id', auth, async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1 AND user_id=$2', [req.params.id, req.userId])).rows[0];
    if (!ig) return res.status(404).json({ error: 'Integración no encontrada' });
    try {
      if (ig.webhook_id_remoto && ig.tipo === 'woocommerce') await wooApi(ig, 'DELETE', `/webhooks/${ig.webhook_id_remoto}`, { force: true });
      if (ig.webhook_id_remoto && ig.tipo === 'shopify') await shopifyApi(ig, 'DELETE', `/webhooks/${ig.webhook_id_remoto}.json`);
    } catch (e) { console.error('No se pudo borrar el webhook remoto:', e.message); }
    try {
      for (const hid of String(ig.webhook_pedidos_remoto || '').split(',').filter(Boolean)) {
        if (ig.tipo === 'woocommerce') await wooApi(ig, 'DELETE', `/webhooks/${hid}`, { force: true });
        else await shopifyApi(ig, 'DELETE', `/webhooks/${hid}.json`);
      }
    } catch (e) { console.error('No se pudo borrar el webhook de pedidos remoto:', e.message); }
    await pool.query('DELETE FROM integraciones_tienda WHERE id=$1', [ig.id]);
    res.json({ ok: true });
  } catch (e) { fail(res, e, 'No se pudo desconectar la tienda'); }
});

app.post('/api/webhooks/woocommerce/:integracionId', async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1', [req.params.integracionId])).rows[0];
    if (!ig || !ig.webhook_secret || !verificarFirmaWoo(req, ig.webhook_secret)) return res.sendStatus(401);
    const c = req.body;
    await upsertClienteExterno(ig.user_id, ig.empresa_id, 'woocommerce', String(c.id), {
      nombre: `${c.first_name || ''} ${c.last_name || ''}`.trim() || c.username, email: c.email, telefono: c.billing?.phone || ''
    });
    await pool.query('UPDATE integraciones_tienda SET ultima_sync=NOW() WHERE id=$1', [ig.id]);
    res.sendStatus(200);
  } catch (e) { console.error('Webhook WooCommerce:', e.message); res.sendStatus(500); }
});

app.post('/api/webhooks/shopify/:integracionId', async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1', [req.params.integracionId])).rows[0];
    if (!ig || !verificarFirmaShopify(req, ig.cred2)) return res.sendStatus(401);
    const c = req.body;
    await upsertClienteExterno(ig.user_id, ig.empresa_id, 'shopify', String(c.id), {
      nombre: `${c.first_name || ''} ${c.last_name || ''}`.trim(), email: c.email, telefono: c.phone || ''
    });
    await pool.query('UPDATE integraciones_tienda SET ultima_sync=NOW() WHERE id=$1', [ig.id]);
    res.sendStatus(200);
  } catch (e) { console.error('Webhook Shopify:', e.message); res.sendStatus(500); }
});

app.post('/api/webhooks/woocommerce-pedido/:integracionId', async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1', [req.params.integracionId])).rows[0];
    if (!ig || !ig.webhook_secret) return res.sendStatus(401);
    // Al crear un webhook, WooCommerce manda un "ping" de prueba sin datos de pedido: se responde OK y no se hace nada
    if (req.body && req.body.webhook_id !== undefined && req.body.id === undefined) return res.sendStatus(200);
    if (!verificarFirmaWoo(req, ig.webhook_secret)) return res.sendStatus(401);
    await upsertVentaExterna(ig, String(req.body.id), datosPedidoWoo(req.body));
    await pool.query('UPDATE integraciones_tienda SET ultima_sync=NOW() WHERE id=$1', [ig.id]);
    res.sendStatus(200);
  } catch (e) { console.error('Webhook WooCommerce pedido:', e.message); res.sendStatus(500); }
});

app.post('/api/webhooks/shopify-pedido/:integracionId', async (req, res) => {
  try {
    const ig = (await pool.query('SELECT * FROM integraciones_tienda WHERE id=$1', [req.params.integracionId])).rows[0];
    if (!ig || !verificarFirmaShopify(req, ig.cred2)) return res.sendStatus(401);
    await upsertVentaExterna(ig, String(req.body.id), datosPedidoShopify(req.body));
    await pool.query('UPDATE integraciones_tienda SET ultima_sync=NOW() WHERE id=$1', [ig.id]);
    res.sendStatus(200);
  } catch (e) { console.error('Webhook Shopify pedido:', e.message); res.sendStatus(500); }
});

// ── Mercado Pago: cada usuario conecta su propia cuenta (OAuth) ──
// No necesita que nadie te apruebe nada: es autoservicio, a diferencia de lo que pasaba con Flow.
app.get('/api/mp/conectar', (req, res) => {
  try {
    jwt.verify(req.query.token || '', JWT_SECRET); // solo valida que el link no esté vencido/alterado
    const qs = new URLSearchParams({
      client_id: MP_CLIENT_ID, response_type: 'code', platform_id: 'mp',
      redirect_uri: `${APP_URL}/api/mp/callback`, state: req.query.token }).toString();
    res.redirect(`https://auth.mercadopago.cl/authorization?${qs}`);
  } catch (e) { res.status(401).send('Sesión inválida, vuelve a intentarlo desde Vencio.'); }
});

app.get('/api/mp/callback', async (req, res) => {
  // Ante cualquier fallo: lo anota en el log del servidor y manda el motivo a la pantalla
  const fallo = motivo => { console.error('MP callback falló:', motivo); res.redirect(303, '/?mp=error&motivo=' + encodeURIComponent(motivo.slice(0, 200))); };
  try {
    if (req.query.error) return fallo(`Mercado Pago devolvió: ${req.query.error} ${req.query.error_description || ''}`.trim());
    let userId;
    try { userId = jwt.verify(req.query.state || '', JWT_SECRET).id; } catch { return fallo('La sesión no es válida o venció (state)'); }
    const r = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'authorization_code',
        code: req.query.code, redirect_uri: `${APP_URL}/api/mp/callback` }) });
    const t = await r.json().catch(() => ({}));
    if (!r.ok) return fallo(`Mercado Pago rechazó el código (${r.status}): ${t.error || ''} ${t.message || ''}`.trim());
    if (!t.access_token || !t.refresh_token) return fallo('Mercado Pago no devolvió los tokens (¿permiso offline_access?)');
    await pool.query(
      `INSERT INTO mp_cuentas(user_id,mp_user_id,access_token,refresh_token,public_key,expires_at)
       VALUES($1,$2,$3,$4,$5,NOW() + ($6||' seconds')::interval)
       ON CONFLICT(user_id) DO UPDATE SET mp_user_id=$2,access_token=$3,refresh_token=$4,public_key=$5,expires_at=NOW() + ($6||' seconds')::interval`,
      [userId, t.user_id, encrypt(t.access_token), encrypt(t.refresh_token), t.public_key, t.expires_in]);
    olvidarCuentaMP(userId);
    res.redirect(303, '/?mp=ok');
  } catch (e) { fallo('Error interno: ' + e.message); }
});

// Devuelve (y si hace falta renueva) el access_token ya descifrado de la cuenta MP conectada por un usuario
const mpTokenDeUsuario = async userId => {
  const c = (await pool.query('SELECT * FROM mp_cuentas WHERE user_id=$1', [userId])).rows[0];
  if (!c) return null;
  if (new Date(c.expires_at) > new Date()) return decrypt(c.access_token);
  const r = await fetch('https://api.mercadopago.com/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'refresh_token', refresh_token: decrypt(c.refresh_token) }) });
  const t = await r.json();
  if (!r.ok) { await pool.query('DELETE FROM mp_cuentas WHERE user_id=$1', [userId]); return null; }
  await pool.query(`UPDATE mp_cuentas SET access_token=$1,refresh_token=$2,expires_at=NOW() + ($3||' seconds')::interval WHERE user_id=$4`,
    [encrypt(t.access_token), encrypt(t.refresh_token), t.expires_in, userId]);
  return t.access_token;
};

// ── Estado financiero en vivo de la cuenta de Mercado Pago que conectó el usuario ──
// Lo que la API de Mercado Pago SÍ entrega con el token del usuario: los datos de su cuenta (/users/me) y los pagos
// que recibió (/v1/payments/search). El saldo exacto no tiene API oficial documentada: se intenta (puede no estar
// disponible) y, si no, se muestra el dinero "por liberar", calculado desde los pagos.
const mpCuentaCache = new Map(); // "userId:dias" -> { t, data }. Dura 30 s para no martillar a Mercado Pago.
const olvidarCuentaMP = userId => { for (const k of mpCuentaCache.keys()) if (k.startsWith(`${userId}:`)) mpCuentaCache.delete(k); };

const nombreCuentaMP = u => (u.company && (u.company.corporate_name || u.company.brand_name))
  || [u.first_name, u.last_name].filter(Boolean).join(' ') || u.nickname || null;

// Mercado Pago no tiene un campo oficial "es empresa". Se usa lo mejor disponible y se dice de dónde sale:
// 1) si MP informa datos de empresa (company); 2) si el RUT es de persona jurídica (cuerpo entre 50.000.000 y 99.999.999).
// Nunca se afirma "persona": si no hay indicios de empresa, queda "no_confirmado".
const tipoCuentaMP = u => {
  if (u.company && (u.company.corporate_name || u.company.brand_name)) return { tipo: 'empresa', tipoFuente: 'mercadopago' };
  const idf = u.identification;
  if (idf && String(idf.type).toUpperCase() === 'RUT' && idf.number) {
    const txt = String(idf.number).replace(/[.\s]/g, '');
    const cuerpo = txt.includes('-') ? txt.split('-')[0] : txt.slice(0, -1); // sin el dígito verificador
    if (/^\d+$/.test(cuerpo) && Number(cuerpo) >= 50000000 && Number(cuerpo) < 100000000) return { tipo: 'empresa', tipoFuente: 'rut' };
  }
  return { tipo: 'no_confirmado', tipoFuente: null };
};

// Saldo: endpoint antiguo y no documentado oficialmente (hay reportes de que a veces responde not_found o se cuelga),
// por eso es "mejor esfuerzo": 5 s de espera como máximo por intento y, si falla, el resto de la pantalla sigue funcionando.
const saldoMP = async (token, mpId) => {
  let ultimo = 'sin respuesta';
  for (const host of ['https://api.mercadopago.com', 'https://api.mercadolibre.com']) {
    try {
      const r = await fetch(`${host}/users/${mpId}/mercadopago_account/balance`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      const d = await r.json().catch(() => ({}));
      if (r.ok && d.available_balance != null) {
        const total = Number(d.total_amount != null ? d.total_amount : d.available_balance) || 0, disponible = Number(d.available_balance) || 0;
        return { total, disponible, noDisponible: Number(d.unavailable_balance != null ? d.unavailable_balance : total - disponible) || 0 };
      }
      ultimo = (d && d.message) || `HTTP ${r.status}`;
    } catch (e) { ultimo = e.name === 'TimeoutError' ? 'tardó demasiado en responder' : e.message; }
  }
  throw new Error(ultimo);
};

// Pagos RECIBIDOS por la cuenta (collector.id) en los últimos N días. Hasta 500 (5 páginas de 100).
const traerPagosMP = async (token, mpId, dias) => {
  const pagos = []; let total = null;
  for (let offset = 0; offset < 500; offset += 100) {
    const qs = new URLSearchParams({ sort: 'date_created', criteria: 'desc', range: 'date_created', begin_date: `NOW-${dias}DAYS`,
      end_date: 'NOW', 'collector.id': String(mpId), limit: '100', offset: String(offset) }).toString();
    const d = await mpCall('GET', `/v1/payments/search?${qs}`, token);
    const lista = Array.isArray(d.results) ? d.results : [];
    if (d.paging && d.paging.total != null) total = Number(d.paging.total);
    pagos.push(...lista);
    if (lista.length < 100 || (total != null && pagos.length >= total)) break;
  }
  return { pagos, truncado: total != null && pagos.length < total };
};

const resumirPagosMP = (pagos, dias) => {
  const ahora = Date.now(), num = v => Number(v) || 0;
  const diaChile = f => new Date(f).toLocaleDateString('en-CA', { timeZone: 'America/Santiago' });
  const neto = p => p.transaction_details && p.transaction_details.net_received_amount != null
    ? num(p.transaction_details.net_received_amount)
    : num(p.transaction_amount) - (p.fee_details || []).reduce((a, f) => a + num(f.amount), 0);
  const serie = new Map();
  for (let i = dias - 1; i >= 0; i--) serie.set(diaChile(ahora - i * 86400000), 0);
  const r = { ingresos: 0, neto: 0, comisiones: 0, reembolsado: 0, pagosAprobados: 0,
    pendientes: { monto: 0, cantidad: 0 }, porLiberar: { monto: 0, cantidad: 0 } };
  for (const p of pagos) {
    const monto = num(p.transaction_amount);
    if (p.status === 'approved') {
      const n = neto(p);
      r.pagosAprobados++; r.ingresos += monto; r.neto += n; r.comisiones += monto - n;
      const dia = diaChile(p.date_approved || p.date_created);
      if (serie.has(dia)) serie.set(dia, serie.get(dia) + monto);
      if (p.money_release_date && new Date(p.money_release_date).getTime() > ahora) { r.porLiberar.monto += n; r.porLiberar.cantidad++; }
    } else if (['pending', 'in_process', 'authorized'].includes(p.status)) { r.pendientes.monto += monto; r.pendientes.cantidad++; }
    r.reembolsado += num(p.transaction_amount_refunded);
  }
  const redond = Math.round;
  const resumen = { ingresos: redond(r.ingresos), neto: redond(r.neto), comisiones: redond(r.comisiones), reembolsado: redond(r.reembolsado),
    pagosAprobados: r.pagosAprobados, ticketPromedio: r.pagosAprobados ? redond(r.ingresos / r.pagosAprobados) : 0,
    pendientes: { monto: redond(r.pendientes.monto), cantidad: r.pendientes.cantidad },
    porLiberar: { monto: redond(r.porLiberar.monto), cantidad: r.porLiberar.cantidad } };
  const movimientos = pagos.slice(0, 8).map(p => ({ id: String(p.id), fecha: p.date_created, estado: p.status,
    descripcion: String(p.description || p.payment_method_id || 'Pago').slice(0, 80), monto: redond(num(p.transaction_amount)) }));
  return { resumen, serie: [...serie].map(([dia, total]) => ({ dia, total: redond(total) })), movimientos,
    moneda: (pagos[0] && pagos[0].currency_id) || 'CLP' };
};

// Arma el resumen financiero de una cuenta de Mercado Pago a partir de su token. Lo usan /api/mp/cuenta (cuenta que conectó un
// usuario por OAuth) y /api/mp/mi-cuenta (la cuenta dueña de Vencio, con MP_ACCESS_TOKEN).
const consultarCuentaMP = async (token, mpIdPrevio, dias) => {
  const avisos = [];
  let mpId = mpIdPrevio || null, cuenta = null;
  try {
    const u = await mpCall('GET', '/users/me', token);
    if (!mpId && u.id) mpId = String(u.id);
    // "campos" = solo los NOMBRES de los datos que devolvió Mercado Pago (sin valores), por si hay que ajustar el tipo de cuenta
    cuenta = { nombre: nombreCuentaMP(u), ...tipoCuentaMP(u), sitio: u.site_id || null, campos: Object.keys(u) };
  } catch (e) { avisos.push('No se pudieron leer los datos de la cuenta: ' + e.message); }
  const sinId = () => Promise.reject(new Error('no se conoce el ID de la cuenta'));
  const [rSaldo, rPagos] = await Promise.allSettled([mpId ? saldoMP(token, mpId) : sinId(), mpId ? traerPagosMP(token, mpId, dias) : sinId()]);
  let saldo = null, resumen = null, serie = [], movimientos = [], moneda = 'CLP';
  if (rSaldo.status === 'fulfilled') saldo = rSaldo.value;
  else avisos.push(`El saldo exacto no está disponible por API en esta conexión (Mercado Pago respondió: ${rSaldo.reason.message}). Se muestra el dinero por liberar, calculado desde tus pagos.`);
  if (rPagos.status === 'fulfilled') {
    ({ resumen, serie, movimientos, moneda } = resumirPagosMP(rPagos.value.pagos, dias));
    resumen.truncado = rPagos.value.truncado;
  } else avisos.push('No se pudieron leer tus pagos: ' + rPagos.reason.message);
  if (!cuenta && !saldo && !resumen) { const e = new Error(avisos[0] || 'Mercado Pago no respondió'); e.http = 502; throw e; }
  return { actualizado: new Date().toISOString(), dias, moneda, cuenta, saldo, resumen, serie, movimientos, avisos };
};
const diasValidos = q => { const n = parseInt(q, 10); return [7, 30, 90].includes(n) ? n : 30; };
const responderCuentaMP = async (res, clave, forzar, obtener) => {
  try {
    const previo = mpCuentaCache.get(clave);
    if (!forzar && previo && Date.now() - previo.t < 30000) return res.json(previo.data);
    const data = await obtener();
    if (!data) return;
    mpCuentaCache.set(clave, { t: Date.now(), data });
    res.json(data);
  } catch (e) {
    if (e.http === 502) return res.status(502).json({ error: e.message });
    fail(res, e, 'Error al consultar Mercado Pago');
  }
};

app.get('/api/mp/cuenta', auth, async (req, res) => {
  const dias = diasValidos(req.query.dias);
  await responderCuentaMP(res, `${req.userId}:${dias}`, req.query.forzar, async () => {
    const token = await mpTokenDeUsuario(req.userId);
    if (!token) { res.status(404).json({ error: 'Tu cuenta de Mercado Pago no está conectada (o venció). Vuelve a conectarla.' }); return null; }
    const fila = (await pool.query('SELECT mp_user_id FROM mp_cuentas WHERE user_id=$1', [req.userId])).rows[0];
    return consultarCuentaMP(token, fila && fila.mp_user_id, dias);
  });
});

// ── Tu PROPIA cuenta de Mercado Pago (la dueña de la app de Vencio) ──
// Mercado Pago no deja que una cuenta se autorice a sí misma por OAuth, pero para tu cuenta no hace falta: ya tienes su token
// (MP_ACCESS_TOKEN). Solo la ve el usuario cuyo correo está en la variable ADMIN_EMAIL; para todos los demás responde 403.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const esPropietario = async userId =>
  !!ADMIN_EMAIL && (await pool.query('SELECT 1 FROM users WHERE id=$1 AND LOWER(email)=$2', [userId, ADMIN_EMAIL])).rowCount > 0;

app.get('/api/mp/mi-cuenta', auth, async (req, res) => {
  if (!(await esPropietario(req.userId).catch(() => false))) return res.status(403).json({ error: 'No tienes acceso a esta sección' });
  if (!MP_ACCESS_TOKEN) return res.status(503).json({ error: 'Falta MP_ACCESS_TOKEN en el servidor' });
  const dias = diasValidos(req.query.dias);
  await responderCuentaMP(res, `propia:${dias}`, req.query.forzar, () => consultarCuentaMP(MP_ACCESS_TOKEN, null, dias));
});

app.get('/api/mp/estado', auth, async (req, res) => {
  try { res.json({ conectado: !!(await pool.query('SELECT 1 FROM mp_cuentas WHERE user_id=$1', [req.userId])).rowCount, propietario: await esPropietario(req.userId) }); }
  catch (e) { fail(res, e, 'Error al consultar Mercado Pago'); }
});

app.post('/api/mp/desconectar', auth, async (req, res) => {
  try { await pool.query('DELETE FROM mp_cuentas WHERE user_id=$1', [req.userId]); olvidarCuentaMP(req.userId); res.json({ ok: true }); }
  catch (e) { fail(res, e, 'Error al desconectar Mercado Pago'); }
});

// ── Cobro a los clientes finales (de cada usuario de Vencio), con la cuenta MP que ellos conectaron ──
// Cuotas: se genera un link de pago puntual que el cliente debe abrir y pagar (no es 100% automático:
// Mercado Pago no permite cobrar un monto variable sin que el cliente confirme, salvo con suscripciones).
app.post('/api/mp/clientes/:clienteId/cobrar', auth, async (req, res) => {
  try {
    const token = await mpTokenDeUsuario(req.userId);
    if (!token) return res.status(400).json({ error: 'Conecta tu cuenta de Mercado Pago primero (sección Integraciones).' });
    const clienteId = Number(req.params.clienteId);
    const monto = Number(req.body.monto), subject = String(req.body.subject || 'Cobro de cuota').slice(0, 100);
    if (!Number.isFinite(monto) || monto < 350) return res.status(400).json({ error: 'Monto inválido (mínimo $350)' });
    const orden = `COB-${req.userId}-${clienteId}-${Date.now()}`;
    await pool.query('INSERT INTO mp_cobros(user_id,cliente_id,commerce_order,monto) VALUES($1,$2,$3,$4)', [req.userId, clienteId, orden, monto]);
    const pref = await mpCall('POST', '/checkout/preferences', token, {
      items: [{ title: subject, quantity: 1, currency_id: 'CLP', unit_price: monto }],
      external_reference: orden, notification_url: `${APP_URL}/api/mp/webhook`,
      back_urls: { success: `${APP_URL}/?cobro=ok`, pending: `${APP_URL}/?cobro=pendiente`, failure: `${APP_URL}/?cobro=error` } });
    res.json({ url: pref.init_point });
  } catch (e) { fail(res, e, 'No se pudo generar el link de cobro'); }
});

const procesarCobroCliente = async (orden, pago) => {
  const c = (await pool.query('SELECT * FROM mp_cobros WHERE commerce_order=$1', [orden])).rows[0];
  if (!c) return;
  const estado = pago.status === 'approved' ? 'pagado' : pago.status;
  await pool.query('UPDATE mp_cobros SET estado=$1, mp_payment_id=$2, pagado_at=CASE WHEN $1=\'pagado\' THEN NOW() ELSE pagado_at END WHERE id=$3',
    [estado, String(pago.id), c.id]);
};

app.get('/api/mp/clientes/:clienteId/cobros', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT commerce_order,monto,estado,created_at,pagado_at FROM mp_cobros WHERE user_id=$1 AND cliente_id=$2 ORDER BY id DESC LIMIT 20',
      [req.userId, Number(req.params.clienteId)]);
    res.json(r.rows);
  } catch (e) { fail(res, e, 'Error al cargar los cobros'); }
});

// Membresías: suscripción con cobro recurrente automático de verdad (el cliente autoriza UNA vez
// y Mercado Pago cobra solo cada mes, sin que vuelvas a pedirle nada).
app.post('/api/mp/clientes/:clienteId/suscribir', auth, async (req, res) => {
  try {
    const token = await mpTokenDeUsuario(req.userId);
    if (!token) return res.status(400).json({ error: 'Conecta tu cuenta de Mercado Pago primero (sección Integraciones).' });
    const clienteId = Number(req.params.clienteId);
    const { nombre, email, monto } = req.body;
    if (!nombre || !email || !Number.isFinite(Number(monto)) || Number(monto) < 350)
      return res.status(400).json({ error: 'Faltan datos del cliente o el monto es inválido (mínimo $350)' });
    const ref = `${req.userId}_${clienteId}`;
    const pre = await mpCall('POST', '/preapproval', token, {
      reason: `Vencio - Membresía (${nombre})`, external_reference: ref, payer_email: email,
      auto_recurring: { frequency: 1, frequency_type: 'months', transaction_amount: Number(monto), currency_id: 'CLP' },
      back_url: `${APP_URL}/?suscripcion=ok`, status: 'pending' });
    await pool.query(
      `INSERT INTO mp_suscripciones(user_id,cliente_id,preapproval_id,monto) VALUES($1,$2,$3,$4)
       ON CONFLICT(user_id,cliente_id) DO UPDATE SET preapproval_id=$3,monto=$4,activo=FALSE`,
      [req.userId, clienteId, pre.id, Number(monto)]);
    res.json({ url: pre.init_point });
  } catch (e) { fail(res, e, 'No se pudo generar el link de suscripción'); }
});

const procesarSuscripcion = async pre => {
  const activo = pre.status === 'authorized';
  await pool.query('UPDATE mp_suscripciones SET activo=$1 WHERE preapproval_id=$2', [activo, pre.id]);
};

app.get('/api/mp/clientes/:clienteId/estado', auth, async (req, res) => {
  try {
    const r = (await pool.query('SELECT activo FROM mp_suscripciones WHERE user_id=$1 AND cliente_id=$2',
      [req.userId, Number(req.params.clienteId)])).rows[0];
    res.json({ activo: !!(r && r.activo) });
  } catch (e) { fail(res, e, 'Error al consultar el estado'); }
});

app.post('/api/mp/clientes/:clienteId/cancelar-suscripcion', auth, async (req, res) => {
  try {
    const token = await mpTokenDeUsuario(req.userId);
    const r = (await pool.query('SELECT preapproval_id FROM mp_suscripciones WHERE user_id=$1 AND cliente_id=$2',
      [req.userId, Number(req.params.clienteId)])).rows[0];
    if (!r) return res.status(404).json({ error: 'Este cliente no tiene suscripción' });
    if (token) await mpCall('PUT', `/preapproval/${r.preapproval_id}`, token, { status: 'cancelled' }).catch(() => {});
    await pool.query('UPDATE mp_suscripciones SET activo=FALSE WHERE user_id=$1 AND cliente_id=$2', [req.userId, Number(req.params.clienteId)]);
    res.json({ ok: true });
  } catch (e) { fail(res, e, 'No se pudo cancelar la suscripción'); }
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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_usado BOOLEAN NOT NULL DEFAULT FALSE;
    -- Suscripción (preapproval) de Mercado Pago que arma la prueba gratis de 14 días. Una por usuario.
    CREATE TABLE IF NOT EXISTS vencio_suscripciones(
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, preapproval_id VARCHAR(100) NOT NULL,
      estado VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMP DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS pagos(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      commerce_order VARCHAR(100) UNIQUE NOT NULL, mp_payment_id VARCHAR(50),
      plan VARCHAR(50) NOT NULL, monto INT NOT NULL, estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
      created_at TIMESTAMP DEFAULT NOW(), pagado_at TIMESTAMP);
    -- Tiendas de WooCommerce/Shopify conectadas por cada empresa, para traer sus clientes automáticamente
    CREATE TABLE IF NOT EXISTS integraciones_tienda(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      empresa_id INT NOT NULL, tipo VARCHAR(20) NOT NULL CHECK (tipo IN ('woocommerce','shopify')),
      nombre VARCHAR(100) NOT NULL, dominio VARCHAR(255) NOT NULL,
      cred1 VARCHAR(255) NOT NULL, cred2 VARCHAR(255) NOT NULL,
      webhook_secret VARCHAR(100), webhook_id_remoto VARCHAR(100),
      activa BOOLEAN NOT NULL DEFAULT TRUE, ultima_sync TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW());
    ALTER TABLE integraciones_tienda ADD COLUMN IF NOT EXISTS webhook_pedidos_remoto VARCHAR(100);
    -- Pedidos/ventas traídos de las tiendas conectadas, para las gráficas de ingresos
    CREATE TABLE IF NOT EXISTS ventas_tienda(
      id SERIAL PRIMARY KEY, integracion_id INT NOT NULL REFERENCES integraciones_tienda(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, empresa_id INT NOT NULL,
      external_id VARCHAR(50) NOT NULL, monto NUMERIC(14,2) NOT NULL, moneda VARCHAR(10) NOT NULL DEFAULT 'CLP',
      estado VARCHAR(30) NOT NULL DEFAULT '', cliente_nombre VARCHAR(255),
      fecha_pedido TIMESTAMPTZ NOT NULL, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(integracion_id, external_id));
    CREATE INDEX IF NOT EXISTS ventas_tienda_resumen_idx ON ventas_tienda(user_id, empresa_id, fecha_pedido);
    -- Cuenta de Mercado Pago que cada usuario conectó (OAuth), para cobrar a SUS clientes
    CREATE TABLE IF NOT EXISTS mp_cuentas(
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, mp_user_id VARCHAR(50),
      access_token TEXT NOT NULL, refresh_token TEXT NOT NULL, public_key VARCHAR(100), expires_at TIMESTAMP NOT NULL);
    -- Cobros puntuales a clientes (cuotas). cliente_id apunta al "id" dentro de estado.clientes (no hay tabla clientes).
    CREATE TABLE IF NOT EXISTS mp_cobros(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      cliente_id INT NOT NULL, commerce_order VARCHAR(100) UNIQUE NOT NULL, mp_payment_id VARCHAR(50),
      monto INT NOT NULL, estado VARCHAR(20) NOT NULL DEFAULT 'pendiente',
      created_at TIMESTAMP DEFAULT NOW(), pagado_at TIMESTAMP);
    -- Suscripciones (membresías) con cobro recurrente automático
    CREATE TABLE IF NOT EXISTS mp_suscripciones(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      cliente_id INT NOT NULL, preapproval_id VARCHAR(100) NOT NULL, monto INT NOT NULL,
      activo BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, cliente_id));`);
  if (ADMIN_EMAIL && !(await pool.query('SELECT 1 FROM users WHERE LOWER(email)=$1', [ADMIN_EMAIL])).rowCount)
    console.warn('⚠ ADMIN_EMAIL no coincide con ningún usuario registrado: revisa que sea EXACTAMENTE el correo con el que entras a Vencio.');
  app.listen(PORT, () => console.log(`✓ Vencio corriendo en http://localhost:${PORT}`));
})().catch(e => { console.error('No se pudo conectar a PostgreSQL:', e.message); process.exit(1); });
