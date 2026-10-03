require('dotenv').config();
const express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), { Pool } = require('pg'), path = require('path');

const PORT = process.env.PORT || 5000, JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error('Falta DATABASE_URL o JWT_SECRET. Revisa que el archivo se llame ".env" (con punto) y esté junto a server.js.');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const fail = (res, e, msg) => { console.error(e); res.status(500).json({ error: msg }); };
const makeToken = u => jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try { req.userId = jwt.verify((req.headers.authorization || '').split(' ')[1], JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Sesión inválida' }); }
};
const estadoInicial = empresa => ({ empresas: [{ id: 1, nombre: empresa || 'Mi Empresa' }], clientes: [], ventas: [], notifs: [], moderadores: [] });

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

(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL,
      nombre VARCHAR(255) NOT NULL, iniciales VARCHAR(5), iva_porc INT DEFAULT 19,
      plan VARCHAR(50) DEFAULT 'basico', created_at TIMESTAMP DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS user_data(
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      estado JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMP DEFAULT NOW());`);
  app.listen(PORT, () => console.log(`✓ Vencio corriendo en http://localhost:${PORT}`));
})().catch(e => { console.error('No se pudo conectar a PostgreSQL:', e.message); process.exit(1); });
