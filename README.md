# Vencio Backend - Node.js + Express + PostgreSQL

Backend funcional para Vencio con autenticación de usuarios, gestión de clientes y pagos.

## 📋 Requisitos previos

- **Node.js** (v14+)
- **PostgreSQL** (v12+)
- **npm** o **yarn**

## 🚀 Instalación rápida (local)

### 1. Clonar y configurar

```bash
cd vencio-backend
npm install
```

### 2. Crear base de datos PostgreSQL

```bash
# Conectarse a PostgreSQL
psql -U postgres

# Crear la base de datos
CREATE DATABASE vencio;

# Salir
\q
```

### 3. Configurar variables de entorno

Edita el archivo `.env`:

```env
PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/vencio
JWT_SECRET=tu-clave-secreta-super-segura-aqui
NODE_ENV=development
```

Reemplaza:
- `user` → tu usuario de PostgreSQL (ej: `postgres`)
- `password` → tu contraseña
- `JWT_SECRET` → una contraseña segura (ej: `Sk9ZvX8mP2qL4nR6`)

### 4. Inicializar la base de datos

```bash
npm run init-db
```

Deberías ver: ✓ Base de datos inicializada correctamente

### 5. Iniciar el servidor

```bash
npm run dev
```

Deberías ver: ✓ Servidor Vencio corriendo en puerto 5000

## 🌐 Acceder a la app

Abre en tu navegador: **http://localhost:5000**

### Crear cuenta de prueba

1. Haz clic en **"Regístrate"**
2. Ingresa:
   - Nombre: `Juan Rodriguez`
   - Email: `juan@example.com`
   - Contraseña: `123456`
3. Haz clic en **"Crear cuenta"**

## 📁 Estructura del proyecto

```
vencio-backend/
├── server.js          # Servidor principal Express
├── init-db.js         # Script de inicialización de BD
├── package.json       # Dependencias
├── .env              # Variables de entorno
├── public/
│   └── index.html    # Frontend
└── README.md         # Este archivo
```

## 🔧 Endpoints API disponibles

### Autenticación
- `POST /api/auth/register` - Crear cuenta
- `POST /api/auth/login` - Iniciar sesión
- `GET /api/auth/profile` - Obtener perfil

### Clientes
- `GET /api/clientes` - Listar clientes
- `POST /api/clientes` - Crear cliente
- `PUT /api/clientes/:id` - Actualizar cliente
- `DELETE /api/clientes/:id` - Eliminar cliente

### Pagos
- `POST /api/pagos` - Registrar pago
- `GET /api/clientes/:id/pagos` - Obtener pagos de cliente

### Empresas
- `GET /api/empresas` - Listar empresas
- `POST /api/empresas` - Crear empresa

### Config
- `PUT /api/config` - Actualizar configuración

## 🚢 Deployment en producción

### Opción 1: Render.com (Recomendado - Gratis)

1. Sube tu código a GitHub
2. Crea cuenta en [render.com](https://render.com)
3. Conecta tu repositorio
4. Crea una **PostgreSQL Database**
5. Crea un **Web Service** apuntando a tu repo
6. En variables de entorno, copia la `DATABASE_URL` de la BD que creaste
7. Agrega `JWT_SECRET=tu-clave-segura`
8. Deploy automático

### Opción 2: Railway.app

1. `npm install -g railway`
2. `railway login`
3. `railway init`
4. Conectar PostgreSQL
5. `railway up`

### Opción 3: Heroku (Requiere tarjeta)

```bash
heroku create mi-vencio
heroku addons:create heroku-postgresql:hobby-dev
git push heroku main
```

## 📝 Variables de entorno en producción

```env
PORT=5000
DATABASE_URL=postgresql://user:pass@host:5432/vencio
JWT_SECRET=clave-super-segura-de-32-caracteres-minimo
NODE_ENV=production
```

## 🔐 Seguridad

- Las contraseñas se hashean con `bcryptjs`
- Los tokens JWT expiran en 30 días
- Todas las rutas autenticadas requieren un token válido
- CORS habilitado para desarrollo (configura en producción)

## 🐛 Troubleshooting

### Error: "ECONNREFUSED" en PostgreSQL

✅ Solución: Verifica que PostgreSQL está corriendo
```bash
# En Windows (PowerShell como admin)
Get-Service postgresql*

# En Mac/Linux
brew services list
```

### Error: "relation users does not exist"

✅ Solución: Ejecuta el script de inicialización
```bash
npm run init-db
```

### Error CORS

✅ En desarrollo está habilitado. Si necesitas agregar más dominios:

Edita `server.js` línea ~13:
```javascript
app.use(cors({
  origin: ['http://localhost:3000', 'https://tudominio.com']
}));
```

## 📦 Próximos pasos

- [ ] Agregar validación de datos más robusta
- [ ] Implementar multas y recordatorios automáticos
- [ ] Agregar integración con Stripe/Flow para pagos online
- [ ] Dashboard mejorado con gráficos
- [ ] Exportar reportes en PDF
- [ ] Notificaciones por email

## 📞 Soporte

Si tienes problemas:
1. Verifica que PostgreSQL está corriendo
2. Comprueba que la `.env` tiene los datos correctos
3. Revisa los logs del servidor (aparecerán en terminal)

---

**¡Vencio está listo para usar!** 🎉
