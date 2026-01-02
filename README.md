# RigCore Auth Service 🛡️

**RigCore Auth Service** es el núcleo de identidad y seguridad del ecosistema RigCore. Actúa como un proveedor centralizado para la gestión de autenticación, control de sesiones en tiempo real y protección de API de alto nivel.

---

## 🚀 Funcionalidades Principales

### 🔐 Gestión de Identidad (Auth)
*   **Integración con Supabase:** Autenticación robusta de usuarios con email y contraseña.
*   **Gestión de Flujos:** Soporte completo para login, logout, refresh de tokens y validación de perfiles.
*   **JWT Backend:** Tokens securizados con firma HMAC para comunicación entre servicios.

### ⚡ Control de Sesiones con Redis
*   **Sesiones Distribuidas:** Almacenamiento ultra-rápido de sesiones activas.
*   **Invalidación Instantánea:** Funcionalidad de *Global Logout* para cerrar todas las sesiones de un usuario simultáneamente.
*   **Scan Inteligente:** Búsqueda optimizada de sesiones con paginación y timeouts para evitar bloqueos.

### 🛡️ Seguridad de API (API Security)
*   **API Keys Dinámicas:** Sistema de claves firmadas digitalmente (**HMAC SHA-256**) con scopes y fechas de expiración.
*   **Rate Limiting Multinivel:** Protección contra ataques de fuerza bruta:
    *   🔴 **Strict:** (3 req/5 min) para endpoints críticos como login.
    *   🟡 **Moderate:** (20 req/1 min) para consultas generales.
    *   🟢 **Lenient:** (100 req/5 min) para endpoints públicos.

---

## 🛠️ Tecnologías

*   **Framework:** [NestJS 11.x](https://nestjs.com/)
*   **Identity Provider:** [Supabase](https://supabase.com/)
*   **Storage & Cache:** [Redis](https://redis.io/) (ioredis)
*   **Seguridad:** JWT, Passport, HMAC SHA-256
*   **Lenguaje:** [TypeScript](https://www.typescriptlang.org/)

---

## 📦 Instalación y Configuración

1. **Clonar el repositorio:**
   ```bash
   git clone <repository-url>
   cd rigcore-auth-service
   ```

2. **Instalar dependencias:**
   ```bash
   npm install
   ```

3. **Variables de Entorno:**
   Crea un archivo `.env` basado en `.env.example`:
   ```env
   # Supabase
   SUPABASE_URL=...
   SUPABASE_ANON_KEY=...

   # JWT & Security
   JWT_SECRET=...
   HMAC_SECRET=...
   API_KEY_SECRET=...
   
   # Redis
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_PASSWORD=...
   ```

---

## 🚦 Ejecución

```bash
# Desarrollo con recarga automática
npm run start:dev

# Producción
npm run build
npm run start:prod
```

---

## 📚 API Endpoints (Resumen)

### Autenticación
*   `POST /auth/login` - Inicia sesión y crea sesión en Redis.
*   `POST /auth/refresh` - Renueva tokens usando el refresh token de Supabase.
*   `POST /auth/logout` - Cierra la sesión actual.
*   `POST /auth/logout-all` - Invalida todas las sesiones del usuario.

### Seguridad & Monitoreo
*   `POST /auth/generate-api-key` - Genera una nueva API Key firmada.
*   `GET /redis/health` - Verifica la salud de la conexión con Redis.

---

## 🧪 Testing

```bash
# Ejecutar todos los tests
npm run test

# Coverage de código
npm run test:cov
```

---

## 🤝 Arquitectura del Proyecto

El proyecto sigue una arquitectura modular en NestJS:
*   `src/auth`: Lógica de autenticación, DTOs, guards y estrategias.
*   `src/supabase`: Cliente y wrappers para Supabase.
*   `src/redis`: Operaciones de bajo nivel y smart scan para Redis.
*   `src/common`: Decoradores de rate limiting e interceptores globales.

---

Desarrollado con ❤️ por el equipo de **RigCore**.
