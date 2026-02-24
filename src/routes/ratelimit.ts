/**
 * Rutas Rate Limit — Fase 7 (demo educativo)
 *
 *   GET  /api/v1/ratelimit/info     → explicación de los límites configurados
 *   GET  /api/v1/ratelimit/test     → endpoint con límite bajo para probar la respuesta 429
 *
 * Las cabeceras RateLimit-* (Draft-7) se incluyen en TODAS las respuestas de la API:
 *   RateLimit-Limit:     máximo de requests en la ventana
 *   RateLimit-Remaining: requests restantes antes de ser bloqueado
 *   RateLimit-Reset:     timestamp Unix cuando se reinicia el contador
 */
import { Router } from 'express';
import { authLimiter } from '../middleware/rateLimiter';
import rateLimit from 'express-rate-limit';

const router = Router();

// ── GET /info ─────────────────────────────────────────────────────────────────

router.get('/info', (_req, res) => {
  res.json({
    descripcion: 'Rate limiting — protección contra fuerza bruta y flooding (Fase 7)',
    implementacion: 'express-rate-limit v7 con MemoryStore (in-process)',
    limitadores: {
      globalLimiter: {
        aplica_a: 'Todas las rutas /api/v1/*',
        ventana_min: 15,
        max_requests: 300,
        proposito: 'Protección general contra flooding',
      },
      authLimiter: {
        aplica_a: 'POST /auth/login, POST /auth/register, POST /dpop/token',
        ventana_min: 15,
        max_requests: 20,
        proposito: 'Prevenir credential stuffing y ataques de fuerza bruta',
      },
      strictLimiter: {
        aplica_a: 'POST /auth/forgot-password, POST /auth/reset-password, POST /magic/request',
        ventana_min: 60,
        max_requests: 10,
        proposito: 'Prevenir abuso de endpoints que emiten tokens por email (enumeration)',
      },
      mfaLimiter: {
        aplica_a: 'POST /mfa/enable, POST /mfa/verify',
        ventana_min: 15,
        max_requests: 15,
        proposito: 'Prevenir fuerza bruta sobre códigos TOTP de 6 dígitos',
      },
      refreshLimiter: {
        aplica_a: 'POST /jwt/refresh',
        ventana_min: 15,
        max_requests: 60,
        proposito: 'Permite renovación frecuente (SPAs) pero bloquea abusos sostenidos',
      },
    },
    cabeceras_en_respuesta: {
      'RateLimit-Limit':     'Máximo de requests permitidos en la ventana',
      'RateLimit-Remaining': 'Requests restantes en la ventana actual',
      'RateLimit-Reset':     'Timestamp UNIX cuando se reinicia el contador',
      'Retry-After':         'Segundos hasta poder reintentar (solo en respuestas 429)',
    },
    respuesta_429: {
      error: 'Mensaje descriptivo con el tiempo de espera',
      code: 'LIMITE_EXCEDIDO',
      retryAfter: '<segundos>',
    },
    nota_produccion:
      'En producción multi-réplica usar Redis como store: new RedisStore({ client, prefix: "rl:" }). ' +
      'El MemoryStore actual es per-proceso y no se comparte entre réplicas.',
  });
});

// ── GET /test — limiter muy bajo para demostrar el 429 ────────────────────────

/**
 * Tiene un límite de 3 req/min para que sea fácil provocar un 429.
 * Ideal para ver las cabeceras RateLimit-* en el inspector del navegador.
 */
const demoLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  limit: 3,
  standardHeaders: true,  // RateLimit-Limit/Remaining/Reset separados (draft-6)
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Límite de demo alcanzado — espera 1 minuto',
      code: 'LIMITE_EXCEDIDO',
      retryAfter: 60,
      tip: 'Mira las cabeceras RateLimit-* en las respuestas anteriores a este 429',
    });
  },
});

router.get('/test', demoLimiter, (_req, res) => {
  res.json({
    mensaje: 'Request contabilizado — llama 3 veces para ver el 429',
    tip: 'Observa las cabeceras RateLimit-Limit, RateLimit-Remaining y RateLimit-Reset',
  });
});

// ── GET /test-auth — usa el authLimiter real para ver su config ───────────────

router.get('/test-auth', authLimiter, (_req, res) => {
  res.json({
    mensaje: 'Usando el authLimiter real (20 req / 15 min)',
    tip: 'La cabecera RateLimit-Remaining muestra cuántas requests quedan',
  });
});

export default router;
