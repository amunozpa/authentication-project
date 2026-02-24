/**
 * Rate Limiters — Fase 7
 *
 * Protege los endpoints de autenticación contra:
 *   · Credential stuffing / fuerza bruta en login
 *   · Abuso de endpoints de emisión de tokens (magic links, password reset)
 *   · Fuerza bruta en verificación MFA
 *   · Flooding general de la API
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ LIMITADORES DISPONIBLES                                                  │
 * │                                                                          │
 * │  globalLimiter   — 300 req / 15 min por IP  (todas las rutas)           │
 * │  authLimiter     — 20 req  / 15 min por IP  (login, register, OAuth)    │
 * │  strictLimiter   — 10 req  /  1 h   por IP  (forgot-pwd, magic link)    │
 * │  mfaLimiter      — 15 req  / 15 min por IP  (mfa/verify, mfa/enable)    │
 * │  refreshLimiter  — 60 req  / 15 min por IP  (jwt/refresh — bajo carga)  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Cabeceras que se añaden a cada respuesta (RFC 6585 / Draft-7):
 *   RateLimit-Limit:     máximo de peticiones permitidas en la ventana
 *   RateLimit-Remaining: peticiones restantes en la ventana actual
 *   RateLimit-Reset:     timestamp UNIX cuando se reinicia el contador
 *   Retry-After:         segundos hasta poder reintentar (solo en 429)
 */
import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';

// En tests, todos los limitadores son no-op para no interferir con los tests de carga
const isTest = process.env['NODE_ENV'] === 'test';
const noopMiddleware = (_req: Request, _res: Response, next: NextFunction) => next();

// ── Handler de error 429 — responde con nuestro formato estándar ──────────────

function make429Handler(windowMs: number) {
  return (_req: Request, res: Response) => {
    const retryAfter = Math.ceil(windowMs / 1000);
    res.status(429).json({
      error: `Demasiadas peticiones — espera ${retryAfter < 120 ? `${retryAfter}s` : `${Math.ceil(retryAfter / 60)}min`} antes de reintentar`,
      code: 'LIMITE_EXCEDIDO',
      retryAfter,
    });
  };
}

// ── Opciones comunes ──────────────────────────────────────────────────────────

const commonOptions = {
  standardHeaders: true,                // RateLimit-Limit/Remaining/Reset headers (draft-6)
  legacyHeaders: false,                 // no X-RateLimit-* (obsoleto)
  // Clave de identificación: IP del cliente
  keyGenerator: (req: Request) => req.ip ?? 'unknown',
} as const;

// ── Limitadores ───────────────────────────────────────────────────────────────

/**
 * globalLimiter — aplicado a todas las rutas /api/v1/*
 * Protege contra flooding general de la API.
 */
export const globalLimiter = isTest ? noopMiddleware : rateLimit({
  ...commonOptions,
  windowMs: 15 * 60 * 1000, // 15 minutos
  limit: 300,
  message: { error: 'Demasiadas peticiones', code: 'LIMITE_EXCEDIDO' },
  handler: make429Handler(15 * 60 * 1000),
});

/**
 * authLimiter — login, register, /dpop/token
 * Protege contra credential stuffing y ataques de fuerza bruta.
 */
export const authLimiter = isTest ? noopMiddleware : rateLimit({
  ...commonOptions,
  windowMs: 15 * 60 * 1000, // 15 minutos
  limit: 20,
  message: { error: 'Demasiados intentos de autenticación', code: 'LIMITE_EXCEDIDO' },
  handler: make429Handler(15 * 60 * 1000),
});

/**
 * strictLimiter — forgot-password, reset-password, magic link request
 * Protege endpoints que emiten tokens sensibles por email.
 * Ventana larga (1h) para que sea inviable la enumeración de emails.
 */
export const strictLimiter = isTest ? noopMiddleware : rateLimit({
  ...commonOptions,
  windowMs: 60 * 60 * 1000, // 1 hora
  limit: 10,
  message: { error: 'Demasiadas solicitudes — espera 1 hora', code: 'LIMITE_EXCEDIDO' },
  handler: make429Handler(60 * 60 * 1000),
});

/**
 * mfaLimiter — mfa/verify, mfa/enable
 * Protege contra fuerza bruta sobre códigos TOTP de 6 dígitos.
 */
export const mfaLimiter = isTest ? noopMiddleware : rateLimit({
  ...commonOptions,
  windowMs: 15 * 60 * 1000, // 15 minutos
  limit: 15,
  message: { error: 'Demasiados intentos MFA — espera 15 minutos', code: 'LIMITE_EXCEDIDO' },
  handler: make429Handler(15 * 60 * 1000),
});

/**
 * refreshLimiter — jwt/refresh
 * Permite alta frecuencia (clientes SPA renovando proactivamente)
 * pero bloquea abusos sostenidos.
 */
export const refreshLimiter = isTest ? noopMiddleware : rateLimit({
  ...commonOptions,
  windowMs: 15 * 60 * 1000, // 15 minutos
  limit: 60,
  message: { error: 'Demasiadas renovaciones de token', code: 'LIMITE_EXCEDIDO' },
  handler: make429Handler(15 * 60 * 1000),
});
