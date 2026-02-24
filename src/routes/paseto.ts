/**
 * Rutas PASETO v4 — Fase 5.10 (demo educativo)
 *
 *   POST /api/v1/paseto/sign    → firma un payload con PASETO v4.public (Ed25519)
 *   POST /api/v1/paseto/verify  → verifica un token PASETO v4.public
 *   GET  /api/v1/paseto/info    → comparativa educativa JWT vs PASETO
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ Por qué PASETO v4 es más seguro que JWT                                 │
 * │                                                                         │
 * │ 1. Sin `alg` en el token → imposible alg:none ni alg confusion          │
 * │ 2. Algoritmo fijo por versión → Ed25519 para v4.public                  │
 * │ 3. No se puede intercambiar clave pública/privada por error de código    │
 * │ 4. Payload legible (signed) o cifrado (v4.local) sin mezclar conceptos  │
 * │ 5. Footers opcionales para key-id u otros metadatos no firmados         │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../middleware/authenticate';
import { asyncHandler } from '../utils/asyncHandler';
import { AppError } from '../middleware/errorHandler';
import {
  signPaseto,
  verifyPaseto,
  getPasetoPublicKeyB64,
  PASETO_DEFAULT_TTL_SECONDS,
} from '../services/pasetoService';

const router = Router();

// ── POST /sign ────────────────────────────────────────────────────────────────

const signSchema = z.object({
  payload: z.record(z.string(), z.unknown()).default({}),
  ttl_seconds: z.number().int().min(1).max(86400).default(PASETO_DEFAULT_TTL_SECONDS),
});

/**
 * Firma un payload con PASETO v4.public (Ed25519).
 * Requiere autenticación — el `sub` del AT se incluye automáticamente en el token.
 *
 * El caller puede añadir cualquier clave al payload; el servicio añade `iss`, `iat`, `exp`.
 */
router.post(
  '/sign',
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = signSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { payload, ttl_seconds } = parsed.data;

    // Incluir sub del usuario autenticado
    const fullPayload = {
      sub: req.user!.userId,
      roles: req.user!.roles,
      ...payload,
    };

    const token = await signPaseto(fullPayload, ttl_seconds);

    // Mostrar las partes del token de forma educativa
    const parts = token.split('.');
    // v4.public.<base64url(payload+sig)>
    // parts[0] = 'v4', parts[1] = 'public', parts[2] = payload+sig
    const payloadPreview = parts[2]
      ? (() => {
          try {
            // El payload está en los primeros bytes antes de la firma (64 bytes Ed25519)
            const raw = Buffer.from(parts[2], 'base64url');
            const payloadBytes = raw.subarray(0, raw.length - 64);
            return JSON.parse(payloadBytes.toString('utf-8'));
          } catch {
            return null;
          }
        })()
      : null;

    res.json({
      token,
      type: 'v4.public',
      algorithm: 'Ed25519',
      expires_in: ttl_seconds,
      estructura: {
        version: parts[0],    // 'v4'
        purpose: parts[1],    // 'public' (firmado) o 'local' (cifrado)
        payload: parts[2] ? `${parts[2].slice(0, 20)}...` : null,
      },
      payload_decodificado: payloadPreview,
      nota: 'El payload es legible (base64url) pero la firma garantiza integridad. No incluyas datos sensibles.',
    });
  }),
);

// ── POST /verify ──────────────────────────────────────────────────────────────

const verifySchema = z.object({
  token: z.string().min(1, 'Token requerido'),
});

/**
 * Verifica un token PASETO v4.public y devuelve el payload.
 * Endpoint público — no requiere autenticación (el token se verifica con la clave pública).
 */
router.post(
  '/verify',
  asyncHandler(async (req, res) => {
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Token requerido', 'VALIDACION_FALLIDA');
    }

    const { token } = parsed.data;

    // Validación básica de formato
    if (!token.startsWith('v4.public.')) {
      throw new AppError(400, 'Token inválido — se esperaba un token v4.public', 'TOKEN_INVALIDO');
    }

    try {
      const payload = await verifyPaseto(token);
      res.json({
        valido: true,
        payload,
        algoritmo: 'Ed25519 (PASETO v4.public)',
        nota: 'Firma verificada con la clave pública Ed25519 del servidor',
      });
    } catch (err) {
      // El error puede ser de expiración, firma inválida, etc.
      const message = err instanceof Error ? err.message : 'Token inválido';
      throw new AppError(401, `Token PASETO inválido: ${message}`, 'TOKEN_INVALIDO');
    }
  }),
);

// ── GET /info ─────────────────────────────────────────────────────────────────

/**
 * Devuelve información educativa sobre PASETO v4 y la clave pública activa.
 */
router.get('/info', (_req, res) => {
  const publicKeyB64 = getPasetoPublicKeyB64();

  res.json({
    version: 'PASETO v4',
    proposito: 'v4.public — tokens firmados (no cifrados)',
    algoritmo: 'Ed25519 (Curve25519, 128 bits de seguridad)',
    clave_publica_b64url: publicKeyB64,
    ventajas_sobre_jwt: [
      'Sin campo "alg" en el token → imposible el ataque alg:none',
      'Algoritmo fijo por versión → sin confusión de algoritmos',
      'No se puede usar la clave pública para firmar por error de API',
      'v4.local usa XChaCha20-Poly1305 para tokens cifrados (AEAD)',
      'Especificación más simple y menos ambigua',
    ],
    estructura_token: {
      ejemplo: 'v4.public.<base64url(payload || Ed25519_sig)>',
      partes: {
        version: 'v4 — versión del protocolo',
        purpose: 'public (firmado) | local (cifrado)',
        payload: 'base64url(JSON(payload) + firma Ed25519 de 64 bytes)',
        footer: '(opcional) metadatos no firmados, ej: key-id',
      },
    },
    comparativa_jwt: {
      jwt: {
        header: '{ alg: "HS256", typ: "JWT" } → el algoritmo está EN el token',
        riesgo: 'El verificador puede aceptar alg:none si no valida correctamente',
        flexibilidad: 'Alta pero peligrosa (muchas combinaciones alg+key)',
      },
      paseto: {
        header: 'Ninguno — la versión y purpose determinan el algoritmo',
        riesgo: 'Ninguno — el algoritmo no puede manipularse desde el token',
        flexibilidad: 'Limitada pero segura por diseño',
      },
    },
    endpoints: {
      sign: 'POST /api/v1/paseto/sign   — requiere AT, devuelve token v4.public',
      verify: 'POST /api/v1/paseto/verify — público, verifica token v4.public',
      info: 'GET  /api/v1/paseto/info    — este endpoint',
    },
  });
});

export default router;
