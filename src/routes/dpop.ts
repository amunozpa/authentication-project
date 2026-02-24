/**
 * Rutas DPoP — Fase 5.11 (demo educativo)
 *
 *   POST /api/v1/dpop/token      → credenciales + proof → AT vinculado al JWK del cliente
 *   GET  /api/v1/dpop/protected  → recurso protegido, requiere Authorization: DPoP + proof
 *   GET  /api/v1/dpop/info       → explicación educativa del flujo DPoP
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ DIFERENCIA CLAVE vs Bearer tokens                                       │
 * │                                                                         │
 * │  Bearer: quien tiene el token puede usarlo                              │
 * │  DPoP:   quien tiene el token + la clave privada puede usarlo           │
 * │                                                                         │
 * │  Ataque mitigado: robo del AT en tránsito o en storage                  │
 * │  El atacante tiene el AT pero no la clave privada → 401                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { usersRepository } from '../db/repositories/users';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { authLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import { requireDpopAccess } from '../middleware/requireDpopAccess';
import { verifyDpopProof, issueDpopToken } from '../services/dpopService';
import type { UserRole } from '../types';

const router = Router();

// ── POST /token ───────────────────────────────────────────────────────────────

const tokenSchema = z.object({
  email: z.string().email('Email inválido'),
  password: z.string().min(1, 'Contraseña requerida'),
});

/**
 * Emite un Access Token vinculado al JWK del cliente (DPoP binding).
 *
 * Requiere:
 *   · Header `DPoP: <proof_jwt>` — proof para este endpoint:
 *       header: { alg: 'ES256', typ: 'dpop+jwt', jwk: <tu_clave_publica> }
 *       payload: { jti: '<uuid>', htm: 'POST', htu: '<url_completa>', iat: <ahora> }
 *   · Body: { email, password }
 *
 * El AT resultante incluye `cnf: { jkt }` — solo puede usarse acompañado de
 * un nuevo proof firmado con la misma clave privada.
 */
router.post(
  '/token',
  authLimiter,
  asyncHandler(async (req, res) => {
    // ── Extraer y verificar DPoP proof ────────────────────────────────────
    const proofJwt = req.headers['dpop'];
    if (!proofJwt || typeof proofJwt !== 'string') {
      throw new AppError(
        401,
        'Header DPoP requerido — crea un proof JWT con htm:"POST" y htu:"<url_de_este_endpoint>"',
        'DPOP_PROOF_REQUERIDO',
      );
    }

    // req.originalUrl incluye el prefijo del router (/api/v1/dpop/token) — se quita la query string
    const expectedHtu = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;

    // No se verifica ath aquí — aún no hay AT (es el endpoint de emisión)
    const { jkt } = verifyDpopProof({
      proofJwt,
      htm: 'POST',
      htu: expectedHtu,
    });

    // ── Verificar credenciales ────────────────────────────────────────────
    const parsed = tokenSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { email, password } = parsed.data;
    const ipHash = hashIp(req.ip ?? '');

    const user = usersRepository.findByEmail(email);
    if (!user || !user.email_verified || !user.password_hash) {
      throw new AppError(401, 'Credenciales inválidas', 'CREDENCIALES_INVALIDAS');
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      throw new AppError(401, 'Credenciales inválidas', 'CREDENCIALES_INVALIDAS');
    }

    // ── Emitir AT DPoP-bound ──────────────────────────────────────────────
    const roles = JSON.parse(user.roles) as UserRole[];
    const accessToken = issueDpopToken({ userId: user.id, roles, jkt });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'DPOP_TOKEN_EMITIDO',
      ip_hash: ipHash,
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
      metadata: { jkt },
    });

    res.json({
      access_token: accessToken,
      token_type: 'DPoP',
      expires_in: 15 * 60,
      cnf: { jkt },
      nota: 'Este token solo funciona con un proof DPoP firmado con la misma clave privada (jkt)',
    });
  }),
);

// ── GET /protected ────────────────────────────────────────────────────────────

/**
 * Recurso protegido — requiere AT DPoP-bound + proof para este request.
 *
 * Requiere:
 *   · Header `Authorization: DPoP <access_token>`
 *   · Header `DPoP: <nuevo_proof>` con:
 *       htm: 'GET', htu: '<url_completa>', jti: '<nuevo_uuid>', iat: <ahora>
 *       ath: base64url(sha256(<access_token>))  ← hash del AT
 *
 * Si se intenta usar con `Authorization: Bearer <token>` → 401
 * Si el proof usa la clave equivocada → 401
 * Si el proof ya fue usado (replay) → 401
 */
router.get('/protected', requireDpopAccess, (req, res) => {
  const userId = req.user!.userId;

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'DPOP_VERIFICADO',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
  });

  res.json({
    acceso: 'concedido',
    userId,
    roles: req.user!.roles,
    mensaje: 'Acceso correcto — el token está vinculado a tu clave privada',
    seguridad: 'Un atacante con el AT robado no puede acceder sin la clave privada correspondiente',
  });
});

// ── GET /info ─────────────────────────────────────────────────────────────────

router.get('/info', (_req, res) => {
  res.json({
    protocolo: 'DPoP — Demonstrating Proof of Possession (RFC 9449)',
    problema_que_resuelve:
      'Los Bearer tokens son "tokens portador" — quien los tiene puede usarlos. DPoP vincula el token a una clave privada del cliente.',
    flujo: [
      '1. Cliente genera par ECDSA P-256 efímero (solo en memoria)',
      '2. POST /dpop/token: envía credenciales + proof JWT firmado con clave privada',
      '   Servidor verifica proof → extrae JWK público → calcula thumbprint (jkt)',
      '   Emite AT con cnf: { jkt } — token vinculado a esa clave',
      '3. GET /dpop/protected: envía Authorization: DPoP <AT> + nuevo proof',
      '   proof incluye ath: base64url(sha256(AT)) para ligar proof ↔ AT',
      '   Servidor: verifica AT + proof + que jkt del proof == cnf.jkt del AT',
    ],
    proof_jwt: {
      header: '{ alg: "ES256", typ: "dpop+jwt", jwk: <clave_publica_como_JWK> }',
      payload: {
        jti: 'UUID único por request (anti-replay)',
        htm: 'Método HTTP exacto: GET, POST...',
        htu: 'URI exacta del endpoint (sin query params)',
        iat: 'Timestamp UNIX — ventana ±30s',
        ath: '(solo recursos protegidos) base64url(sha256(access_token))',
      },
    },
    endpoints: {
      token: 'POST /api/v1/dpop/token   — obtener AT DPoP-bound',
      protected: 'GET  /api/v1/dpop/protected — recurso protegido',
      info: 'GET  /api/v1/dpop/info      — este endpoint',
    },
    algoritmos_permitidos: ['ES256 (ECDSA P-256)', 'EdDSA (Ed25519)'],
    limitacion_staging:
      'La caché de replay (jti) es in-process. En producción multi-réplica usar Redis con TTL.',
  });
});

export default router;
