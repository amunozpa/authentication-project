/**
 * Rutas API Keys Stripe-style — Fase 3
 * POST /api/v1/keys              → crear key (requiere JWT)
 * GET  /api/v1/keys              → listar keys del usuario (requiere JWT)
 * POST /api/v1/keys/:id/revoke   → revocar key (requiere JWT)
 * GET  /api/v1/keys/protected    → ruta demo con API Key + scope
 *
 * Formato de key: sk_live_<64 hex chars>
 * Prefijo almacenado: sk_live_<primeros 8 hex chars> (16 chars total)
 * Hash almacenado: bcrypt(key_completa)
 * La key completa se muestra UNA SOLA VEZ al crearse.
 */
import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { apiKeysRepository } from '../db/repositories/apiKeys';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { authenticate } from '../middleware/authenticate';
import { apiKeyAuthMiddleware } from '../middleware/apiKeyAuth';
import { requireScope } from '../middleware/requireScope';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { AppError } from '../middleware/errorHandler';

const router = Router();

const BCRYPT_COST = 12;
const API_KEY_RANDOM_BYTES = 32; // 64 hex chars
const PREFIX_VISIBLE_BYTES = 4; // 8 hex chars visibles en el prefijo

const createKeySchema = z.object({
  name: z.string().min(1).max(100),
  scopes: z
    .array(z.enum(['read:data', 'write:data', 'read:profile', 'write:posts', 'admin:users']))
    .min(1, 'Selecciona al menos un scope'),
});

// ── POST /api/v1/keys ─────────────────────────────────────────────────────────

router.post(
  '/',
  authenticate,
  asyncHandler(async (req, res) => {
    const result = createKeySchema.safeParse(req.body);
    if (!result.success) {
      throw new AppError(400, result.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { name, scopes } = result.data;
    const userId = req.user!.userId;

    // Generar key: sk_live_ + 64 hex chars aleatorios
    const randomPart = randomBytes(API_KEY_RANDOM_BYTES).toString('hex'); // 64 chars
    const fullKey = `sk_live_${randomPart}`;

    // Prefijo visible: sk_live_ + primeros 8 chars del random
    const prefix = `sk_live_${randomPart.slice(0, PREFIX_VISIBLE_BYTES * 2)}`;

    // Hash con bcrypt — la key completa NUNCA se almacena en claro
    const key_hash = await bcrypt.hash(fullKey, BCRYPT_COST);

    const apiKey = apiKeysRepository.create({
      user_id: userId,
      name,
      key_prefix: prefix,
      key_hash,
      scopes,
    });

    auditLogsRepository.create({
      user_id: userId,
      event_type: 'API_KEY_CREADA',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: { key_id: apiKey.id, name, scopes },
    });

    res.status(201).json({
      id: apiKey.id,
      name: apiKey.name,
      key: fullKey, // ⚠️ ÚLTIMA VEZ que se muestra — guárdala ahora
      key_prefix: apiKey.key_prefix,
      scopes,
      created_at: apiKey.created_at,
      advertencia: 'Esta es la ÚNICA vez que verás la key completa. No hay forma de recuperarla.',
    });
  }),
);

// ── GET /api/v1/keys ──────────────────────────────────────────────────────────

router.get('/', authenticate, (req, res) => {
  const userId = req.user!.userId;
  const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
  const limit = typeof req.query['limit'] === 'string' ? Number(req.query['limit']) : undefined;

  const page = apiKeysRepository.findByUserId(userId, { cursor, limit });

  res.json({
    ...page,
    data: page.data.map((k) => ({
      id: k.id,
      name: k.name,
      key_prefix: k.key_prefix,
      scopes: JSON.parse(k.scopes) as string[],
      last_used_at: k.last_used_at,
      revoked_at: k.revoked_at,
      created_at: k.created_at,
    })),
    nota: 'La key completa no se puede recuperar — solo se muestra el prefijo',
  });
});

// ── POST /api/v1/keys/:id/revoke ──────────────────────────────────────────────

router.post('/:id/revoke', authenticate, (req, res) => {
  const userId = req.user!.userId;
  const keyId = req.params['id'];

  if (!keyId) throw new AppError(400, 'ID de API Key requerido', 'VALIDACION_FALLIDA');

  const revoked = apiKeysRepository.revoke(keyId, userId);

  if (!revoked) {
    throw new AppError(404, 'API Key no encontrada o ya revocada', 'NO_ENCONTRADO');
  }

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'API_KEY_REVOCADA',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { key_id: keyId },
  });

  res.json({ mensaje: 'API Key revocada correctamente' });
});

// ── GET /api/v1/keys/protected ────────────────────────────────────────────────
// Demo: ruta protegida con API Key + scope

router.get(
  '/protected',
  apiKeyAuthMiddleware,
  requireScope('read:data'),
  (req, res) => {
    res.json({
      mensaje: 'Acceso concedido con API Key + scope read:data',
      usuario_id: req.user?.userId,
      scopes: req.user?.scopes,
      por_que_header: [
        'Los query params aparecen en logs del servidor: GET /data?key=sk_live_...',
        'Los headers NO aparecen en logs de acceso por defecto',
        'Los headers no se guardan en historial del navegador ni bookmarks',
        'La spec de OAuth 2.0 prohíbe explícitamente API Keys en query params',
      ],
    });
  },
);

export default router;
