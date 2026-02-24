/**
 * Rutas de administración — Fase 4
 * POST /api/v1/admin/keys/rotate  → rotar clave de firma JWT (solo admin, solo dev)
 *
 * Rotación de claves sin logout masivo:
 * - Se crea una nueva clave activa (nueva kid, nuevo secret)
 * - La clave anterior queda "retirada" (active=0, retired_at=now)
 * - Los tokens firmados con la clave retirada SIGUEN SIENDO VERIFICABLES
 *   hasta que expiren (el servidor busca la clave por kid, no solo la activa)
 * - Solo la nueva clave firma tokens nuevos
 *
 * En producción, la clave debería venir de un vault (AWS Secrets Manager,
 * HashiCorp Vault, etc.), no generarse en el servidor.
 */
import { Router } from 'express';
import { randomBytes } from 'crypto';
import { jwtSigningKeysRepository } from '../db/repositories/jwtSigningKeys';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { usersRepository } from '../db/repositories/users';
import { deleteAccountGdpr } from '../db/transactions';
import { authenticate } from '../middleware/authenticate';
import { requireRole } from '../middleware/requireRole';
import { hashIp } from '../utils/hash';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';

const router = Router();

// ── POST /api/v1/admin/keys/rotate ────────────────────────────────────────────

router.post(
  '/keys/rotate',
  authenticate,
  requireRole('admin'),
  (req, res) => {
    // Operación de alta sensibilidad — solo en entornos de desarrollo/staging
    if (req.app.get('env') === 'production') {
      throw new AppError(
        403,
        'La rotación manual de claves JWT no está disponible en producción. Usa el vault configurado.',
        'OPERACION_NO_PERMITIDA_EN_PROD',
      );
    }

    const currentActive = jwtSigningKeysRepository.findActive();

    // Generar nueva clave con 32 bytes aleatorios (256 bits)
    const newSecret = randomBytes(32).toString('hex');
    const newKey = jwtSigningKeysRepository.create(newSecret);

    // Retirar la clave anterior — sigue verificando tokens existentes hasta que expiren
    if (currentActive) {
      jwtSigningKeysRepository.retire(currentActive.id);
    }

    auditLogsRepository.create({
      user_id: req.user!.userId,
      event_type: 'CLAVE_JWT_ROTADA',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: {
        old_kid: currentActive?.id ?? null,
        new_kid: newKey.id,
      },
    });

    res.json({
      mensaje: 'Clave JWT rotada correctamente',
      nuevo_kid: newKey.id,
      kid_anterior: currentActive?.id ?? null,
      estado_anterior: currentActive ? 'retirada (active=0)' : 'no existía',
      notas: [
        'Los tokens firmados con la clave anterior siguen siendo válidos hasta que expiren',
        'El servidor busca la clave por kid en el header JWT, no solo la activa',
        'Activa → firma nuevos tokens; Retirada → solo verifica tokens existentes',
      ],
      todas_las_claves: jwtSigningKeysRepository.findAll().map((k) => ({
        kid: k.id,
        active: k.active === 1,
        created_at: k.created_at,
        retired_at: k.retired_at,
      })),
    });
  },
);

// ── GET /api/v1/admin/keys ────────────────────────────────────────────────────

router.get('/keys', authenticate, requireRole('admin'), (_req, res) => {
  const keys = jwtSigningKeysRepository.findAll();

  res.json({
    data: keys.map((k) => ({
      kid: k.id,
      active: k.active === 1,
      created_at: k.created_at,
      retired_at: k.retired_at,
    })),
    nota: 'El campo "secret" nunca se expone — en producción debería estar en un vault externo',
  });
});

// ── GET /api/v1/admin/users ───────────────────────────────────────────────────

/**
 * Lista paginada de usuarios activos — solo admin.
 *
 * Query params opcionales:
 *   ?role=admin|editor|user|viewer  — filtrar por rol
 *   ?cursor=<token>                 — paginación por cursor
 *   ?limit=<n>                      — tamaño de página (máx. 50)
 */
router.get('/users', authenticate, requireRole('admin'), (req, res) => {
  const role = typeof req.query['role'] === 'string' ? (req.query['role'] as UserRole) : undefined;
  const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
  const limit = typeof req.query['limit'] === 'string' ? Number(req.query['limit']) : undefined;

  const page = usersRepository.list({ cursor, limit, role });

  res.json({
    ...page,
    data: page.data.map((u) => ({
      id: u.id,
      email: u.email,
      roles: JSON.parse(u.roles),
      email_verified: u.email_verified === 1,
      mfa_enabled: u.mfa_enabled === 1,
      locked_until: u.locked_until,
      created_at: u.created_at,
    })),
  });
});

// ── POST /api/v1/admin/users/:id/unlock ───────────────────────────────────────

/**
 * Desbloquea una cuenta bloqueada por lockout — solo admin.
 * El usuario podrá volver a iniciar sesión inmediatamente.
 */
router.post('/users/:id/unlock', authenticate, requireRole('admin'), (req, res) => {
  const userId = req.params['id'] as string;
  const user = usersRepository.findById(userId);

  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  if (!user.locked_until || user.locked_until <= Date.now()) {
    throw new AppError(409, 'La cuenta no está bloqueada actualmente', 'CUENTA_NO_BLOQUEADA');
  }

  usersRepository.unlock(userId);

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'CUENTA_DESBLOQUEADA',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { initiatedBy: req.user!.userId },
  });

  res.json({ mensaje: `Cuenta ${user.email} desbloqueada correctamente` });
});

// ── DELETE /api/v1/admin/users/:id ────────────────────────────────────────────

/**
 * Eliminación de cuenta por un administrador — solo admin.
 *
 * Ejecuta la misma transacción GDPR que DELETE /user/me:
 *   · Soft-delete del usuario
 *   · Hard-delete de datos relacionados
 *   · Anonimización de audit_logs
 * Log: CUENTA_ELIMINADA con { initiatedBy: adminId }
 */
router.delete('/users/:id', authenticate, requireRole('admin'), (req, res) => {
  const userId = req.params['id'] as string;
  const adminId = req.user!.userId;
  const user = usersRepository.findById(userId);

  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');
  if (userId === adminId) throw new AppError(409, 'No puedes eliminar tu propia cuenta como admin', 'OPERACION_NO_PERMITIDA');

  deleteAccountGdpr({
    userId,
    auditData: {
      ipHash: hashIp(req.ip ?? ''),
      correlationId: req.correlationId,
    },
  });

  // Registrar quién inició la eliminación (en un log separado, ya que la transacción anonimiza)
  auditLogsRepository.create({
    user_id: adminId,
    event_type: 'CUENTA_ELIMINADA',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { initiatedBy: adminId, targetUserId: userId, targetEmail: user.email },
  });

  res.json({ mensaje: `Cuenta ${user.email} eliminada correctamente` });
});

// ── GET /api/v1/admin/anomalies — Fase 7 ─────────────────────────────────────

/**
 * Lista paginada de eventos de anomalía de seguridad — solo admin.
 *
 * Query params opcionales:
 *   ?type=credential_stuffing|brute_force|unusual_session — filtrar por tipo
 *   ?since=<timestamp_ms>   — desde cuándo
 *   ?until=<timestamp_ms>   — hasta cuándo
 *   ?cursor=<token>         — paginación
 *   ?limit=<n>              — tamaño de página
 */
router.get('/anomalies', authenticate, requireRole('admin'), (req, res) => {
  const typeParam = typeof req.query['type'] === 'string' ? req.query['type'] : undefined;
  const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
  const limit = typeof req.query['limit'] === 'string' ? Number(req.query['limit']) : undefined;
  const since = typeof req.query['since'] === 'string' ? Number(req.query['since']) : undefined;
  const until = typeof req.query['until'] === 'string' ? Number(req.query['until']) : undefined;

  const page = auditLogsRepository.findAnomalies({ typeParam, cursor, limit, since, until });

  res.json({
    ...page,
    data: page.data.map((e) => ({
      id: e.id,
      event_type: e.event_type,
      ip_hash: e.ip_hash,
      metadata: e.metadata ? (JSON.parse(e.metadata) as unknown) : null,
      created_at: e.created_at,
    })),
    severidad: {
      ANOMALIA_CREDENTIAL_STUFFING: 'alta',
      ANOMALIA_FUERZA_BRUTA: 'media',
      ANOMALIA_SESION_INUSUAL: 'media',
    },
  });
});

export default router;
