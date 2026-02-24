/**
 * Rutas JWT con Defensas Completas — Fase 4
 * POST /api/v1/jwt/refresh    → renovar AT+RT con Family Tracking (detección de robo)
 * POST /api/v1/jwt/logout-all → cerrar TODAS las sesiones activas del usuario
 * GET  /api/v1/jwt/sessions   → listar familias de tokens activas (paginado)
 *
 * Family Tracking — ¿qué resuelve?
 * Si un atacante roba un RT y lo usa, el servidor detecta que el jti no coincide
 * con current_jti de la familia. En ese momento REVOCA TODA LA FAMILIA (todas las
 * sesiones de ese login) y alerta con TOKEN_ROBO_DETECTADO. El usuario legítimo
 * pierde la sesión pero su cuenta queda protegida.
 */
import { Router } from 'express';
import { config } from '../config/env';
import { usersRepository } from '../db/repositories/users';
import { refreshTokenFamiliesRepository } from '../db/repositories/refreshTokenFamilies';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { revokeFamily } from '../db/transactions';
import { verifyRefreshToken, refreshTokenPair } from '../services/jwtService';
import { authenticate } from '../middleware/authenticate';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { refreshLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import { checkUnusualSession } from '../services/anomalyDetection';
import type { UserRole } from '../types';

const router = Router();

/** Lee la cookie refreshToken del header Cookie sin necesitar cookie-parser */
function getRefreshTokenCookie(cookieHeader: string): string | null {
  const match = /(?:^|;\s*)refreshToken=([^;]*)/.exec(cookieHeader);
  return match ? decodeURIComponent(match[1]!) : null;
}

// ── POST /api/v1/jwt/refresh ──────────────────────────────────────────────────

router.post(
  '/refresh',
  refreshLimiter,
  asyncHandler(async (req, res) => {
    const rawRt = getRefreshTokenCookie(req.headers.cookie ?? '');

    if (!rawRt) {
      throw new AppError(
        401,
        'No hay Refresh Token — inicia sesión de nuevo',
        'TOKEN_AUSENTE',
      );
    }

    // ── Verificar firma y expiración del RT ───────────────────────────────
    const rtPayload = verifyRefreshToken(rawRt);
    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    // ── Buscar la familia en BD ────────────────────────────────────────────
    const family = refreshTokenFamiliesRepository.findById(rtPayload.familyId);

    if (!family) {
      throw new AppError(401, 'Sesión no encontrada — inicia sesión de nuevo', 'SESION_NO_ENCONTRADA');
    }

    // ── Detectar familia ya revocada ───────────────────────────────────────
    if (family.revoked_at) {
      throw new AppError(
        401,
        'La sesión ha sido cerrada — inicia sesión de nuevo',
        'SESION_REVOCADA',
      );
    }

    // ── FAMILY TRACKING: detectar reutilización de RT (posible robo) ──────
    // Si el jti del RT presentado !== current_jti guardado → el RT fue reutilizado.
    // Esto significa que alguien ya usó este RT antes (posible atacante).
    // Respuesta: revocar toda la familia para invalidar TODAS las sesiones.
    if (family.current_jti !== rtPayload.jti) {
      revokeFamily({
        familyId: family.id,
        reason: 'stolen',
        eventType: 'TOKEN_ROBO_DETECTADO',
        auditData: {
          userId: rtPayload.sub,
          ipHash,
          correlationId: req.correlationId,
        },
      });

      // Limpiar cookie — el usuario debe hacer login completo de nuevo
      res.clearCookie('refreshToken', { path: '/api/v1' });

      throw new AppError(
        401,
        'Sesión comprometida — se ha cerrado por seguridad. Por favor inicia sesión de nuevo',
        'TOKEN_ROBO_DETECTADO',
      );
    }

    // ── Obtener usuario (roles actuales, no los del token viejo) ──────────
    const user = usersRepository.findById(rtPayload.sub);
    if (!user) {
      throw new AppError(401, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');
    }

    const roles = JSON.parse(user.roles) as UserRole[];

    // ── Emitir nuevo par AT+RT (misma familia) ─────────────────────────────
    const { accessToken, refreshToken } = refreshTokenPair({
      familyId: family.id,
      userId: user.id,
      roles,
      auditData: { ipHash, userAgent, correlationId: req.correlationId },
    });

    // Fase 7: Detección de sesión inusual — verificar tras emitir nuevo par
    checkUnusualSession(family.id, ipHash, user.id, req.correlationId);

    // Nuevo RT en cookie HttpOnly (reemplaza el anterior)
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      accessToken,
      expiresIn: 15 * 60, // segundos
      tokenType: 'Bearer' as const,
    });
  }),
);

// ── POST /api/v1/jwt/logout-all ───────────────────────────────────────────────

router.post('/logout-all', authenticate, (req, res) => {
  const userId = req.user!.userId;
  const ipHash = hashIp(req.ip ?? '');

  // Revocar TODAS las familias activas del usuario
  refreshTokenFamiliesRepository.revokeAllForUser(userId, 'global_logout');

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'SESION_GLOBAL_CERRADA',
    ip_hash: ipHash,
    correlation_id: req.correlationId,
    metadata: { metodo: 'jwt' },
  });

  // Limpiar la cookie del dispositivo actual
  res.clearCookie('refreshToken', { path: '/api/v1' });

  res.json({
    mensaje: 'Todas las sesiones han sido cerradas correctamente',
    nota: 'El Access Token actual sigue siendo válido hasta su expiración (máx. 15min)',
  });
});

// ── GET /api/v1/jwt/sessions ──────────────────────────────────────────────────

router.get('/sessions', authenticate, (req, res) => {
  const userId = req.user!.userId;
  const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
  const limit = typeof req.query['limit'] === 'string' ? Number(req.query['limit']) : undefined;

  const page = refreshTokenFamiliesRepository.findActiveByUserId(userId, { cursor, limit });

  res.json({
    ...page,
    data: page.data.map((f) => ({
      id: f.id,
      ip_hash: f.ip_hash,
      user_agent: f.user_agent,
      kid: f.kid,
      created_at: f.created_at,
      expires_at: f.expires_at,
    })),
    nota: 'ip_hash es SHA-256(ip + salt) — nunca se guarda la IP en claro (GDPR)',
  });
});

export default router;
