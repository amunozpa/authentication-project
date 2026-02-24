/**
 * Rutas Magic Links / Passwordless — Fase 5.7
 *
 *   POST /api/v1/magic/request    → solicita un magic link por email
 *   GET  /api/v1/magic/verify     → verifica el token → emite AT + RT (o mfa_session si MFA activo)
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ FLUJO MAGIC LINK                                                        │
 * │                                                                         │
 * │  1. Usuario → POST /magic/request { email }                             │
 * │  2. Servidor genera token de 32 bytes aleatorios (256 bits de entropía) │
 * │     Guarda SHA-256(token) en email_tokens (TTL 15 min, one-time)        │
 * │     Envía email con enlace: GET /magic/verify?token=<raw_token>         │
 * │  3. Usuario hace clic → GET /magic/verify?token=...                     │
 * │  4. Servidor: SHA-256(token) → busca en DB → verifica no expirado/usado │
 * │     Marca como usado → emite AT + RT                                    │
 * │                                                                         │
 * │ Si el usuario tiene MFA activado → /verify devuelve mfa_session_token   │
 * │ en lugar de AT (el usuario completa con POST /mfa/verify como siempre)  │
 * │                                                                         │
 * │ Seguridad:                                                              │
 * │  - El token raw nunca se guarda en BD (solo su hash SHA-256)            │
 * │  - Anti-enumeración: siempre responde 200 en /request                   │
 * │  - One-time: se marca como usado antes de emitir tokens                 │
 * │  - TTL: 15 minutos                                                      │
 * │  - Invalida magic links anteriores al crear uno nuevo                   │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import { randomBytes } from 'crypto';
import { usersRepository } from '../db/repositories/users';
import { emailTokensRepository } from '../db/repositories/emailTokens';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { issueTokenPair, issueTemporaryToken } from '../services/jwtService';
import { sendMagicLinkEmail } from '../services/emailService';
import { hashToken, hashIp } from '../utils/hash';
import { asyncHandler } from '../utils/asyncHandler';
import { strictLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';

const router = Router();

const MAGIC_LINK_TTL_MS = 15 * 60 * 1000; // 15 minutos

// ── POST /request ─────────────────────────────────────────────────────────────

const requestSchema = z.object({
  email: z.string().email('Email inválido'),
});

/**
 * Genera y envía un magic link al email indicado.
 *
 * Siempre responde 200 — nunca revela si el email está registrado
 * (anti-enumeración: un atacante no puede descubrir qué emails existen en el sistema).
 *
 * Si el usuario tiene magic links anteriores activos, los invalida primero
 * (solo un magic link activo por usuario en cada momento).
 */
router.post(
  '/request',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const parsed = requestSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Email inválido', 'VALIDACION_FALLIDA');
    }

    const { email } = parsed.data;
    const ipHash = hashIp(req.ip ?? '');

    // Siempre responder con el mismo mensaje — no revelar si el email existe
    const user = usersRepository.findByEmail(email);

    if (user) {
      // Invalidar magic links anteriores (solo uno activo por usuario)
      emailTokensRepository.invalidateActiveByUserAndType(user.id, 'MAGIC_LINK');

      // Generar token de alta entropía
      const rawToken = randomBytes(32).toString('hex'); // 64 chars hex = 256 bits
      const tokenHash = hashToken(rawToken);

      emailTokensRepository.create({
        user_id: user.id,
        token_hash: tokenHash,
        type: 'MAGIC_LINK',
        expires_at: Date.now() + MAGIC_LINK_TTL_MS,
      });

      // Enviar email (consola en dev, Gmail SMTP en prod cuando GMAIL_USER esté configurado)
      await sendMagicLinkEmail(email, rawToken);

      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MAGIC_LINK_ENVIADO',
        ip_hash: ipHash,
        user_agent: req.headers['user-agent'] ?? null,
        correlation_id: req.correlationId,
      });
    }
    // Si el usuario no existe — no hacer nada, pero responder igual

    res.json({
      mensaje: 'Si el email está registrado, recibirás un enlace de acceso en los próximos minutos',
      expira_en: '15 minutos',
      nota_dev: 'En desarrollo el enlace se muestra en los logs del servidor (INFO)',
    });
  }),
);

// ── GET /verify?token=... ─────────────────────────────────────────────────────

/**
 * Verifica el magic link y emite tokens de acceso.
 *
 * Si el usuario tiene MFA activado:
 *   → devuelve mfa_session_token (el usuario completa con POST /mfa/verify)
 *
 * Si el usuario no tiene MFA:
 *   → emite AT + RT directamente
 *
 * El token se marca como usado ANTES de emitir credenciales (one-time garantizado).
 */
router.get(
  '/verify',
  asyncHandler(async (req, res) => {
    const rawToken = req.query['token'];

    if (typeof rawToken !== 'string' || !rawToken) {
      throw new AppError(400, 'Token requerido — usa el enlace del email', 'VALIDACION_FALLIDA');
    }

    const tokenHash = hashToken(rawToken);
    const emailToken = emailTokensRepository.findByHash(tokenHash);

    // Token no encontrado
    if (!emailToken || emailToken.type !== 'MAGIC_LINK') {
      throw new AppError(400, 'Enlace inválido — solicita uno nuevo', 'TOKEN_INVALIDO');
    }

    // Token ya usado
    if (emailToken.used_at) {
      throw new AppError(400, 'Este enlace ya fue usado — solicita uno nuevo', 'TOKEN_YA_USADO');
    }

    // Token expirado
    if (emailToken.expires_at < Date.now()) {
      auditLogsRepository.create({
        user_id: emailToken.user_id,
        event_type: 'MAGIC_LINK_EXPIRADO',
        ip_hash: hashIp(req.ip ?? ''),
        correlation_id: req.correlationId,
      });
      throw new AppError(
        400,
        'El enlace ha expirado — solicita uno nuevo con POST /api/v1/magic/request',
        'TOKEN_EXPIRADO',
      );
    }

    // Marcar como usado ANTES de emitir — garantiza one-time incluso ante condiciones de carrera
    emailTokensRepository.markUsed(emailToken.id);

    const user = usersRepository.findById(emailToken.user_id);
    if (!user) {
      throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');
    }

    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    // ── MFA activo: no emitir AT — devolver mfa_session_token ────────────────
    if (user.mfa_enabled) {
      const mfaToken = issueTemporaryToken(user.id, 'mfa_session', '5m');

      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MAGIC_LINK_VERIFICADO',
        ip_hash: ipHash,
        user_agent: userAgent,
        correlation_id: req.correlationId,
        metadata: { mfa_required: true },
      });

      res.json({
        mfa_required: true,
        mfa_session_token: mfaToken,
        mensaje: 'Magic link verificado — introduce tu código TOTP para completar el acceso',
      });
      return;
    }

    // ── Sin MFA: emitir AT + RT ───────────────────────────────────────────────
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken, familyId } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'MAGIC_LINK_VERIFICADO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { family_id: familyId },
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env['NODE_ENV'] === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      accessToken,
      expiresIn: 15 * 60,
      tokenType: 'Bearer' as const,
      familyId,
      usuario: {
        id: user.id,
        email: user.email,
        roles,
      },
    });
  }),
);

export default router;
