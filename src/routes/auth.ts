/**
 * Rutas de autenticación con contraseña — Fase 3/4/5.8
 * POST /api/v1/auth/register
 * POST /api/v1/auth/login
 * POST /api/v1/auth/logout           ← Fase 4: revoca la familia del RT actual
 * GET  /api/v1/auth/verify-email
 * POST /api/v1/auth/resend-verification
 * POST /api/v1/auth/forgot-password  ← Fase 5.8: solicita enlace de reset
 * POST /api/v1/auth/reset-password   ← Fase 5.8: establece nueva contraseña
 */
import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { config } from '../config/env';
import { usersRepository } from '../db/repositories/users';
import { emailTokensRepository } from '../db/repositories/emailTokens';
import { refreshTokenFamiliesRepository } from '../db/repositories/refreshTokenFamilies';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { verifyEmail as verifyEmailTx, revokeFamily } from '../db/transactions';
import { issueTokenPair, verifyRefreshToken } from '../services/jwtService';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/emailService';
import { hashToken, hashIp } from '../utils/hash';
import { asyncHandler } from '../utils/asyncHandler';
import { authenticate } from '../middleware/authenticate';
import { authLimiter, strictLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import { checkCredentialStuffing, checkBruteForce } from '../services/anomalyDetection';
import type { UserRole } from '../types';

const router = Router();

const BCRYPT_COST = 12;
const LOCKOUT_FAILURES = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutos
const LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutos
const EMAIL_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 horas (verificación de email)
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hora (reset de contraseña)

// ── Schemas de validación Zod ─────────────────────────────────────────────────

const registerSchema = z.object({
  email: z.string().email('Email inválido'),
  password: z
    .string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'Contraseña demasiado larga'),
});

const loginSchema = z.object({
  email: z.string().email('Email inválido'),
  password: z.string().min(1, 'Contraseña requerida'),
});

// ── POST /api/v1/auth/register ────────────────────────────────────────────────

router.post(
  '/register',
  authLimiter,
  asyncHandler(async (req, res) => {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      throw new AppError(400, result.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { email, password } = result.data;
    const ipHash = hashIp(req.ip ?? '');

    // Verificar si el email ya existe (responder igual si existe para prevenir enumeración)
    const existing = usersRepository.findByEmailIncludingDeleted(email);
    if (existing) {
      // Responder con 200 y mismo mensaje para no revelar si el email existe
      res.status(200).json({
        mensaje: 'Si el email no está registrado, recibirás un correo de verificación',
      });
      return;
    }

    // Hash de contraseña con bcrypt (cost 12 — balance seguridad/rendimiento)
    const password_hash = await bcrypt.hash(password, BCRYPT_COST);

    // Crear usuario con email_verified=0
    const user = usersRepository.create({ email, password_hash, email_verified: 0 });

    // Generar token de verificación de email
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);

    emailTokensRepository.create({
      user_id: user.id,
      token_hash: tokenHash,
      type: 'VERIFY_EMAIL',
      expires_at: Date.now() + EMAIL_TOKEN_TTL_MS,
    });

    // Enviar email (consola en dev, Gmail en prod)
    await sendVerificationEmail(email, rawToken);

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'REGISTRO_EXITOSO',
      ip_hash: ipHash,
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
    });

    res.status(201).json({
      mensaje: 'Cuenta creada. Revisa tu email para verificar tu cuenta antes de iniciar sesión',
    });
  }),
);

// ── POST /api/v1/auth/login ───────────────────────────────────────────────────

router.post(
  '/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      throw new AppError(400, result.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { email, password } = result.data;
    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    const user = usersRepository.findByEmail(email);

    // Siempre ejecutar bcrypt para prevenir user enumeration por timing
    const hashToCompare = user?.password_hash ?? (await bcrypt.hash('dummy_timing', BCRYPT_COST));
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    // ── Verificar account lockout ──────────────────────────────────────────
    if (user && user.locked_until && user.locked_until > Date.now()) {
      const minutosRestantes = Math.ceil((user.locked_until - Date.now()) / 60000);
      throw new AppError(
        423,
        `Cuenta bloqueada por demasiados intentos fallidos. Intenta en ${minutosRestantes} minutos`,
        'CUENTA_BLOQUEADA',
      );
    }

    // ── Credenciales incorrectas ───────────────────────────────────────────
    if (!passwordMatch || !user) {
      if (user) {
        // Contar fallos recientes para decidir si bloquear
        const recentFailures = auditLogsRepository.countRecentByType(
          'LOGIN_FALLIDO',
          Date.now() - LOCKOUT_WINDOW_MS,
          user.id,
        );

        auditLogsRepository.create({
          user_id: user.id,
          event_type: 'LOGIN_FALLIDO',
          ip_hash: ipHash,
          user_agent: userAgent,
          correlation_id: req.correlationId,
          metadata: { intento: recentFailures + 1 },
        });

        if (recentFailures + 1 >= LOCKOUT_FAILURES) {
          usersRepository.setLocked(user.id, Date.now() + LOCKOUT_DURATION_MS);
          auditLogsRepository.create({
            user_id: user.id,
            event_type: 'CUENTA_BLOQUEADA',
            ip_hash: ipHash,
            correlation_id: req.correlationId,
            metadata: { duracion_ms: LOCKOUT_DURATION_MS },
          });
        }

        // Fase 7: Detección de anomalías — se ejecuta después del log del fallo
        checkBruteForce(user.id, ipHash, req.correlationId);
        checkCredentialStuffing(req.correlationId);
      } else {
        // Usuario desconocido — solo detectar credential stuffing global
        checkCredentialStuffing(req.correlationId);
      }
      throw new AppError(401, 'Email o contraseña incorrectos', 'CREDENCIALES_INVALIDAS');
    }

    // ── Verificar email ────────────────────────────────────────────────────
    if (!user.email_verified) {
      throw new AppError(
        403,
        'Debes verificar tu email antes de iniciar sesión. Revisa tu bandeja de entrada',
        'EMAIL_NO_VERIFICADO',
      );
    }

    // ── MFA pendiente (Fase 5.6) ───────────────────────────────────────────
    if (user.mfa_enabled) {
      const mfaToken = (await import('../services/jwtService')).issueTemporaryToken(
        user.id,
        'mfa_session',
        '5m',
      );
      res.json({
        mfa_required: true,
        mfa_session_token: mfaToken,
        mensaje: 'Introduce tu código TOTP para completar el inicio de sesión',
      });
      return;
    }

    // ── Emitir AT + RT ─────────────────────────────────────────────────────
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent,
    });

    // RT en cookie HttpOnly
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: 'password' },
    });

    res.json({
      accessToken,
      expiresIn: 15 * 60, // segundos
      tokenType: 'Bearer' as const,
    });
  }),
);

// ── GET /api/v1/auth/verify-email?token=... ───────────────────────────────────

router.get(
  '/verify-email',
  asyncHandler(async (req, res) => {
    const rawToken = req.query['token'];
    if (typeof rawToken !== 'string' || !rawToken) {
      throw new AppError(400, 'Token de verificación requerido', 'VALIDACION_FALLIDA');
    }

    const tokenHash = hashToken(rawToken);
    const emailToken = emailTokensRepository.findByHash(tokenHash);

    if (!emailToken) {
      throw new AppError(400, 'Token de verificación inválido', 'TOKEN_INVALIDO');
    }

    if (emailToken.type !== 'VERIFY_EMAIL') {
      throw new AppError(400, 'Token de tipo incorrecto', 'TOKEN_INVALIDO');
    }

    if (emailToken.expires_at < Date.now()) {
      throw new AppError(400, 'El token de verificación ha expirado — solicita uno nuevo', 'TOKEN_EXPIRADO');
    }

    if (emailToken.used_at) {
      throw new AppError(400, 'Este token ya fue usado', 'TOKEN_YA_USADO');
    }

    // Transacción: marcar token + verificar email + log (atómico)
    verifyEmailTx({
      tokenId: emailToken.id,
      userId: emailToken.user_id,
      auditData: {
        ipHash: hashIp(req.ip ?? ''),
        correlationId: req.correlationId,
      },
    });

    res.json({ mensaje: 'Email verificado correctamente. Ya puedes iniciar sesión' });
  }),
);

// ── POST /api/v1/auth/logout ──────────────────────────────────────────────────
// Requiere AT válido. Revoca la familia del RT actual y limpia la cookie.

router.post(
  '/logout',
  authenticate,
  asyncHandler(async (req, res) => {
    const userId = req.user!.userId;
    const ipHash = hashIp(req.ip ?? '');

    // Intentar revocar la familia del RT en cookie
    const cookieHeader = req.headers.cookie ?? '';
    const rtMatch = /(?:^|;\s*)refreshToken=([^;]*)/.exec(cookieHeader);
    const rawRt = rtMatch ? decodeURIComponent(rtMatch[1]!) : null;

    if (rawRt) {
      try {
        const rtPayload = verifyRefreshToken(rawRt);
        const family = refreshTokenFamiliesRepository.findById(rtPayload.familyId);

        if (family && !family.revoked_at) {
          // revokeFamily crea el log LOGOUT atómicamente
          revokeFamily({
            familyId: family.id,
            reason: 'logout',
            eventType: 'LOGOUT',
            auditData: {
              userId,
              ipHash,
              correlationId: req.correlationId,
            },
          });

          res.clearCookie('refreshToken', { path: '/api/v1' });
          res.json({ mensaje: 'Sesión cerrada correctamente' });
          return;
        }
      } catch {
        // RT inválido o expirado — continuar sin él
      }
    }

    // Sin RT válido: igual registramos el logout
    auditLogsRepository.create({
      user_id: userId,
      event_type: 'LOGOUT',
      ip_hash: ipHash,
      correlation_id: req.correlationId,
      metadata: { sin_rt_cookie: true },
    });

    res.clearCookie('refreshToken', { path: '/api/v1' });
    res.json({ mensaje: 'Sesión cerrada correctamente' });
  }),
);

// ── POST /api/v1/auth/resend-verification ─────────────────────────────────────

router.post(
  '/resend-verification',
  asyncHandler(async (req, res) => {
    const result = z.object({ email: z.string().email() }).safeParse(req.body);
    if (!result.success) {
      throw new AppError(400, 'Email inválido', 'VALIDACION_FALLIDA');
    }

    const { email } = result.data;

    // Responder siempre con 200 — no revelar si el email existe
    const user = usersRepository.findByEmail(email);
    if (!user || user.email_verified) {
      res.json({ mensaje: 'Si el email está pendiente de verificación, recibirás un correo' });
      return;
    }

    // Invalidar tokens previos del mismo tipo
    emailTokensRepository.invalidateActiveByUserAndType(user.id, 'VERIFY_EMAIL');

    const rawToken = randomBytes(32).toString('hex');
    emailTokensRepository.create({
      user_id: user.id,
      token_hash: hashToken(rawToken),
      type: 'VERIFY_EMAIL',
      expires_at: Date.now() + EMAIL_TOKEN_TTL_MS,
    });

    await sendVerificationEmail(email, rawToken);

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'VERIFICACION_REENVIADA',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
    });

    res.json({ mensaje: 'Si el email está pendiente de verificación, recibirás un correo' });
  }),
);

// ── POST /api/v1/auth/forgot-password ────────────────────────────────────────

const forgotPasswordSchema = z.object({
  email: z.string().email('Email inválido'),
});

/**
 * Solicita un enlace de restablecimiento de contraseña.
 *
 * Siempre responde 200 — no revela si el email existe (anti-enumeración).
 * Solo envía el email si el usuario existe Y tiene el email verificado.
 * Invalida tokens de reset anteriores (solo uno activo por usuario).
 * TTL: 1 hora.
 */
router.post(
  '/forgot-password',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Email inválido', 'VALIDACION_FALLIDA');
    }

    const { email } = parsed.data;
    const ipHash = hashIp(req.ip ?? '');

    const user = usersRepository.findByEmail(email);

    // Solo actuar si el usuario existe Y tiene el email verificado
    // (un usuario sin verificar no puede resetear contraseña — podría ser una cuenta que no le pertenece)
    if (user && user.email_verified) {
      // Un solo token activo por usuario
      emailTokensRepository.invalidateActiveByUserAndType(user.id, 'PASSWORD_RESET');

      const rawToken = randomBytes(32).toString('hex'); // 256 bits de entropía
      emailTokensRepository.create({
        user_id: user.id,
        token_hash: hashToken(rawToken),
        type: 'PASSWORD_RESET',
        expires_at: Date.now() + RESET_TOKEN_TTL_MS,
      });

      await sendPasswordResetEmail(email, rawToken);

      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'RESET_SOLICITADO',
        ip_hash: ipHash,
        user_agent: req.headers['user-agent'] ?? null,
        correlation_id: req.correlationId,
      });
    }
    // Si el usuario no existe o no tiene email verificado — no hacer nada, pero responder igual

    res.json({
      mensaje: 'Si el email está registrado y verificado, recibirás un enlace para restablecer tu contraseña',
      expira_en: '1 hora',
      nota_dev: 'En desarrollo el enlace se muestra en los logs del servidor (INFO)',
    });
  }),
);

// ── POST /api/v1/auth/reset-password ─────────────────────────────────────────

const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token requerido'),
  new_password: z
    .string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'Contraseña demasiado larga'),
});

/**
 * Establece una nueva contraseña usando el token del enlace de reset.
 *
 * Seguridad:
 *   - El token se marca como usado ANTES de actualizar la contraseña (one-time garantizado)
 *   - Se revocan TODAS las sesiones activas del usuario (fuerza re-login en todos los dispositivos)
 *   - Si el usuario tiene MFA, NO se deshabilita (el atacante no puede desactivar el 2FA)
 */
router.post(
  '/reset-password',
  strictLimiter,
  asyncHandler(async (req, res) => {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { token, new_password } = parsed.data;
    const ipHash = hashIp(req.ip ?? '');

    const tokenHash = hashToken(token);
    const emailToken = emailTokensRepository.findByHash(tokenHash);

    // Token no encontrado o tipo incorrecto
    if (!emailToken || emailToken.type !== 'PASSWORD_RESET') {
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
        event_type: 'RESET_SOLICITADO', // reutilizamos para marcar intento con token expirado
        ip_hash: ipHash,
        correlation_id: req.correlationId,
        metadata: { expired: true },
      });
      throw new AppError(
        400,
        'El enlace ha expirado — solicita uno nuevo con POST /api/v1/auth/forgot-password',
        'TOKEN_EXPIRADO',
      );
    }

    const user = usersRepository.findById(emailToken.user_id);
    if (!user) {
      throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');
    }

    // Marcar token como usado ANTES de cualquier cambio — garantiza one-time
    emailTokensRepository.markUsed(emailToken.id);

    // Hashear nueva contraseña
    const newHash = await bcrypt.hash(new_password, BCRYPT_COST);
    usersRepository.updatePasswordHash(user.id, newHash);

    // Revocar TODAS las sesiones activas — el atacante no puede seguir logueado
    refreshTokenFamiliesRepository.revokeAllForUser(user.id, 'password_reset');

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'RESET_COMPLETADO',
      ip_hash: ipHash,
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
    });

    res.json({
      mensaje: 'Contraseña restablecida correctamente — todas las sesiones activas han sido cerradas',
    });
  }),
);

export default router;
