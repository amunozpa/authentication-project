/**
 * Rutas MFA / TOTP — Fase 5.6
 *
 * Gestión de MFA (requieren AT válido):
 *   POST   /api/v1/mfa/setup      → genera secret + QR code (no activa aún)
 *   POST   /api/v1/mfa/enable     → verifica primer TOTP → activa MFA + devuelve recovery codes
 *   DELETE /api/v1/mfa/disable    → desactiva MFA (requiere TOTP actual)
 *
 * Login con MFA (usan mfa_session_token en lugar de AT):
 *   POST   /api/v1/mfa/verify     → TOTP + mfa_session_token → AT + RT
 *   POST   /api/v1/mfa/recovery   → recovery_code + mfa_session_token → AT + RT
 *
 * Step-up Authentication (AT + TOTP → privilegio elevado temporal):
 *   POST   /api/v1/mfa/step-up    → TOTP → step_up_token (10 min)
 *   GET    /api/v1/mfa/protected  → demo: requiere AT + X-Step-Up-Token
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ TOTP (RFC 6238) — Resumen                                               │
 * │                                                                          │
 * │  HOTP(K, C) = HMAC-SHA1(K, C) truncado a N dígitos                     │
 * │  TOTP(K, T) = HOTP(K, floor(unixTime / periodo))                        │
 * │                                                                          │
 * │  K = secreto compartido (Base32 de 20 bytes)                            │
 * │  T = contador de tiempo: floor(unix_timestamp / 30)                     │
 * │  N = 6 dígitos (estándar RFC 4226)                                      │
 * │  periodo = 30 segundos                                                   │
 * │                                                                          │
 * │  Ventana ±1: el servidor acepta el código del periodo anterior/siguiente │
 * │  para tolerar diferencias de reloj entre cliente y servidor              │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import { usersRepository } from '../db/repositories/users';
import { mfaRecoveryCodesRepository } from '../db/repositories/mfaRecoveryCodes';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { enableMfa, disableMfaTx } from '../db/transactions';
import {
  generateTotpSecret,
  generateOtpAuthUri,
  generateQrCodeDataUrl,
  verifyTotp,
  generateRecoveryCodes,
  hashRecoveryCodes,
  verifyRecoveryCode,
} from '../services/mfaService';
import { issueTokenPair, issueTemporaryToken, verifyTemporaryToken } from '../services/jwtService';
import { authenticate } from '../middleware/authenticate';
import { requireStepUp } from '../middleware/requireStepUp';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { mfaLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';

const router = Router();

// ── POST /setup ───────────────────────────────────────────────────────────────

/**
 * Genera un secreto TOTP y el QR code para que el usuario lo escanee.
 * No activa MFA aún — el usuario debe confirmar con /enable.
 *
 * El secreto se devuelve en claro aquí (única vez) para que el usuario lo guarde
 * como backup. NO se almacena en BD hasta confirmar con /enable.
 */
router.post(
  '/setup',
  authenticate,
  asyncHandler(async (req, res) => {
    const user = usersRepository.findById(req.user!.userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    if (user.mfa_enabled) {
      throw new AppError(
        409,
        'MFA ya está activado — desactívalo primero con DELETE /mfa/disable',
        'MFA_YA_ACTIVO',
      );
    }

    const secret = generateTotpSecret();
    const otpauthUri = generateOtpAuthUri(user.email, secret);
    const qrCodeDataUrl = await generateQrCodeDataUrl(otpauthUri);

    res.json({
      secret,
      otpauth_uri: otpauthUri,
      qr_code: qrCodeDataUrl, // data:image/png;base64,... — pegar en <img src="">
      instrucciones: [
        '1. Escanea el QR code con Google Authenticator, Authy, 1Password, etc.',
        `2. O introduce el secreto manualmente: ${secret}`,
        '3. Llama a POST /api/v1/mfa/enable con el código que genera la app y este secret',
        '⚠️  Guarda el secret — no se volverá a mostrar',
      ],
    });
  }),
);

// ── POST /enable ──────────────────────────────────────────────────────────────

const enableSchema = z.object({
  secret: z.string().min(16, 'Secret TOTP inválido — usa el que devolvió /setup'),
  totp_code: z.string().length(6, 'El código TOTP debe tener exactamente 6 dígitos').regex(/^\d+$/, 'El código TOTP solo debe contener dígitos'),
});

/**
 * Activa MFA verificando el primer código TOTP.
 * Genera 8 códigos de recuperación — mostrarlos al usuario UNA sola vez.
 */
router.post(
  '/enable',
  mfaLimiter,
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = enableSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const user = usersRepository.findById(req.user!.userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    if (user.mfa_enabled) {
      throw new AppError(409, 'MFA ya está activado', 'MFA_YA_ACTIVO');
    }

    const { secret, totp_code } = parsed.data;

    // Verificar el código TOTP para confirmar que el usuario configuró el authenticator
    if (!verifyTotp(totp_code, secret)) {
      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MFA_FALLIDO',
        ip_hash: hashIp(req.ip ?? ''),
        correlation_id: req.correlationId,
        metadata: { motivo: 'codigo_invalido_al_activar' },
      });
      throw new AppError(
        401,
        'Código TOTP incorrecto — asegúrate de que la app está sincronizada y el secreto es correcto',
        'TOTP_INVALIDO',
      );
    }

    // Generar 8 códigos de recuperación en claro (solo se devuelven aquí)
    const recoveryCodes = generateRecoveryCodes();
    const recoveryHashes = await hashRecoveryCodes(recoveryCodes);

    // Transacción: activa MFA + guarda secret + guarda hashes de recovery codes + log
    const ipHash = hashIp(req.ip ?? '');
    enableMfa({
      userId: user.id,
      secret,
      recoveryCodeHashes: recoveryHashes,
      auditData: { ipHash, correlationId: req.correlationId },
    });

    res.json({
      mensaje: 'MFA activado correctamente',
      recovery_codes: recoveryCodes, // mostrar UNA SOLA VEZ
      aviso: [
        '⚠️  GUARDA estos códigos en un lugar seguro — no se volverán a mostrar',
        'Si pierdes tu authenticator, estos códigos son tu único acceso a la cuenta',
        'Cada código solo puede usarse una vez',
      ],
    });
  }),
);

// ── DELETE /disable ───────────────────────────────────────────────────────────

const disableSchema = z.object({
  totp_code: z.string().length(6).regex(/^\d+$/),
});

/**
 * Desactiva MFA. Requiere el código TOTP actual para confirmar que el usuario
 * tiene acceso al authenticator (evita que alguien con AT robado desactive MFA).
 */
router.delete(
  '/disable',
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = disableSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, 'Código TOTP inválido', 'VALIDACION_FALLIDA');
    }

    const user = usersRepository.findById(req.user!.userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    if (!user.mfa_enabled || !user.mfa_secret) {
      throw new AppError(409, 'MFA no está activado', 'MFA_NO_ACTIVO');
    }

    if (!verifyTotp(parsed.data.totp_code, user.mfa_secret)) {
      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MFA_FALLIDO',
        ip_hash: hashIp(req.ip ?? ''),
        correlation_id: req.correlationId,
        metadata: { motivo: 'codigo_invalido_al_desactivar' },
      });
      throw new AppError(401, 'Código TOTP incorrecto', 'TOTP_INVALIDO');
    }

    disableMfaTx({
      userId: user.id,
      auditData: { ipHash: hashIp(req.ip ?? ''), correlationId: req.correlationId },
    });

    res.json({ mensaje: 'MFA desactivado correctamente' });
  }),
);

// ── POST /verify (login step 2) ───────────────────────────────────────────────

const verifySchema = z.object({
  mfa_session_token: z.string().min(1, 'mfa_session_token requerido'),
  totp_code: z.string().length(6, 'El código TOTP debe tener 6 dígitos').regex(/^\d+$/),
});

/**
 * Paso 2 del login cuando MFA está activado.
 * Recibe el mfa_session_token (emitido por POST /auth/login) + el código TOTP.
 * Si es válido → emite AT + RT.
 */
router.post(
  '/verify',
  mfaLimiter,
  asyncHandler(async (req, res) => {
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { mfa_session_token, totp_code } = parsed.data;

    // Verificar el mfa_session_token — contiene el userId
    let sessionPayload: { sub: string; type: string };
    try {
      sessionPayload = verifyTemporaryToken(mfa_session_token, 'mfa_session');
    } catch {
      throw new AppError(401, 'mfa_session_token inválido o expirado — inicia sesión de nuevo', 'TOKEN_INVALIDO');
    }

    const user = usersRepository.findById(sessionPayload.sub);
    if (!user || !user.mfa_enabled || !user.mfa_secret) {
      throw new AppError(401, 'MFA no configurado para este usuario', 'MFA_NO_ACTIVO');
    }

    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    // Verificar TOTP
    if (!verifyTotp(totp_code, user.mfa_secret)) {
      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MFA_FALLIDO',
        ip_hash: ipHash,
        user_agent: userAgent,
        correlation_id: req.correlationId,
        metadata: { metodo: 'totp' },
      });
      throw new AppError(401, 'Código TOTP incorrecto o expirado', 'TOTP_INVALIDO');
    }

    // MFA verificado → emitir AT + RT
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken, familyId } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'MFA_VERIFICADO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: 'totp', family_id: familyId },
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
    });
  }),
);

// ── POST /recovery (login con código de recuperación) ─────────────────────────

const recoverySchema = z.object({
  mfa_session_token: z.string().min(1),
  recovery_code: z
    .string()
    .regex(/^[A-F0-9]{4}-[A-F0-9]{4}$/i, 'Formato de código inválido — usa XXXX-XXXX'),
});

/**
 * Alternativa a /verify cuando el usuario no tiene acceso al authenticator.
 * Usa uno de los 8 códigos de recuperación (cada uno es de un solo uso).
 */
router.post(
  '/recovery',
  asyncHandler(async (req, res) => {
    const parsed = recoverySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { mfa_session_token, recovery_code } = parsed.data;

    let sessionPayload: { sub: string; type: string };
    try {
      sessionPayload = verifyTemporaryToken(mfa_session_token, 'mfa_session');
    } catch {
      throw new AppError(401, 'mfa_session_token inválido o expirado', 'TOKEN_INVALIDO');
    }

    const user = usersRepository.findById(sessionPayload.sub);
    if (!user || !user.mfa_enabled) {
      throw new AppError(401, 'MFA no configurado para este usuario', 'MFA_NO_ACTIVO');
    }

    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    // Buscar y verificar el código de recuperación
    const codeRecord = await verifyRecoveryCode(user.id, recovery_code);
    if (!codeRecord) {
      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MFA_FALLIDO',
        ip_hash: ipHash,
        user_agent: userAgent,
        correlation_id: req.correlationId,
        metadata: { metodo: 'recovery_code', resultado: 'invalido' },
      });
      throw new AppError(401, 'Código de recuperación incorrecto o ya usado', 'CODIGO_INVALIDO');
    }

    // Marcar el código como usado (one-time)
    mfaRecoveryCodesRepository.markUsed(codeRecord.id);

    const remainingCodes = mfaRecoveryCodesRepository.findUnusedByUserId(user.id).length;

    // Emitir AT + RT
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken, familyId } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'MFA_RECUPERACION_USADA',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { family_id: familyId, remaining_codes: remainingCodes },
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
      aviso: remainingCodes <= 2
        ? `⚠️  Solo te quedan ${remainingCodes} códigos de recuperación — genera nuevos activando /mfa/enable de nuevo`
        : undefined,
    });
  }),
);

// ── POST /step-up ─────────────────────────────────────────────────────────────

const stepUpSchema = z.object({
  totp_code: z.string().length(6).regex(/^\d+$/),
});

/**
 * Eleva el nivel de privilegio del AT actual con una verificación TOTP adicional.
 * Devuelve un step_up_token (10 min) que se pasa en X-Step-Up-Token para rutas sensibles.
 *
 * Casos de uso:
 *   - Cambio de contraseña
 *   - Ver datos de pago
 *   - Exportar datos personales
 *   - Aprobar transferencias bancarias
 */
router.post(
  '/step-up',
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = stepUpSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, 'Código TOTP inválido', 'VALIDACION_FALLIDA');
    }

    const user = usersRepository.findById(req.user!.userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    if (!user.mfa_enabled || !user.mfa_secret) {
      throw new AppError(
        400,
        'Necesitas MFA activado para usar Step-up Auth — llama a POST /mfa/enable primero',
        'MFA_NO_ACTIVO',
      );
    }

    const ipHash = hashIp(req.ip ?? '');

    if (!verifyTotp(parsed.data.totp_code, user.mfa_secret)) {
      auditLogsRepository.create({
        user_id: user.id,
        event_type: 'MFA_FALLIDO',
        ip_hash: ipHash,
        correlation_id: req.correlationId,
        metadata: { metodo: 'step_up' },
      });
      throw new AppError(401, 'Código TOTP incorrecto', 'TOTP_INVALIDO');
    }

    // Emitir step_up_token — JWT de corta duración con type='step_up'
    const stepUpToken = issueTemporaryToken(user.id, 'step_up', '10m');

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'MFA_VERIFICADO',
      ip_hash: ipHash,
      correlation_id: req.correlationId,
      metadata: { metodo: 'step_up', expira_en: '10m' },
    });

    res.json({
      step_up_token: stepUpToken,
      expires_in: 10 * 60,
      uso: 'Incluir en X-Step-Up-Token header al llamar a rutas protegidas',
    });
  }),
);

// ── GET /protected (demo de step-up) ─────────────────────────────────────────

/**
 * Ejemplo de ruta que requiere Step-up Authentication.
 * Requiere: AT válido (authenticate) + step_up_token válido (requireStepUp).
 */
router.get(
  '/protected',
  authenticate,
  requireStepUp,
  (req, res) => {
    res.json({
      mensaje: 'Acceso a recurso sensible concedido con Step-Up Authentication',
      userId: req.user!.userId,
      roles: req.user!.roles,
      nota: 'Este endpoint requiere AT + X-Step-Up-Token válido (10 min)',
      ejemplo_casos_uso: [
        'Exportar datos GDPR',
        'Cambio de contraseña',
        'Ver datos de pago completos',
        'Aprobar transacciones de alto valor',
      ],
    });
  },
);

// ── GET /status ───────────────────────────────────────────────────────────────

/**
 * Muestra el estado actual de MFA del usuario: activado/desactivado, recovery codes restantes.
 */
router.get('/status', authenticate, (req, res) => {
  const user = usersRepository.findById(req.user!.userId);
  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  const unusedCodes = user.mfa_enabled
    ? mfaRecoveryCodesRepository.findUnusedByUserId(user.id).length
    : 0;

  res.json({
    mfa_enabled: user.mfa_enabled === 1,
    recovery_codes_remaining: unusedCodes,
    ...(user.mfa_enabled
      ? { aviso: unusedCodes <= 2 ? `Solo quedan ${unusedCodes} códigos de recuperación` : undefined }
      : { siguiente_paso: 'POST /api/v1/mfa/setup para generar un secreto TOTP' }),
  });
});

export default router;
