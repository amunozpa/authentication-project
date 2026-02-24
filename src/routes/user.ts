/**
 * Rutas de usuario autenticado — Fase 5 / 5.9
 *
 * GET    /api/v1/user/me                        → perfil del usuario actual
 * GET    /api/v1/user/linked-accounts           → providers OAuth vinculados
 * DELETE /api/v1/user/linked-accounts/:provider → desvincular provider
 *
 * Fase 5.9 — Account Linking Dashboard:
 * GET    /api/v1/user/security                  → panel de seguridad unificado
 * POST   /api/v1/user/change-password           → cambiar contraseña (autenticado)
 * GET    /api/v1/user/link/:provider            → iniciar vinculación OAuth (autenticado)
 *
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ FLUJO DE VINCULACIÓN (GET /link/:provider)                       │
 * │                                                                  │
 * │  1. Usuario autenticado → GET /user/link/github                  │
 * │     Servidor: genera PKCE + state                                │
 * │     Guarda en oauth_states con link_user_id = userId actual      │
 * │     Devuelve { url } → URL de autorización del provider          │
 * │  2. Usuario completa OAuth en el provider                        │
 * │  3. Callback detecta link_user_id en el state                    │
 * │     → vincula el provider al usuario existente (no crea uno nuevo│
 * │     → devuelve { vinculado: true, provider }                     │
 * └──────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { config } from '../config/env';
import { usersRepository } from '../db/repositories/users';
import { linkedIdentitiesRepository } from '../db/repositories/linkedIdentities';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { mfaRecoveryCodesRepository } from '../db/repositories/mfaRecoveryCodes';
import { refreshTokenFamiliesRepository } from '../db/repositories/refreshTokenFamilies';
import { oauthStatesRepository } from '../db/repositories/oauthStates';
import { authenticate } from '../middleware/authenticate';
import { requireStepUp } from '../middleware/requireStepUp';
import { deleteAccountGdpr } from '../db/transactions';
import { generatePkce, generateState } from '../services/oauthService';
import { hashIp } from '../utils/hash';
import { asyncHandler } from '../utils/asyncHandler';
import { AppError } from '../middleware/errorHandler';
import type { OAuthProvider } from '../types';

const router = Router();

const BCRYPT_COST = 12;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // 10 minutos

// ── GET /api/v1/user/me ───────────────────────────────────────────────────────

router.get('/me', authenticate, (req, res) => {
  const user = usersRepository.findById(req.user!.userId);
  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  res.json({
    id: user.id,
    email: user.email,
    roles: JSON.parse(user.roles),
    email_verified: user.email_verified === 1,
    mfa_enabled: user.mfa_enabled === 1,
    created_at: user.created_at,
  });
});

// ── GET /api/v1/user/linked-accounts ─────────────────────────────────────────

router.get('/linked-accounts', authenticate, (req, res) => {
  const identities = linkedIdentitiesRepository.findByUserId(req.user!.userId);

  res.json({
    data: identities.map((i) => ({
      provider: i.provider,
      provider_email: i.provider_email,
      linked_at: i.created_at,
    })),
    nota: 'El access_token del provider nunca se expone aquí',
  });
});

// ── DELETE /api/v1/user/linked-accounts/:provider ─────────────────────────────

router.delete('/linked-accounts/:provider', authenticate, (req, res) => {
  const provider = req.params['provider'] as OAuthProvider;

  if (!['github', 'google'].includes(provider)) {
    throw new AppError(400, 'Provider inválido — usa "github" o "google"', 'VALIDACION_FALLIDA');
  }

  const userId = req.user!.userId;
  const user = usersRepository.findById(userId);
  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  // Protección: el usuario debe tener otro método de login antes de desvincular
  const hasPassword = user.password_hash !== null;
  const linkedCount = linkedIdentitiesRepository.countForUser(userId);

  if (!hasPassword && linkedCount <= 1) {
    throw new AppError(
      409,
      'No puedes desvincular el único método de acceso — añade contraseña primero',
      'ULTIMO_METODO_LOGIN',
    );
  }

  const deleted = linkedIdentitiesRepository.delete(userId, provider);

  if (!deleted) {
    throw new AppError(404, `No tienes vinculada una cuenta de ${provider}`, 'NO_ENCONTRADO');
  }

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'CUENTA_DESVINCULADA',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { provider },
  });

  res.json({ mensaje: `Cuenta de ${provider} desvinculada correctamente` });
});

// ── GET /api/v1/user/security ─────────────────────────────────────────────────

/**
 * Panel de seguridad unificado — muestra el estado de la cuenta en una sola llamada.
 *
 * Responde con:
 *   - has_password: si el usuario puede autenticarse con contraseña
 *   - mfa_enabled: si tiene TOTP activo
 *   - recovery_codes_remaining: cuántos códigos de recuperación quedan sin usar
 *   - linked_providers: providers OAuth vinculados (sin exponer tokens)
 *   - active_sessions: número de sesiones JWT activas (RT families)
 *   - email_verified: si el email está verificado
 */
router.get('/security', authenticate, (req, res) => {
  const userId = req.user!.userId;
  const user = usersRepository.findById(userId);
  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  const linkedIdentities = linkedIdentitiesRepository.findByUserId(userId);
  const recoveryCodes = user.mfa_enabled
    ? mfaRecoveryCodesRepository.findUnusedByUserId(userId)
    : [];
  const activeSessions = refreshTokenFamiliesRepository.countActiveByUserId(userId);

  res.json({
    email: user.email,
    email_verified: user.email_verified === 1,
    has_password: user.password_hash !== null,
    mfa_enabled: user.mfa_enabled === 1,
    recovery_codes_remaining: recoveryCodes.length,
    linked_providers: linkedIdentities.map((i) => ({
      provider: i.provider,
      provider_email: i.provider_email,
      linked_at: i.created_at,
    })),
    active_sessions: activeSessions,
    login_methods: {
      password: user.password_hash !== null,
      mfa: user.mfa_enabled === 1,
      passkeys: false, // fase 5.5 — no hay API de conteo aún; booleaneo orientativo
      magic_link: true, // siempre disponible si el email está verificado
      oauth: linkedIdentities.map((i) => i.provider),
    },
  });
});

// ── POST /api/v1/user/change-password ────────────────────────────────────────

const changePasswordSchema = z.object({
  current_password: z.string().optional(),
  new_password: z
    .string()
    .min(8, 'La contraseña debe tener al menos 8 caracteres')
    .max(128, 'Contraseña demasiado larga'),
});

/**
 * Cambia la contraseña del usuario autenticado.
 *
 * Reglas:
 *   - Si el usuario ya tiene contraseña: se requiere `current_password` para confirmar identidad.
 *   - Si el usuario no tiene contraseña (solo OAuth): `current_password` no es necesario.
 *   - Revoca TODAS las sesiones activas (incluyendo la actual) — fuerza re-login.
 *   - El MFA no se toca.
 */
router.post(
  '/change-password',
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { current_password, new_password } = parsed.data;
    const userId = req.user!.userId;
    const ipHash = hashIp(req.ip ?? '');

    const user = usersRepository.findById(userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    const hasPassword = user.password_hash !== null;

    if (hasPassword) {
      // Usuario con contraseña: debe confirmar la actual
      if (!current_password) {
        throw new AppError(400, 'current_password es requerido para cambiar la contraseña', 'VALIDACION_FALLIDA');
      }
      const valid = await bcrypt.compare(current_password, user.password_hash!);
      if (!valid) {
        auditLogsRepository.create({
          user_id: userId,
          event_type: 'PASSWORD_CAMBIADO',
          ip_hash: ipHash,
          correlation_id: req.correlationId,
          metadata: { exito: false, motivo: 'contrasena_actual_incorrecta' },
        });
        throw new AppError(401, 'Contraseña actual incorrecta', 'CREDENCIALES_INVALIDAS');
      }
    }
    // Usuario sin contraseña (OAuth puro): no se requiere current_password

    const newHash = await bcrypt.hash(new_password, BCRYPT_COST);
    usersRepository.updatePasswordHash(userId, newHash);

    // Revocar TODAS las sesiones — fuerza re-login en todos los dispositivos
    refreshTokenFamiliesRepository.revokeAllForUser(userId, 'password_changed');

    auditLogsRepository.create({
      user_id: userId,
      event_type: 'PASSWORD_CAMBIADO',
      ip_hash: ipHash,
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
      metadata: { exito: true, tenia_contrasena: hasPassword },
    });

    res.json({
      mensaje: hasPassword
        ? 'Contraseña actualizada — todas las sesiones activas han sido cerradas'
        : 'Contraseña establecida — ahora puedes acceder con email y contraseña',
    });
  }),
);

// ── DELETE /api/v1/user/me — GDPR account deletion (Fase 6.5) ────────────────

/**
 * Elimina la cuenta del usuario autenticado de forma conforme con GDPR.
 *
 * Si el usuario tiene MFA activo, requiere un Step-Up token válido
 * (X-Step-Up-Token header) antes de proceder.
 *
 * La transacción realiza:
 *   · Soft-delete del usuario (deleted_at = now)
 *   · Hard-delete: sessions, refresh_token_families, email_tokens,
 *     linked_identities, webauthn_credentials, mfa_recovery_codes, api_keys
 *   · Anonimización de audit_logs (user_id, ip_hash, user_agent → NULL)
 *   · Log CUENTA_ELIMINADA (con NULL en user_id — ya anonimizado)
 *
 * Después de la eliminación se limpian las cookies de sesión.
 */
router.delete(
  '/me',
  authenticate,
  (req, res, next) => {
    const userId = req.user!.userId;
    const user = usersRepository.findById(userId);
    if (!user) { next(new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO')); return; }

    // Si tiene MFA activo → verificar step-up token antes de continuar
    if (user.mfa_enabled) {
      requireStepUp(req, res, next);
    } else {
      next();
    }
  },
  (req, res) => {
    const userId = req.user!.userId;
    const ipHash = hashIp(req.ip ?? '');

    deleteAccountGdpr({
      userId,
      auditData: { ipHash, correlationId: req.correlationId },
    });

    // Limpiar cookies de sesión del dispositivo actual
    res.clearCookie('refreshToken', { path: '/api/v1' });

    res.json({
      mensaje: 'Cuenta eliminada correctamente. Todos tus datos han sido borrados o anonimizados',
      gdpr: {
        eliminado: ['sessions', 'refresh_token_families', 'email_tokens', 'linked_identities', 'webauthn_credentials', 'mfa_recovery_codes', 'api_keys'],
        anonimizado: 'audit_logs (user_id, ip_hash, user_agent → NULL)',
        conservado: 'Registros de audit_logs anonimizados para estadísticas',
      },
    });
  },
);

// ── GET /api/v1/user/link/:provider ──────────────────────────────────────────

/**
 * Inicia un flujo OAuth para vincular un provider al usuario autenticado.
 *
 * Devuelve la URL de autorización del provider. El state almacena el userId
 * del usuario autenticado para que el callback pueda vincular en lugar de crear.
 *
 * El frontend debe redirigir al usuario a `url`.
 * Cuando el provider redirige al callback, éste detecta `link_user_id` en el state
 * y vincula el provider al usuario existente.
 */
router.get(
  '/link/:provider',
  authenticate,
  asyncHandler(async (req, res) => {
    const provider = req.params['provider'] as OAuthProvider;

    if (!['github', 'google'].includes(provider)) {
      throw new AppError(400, 'Provider inválido — usa "github" o "google"', 'VALIDACION_FALLIDA');
    }

    const userId = req.user!.userId;

    // Verificar que el provider esté configurado
    if (provider === 'github' && !config.GITHUB_CLIENT_ID) {
      throw new AppError(503, 'OAuth GitHub no configurado — añade GITHUB_CLIENT_ID al .env', 'NO_CONFIGURADO');
    }
    if (provider === 'google' && !config.GOOGLE_CLIENT_ID) {
      throw new AppError(503, 'OAuth Google no configurado — añade GOOGLE_CLIENT_ID al .env', 'NO_CONFIGURADO');
    }

    // Verificar que el usuario no tenga ya vinculado este provider
    const identities = linkedIdentitiesRepository.findByUserId(userId);
    if (identities.some((i) => i.provider === provider)) {
      throw new AppError(409, `Ya tienes vinculada una cuenta de ${provider}`, 'YA_VINCULADO');
    }

    const { codeVerifier, codeChallenge } = generatePkce();
    const state = generateState();

    // Guardar state con link_user_id → el callback sabrá que es un flujo de vinculación
    oauthStatesRepository.create({
      state,
      code_verifier: codeVerifier,
      provider,
      expires_at: Date.now() + OAUTH_STATE_TTL_MS,
      link_user_id: userId,
    });

    auditLogsRepository.create({
      user_id: userId,
      event_type: 'OAUTH_INICIO',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: { provider, modo: 'link', pkce_challenge: codeChallenge },
    });

    // Construir URL de autorización según el provider
    let authUrl: string;
    if (provider === 'github') {
      const params = new URLSearchParams({
        client_id: config.GITHUB_CLIENT_ID,
        redirect_uri: config.GITHUB_CALLBACK_URL,
        scope: 'user:email',
        state,
      });
      authUrl = `https://github.com/login/oauth/authorize?${params}`;
    } else {
      const params = new URLSearchParams({
        client_id: config.GOOGLE_CLIENT_ID,
        redirect_uri: config.GOOGLE_CALLBACK_URL,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        access_type: 'online',
      });
      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
    }

    res.json({
      url: authUrl,
      provider,
      nota_dev: `Redirige al usuario a "url" → tras completar OAuth, el callback vinculará el provider a tu cuenta`,
    });
  }),
);

export default router;
