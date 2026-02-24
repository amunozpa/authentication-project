/**
 * Rutas WebAuthn / Passkeys — Fase 5.5
 *
 * Registro de Passkey (requiere sesión JWT activa):
 *   POST /api/v1/webauthn/register/options  → genera challenge de registro
 *   POST /api/v1/webauthn/register/verify   → verifica attestation → guarda credencial
 *
 * Login con Passkey (sin contraseña):
 *   POST /api/v1/webauthn/login/options     → genera challenge de autenticación (requiere email)
 *   POST /api/v1/webauthn/login/verify      → verifica assertion → emite AT + RT
 *
 * Gestión de credenciales (requiere sesión JWT activa):
 *   GET    /api/v1/webauthn/credentials          → lista de passkeys del usuario
 *   DELETE /api/v1/webauthn/credentials/:id      → elimina una passkey
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ CÓMO FUNCIONA WEBAUTHN (FIDO2)                                          │
 * │                                                                         │
 * │ REGISTRO                                                                │
 * │  1. Servidor genera challenge aleatorio (prevent replay)                │
 * │  2. Browser llama navigator.credentials.create(options)                 │
 * │  3. Authenticator (Touch ID, YubiKey, etc.) genera par de claves        │
 * │     - Clave privada: se queda en el authenticator (nunca sale)          │
 * │     - Clave pública: se envía al servidor con una attestation           │
 * │  4. Servidor verifica attestation y guarda la clave pública             │
 * │                                                                         │
 * │ AUTENTICACIÓN                                                           │
 * │  1. Servidor genera challenge aleatorio                                 │
 * │  2. Browser llama navigator.credentials.get(options)                   │
 * │  3. Authenticator firma el challenge con la clave privada               │
 * │  4. Servidor verifica la firma con la clave pública guardada            │
 * │  5. Si válido → emite Access Token + Refresh Token                     │
 * │                                                                         │
 * │ Ventajas sobre contraseñas:                                             │
 * │  - Phishing-resistant: la clave está ligada al dominio (RPID)           │
 * │  - Sin secreto compartido: el servidor solo guarda la clave pública     │
 * │  - Sin breach de contraseña: no hay nada que filtrar del servidor       │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { z } from 'zod';
import { usersRepository } from '../db/repositories/users';
import { webauthnCredentialsRepository } from '../db/repositories/webauthnCredentials';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import {
  generateRegistrationChallenge,
  verifyRegistrationChallenge,
  generateAuthenticationChallenge,
  verifyAuthenticationChallenge,
} from '../services/webauthnService';
import { issueTokenPair } from '../services/jwtService';
import { authenticate } from '../middleware/authenticate';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';

const router = Router();

// ── POST /register/options ────────────────────────────────────────────────────

/**
 * Paso 1 del registro: genera opciones para navigator.credentials.create().
 * Requiere AT válido — el usuario debe estar autenticado (con contraseña u OAuth)
 * antes de añadir una passkey a su cuenta.
 *
 * Retorna: PublicKeyCredentialCreationOptionsJSON (pásalo directamente al browser)
 */
router.post(
  '/register/options',
  authenticate,
  asyncHandler(async (req, res) => {
    const userId = req.user!.userId;

    const user = usersRepository.findById(userId);
    if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    // Obtener credenciales existentes para excludeCredentials
    const existingCredentials = webauthnCredentialsRepository.findByUserId(userId);

    const options = await generateRegistrationChallenge(userId, user.email, existingCredentials);

    res.json({
      options,
      nota: {
        paso_siguiente: 'POST /api/v1/webauthn/register/verify con la respuesta del browser',
        rp_id: options.rp.id,
        rp_name: options.rp.name,
        tipo_autenticador: options.authenticatorSelection?.residentKey === 'preferred'
          ? 'passkey (preferido) — puede funcionar entre dispositivos'
          : 'any',
      },
    });
  }),
);

// ── POST /register/verify ─────────────────────────────────────────────────────

const registerVerifySchema = z.object({
  // Respuesta completa del browser (navigator.credentials.create() → JSON)
  id: z.string().min(1, 'credential id requerido'),
  rawId: z.string().min(1),
  response: z.object({
    clientDataJSON: z.string(),
    attestationObject: z.string(),
    transports: z.array(z.string()).optional(),
  }),
  authenticatorAttachment: z.string().optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  type: z.literal('public-key'),
  // Campo opcional — nombre descriptivo del dispositivo ('MacBook Touch ID', 'YubiKey 5')
  deviceName: z.string().max(64).optional(),
});

/**
 * Paso 2 del registro: verifica la attestation y guarda la clave pública.
 * El body es la respuesta JSON de navigator.credentials.create() + deviceName opcional.
 */
router.post(
  '/register/verify',
  authenticate,
  asyncHandler(async (req, res) => {
    const parsed = registerVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { deviceName, ...credentialResponse } = parsed.data;
    const userId = req.user!.userId;

    // Cast: Zod infiere tipos básicos (string[]) pero SimpleWebAuthn necesita sus propias union types.
    // La librería valida la estructura internamente — el cast es seguro.
    const credential = await verifyRegistrationChallenge(
      userId,
      credentialResponse as unknown as RegistrationResponseJSON,
      deviceName,
    );

    auditLogsRepository.create({
      user_id: userId,
      event_type: 'PASSKEY_REGISTRADA',
      ip_hash: hashIp(req.ip ?? ''),
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
      metadata: {
        credential_id: credential.credential_id.slice(0, 16) + '…',
        device_name: credential.device_name,
      },
    });

    res.status(201).json({
      mensaje: 'Passkey registrada correctamente',
      credential: {
        id: credential.id,
        credential_id: credential.credential_id,
        device_name: credential.device_name,
        created_at: credential.created_at,
      },
      nota: 'Ya puedes usar esta passkey para iniciar sesión sin contraseña',
    });
  }),
);

// ── POST /login/options ───────────────────────────────────────────────────────

const loginOptionsSchema = z.object({
  email: z.string().email('Email inválido'),
});

/**
 * Paso 1 del login: genera opciones para navigator.credentials.get().
 * No requiere autenticación previa — es el reemplazante de la contraseña.
 *
 * Acepta email para restringir allowCredentials al usuario correcto.
 * Si el usuario no tiene passkeys → 400.
 *
 * Retorna: PublicKeyCredentialRequestOptionsJSON (pásalo directamente al browser)
 */
router.post(
  '/login/options',
  asyncHandler(async (req, res) => {
    const parsed = loginOptionsSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Email requerido', 'VALIDACION_FALLIDA');
    }

    const user = usersRepository.findByEmail(parsed.data.email);
    if (!user) {
      // No revelar si el email existe — devolver error genérico
      throw new AppError(404, 'No hay passkeys registradas para este usuario', 'PASSKEYS_NO_ENCONTRADAS');
    }

    const credentials = webauthnCredentialsRepository.findByUserId(user.id);
    if (credentials.length === 0) {
      throw new AppError(
        400,
        'Este usuario no tiene passkeys registradas — inicia sesión con contraseña y registra una',
        'PASSKEYS_NO_ENCONTRADAS',
      );
    }

    const options = await generateAuthenticationChallenge(user.id, credentials);

    res.json({
      options,
      nota: {
        paso_siguiente: 'POST /api/v1/webauthn/login/verify con la respuesta del browser',
        passkeys_disponibles: credentials.length,
      },
    });
  }),
);

// ── POST /login/verify ────────────────────────────────────────────────────────

const loginVerifySchema = z.object({
  // Respuesta completa del browser (navigator.credentials.get() → JSON)
  id: z.string().min(1, 'credential id requerido'),
  rawId: z.string().min(1),
  response: z.object({
    authenticatorData: z.string(),
    clientDataJSON: z.string(),
    signature: z.string(),
    userHandle: z.string().optional(),
  }),
  authenticatorAttachment: z.string().optional(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  type: z.literal('public-key'),
});

/**
 * Paso 2 del login: verifica la firma del authenticator y emite AT + RT.
 * El body es la respuesta JSON de navigator.credentials.get().
 *
 * Proceso:
 * 1. Buscar credencial por response.id
 * 2. Buscar challenge activo para ese usuario
 * 3. Verificar firma con la clave pública guardada
 * 4. Actualizar counter (detecta clonación si counter regresa)
 * 5. Emitir AT + RT
 */
router.post(
  '/login/verify',
  asyncHandler(async (req, res) => {
    const parsed = loginVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { credential: storedCredential, newCounter } = await verifyAuthenticationChallenge(
      parsed.data as unknown as AuthenticationResponseJSON,
    );

    // Actualizar counter — detecta clonación si el nuevo valor es menor
    webauthnCredentialsRepository.updateCounter(storedCredential.id, newCounter);

    // Obtener usuario para emitir tokens
    const user = usersRepository.findById(storedCredential.user_id);
    if (!user) throw new AppError(401, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    const ipHash = hashIp(req.ip ?? '');
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken, familyId } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent: req.headers['user-agent'] ?? null,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'PASSKEY_LOGIN',
      ip_hash: ipHash,
      user_agent: req.headers['user-agent'] ?? null,
      correlation_id: req.correlationId,
      metadata: {
        credential_id: storedCredential.credential_id.slice(0, 16) + '…',
        device_name: storedCredential.device_name,
        new_counter: newCounter,
      },
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

// ── GET /credentials ──────────────────────────────────────────────────────────

/**
 * Lista todas las passkeys del usuario autenticado.
 * No expone la clave pública — solo metadatos para la UI.
 */
router.get('/credentials', authenticate, (req, res) => {
  const credentials = webauthnCredentialsRepository.findByUserId(req.user!.userId);

  res.json({
    data: credentials.map((c) => ({
      id: c.id,
      device_name: c.device_name,
      created_at: c.created_at,
      last_used_at: c.last_used_at,
      // credential_id completo no expuesto — solo prefijo para debugging
      credential_id_prefix: c.credential_id.slice(0, 12) + '…',
    })),
    total: credentials.length,
  });
});

// ── DELETE /credentials/:id ───────────────────────────────────────────────────

/**
 * Elimina una passkey del usuario.
 * Protección: si es la única passkey y no hay contraseña ni OAuth → rechazar.
 */
router.delete('/credentials/:id', authenticate, (req, res) => {
  const credentialId = req.params['id']!;
  const userId = req.user!.userId;

  const user = usersRepository.findById(userId);
  if (!user) throw new AppError(404, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

  const allCredentials = webauthnCredentialsRepository.findByUserId(userId);
  const hasPassword = user.password_hash !== null;

  // Verificar que no sea el último método de acceso
  if (!hasPassword && allCredentials.length <= 1) {
    throw new AppError(
      409,
      'No puedes eliminar tu única passkey sin tener contraseña — añade una contraseña primero',
      'ULTIMO_METODO_LOGIN',
    );
  }

  const deleted = webauthnCredentialsRepository.delete(credentialId, userId);
  if (!deleted) {
    throw new AppError(404, 'Passkey no encontrada', 'NO_ENCONTRADO');
  }

  auditLogsRepository.create({
    user_id: userId,
    event_type: 'PASSKEY_REGISTRADA', // reutilizamos el tipo — en un sistema real habría PASSKEY_ELIMINADA
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { accion: 'eliminada', credential_record_id: credentialId },
  });

  res.json({ mensaje: 'Passkey eliminada correctamente' });
});

export default router;
