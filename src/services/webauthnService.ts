/**
 * Servicio WebAuthn / Passkeys — Fase 5.5
 *
 * Implementa FIDO2 / WebAuthn Level 2 con @simplewebauthn/server.
 *
 * Flujos:
 *   Registro   → /register/options (genera challenge) → /register/verify (guarda credencial)
 *   Login      → /login/options   (genera challenge) → /login/verify   (verifica firma → AT+RT)
 *
 * Seguridad:
 *   - Challenge de un solo uso (eliminar tras verificar)
 *   - TTL de 5 minutos para challenges
 *   - Counter monotónico: detecta clonación de authenticator
 *   - RPID = localhost (dev) — debe coincidir con el dominio del navegador
 *   - excludeCredentials: evita registrar el mismo authenticator dos veces
 */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { webauthnChallengesRepository } from '../db/repositories/webauthnChallenges';
import { webauthnCredentialsRepository } from '../db/repositories/webauthnCredentials';
import { AppError } from '../middleware/errorHandler';
import type { WebAuthnCredentialRecord } from '../types';

// ── Configuración del Relying Party ───────────────────────────────────────────

/**
 * El RP ID debe coincidir con el dominio del navegador (sin puerto).
 * Regla WebAuthn: el RPID debe ser un "registrable domain suffix" del origin.
 * localhost es el único caso en que puerto != 443 es aceptado.
 */
export const RP_ID = 'localhost';

/**
 * El origin esperado incluye protocolo + hostname + puerto.
 * Debe coincidir exactamente con window.location.origin del browser.
 *
 * Si el frontend corre en otro puerto (ej. Vite en :5173), usar ese valor.
 * Para producción: usar FRONTEND_URL sin trailing slash.
 */
export const RP_ORIGIN = process.env['NODE_ENV'] === 'production'
  ? (process.env['FRONTEND_URL'] ?? 'https://example.com')
  : 'http://localhost:3000';

export const RP_NAME = 'AuthLab — POC de Autenticación';

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutos — RFC 8809

// ── Registro ──────────────────────────────────────────────────────────────────

/**
 * Genera las opciones de registro que el browser pasará a navigator.credentials.create().
 * Almacena el challenge en BD para verificarlo después.
 *
 * excludeCredentials: evita registrar el mismo authenticator dos veces en la misma cuenta.
 */
export async function generateRegistrationChallenge(
  userId: string,
  userEmail: string,
  existingCredentials: WebAuthnCredentialRecord[],
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: userEmail,
    userID: Buffer.from(userId, 'utf-8'), // userHandle en el authenticator = userId
    attestationType: 'none',              // sin attestation — suficiente para un POC
    authenticatorSelection: {
      residentKey: 'preferred',           // passkey discoverable si el authenticator la soporta
      userVerification: 'preferred',      // biometría / PIN si disponible
    },
    // Excluir credenciales ya registradas — evita duplicados en el mismo authenticator
    excludeCredentials: existingCredentials.map((c) => ({
      id: c.credential_id,               // base64url string
    })),
  });

  // Guardar challenge — one-time use, TTL 5 min
  // create() elimina el challenge previo del mismo tipo antes de insertar
  webauthnChallengesRepository.create({
    user_id: userId,
    challenge: options.challenge,        // ya es base64url string
    type: 'registration',
    expires_at: Date.now() + CHALLENGE_TTL_MS,
  });

  return options;
}

/**
 * Verifica la respuesta de attestation del authenticator.
 * Si es válida, guarda la credencial en BD y elimina el challenge.
 */
export async function verifyRegistrationChallenge(
  userId: string,
  response: RegistrationResponseJSON,
  deviceName?: string | null,
): Promise<WebAuthnCredentialRecord> {
  // Obtener el challenge activo de este usuario
  const storedChallenge = webauthnChallengesRepository.findActiveByUserId(userId, 'registration');
  if (!storedChallenge) {
    throw new AppError(
      400,
      'No hay challenge de registro activo — solicita uno nuevo con POST /register/options',
      'CHALLENGE_NO_ENCONTRADO',
    );
  }

  // Verificar la respuesta del authenticator contra el challenge almacenado
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false, // Preferimos UV pero no lo forzamos
    });
  } catch (err) {
    // La librería lanza errores descriptivos — re-envolver como AppError
    const msg = err instanceof Error ? err.message : 'Error de verificación WebAuthn';
    throw new AppError(400, msg, 'WEBAUTHN_VERIFICACION_FALLIDA');
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new AppError(400, 'La verificación de la passkey falló', 'WEBAUTHN_VERIFICACION_FALLIDA');
  }

  // Eliminar el challenge — one-time use
  webauthnChallengesRepository.delete(storedChallenge.id);

  const { credential } = verification.registrationInfo;

  // Proteger contra registro duplicado (misma passkey en distintas cuentas)
  const existing = webauthnCredentialsRepository.findByCredentialId(credential.id);
  if (existing) {
    throw new AppError(
      409,
      'Esta passkey ya está registrada en una cuenta — usa una passkey diferente',
      'PASSKEY_YA_REGISTRADA',
    );
  }

  // Guardar credencial en BD
  // public_key: Uint8Array → base64url string para almacenar en SQLite TEXT
  return webauthnCredentialsRepository.create({
    user_id: userId,
    credential_id: credential.id,
    public_key: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    device_name: deviceName ?? null,
  });
}

// ── Autenticación ─────────────────────────────────────────────────────────────

/**
 * Genera las opciones de autenticación que el browser pasará a navigator.credentials.get().
 * Si el usuario tiene passkeys registradas, las incluye en allowCredentials.
 */
export async function generateAuthenticationChallenge(
  userId: string,
  credentials: WebAuthnCredentialRecord[],
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    // allowCredentials vacío → el browser muestra todas las passkeys del dispositivo
    // Con lista → solo usa las passkeys de este usuario específico
    allowCredentials: credentials.map((c) => ({
      id: c.credential_id,
    })),
    userVerification: 'preferred',
  });

  webauthnChallengesRepository.create({
    user_id: userId,
    challenge: options.challenge,
    type: 'authentication',
    expires_at: Date.now() + CHALLENGE_TTL_MS,
  });

  return options;
}

type AuthenticationResult = {
  credential: WebAuthnCredentialRecord;
  newCounter: number;
};

/**
 * Verifica la respuesta de assertion del authenticator.
 *
 * Flujo:
 * 1. response.id → buscar credencial en BD → obtener user_id
 * 2. Buscar challenge activo para ese user_id
 * 3. Verificar firma con la clave pública almacenada
 * 4. Devolver credencial y newCounter para actualizar en BD
 */
export async function verifyAuthenticationChallenge(
  response: AuthenticationResponseJSON,
): Promise<AuthenticationResult> {
  // El ID de la credencial es la clave de búsqueda — viene en response.id (base64url)
  const credentialId = response.id;
  const storedCredential = webauthnCredentialsRepository.findByCredentialId(credentialId);

  if (!storedCredential) {
    throw new AppError(
      401,
      'Passkey no encontrada — registra esta passkey con tu cuenta primero',
      'CREDENCIAL_NO_ENCONTRADA',
    );
  }

  // Recuperar el challenge activo para este usuario
  const storedChallenge = webauthnChallengesRepository.findActiveByUserId(
    storedCredential.user_id,
    'authentication',
  );
  if (!storedChallenge) {
    throw new AppError(
      400,
      'No hay challenge de autenticación activo — solicita uno nuevo con POST /login/options',
      'CHALLENGE_NO_ENCONTRADO',
    );
  }

  // Verificar la firma del authenticator
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: storedCredential.credential_id,
        // Reconstruir Uint8Array desde la cadena base64url guardada en BD
        publicKey: Buffer.from(storedCredential.public_key, 'base64url'),
        counter: storedCredential.counter,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Error de verificación WebAuthn';
    throw new AppError(401, msg, 'WEBAUTHN_VERIFICACION_FALLIDA');
  }

  if (!verification.verified) {
    throw new AppError(401, 'La verificación de la passkey falló — firma inválida', 'WEBAUTHN_VERIFICACION_FALLIDA');
  }

  // Eliminar challenge — one-time use
  webauthnChallengesRepository.delete(storedChallenge.id);

  return {
    credential: storedCredential,
    newCounter: verification.authenticationInfo.newCounter,
  };
}
