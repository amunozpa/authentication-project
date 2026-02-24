/**
 * Servicio MFA / TOTP — Fase 5.6
 *
 * Implementa TOTP (RFC 6238) con otplib:
 *   - Secretos Base32 de 20 bytes (compatible con Google Authenticator, Authy, 1Password)
 *   - Ventana de ±1 periodo (30s) para tolerar desfase de reloj
 *   - Códigos de 6 dígitos, renovados cada 30 segundos
 *
 * Flujo de activación:
 *   1. POST /mfa/setup   → genera secret + URI otpauth + QR code
 *   2. POST /mfa/enable  → cliente envía secret + primer código TOTP válido
 *                         → servidor verifica, activa MFA, emite 8 códigos de recuperación
 *
 * Flujo de login con MFA:
 *   1. POST /auth/login  → credenciales válidas + mfa_enabled → mfa_session_token (5 min)
 *   2. POST /mfa/verify  → mfa_session_token + código TOTP → AT + RT
 *   2b. POST /mfa/recovery → mfa_session_token + código de recuperación → AT + RT
 *
 * Flujo Step-up:
 *   POST /mfa/step-up   → AT válido + TOTP → step_up_token (10 min)
 *   GET /mfa/protected  → AT + X-Step-Up-Token → acceso a recurso sensible
 */
import { authenticator } from 'otplib';
import qrcode from 'qrcode';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { mfaRecoveryCodesRepository } from '../db/repositories/mfaRecoveryCodes';
import type { MfaRecoveryCodeRecord } from '../types';

// ── Configuración de otplib ────────────────────────────────────────────────────

// Ventana de ±1 periodo para tolerar desfase de reloj (30s antes/después)
authenticator.options = { window: 1 };

export const TOTP_ISSUER = 'AuthLab';
const BCRYPT_COST = 10; // Menor que para contraseñas — los recovery codes son largos y aleatorios
const RECOVERY_CODE_COUNT = 8;

// ── Generación de secreto TOTP ────────────────────────────────────────────────

/**
 * Genera un secreto TOTP Base32 de 20 bytes.
 * Compatible con cualquier app TOTP: Google Authenticator, Authy, 1Password, etc.
 */
export function generateTotpSecret(): string {
  return authenticator.generateSecret(20); // 20 bytes → 32 chars Base32
}

/**
 * Genera la URI otpauth:// para el código QR.
 * Formato: otpauth://totp/ISSUER:email?secret=BASE32&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
 */
export function generateOtpAuthUri(email: string, secret: string): string {
  return authenticator.keyuri(email, TOTP_ISSUER, secret);
}

/**
 * Genera un QR code en formato Data URL (PNG base64) a partir del URI otpauth.
 * El browser puede mostrarlo directamente en un <img src="..."> sin necesidad de archivos.
 */
export async function generateQrCodeDataUrl(otpauthUri: string): Promise<string> {
  return qrcode.toDataURL(otpauthUri, {
    errorCorrectionLevel: 'M', // Medium error correction — buen balance tamaño/robustez
    margin: 2,
    width: 256,
  });
}

// ── Verificación TOTP ─────────────────────────────────────────────────────────

/**
 * Verifica un código TOTP de 6 dígitos contra el secreto del usuario.
 * Acepta el periodo actual ± 1 (ventana configurada arriba) para tolerar desfase de reloj.
 * Devuelve true si el código es válido.
 */
export function verifyTotp(totpCode: string, secret: string): boolean {
  try {
    return authenticator.verify({ token: totpCode, secret });
  } catch {
    return false; // código malformado (no 6 dígitos, etc.)
  }
}

// ── Códigos de recuperación ───────────────────────────────────────────────────

/**
 * Genera 8 códigos de recuperación en formato XXXX-XXXX.
 * Los códigos se muestran al usuario UNA SOLA VEZ — después solo están los hashes.
 * Formato: 8 bytes aleatorios → hex → XXXX-XXXX (fácil de anotar)
 */
export function generateRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
    const hex = randomBytes(4).toString('hex').toUpperCase();
    return `${hex.slice(0, 4)}-${hex.slice(4)}`;
  });
}

/**
 * Hashea un código de recuperación con bcrypt.
 * Nota: normalizamos eliminando el guion antes de hashear.
 */
export async function hashRecoveryCode(code: string): Promise<string> {
  const normalized = code.replace(/-/g, '').toUpperCase();
  return bcrypt.hash(normalized, BCRYPT_COST);
}

/**
 * Hashea todos los códigos de recuperación en paralelo.
 */
export async function hashRecoveryCodes(codes: string[]): Promise<string[]> {
  return Promise.all(codes.map(hashRecoveryCode));
}

/**
 * Busca y verifica un código de recuperación contra los hashes almacenados.
 * Compara secuencialmente — en promedio O(n/2) operaciones bcrypt (n=8).
 * Devuelve el registro si es válido, null si no.
 */
export async function verifyRecoveryCode(
  userId: string,
  code: string,
): Promise<MfaRecoveryCodeRecord | null> {
  const normalized = code.replace(/-/g, '').toUpperCase();
  const unusedCodes = mfaRecoveryCodesRepository.findUnusedByUserId(userId);

  for (const record of unusedCodes) {
    const match = await bcrypt.compare(normalized, record.code_hash);
    if (match) return record;
  }

  return null;
}
