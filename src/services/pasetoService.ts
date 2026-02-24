/**
 * Servicio PASETO v4 — Fase 5.10
 *
 * PASETO (Platform-Agnostic Security Tokens) v4 — alternativa moderna a JWT.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ PASETO v4 vs JWT                                                        │
 * │                                                                         │
 * │  JWT:                                                                   │
 * │  · El header incluye `alg` → posible ataque alg:none / alg:confusion   │
 * │  · Flexible pero peligroso si el verificador acepta cualquier alg       │
 * │  · Muchas combinaciones: HS256, RS256, ES256, EdDSA...                  │
 * │                                                                         │
 * │  PASETO v4 public (v4.public):                                          │
 * │  · Algoritmo fijo por versión: Ed25519 — no hay `alg` en el token       │
 * │  · Imposible el ataque alg:none                                         │
 * │  · Imposible la confusión de clave pública/privada                      │
 * │  · Estructura: v4.public.<base64url(payload+sig)>                       │
 * │  · Payload legible (base64) pero firmado — no confidencial por defecto  │
 * │  · v4.local usaría AEAD (XChaCha20-Poly1305) para tokens opacos        │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Flujo de inicialización:
 *   1. Si PASETO_PRIVATE_KEY y PASETO_PUBLIC_KEY están en .env → cargar
 *   2. Si no → generar par Ed25519 en memoria (efímero), loguear para copiar al .env
 */
import { V4 } from 'paseto';
import { createPrivateKey, createPublicKey, type KeyObject } from 'crypto';
import { logger } from '../logger';
import { config } from '../config/env';

// Claves en memoria — inicializadas en initializePasetoKeys()
let _privateKey: KeyObject | null = null;
let _publicKey: KeyObject | null = null;
let _publicKeyB64: string = '';

// ── Inicialización ────────────────────────────────────────────────────────────

/**
 * Inicializa las claves PASETO v4 Ed25519.
 *
 * Si PASETO_PRIVATE_KEY / PASETO_PUBLIC_KEY están en .env → las carga.
 * Si no → genera un par efímero y registra los valores para copiar al .env.
 * Las claves efímeras son válidas hasta el próximo reinicio.
 */
export async function initializePasetoKeys(): Promise<void> {
  if (config.PASETO_PRIVATE_KEY && config.PASETO_PUBLIC_KEY) {
    // Cargar desde variables de entorno
    _privateKey = createPrivateKey({
      key: Buffer.from(config.PASETO_PRIVATE_KEY, 'base64url'),
      format: 'der',
      type: 'pkcs8',
    });
    _publicKey = createPublicKey({
      key: Buffer.from(config.PASETO_PUBLIC_KEY, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    _publicKeyB64 = config.PASETO_PUBLIC_KEY;
    logger.info('Claves PASETO v4 (Ed25519) cargadas desde .env');
  } else {
    // Generar par efímero y loguear para que el usuario las copie
    const privateKey = await V4.generateKey('public') as unknown as KeyObject;
    const publicKey = createPublicKey(privateKey);

    const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
    const pubB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

    _privateKey = privateKey;
    _publicKey = publicKey;
    _publicKeyB64 = pubB64;

    logger.warn('PASETO_PRIVATE_KEY / PASETO_PUBLIC_KEY no configuradas — usando claves EFÍMERAS (se regeneran en cada reinicio)');
    logger.warn('Para claves persistentes, añade estas líneas al .env y reinicia:');
    logger.info(`PASETO_PRIVATE_KEY=${privB64}`);
    logger.info(`PASETO_PUBLIC_KEY=${pubB64}`);
  }
}

function getPrivateKey(): KeyObject {
  if (!_privateKey) throw new Error('Claves PASETO no inicializadas — llama initializePasetoKeys() al arrancar');
  return _privateKey;
}

function getPublicKey(): KeyObject {
  if (!_publicKey) throw new Error('Claves PASETO no inicializadas — llama initializePasetoKeys() al arrancar');
  return _publicKey;
}

// ── Firma y verificación ──────────────────────────────────────────────────────

export const PASETO_DEFAULT_TTL_SECONDS = 15 * 60; // 15 minutos

/**
 * Firma un payload con PASETO v4.public (Ed25519).
 *
 * Añade automáticamente:
 *   - `iss`: "AuthLab" (issuer)
 *   - `iat`: timestamp de emisión (ISO 8601)
 *   - `exp`: timestamp de expiración (ISO 8601)
 *
 * El token resultante tiene la forma: `v4.public.<base64url(payload+sig)>`
 *
 * @param payload  Datos a incluir en el token (el caller controla el contenido)
 * @param ttlSeconds  Tiempo de vida en segundos (defecto: 15 min)
 */
export async function signPaseto(
  payload: Record<string, unknown>,
  ttlSeconds: number = PASETO_DEFAULT_TTL_SECONDS,
): Promise<string> {
  const privateKey = getPrivateKey();
  return V4.sign(
    { iss: 'AuthLab', ...payload },
    privateKey,
    { expiresIn: `${ttlSeconds}s` },
  );
}

/**
 * Verifica un token PASETO v4.public y devuelve el payload.
 * Lanza un error si el token es inválido, expirado o mal formado.
 */
export async function verifyPaseto(token: string): Promise<Record<string, unknown>> {
  const publicKey = getPublicKey();
  return V4.verify(token, publicKey) as Promise<Record<string, unknown>>;
}

/**
 * Devuelve la clave pública Ed25519 codificada en base64url (PKCS#8 DER).
 * Útil para que clientes externos puedan verificar tokens sin llamar al servidor.
 */
export function getPasetoPublicKeyB64(): string {
  return _publicKeyB64;
}
