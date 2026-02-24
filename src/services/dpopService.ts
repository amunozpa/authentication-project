/**
 * Servicio DPoP — Fase 5.11
 *
 * DPoP (Demonstrating Proof of Possession, RFC 9449) vincula un Access Token
 * a un par de claves asimétrico del cliente. Aunque un atacante robe el AT,
 * no puede usarlo sin la clave privada correspondiente.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ FLUJO DPoP                                                              │
 * │                                                                         │
 * │  1. Cliente genera par ECDSA P-256 efímero (o Ed25519)                  │
 * │  2. POST /dpop/token                                                    │
 * │     · Header DPoP: <proof_jwt>                                          │
 * │       proof = { typ:'dpop+jwt', alg:'ES256', jwk:<pubkey> }             │
 * │              . { jti, htm:'POST', htu:'/.../token', iat }               │
 * │     · Body: { email, password }                                         │
 * │     → Servidor verifica proof → extrae JWK → calcula thumbprint (jkt)   │
 * │     → Emite AT con cnf: { jkt } (token vinculado a esa clave)           │
 * │                                                                         │
 * │  3. GET /dpop/protected                                                 │
 * │     · Header Authorization: DPoP <access_token>                         │
 * │     · Header DPoP: <nuevo_proof_jwt>                                    │
 * │       proof = { ..., htm:'GET', htu:'/.../protected',                   │
 * │                 ath: base64url(sha256(access_token)) }                  │
 * │     → Servidor verifica proof + ath + que cnf.jkt == thumbprint(JWK)   │
 * │     → Acceso concedido solo si el cliente tiene la clave privada        │
 * │                                                                         │
 * │ Protecciones:                                                           │
 * │  - Replay: cada proof tiene un jti único → Map<jti,expiresAt>           │
 * │  - Binding: cnf.jkt en AT vincula el token al JWK del proof             │
 * │  - HTM/HTU: el proof es válido solo para ese método y URI exactos       │
 * │  - IAT: ventana de ±30 segundos para tolerar desfase de reloj           │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import jwt from 'jsonwebtoken';
import { createPublicKey, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { isDpopJtiSeen, markDpopJtiSeen } from '../cache/dpopReplay';
import { jwtSigningKeysRepository } from '../db/repositories/jwtSigningKeys';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';

// ── Constantes ────────────────────────────────────────────────────────────────

/** Algoritmos asimétricos permitidos en el proof DPoP (no se permiten HMAC) */
const ALLOWED_ALGORITHMS = ['ES256', 'EdDSA'] as const;

/** Ventana de tolerancia para `iat` en segundos (±30s) */
const IAT_WINDOW_SECONDS = 30;

/** TTL del jti en la caché de replay (60s = ventana completa + margen) */
const JTI_CACHE_TTL_SECONDS = 60;

// ── JWK Thumbprint (RFC 7638) ─────────────────────────────────────────────────

type SupportedJwk =
  | { kty: 'EC'; crv: string; x: string; y: string }
  | { kty: 'OKP'; crv: string; x: string }
  | { kty: 'RSA'; e: string; n: string }
  | { kty: string; [k: string]: unknown };

/**
 * Calcula el JWK Thumbprint (RFC 7638): SHA-256 del JSON canónico de la clave.
 * Las claves del JSON canónico están en orden lexicográfico y solo incluyen
 * los campos requeridos por el tipo de clave (EC, OKP, RSA).
 */
export function computeJwkThumbprint(jwk: SupportedJwk): string {
  let canonical: Record<string, string>;

  if (jwk.kty === 'EC') {
    const { crv, x, y } = jwk as { kty: 'EC'; crv: string; x: string; y: string };
    canonical = { crv, kty: 'EC', x, y };
  } else if (jwk.kty === 'OKP') {
    const { crv, x } = jwk as { kty: 'OKP'; crv: string; x: string };
    canonical = { crv, kty: 'OKP', x };
  } else if (jwk.kty === 'RSA') {
    const { e, n } = jwk as { kty: 'RSA'; e: string; n: string };
    canonical = { e, kty: 'RSA', n };
  } else {
    throw new AppError(400, `Tipo de clave JWK no soportado: ${jwk.kty}`, 'DPOP_INVALIDO');
  }

  return createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');
}

// ── Verificación del proof DPoP ───────────────────────────────────────────────

export interface DpopVerifyParams {
  proofJwt: string;
  htm: string;          // HTTP method esperado (se normaliza a mayúsculas)
  htu: string;          // HTTP URI esperado (scheme + authority + path, sin query)
  accessToken?: string; // Si se proporciona, verifica el claim `ath` (hash del AT)
}

export interface DpopVerifyResult {
  jwk: SupportedJwk;
  jkt: string;          // JWK thumbprint — identifica de forma única al cliente
}

/**
 * Verifica un DPoP proof JWT (RFC 9449 §4.3).
 *
 * Pasos de verificación (en orden):
 *   1. Decode del header para extraer jwk, typ, alg (antes de verificar firma)
 *   2. typ == 'dpop+jwt'
 *   3. alg es asimétrico (ES256 o EdDSA)
 *   4. jwk presente y válido
 *   5. Importar JWK como KeyObject y verificar firma
 *   6. htm == método HTTP del request
 *   7. htu == URI del request
 *   8. iat dentro de ±30 segundos
 *   9. jti no en caché de replay → marcar como visto
 *  10. Si accessToken presente: ath == base64url(sha256(accessToken))
 */
export function verifyDpopProof({ proofJwt, htm, htu, accessToken }: DpopVerifyParams): DpopVerifyResult {
  // ── 1. Decode sin verificar — solo para leer el header ────────────────────
  const decoded = jwt.decode(proofJwt, { complete: true });
  if (!decoded || typeof decoded === 'string') {
    throw new AppError(400, 'DPoP proof malformado — no es un JWT válido', 'DPOP_INVALIDO');
  }

  const header = decoded.header as {
    typ?: string;
    alg?: string;
    jwk?: Record<string, unknown>;
  };

  // ── 2. Validar typ ────────────────────────────────────────────────────────
  if (header.typ !== 'dpop+jwt') {
    throw new AppError(400, `DPoP proof: typ debe ser "dpop+jwt", recibido: "${header.typ}"`, 'DPOP_INVALIDO');
  }

  // ── 3. Validar alg (solo asimétrico — nunca HS256) ───────────────────────
  const alg = header.alg as string | undefined;
  if (!alg || !(ALLOWED_ALGORITHMS as readonly string[]).includes(alg)) {
    throw new AppError(
      400,
      `DPoP proof: alg "${alg}" no permitido — usa ES256 (ECDSA P-256) o EdDSA (Ed25519)`,
      'DPOP_INVALIDO',
    );
  }

  // ── 4. Extraer y validar JWK del header ──────────────────────────────────
  const rawJwk = header.jwk;
  if (!rawJwk || typeof rawJwk !== 'object' || !rawJwk['kty']) {
    throw new AppError(400, 'DPoP proof: header debe incluir jwk con kty', 'DPOP_INVALIDO');
  }
  const jwk = rawJwk as SupportedJwk;

  // ── 5. Importar JWK y verificar firma ─────────────────────────────────────
  let publicKeyPem: string;
  try {
    const keyObject = createPublicKey({ key: jwk as unknown as Parameters<typeof createPublicKey>[0], format: 'jwk' } as Parameters<typeof createPublicKey>[0]);
    publicKeyPem = keyObject.export({ type: 'spki', format: 'pem' }) as string;
  } catch {
    throw new AppError(400, 'DPoP proof: JWK inválido o algoritmo no soportado', 'DPOP_INVALIDO');
  }

  let verifiedPayload: jwt.JwtPayload;
  try {
    const result = jwt.verify(proofJwt, publicKeyPem, {
      algorithms: ALLOWED_ALGORITHMS as unknown as jwt.Algorithm[],
      // No verificar exp — el proof no tiene expiración JWT (usamos iat ±30s)
      ignoreExpiration: true,
    });
    verifiedPayload = result as jwt.JwtPayload;
  } catch {
    throw new AppError(401, 'DPoP proof: firma inválida', 'DPOP_FIRMA_INVALIDA');
  }

  const { jti, htm: claimedHtm, htu: claimedHtu, iat, ath } = verifiedPayload;

  // ── 6. Validar htm ────────────────────────────────────────────────────────
  if (typeof claimedHtm !== 'string' || claimedHtm.toUpperCase() !== htm.toUpperCase()) {
    throw new AppError(
      401,
      `DPoP proof: htm incorrecto — esperado "${htm.toUpperCase()}", recibido "${claimedHtm}"`,
      'DPOP_HTM_INVALIDO',
    );
  }

  // ── 7. Validar htu ────────────────────────────────────────────────────────
  if (typeof claimedHtu !== 'string' || claimedHtu !== htu) {
    throw new AppError(
      401,
      `DPoP proof: htu incorrecto — esperado "${htu}", recibido "${claimedHtu}"`,
      'DPOP_HTU_INVALIDO',
    );
  }

  // ── 8. Validar iat (±30 segundos) ─────────────────────────────────────────
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof iat !== 'number' || Math.abs(nowSeconds - iat) > IAT_WINDOW_SECONDS) {
    throw new AppError(
      401,
      'DPoP proof: iat fuera de la ventana permitida (±30s) — genera un nuevo proof',
      'DPOP_IAT_INVALIDO',
    );
  }

  // ── 9. Replay protection ──────────────────────────────────────────────────
  if (typeof jti !== 'string' || !jti) {
    throw new AppError(400, 'DPoP proof: jti requerido', 'DPOP_INVALIDO');
  }
  if (isDpopJtiSeen(jti)) {
    throw new AppError(
      401,
      'DPoP proof replay detectado — cada request necesita un nuevo proof con jti único',
      'DPOP_REPLAY',
    );
  }
  markDpopJtiSeen(jti, JTI_CACHE_TTL_SECONDS);

  // ── 10. Verificar ath si se proporciona accessToken ───────────────────────
  if (accessToken) {
    if (typeof ath !== 'string' || !ath) {
      throw new AppError(
        401,
        'DPoP proof: ath requerido al acceder a un recurso protegido (hash del AT)',
        'DPOP_ATH_REQUERIDO',
      );
    }
    const expectedAth = createHash('sha256').update(accessToken).digest('base64url');
    if (ath !== expectedAth) {
      throw new AppError(
        401,
        'DPoP proof: ath no coincide con el Access Token presentado',
        'DPOP_ATH_INVALIDO',
      );
    }
  }

  const jkt = computeJwkThumbprint(jwk);
  return { jwk, jkt };
}

// ── Emisión de AT DPoP-bound ──────────────────────────────────────────────────

/**
 * Emite un Access Token vinculado al JWK thumbprint del cliente (DPoP binding).
 * Incluye `cnf: { jkt }` en el payload para que las rutas protegidas verifiquen
 * que el proof pertenece al mismo cliente que obtuvo el token.
 *
 * No emite Refresh Token — el cliente obtiene un AT nuevo con un nuevo proof.
 */
export function issueDpopToken(params: {
  userId: string;
  roles: UserRole[];
  jkt: string;
}): string {
  const activeKey = jwtSigningKeysRepository.findActive();
  if (!activeKey) {
    throw new AppError(500, 'No hay clave de firma JWT activa', 'ERROR_INTERNO');
  }

  const atJti = uuidv4();

  return jwt.sign(
    {
      sub: params.userId,
      jti: atJti,
      kid: activeKey.id,
      roles: params.roles,
      cnf: { jkt: params.jkt }, // sender-constraint binding (RFC 9449 §6)
    },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: '15m',
      header: { alg: 'HS256', typ: 'at+jwt', kid: activeKey.id },
    } as jwt.SignOptions,
  );
}
