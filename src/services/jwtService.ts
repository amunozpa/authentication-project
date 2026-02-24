/**
 * Servicio JWT — Fase 3/4
 * Firma y verifica Access Tokens y Refresh Tokens.
 * Implementa: whitelist de algoritmos, kid en header, Family Tracking,
 *             refresh con detección de robo, rotación de claves.
 */
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config/env';
import { logger } from '../logger';
import { jwtSigningKeysRepository } from '../db/repositories/jwtSigningKeys';
import { refreshTokenFamiliesRepository } from '../db/repositories/refreshTokenFamilies';
import { rotateRefreshToken } from '../db/transactions';
import { AppError } from '../middleware/errorHandler';
import type { JWTAccessPayload, JWTRefreshPayload, UserRole } from '../types';

// ── Inicialización ────────────────────────────────────────────────────────────

/**
 * Garantiza que existe al menos una clave de firma activa en BD.
 * Si no existe, crea la primera usando JWT_SECRET del .env.
 * Llamar al arrancar el servidor (antes de manejar requests).
 */
export function initializeJwtKeys(): void {
  const active = jwtSigningKeysRepository.findActive();
  if (!active) {
    const key = jwtSigningKeysRepository.create(config.JWT_SECRET);
    logger.info({ kid: key.id }, 'Clave de firma JWT inicializada');
  } else {
    logger.info({ kid: active.id }, 'Clave de firma JWT activa encontrada');
  }
}

// ── Emisión de tokens ─────────────────────────────────────────────────────────

type IssueTokensInput = {
  userId: string;
  roles: UserRole[];
  ipHash: string;
  userAgent: string | null;
};

type IssuedTokens = {
  accessToken: string;
  refreshToken: string;
  familyId: string;
  rtJti: string;
  atJti: string;
};

/**
 * Emite un par AT + RT y crea la familia de tokens en BD.
 * El AT va en el body, el RT se setea como cookie HttpOnly (hace el caller).
 */
export function issueTokenPair(input: IssueTokensInput): IssuedTokens {
  const activeKey = jwtSigningKeysRepository.findActive();
  if (!activeKey) {
    throw new AppError(500, 'No hay clave de firma JWT activa', 'ERROR_INTERNO');
  }

  const familyId = uuidv4();
  const atJti = uuidv4();
  const rtJti = uuidv4();

  // Access Token — 15 minutos, sin PII
  const accessToken = jwt.sign(
    { sub: input.userId, jti: atJti, kid: activeKey.id, roles: input.roles },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: config.JWT_EXPIRY_ACCESS,
      header: { alg: 'HS256', typ: 'JWT', kid: activeKey.id },
    } as jwt.SignOptions,
  );

  // Refresh Token — 7 días, con familyId para Family Tracking
  // kid en header (igual que AT) para que verifyRefreshToken pueda buscar la clave por kid
  const refreshToken = jwt.sign(
    { sub: input.userId, jti: rtJti, kid: activeKey.id, familyId },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: config.JWT_EXPIRY_REFRESH,
      header: { alg: 'HS256', typ: 'JWT', kid: activeKey.id },
    } as jwt.SignOptions,
  );

  // Calcular expiración del RT en ms para guardar en BD
  const decoded = jwt.decode(refreshToken) as { exp: number };
  const rtExpiresAt = decoded.exp * 1000;

  // Registrar la familia en BD usando familyId como id — debe coincidir con el payload del RT
  refreshTokenFamiliesRepository.create({
    id: familyId,         // ← mismo UUID que en el RT payload para que findById funcione
    user_id: input.userId,
    current_jti: rtJti,
    kid: activeKey.id,
    ip_hash: input.ipHash,
    user_agent: input.userAgent,
    expires_at: rtExpiresAt,
  });

  // Actualizar el access_jti en la familia recién creada
  refreshTokenFamiliesRepository.rotate(familyId, rtJti, atJti);

  return { accessToken, refreshToken, familyId, rtJti, atJti };
}

// ── Verificación ──────────────────────────────────────────────────────────────

/**
 * Verifica un Access Token con todas las defensas:
 * - Whitelist de algoritmos (solo HS256, rechaza alg:none)
 * - Lookup de clave por kid (soporta claves retiradas)
 * - Verificación de firma y expiración
 */
export function verifyAccessToken(token: string): JWTAccessPayload {
  // Decodificar sin verificar para leer kid y alg del header
  const decoded = jwt.decode(token, { complete: true });

  if (!decoded || typeof decoded.payload !== 'object' || decoded.payload === null) {
    throw new AppError(401, 'Token inválido o malformado', 'TOKEN_INVALIDO');
  }

  // ── Whitelist de algoritmos — rechaza alg:none y cualquier otro ──────────
  const alg = decoded.header.alg;
  if (alg !== 'HS256') {
    throw new AppError(
      401,
      `Algoritmo JWT no permitido: ${alg ?? 'none'}. Solo se acepta HS256`,
      'ALGORITMO_NO_PERMITIDO',
    );
  }

  // ── Buscar clave por kid ──────────────────────────────────────────────────
  const kid = decoded.header.kid as string | undefined;
  if (!kid) {
    throw new AppError(401, 'Token sin kid en el header', 'TOKEN_INVALIDO');
  }

  const signingKey = jwtSigningKeysRepository.findByKid(kid);
  if (!signingKey) {
    throw new AppError(401, 'Clave de firma JWT no encontrada', 'CLAVE_NO_ENCONTRADA');
  }

  // ── Verificar firma y expiración ──────────────────────────────────────────
  try {
    const payload = jwt.verify(token, signingKey.secret, {
      algorithms: ['HS256'], // whitelist — biblioteca rechaza cualquier otro
    });
    return payload as JWTAccessPayload;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new AppError(401, 'Token expirado', 'TOKEN_EXPIRADO');
    }
    if (err instanceof jwt.JsonWebTokenError) {
      throw new AppError(401, 'Token inválido', 'TOKEN_INVALIDO');
    }
    throw err;
  }
}

/**
 * Verifica un Refresh Token (se usa en Phase 4 — refresh endpoint).
 * Mismo proceso que AT pero devuelve JWTRefreshPayload.
 */
export function verifyRefreshToken(token: string): JWTRefreshPayload {
  const decoded = jwt.decode(token, { complete: true });

  if (!decoded || typeof decoded.payload !== 'object' || decoded.payload === null) {
    throw new AppError(401, 'Refresh token inválido', 'TOKEN_INVALIDO');
  }

  const alg = decoded.header.alg;
  if (alg !== 'HS256') {
    throw new AppError(401, 'Algoritmo no permitido en refresh token', 'ALGORITMO_NO_PERMITIDO');
  }

  const kid = decoded.header.kid as string | undefined;
  if (!kid) {
    throw new AppError(401, 'Refresh token sin kid', 'TOKEN_INVALIDO');
  }

  const signingKey = jwtSigningKeysRepository.findByKid(kid);
  if (!signingKey) {
    throw new AppError(401, 'Clave de firma no encontrada', 'CLAVE_NO_ENCONTRADA');
  }

  try {
    const payload = jwt.verify(token, signingKey.secret, { algorithms: ['HS256'] });
    return payload as JWTRefreshPayload;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new AppError(401, 'Refresh token expirado', 'TOKEN_EXPIRADO');
    }
    throw new AppError(401, 'Refresh token inválido', 'TOKEN_INVALIDO');
  }
}

/**
 * Emite un token temporal de corta duración (mfa_session_token, step_up_token).
 * No se persiste en BD — la firma garantiza autenticidad.
 */
export function issueTemporaryToken(
  userId: string,
  type: 'mfa_session' | 'step_up',
  expiresIn: string,
): string {
  const activeKey = jwtSigningKeysRepository.findActive();
  if (!activeKey) throw new AppError(500, 'No hay clave de firma JWT activa', 'ERROR_INTERNO');

  return jwt.sign({ sub: userId, type }, activeKey.secret, {
    algorithm: 'HS256',
    expiresIn,
  } as jwt.SignOptions);
}

// ── Token M2M (Client Credentials) ───────────────────────────────────────────

/**
 * Emite un token de máquina a máquina (Client Credentials Grant).
 * No tiene `sub` de usuario ni Refresh Token — el cliente rota con otro /m2m/token.
 * El payload incluye `type: 'm2m'` y `scopes` para que los middlewares puedan distinguirlo.
 */
export function signM2mToken(clientId: string, scopes: string[]): string {
  const activeKey = jwtSigningKeysRepository.findActive();
  if (!activeKey) throw new AppError(500, 'No hay clave de firma JWT activa', 'ERROR_INTERNO');

  return jwt.sign(
    {
      sub: clientId,
      jti: uuidv4(),
      kid: activeKey.id,
      roles: [] as UserRole[],   // sin roles de usuario — usar scopes para autorización
      scopes,
      type: 'm2m' as const,
    },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: '1h',
      header: { alg: 'HS256', typ: 'JWT', kid: activeKey.id },
    } as jwt.SignOptions,
  );
}

// ── Refresh con Family Tracking ───────────────────────────────────────────────

type RefreshTokenPairInput = {
  familyId: string;
  userId: string;
  roles: UserRole[];
  auditData: {
    ipHash: string;
    userAgent: string | null;
    correlationId: string | null;
  };
};

type RefreshedTokens = {
  accessToken: string;
  refreshToken: string;
};

/**
 * Emite un nuevo par AT+RT para una familia existente (renovación de sesión).
 * Actualiza current_jti, access_jti y expires_at atómicamente con el log TOKEN_RENOVADO.
 * NUNCA crea una nueva familia — solo rota dentro de la misma.
 */
export function refreshTokenPair(input: RefreshTokenPairInput): RefreshedTokens {
  const activeKey = jwtSigningKeysRepository.findActive();
  if (!activeKey) {
    throw new AppError(500, 'No hay clave de firma JWT activa', 'ERROR_INTERNO');
  }

  const atJti = uuidv4();
  const rtJti = uuidv4();

  // Access Token — 15 minutos, mismo formato que issueTokenPair
  const accessToken = jwt.sign(
    { sub: input.userId, jti: atJti, kid: activeKey.id, roles: input.roles },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: config.JWT_EXPIRY_ACCESS,
      header: { alg: 'HS256', typ: 'JWT', kid: activeKey.id },
    } as jwt.SignOptions,
  );

  // Refresh Token — 7 días, mismo familyId (Family Tracking: misma familia, nuevo jti)
  // kid en header para que verifyRefreshToken pueda buscar la clave activa o retirada por kid
  const refreshToken = jwt.sign(
    { sub: input.userId, jti: rtJti, kid: activeKey.id, familyId: input.familyId },
    activeKey.secret,
    {
      algorithm: 'HS256',
      expiresIn: config.JWT_EXPIRY_REFRESH,
      header: { alg: 'HS256', typ: 'JWT', kid: activeKey.id },
    } as jwt.SignOptions,
  );

  // Calcular nueva expiración del RT para actualizar la familia en BD
  const decoded = jwt.decode(refreshToken) as { exp: number };
  const newExpiresAt = decoded.exp * 1000;

  // Transacción atómica: actualizar family + insertar TOKEN_RENOVADO en audit_logs
  rotateRefreshToken({
    familyId: input.familyId,
    newJti: rtJti,
    newAccessJti: atJti,
    newExpiresAt,
    auditData: {
      userId: input.userId,
      ipHash: input.auditData.ipHash,
      userAgent: input.auditData.userAgent,
      correlationId: input.auditData.correlationId,
    },
  });

  return { accessToken, refreshToken };
}

/**
 * Verifica un token temporal y comprueba su tipo.
 */
export function verifyTemporaryToken(
  token: string,
  expectedType: 'mfa_session' | 'step_up',
): { sub: string; type: string } {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded.payload !== 'object' || decoded.payload === null) {
    throw new AppError(401, 'Token temporal inválido', 'TOKEN_INVALIDO');
  }

  const kid = decoded.header.kid as string | undefined;
  const activeKey = kid
    ? jwtSigningKeysRepository.findByKid(kid)
    : jwtSigningKeysRepository.findActive();

  if (!activeKey) throw new AppError(401, 'Clave no encontrada', 'TOKEN_INVALIDO');

  try {
    const payload = jwt.verify(token, activeKey.secret, { algorithms: ['HS256'] }) as {
      sub: string;
      type: string;
    };

    if (payload.type !== expectedType) {
      throw new AppError(401, `Token de tipo incorrecto: ${payload.type}`, 'TOKEN_INVALIDO');
    }
    return payload;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err instanceof jwt.TokenExpiredError) {
      throw new AppError(401, 'Token temporal expirado', 'TOKEN_EXPIRADO');
    }
    throw new AppError(401, 'Token temporal inválido', 'TOKEN_INVALIDO');
  }
}
