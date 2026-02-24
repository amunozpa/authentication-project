/**
 * Transacciones críticas SQLite — Fase 2
 * Operaciones multi-tabla que deben ser atómicas.
 * Usa db.transaction() de better-sqlite3 (síncrono, sin async/await).
 *
 * Las 5 transacciones requeridas por el plan:
 * 1. Rotación de Refresh Token
 * 2. Revocación de familia completa
 * 3. Eliminación de cuenta GDPR (6 tablas)
 * 4. Account Linking
 * 5. Verificación de email
 */
import { db } from './index';
import { v4 as uuidv4 } from 'uuid';
import type { AuditEventType, OAuthProvider } from '../types';

// ── 1. Rotación de Refresh Token ─────────────────────────────────────────────
// Actualiza current_jti + access_jti + expires_at + registra TOKEN_RENOVADO en audit_logs.
// Si falla cualquiera de las operaciones, ninguna se aplica.
const _rotateRefreshToken = db.transaction(
  (params: {
    familyId: string;
    newJti: string;
    newAccessJti: string;
    newExpiresAt: number;
    auditData: {
      userId: string;
      ipHash: string;
      userAgent: string | null;
      correlationId: string | null;
    };
  }) => {
    db.prepare(
      'UPDATE refresh_token_families SET current_jti = ?, access_jti = ?, expires_at = ? WHERE id = ?',
    ).run(params.newJti, params.newAccessJti, params.newExpiresAt, params.familyId);

    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, user_agent, correlation_id, metadata, created_at)
       VALUES (?, ?, 'TOKEN_RENOVADO', ?, ?, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.auditData.userId,
      params.auditData.ipHash,
      params.auditData.userAgent,
      params.auditData.correlationId,
      JSON.stringify({ familyId: params.familyId }),
      Date.now(),
    );
  },
);

export function rotateRefreshToken(params: {
  familyId: string;
  newJti: string;
  newAccessJti: string;
  newExpiresAt: number;
  auditData: {
    userId: string;
    ipHash: string;
    userAgent: string | null;
    correlationId: string | null;
  };
}): void {
  _rotateRefreshToken(params);
}

// ── 2. Revocación de familia (robo detectado o logout) ────────────────────────
const _revokeFamily = db.transaction(
  (params: {
    familyId: string;
    reason: string;
    eventType: AuditEventType;
    auditData: {
      userId: string;
      ipHash: string | null;
      correlationId: string | null;
    };
  }) => {
    db.prepare(
      'UPDATE refresh_token_families SET revoked_at = ?, revoked_reason = ? WHERE id = ?',
    ).run(Date.now(), params.reason, params.familyId);

    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.auditData.userId,
      params.eventType,
      params.auditData.ipHash,
      params.auditData.correlationId,
      JSON.stringify({ familyId: params.familyId, reason: params.reason }),
      Date.now(),
    );
  },
);

export function revokeFamily(params: {
  familyId: string;
  reason: string;
  eventType: AuditEventType;
  auditData: {
    userId: string;
    ipHash: string | null;
    correlationId: string | null;
  };
}): void {
  _revokeFamily(params);
}

// ── 3. Eliminación de cuenta GDPR ─────────────────────────────────────────────
// Soft-delete del usuario + hard-delete de 6 tablas + anonimización de audit_logs.
// TODO: se activa desde DELETE /api/v1/user/me (Fase 6.5)
const _deleteAccountGdpr = db.transaction(
  (params: {
    userId: string;
    auditData: { ipHash: string | null; correlationId: string | null };
  }) => {
    const now = Date.now();

    // Hard-delete en tablas relacionadas
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(params.userId);
    db.prepare(
      'UPDATE refresh_token_families SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL',
    ).run(now, 'account_deleted', params.userId);
    db.prepare('DELETE FROM email_tokens WHERE user_id = ?').run(params.userId);
    db.prepare('DELETE FROM linked_identities WHERE user_id = ?').run(params.userId);
    db.prepare('DELETE FROM webauthn_credentials WHERE user_id = ?').run(params.userId);
    db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(params.userId);
    db.prepare('DELETE FROM api_keys WHERE user_id = ?').run(params.userId);

    // Soft-delete del usuario (conservar el registro para integridad)
    db.prepare('UPDATE users SET deleted_at = ? WHERE id = ?').run(now, params.userId);

    // Anonimizar audit_logs (conservar para estadísticas, eliminar PII)
    db.prepare(
      'UPDATE audit_logs SET user_id = NULL, ip_hash = NULL, user_agent = NULL WHERE user_id = ?',
    ).run(params.userId);

    // Registrar el evento ANTES de la anonimización (con los datos todavía disponibles)
    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, metadata, created_at)
       VALUES (?, NULL, 'CUENTA_ELIMINADA', NULL, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.auditData.correlationId,
      JSON.stringify({ deletedUserId: params.userId }),
      now,
    );
  },
);

export function deleteAccountGdpr(params: {
  userId: string;
  auditData: { ipHash: string | null; correlationId: string | null };
}): void {
  _deleteAccountGdpr(params);
}

// ── 4. Account Linking ─────────────────────────────────────────────────────────
// Vincula un provider OAuth a un usuario existente (atómico).
const _linkAccount = db.transaction(
  (params: {
    userId: string;
    provider: OAuthProvider;
    providerId: string;
    providerEmail: string | null;
    accessToken: string | null;
    auditData: { ipHash: string | null; correlationId: string | null };
  }) => {
    const now = Date.now();

    db.prepare(
      `INSERT INTO linked_identities (id, user_id, provider, provider_id, provider_email, access_token, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.userId,
      params.provider,
      params.providerId,
      params.providerEmail,
      params.accessToken,
      now,
    );

    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, metadata, created_at)
       VALUES (?, ?, 'CUENTA_VINCULADA', ?, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.userId,
      params.auditData.ipHash,
      params.auditData.correlationId,
      JSON.stringify({ provider: params.provider }),
      now,
    );
  },
);

export function linkAccount(params: {
  userId: string;
  provider: OAuthProvider;
  providerId: string;
  providerEmail: string | null;
  accessToken: string | null;
  auditData: { ipHash: string | null; correlationId: string | null };
}): void {
  _linkAccount(params);
}

// ── 5a. Activar MFA (TOTP) ────────────────────────────────────────────────────
// Atómico: guarda secret + mfa_enabled=1 + elimina códigos viejos + crea nuevos + log.
const _enableMfa = db.transaction(
  (params: {
    userId: string;
    secret: string;
    recoveryCodeHashes: string[];
    auditData: { ipHash: string | null; correlationId: string | null };
  }) => {
    const now = Date.now();

    db.prepare('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?').run(
      params.secret,
      params.userId,
    );
    db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(params.userId);

    const insert = db.prepare(
      'INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)',
    );
    for (const hash of params.recoveryCodeHashes) {
      insert.run(uuidv4(), params.userId, hash, now);
    }

    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, metadata, created_at)
       VALUES (?, ?, 'MFA_ACTIVADO', ?, ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.userId,
      params.auditData.ipHash,
      params.auditData.correlationId,
      JSON.stringify({ recovery_codes_count: params.recoveryCodeHashes.length }),
      now,
    );
  },
);

export function enableMfa(params: {
  userId: string;
  secret: string;
  recoveryCodeHashes: string[];
  auditData: { ipHash: string | null; correlationId: string | null };
}): void {
  _enableMfa(params);
}

// ── 5b. Desactivar MFA ────────────────────────────────────────────────────────
const _disableMfa = db.transaction(
  (params: {
    userId: string;
    auditData: { ipHash: string | null; correlationId: string | null };
  }) => {
    const now = Date.now();
    db.prepare('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?').run(
      params.userId,
    );
    db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(params.userId);
    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, created_at)
       VALUES (?, ?, 'MFA_DESACTIVADO', ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.userId,
      params.auditData.ipHash,
      params.auditData.correlationId,
      now,
    );
  },
);

export function disableMfaTx(params: {
  userId: string;
  auditData: { ipHash: string | null; correlationId: string | null };
}): void {
  _disableMfa(params);
}

// ── 5. Verificación de email ───────────────────────────────────────────────────
// Marca el token como usado + marca email_verified=1 atómicamente.
const _verifyEmail = db.transaction(
  (params: {
    tokenId: string;
    userId: string;
    auditData: { ipHash: string | null; correlationId: string | null };
  }) => {
    const now = Date.now();

    // Marcar token como usado (invalidar)
    db.prepare('UPDATE email_tokens SET used_at = ? WHERE id = ?').run(now, params.tokenId);

    // Marcar email como verificado
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(params.userId);

    // Registrar evento
    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, correlation_id, created_at)
       VALUES (?, ?, 'VERIFICACION_COMPLETADA', ?, ?, ?)`,
    ).run(
      uuidv4(),
      params.userId,
      params.auditData.ipHash,
      params.auditData.correlationId,
      now,
    );
  },
);

export function verifyEmail(params: {
  tokenId: string;
  userId: string;
  auditData: { ipHash: string | null; correlationId: string | null };
}): void {
  _verifyEmail(params);
}
