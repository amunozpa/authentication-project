import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import { buildPage, decodeCursor, parseLimit } from '../../utils/pagination';
import type { RefreshTokenFamilyRecord, PaginatedResponse } from '../../types';

type CreateFamilyInput = {
  id?: string;          // permite al caller controlar el ID (para que coincida con familyId del RT)
  user_id: string;
  current_jti: string;
  kid: string;
  ip_hash: string;
  user_agent?: string | null;
  expires_at: number;
};

export const refreshTokenFamiliesRepository = {
  findById(familyId: string): RefreshTokenFamilyRecord | null {
    return (
      (db
        .prepare('SELECT * FROM refresh_token_families WHERE id = ?')
        .get(familyId) as RefreshTokenFamilyRecord | undefined) ?? null
    );
  },

  /** Busca la familia activa que contiene el jti del Refresh Token presentado */
  findByCurrentJti(jti: string): RefreshTokenFamilyRecord | null {
    return (
      (db
        .prepare(
          'SELECT * FROM refresh_token_families WHERE current_jti = ? AND revoked_at IS NULL',
        )
        .get(jti) as RefreshTokenFamilyRecord | undefined) ?? null
    );
  },

  create(data: CreateFamilyInput): RefreshTokenFamilyRecord {
    const id = data.id ?? uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO refresh_token_families
         (id, user_id, current_jti, access_jti, kid, ip_hash, user_agent, created_at, expires_at)
       VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.current_jti, data.kid, data.ip_hash, data.user_agent ?? null, now, data.expires_at);

    return db
      .prepare('SELECT * FROM refresh_token_families WHERE id = ?')
      .get(id) as RefreshTokenFamilyRecord;
  },

  /** Rota el token: actualiza current_jti y access_jti en una sola operación */
  rotate(familyId: string, newJti: string, newAccessJti: string): void {
    db.prepare(
      'UPDATE refresh_token_families SET current_jti = ?, access_jti = ? WHERE id = ?',
    ).run(newJti, newAccessJti, familyId);
  },

  revoke(familyId: string, reason: string): void {
    db.prepare(
      'UPDATE refresh_token_families SET revoked_at = ?, revoked_reason = ? WHERE id = ?',
    ).run(Date.now(), reason, familyId);
  },

  /** Revoca TODAS las familias activas de un usuario (logout global, reset de contraseña) */
  revokeAllForUser(userId: string, reason: string): void {
    db.prepare(
      `UPDATE refresh_token_families
       SET revoked_at = ?, revoked_reason = ?
       WHERE user_id = ? AND revoked_at IS NULL`,
    ).run(Date.now(), reason, userId);
  },

  /** Revoca todas las familias EXCEPTO una (usada en cambio de contraseña) */
  revokeAllForUserExcept(userId: string, exceptFamilyId: string, reason: string): void {
    db.prepare(
      `UPDATE refresh_token_families
       SET revoked_at = ?, revoked_reason = ?
       WHERE user_id = ? AND id != ? AND revoked_at IS NULL`,
    ).run(Date.now(), reason, userId, exceptFamilyId);
  },

  /** Lista sesiones activas del usuario para el panel de gestión */
  findActiveByUserId(
    userId: string,
    options: { cursor?: string; limit?: number },
  ): PaginatedResponse<RefreshTokenFamilyRecord> {
    const limit = parseLimit(options.limit);

    if (options.cursor) {
      const { createdAt, id } = decodeCursor(options.cursor);
      const rows = db
        .prepare(
          `SELECT * FROM refresh_token_families
           WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
             AND (created_at > ? OR (created_at = ? AND id > ?))
           ORDER BY created_at ASC, id ASC LIMIT ?`,
        )
        .all(userId, Date.now(), createdAt, createdAt, id, limit + 1) as RefreshTokenFamilyRecord[];
      return buildPage(rows, limit);
    }

    const rows = db
      .prepare(
        `SELECT * FROM refresh_token_families
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         ORDER BY created_at ASC, id ASC LIMIT ?`,
      )
      .all(userId, Date.now(), limit + 1) as RefreshTokenFamilyRecord[];
    return buildPage(rows, limit);
  },

  /** Cuenta sesiones activas para mostrar en el panel de seguridad */
  countActiveByUserId(userId: string): number {
    const row = db
      .prepare(
        `SELECT COUNT(*) as count FROM refresh_token_families
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?`,
      )
      .get(userId, Date.now()) as { count: number };
    return row.count;
  },
};
