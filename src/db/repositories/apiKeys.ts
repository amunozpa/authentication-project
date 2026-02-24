import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import { buildPage, decodeCursor, parseLimit } from '../../utils/pagination';
import type { ApiKeyRecord, PaginatedResponse } from '../../types';

type CreateApiKeyInput = {
  user_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: string[];
};

export const apiKeysRepository = {
  findById(id: string): ApiKeyRecord | null {
    return (
      (db
        .prepare('SELECT * FROM api_keys WHERE id = ? AND revoked_at IS NULL')
        .get(id) as ApiKeyRecord | undefined) ?? null
    );
  },

  /** Busca por prefijo — para encontrar candidatos antes de verificar bcrypt */
  findActiveByPrefix(keyPrefix: string): ApiKeyRecord[] {
    return db
      .prepare('SELECT * FROM api_keys WHERE key_prefix = ? AND revoked_at IS NULL')
      .all(keyPrefix) as ApiKeyRecord[];
  },

  create(data: CreateApiKeyInput): ApiKeyRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, scopes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.name, data.key_prefix, data.key_hash, JSON.stringify(data.scopes), now);

    return db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id) as ApiKeyRecord;
  },

  revoke(id: string, userId: string): boolean {
    const result = db
      .prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ?')
      .run(Date.now(), id, userId);
    return result.changes > 0;
  },

  updateLastUsed(id: string): void {
    db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), id);
  },

  findByUserId(
    userId: string,
    options: { cursor?: string; limit?: number },
  ): PaginatedResponse<ApiKeyRecord> {
    const limit = parseLimit(options.limit);

    if (options.cursor) {
      const { createdAt, id } = decodeCursor(options.cursor);
      const rows = db
        .prepare(
          `SELECT * FROM api_keys
           WHERE user_id = ?
             AND (created_at > ? OR (created_at = ? AND id > ?))
           ORDER BY created_at ASC, id ASC LIMIT ?`,
        )
        .all(userId, createdAt, createdAt, id, limit + 1) as ApiKeyRecord[];
      return buildPage(rows, limit);
    }

    const rows = db
      .prepare(
        'SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at ASC, id ASC LIMIT ?',
      )
      .all(userId, limit + 1) as ApiKeyRecord[];
    return buildPage(rows, limit);
  },
};
