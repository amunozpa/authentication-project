import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { EmailTokenRecord, EmailTokenType } from '../../types';

type CreateEmailTokenInput = {
  user_id: string;
  token_hash: string;
  type: EmailTokenType;
  expires_at: number;
};

export const emailTokensRepository = {
  findByHash(tokenHash: string): EmailTokenRecord | null {
    return (
      (db
        .prepare('SELECT * FROM email_tokens WHERE token_hash = ?')
        .get(tokenHash) as EmailTokenRecord | undefined) ?? null
    );
  },

  /** Busca un token activo (no usado, no expirado) para un usuario y tipo */
  findActiveByUserAndType(userId: string, type: EmailTokenType): EmailTokenRecord | null {
    return (
      (db
        .prepare(
          `SELECT * FROM email_tokens
           WHERE user_id = ? AND type = ? AND used_at IS NULL AND expires_at > ?
           ORDER BY created_at DESC LIMIT 1`,
        )
        .get(userId, type, Date.now()) as EmailTokenRecord | undefined) ?? null
    );
  },

  create(data: CreateEmailTokenInput): EmailTokenRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO email_tokens (id, user_id, token_hash, type, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.token_hash, data.type, data.expires_at, now);

    return db.prepare('SELECT * FROM email_tokens WHERE id = ?').get(id) as EmailTokenRecord;
  },

  markUsed(id: string): void {
    db.prepare('UPDATE email_tokens SET used_at = ? WHERE id = ?').run(Date.now(), id);
  },

  /** Invalida todos los tokens activos de un usuario y tipo (antes de emitir uno nuevo) */
  invalidateActiveByUserAndType(userId: string, type: EmailTokenType): void {
    db.prepare(
      'UPDATE email_tokens SET used_at = ? WHERE user_id = ? AND type = ? AND used_at IS NULL',
    ).run(Date.now(), userId, type);
  },
};
