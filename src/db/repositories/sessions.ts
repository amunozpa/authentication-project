import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { SessionRecord } from '../../types';

type CreateSessionInput = {
  user_id: string;
  token_hash: string;
  ip_hash: string;
  user_agent?: string | null;
  expires_at: number;
};

export const sessionsRepository = {
  findByHash(tokenHash: string): SessionRecord | null {
    return (
      (db
        .prepare(
          'SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?',
        )
        .get(tokenHash, Date.now()) as SessionRecord | undefined) ?? null
    );
  },

  create(data: CreateSessionInput): SessionRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO sessions (id, user_id, token_hash, ip_hash, user_agent, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.token_hash, data.ip_hash, data.user_agent ?? null, data.expires_at, now);

    return db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as SessionRecord;
  },

  deleteById(id: string): void {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  },

  deleteByTokenHash(tokenHash: string): void {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
  },

  deleteAllForUser(userId: string): void {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  },
};
