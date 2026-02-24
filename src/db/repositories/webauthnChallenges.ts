import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { WebAuthnChallengeRecord } from '../../types';

type CreateChallengeInput = {
  user_id: string;
  challenge: string;
  type: 'registration' | 'authentication';
  expires_at: number;
};

export const webauthnChallengesRepository = {
  /** Obtiene el challenge activo más reciente de un usuario para un tipo de operación */
  findActiveByUserId(
    userId: string,
    type: 'registration' | 'authentication',
  ): WebAuthnChallengeRecord | null {
    return (
      (db
        .prepare(
          `SELECT * FROM webauthn_challenges
           WHERE user_id = ? AND type = ? AND expires_at > ?
           ORDER BY created_at DESC LIMIT 1`,
        )
        .get(userId, type, Date.now()) as WebAuthnChallengeRecord | undefined) ?? null
    );
  },

  create(data: CreateChallengeInput): WebAuthnChallengeRecord {
    const id = uuidv4();
    const now = Date.now();

    // Eliminar challenges previos del mismo tipo antes de crear uno nuevo
    db.prepare(
      'DELETE FROM webauthn_challenges WHERE user_id = ? AND type = ?',
    ).run(data.user_id, data.type);

    db.prepare(
      `INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.challenge, data.type, data.expires_at, now);

    return db
      .prepare('SELECT * FROM webauthn_challenges WHERE id = ?')
      .get(id) as WebAuthnChallengeRecord;
  },

  delete(id: string): void {
    db.prepare('DELETE FROM webauthn_challenges WHERE id = ?').run(id);
  },
};
