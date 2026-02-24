import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { LinkedIdentityRecord, OAuthProvider } from '../../types';

type CreateLinkedIdentityInput = {
  user_id: string;
  provider: OAuthProvider;
  provider_id: string;
  provider_email?: string | null;
  access_token?: string | null;
};

export const linkedIdentitiesRepository = {
  findByProvider(provider: OAuthProvider, providerId: string): LinkedIdentityRecord | null {
    return (
      (db
        .prepare(
          'SELECT * FROM linked_identities WHERE provider = ? AND provider_id = ?',
        )
        .get(provider, providerId) as LinkedIdentityRecord | undefined) ?? null
    );
  },

  findByUserId(userId: string): LinkedIdentityRecord[] {
    return db
      .prepare('SELECT * FROM linked_identities WHERE user_id = ?')
      .all(userId) as LinkedIdentityRecord[];
  },

  create(data: CreateLinkedIdentityInput): LinkedIdentityRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO linked_identities (id, user_id, provider, provider_id, provider_email, access_token, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.provider, data.provider_id, data.provider_email ?? null, data.access_token ?? null, now);

    return db
      .prepare('SELECT * FROM linked_identities WHERE id = ?')
      .get(id) as LinkedIdentityRecord;
  },

  updateAccessToken(id: string, accessToken: string): void {
    db.prepare('UPDATE linked_identities SET access_token = ? WHERE id = ?').run(accessToken, id);
  },

  delete(userId: string, provider: OAuthProvider): boolean {
    const result = db
      .prepare('DELETE FROM linked_identities WHERE user_id = ? AND provider = ?')
      .run(userId, provider);
    return result.changes > 0;
  },

  countForUser(userId: string): number {
    const row = db
      .prepare('SELECT COUNT(*) as count FROM linked_identities WHERE user_id = ?')
      .get(userId) as { count: number };
    return row.count;
  },
};
