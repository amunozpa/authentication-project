import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { OAuthStateRecord, OAuthProvider } from '../../types';

type CreateOAuthStateInput = {
  state: string;
  code_verifier: string;
  provider: OAuthProvider;
  expires_at: number;
  /** Fase 5.9: userId del usuario autenticado cuando es un flujo de vinculación */
  link_user_id?: string;
};

export const oauthStatesRepository = {
  findByState(state: string): OAuthStateRecord | null {
    return (
      (db
        .prepare(
          'SELECT * FROM oauth_states WHERE state = ? AND expires_at > ?',
        )
        .get(state, Date.now()) as OAuthStateRecord | undefined) ?? null
    );
  },

  create(data: CreateOAuthStateInput): OAuthStateRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO oauth_states (id, state, code_verifier, provider, expires_at, created_at, link_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, data.state, data.code_verifier, data.provider, data.expires_at, now, data.link_user_id ?? null);

    return db.prepare('SELECT * FROM oauth_states WHERE id = ?').get(id) as OAuthStateRecord;
  },

  delete(id: string): void {
    db.prepare('DELETE FROM oauth_states WHERE id = ?').run(id);
  },
};
