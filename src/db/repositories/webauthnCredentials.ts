import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { WebAuthnCredentialRecord } from '../../types';

type CreateCredentialInput = {
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  device_name?: string | null;
};

export const webauthnCredentialsRepository = {
  findByCredentialId(credentialId: string): WebAuthnCredentialRecord | null {
    return (
      (db
        .prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?')
        .get(credentialId) as WebAuthnCredentialRecord | undefined) ?? null
    );
  },

  findByUserId(userId: string): WebAuthnCredentialRecord[] {
    return db
      .prepare(
        'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC',
      )
      .all(userId) as WebAuthnCredentialRecord[];
  },

  create(data: CreateCredentialInput): WebAuthnCredentialRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter, device_name, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, data.user_id, data.credential_id, data.public_key, data.counter, data.device_name ?? null, now);

    return db
      .prepare('SELECT * FROM webauthn_credentials WHERE id = ?')
      .get(id) as WebAuthnCredentialRecord;
  },

  /** Actualiza el counter tras cada autenticación — detecta clonación si el nuevo counter es menor */
  updateCounter(id: string, counter: number): void {
    db.prepare('UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE id = ?').run(
      counter,
      Date.now(),
      id,
    );
  },

  delete(id: string, userId: string): boolean {
    const result = db
      .prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?')
      .run(id, userId);
    return result.changes > 0;
  },

  deleteAllForUser(userId: string): void {
    db.prepare('DELETE FROM webauthn_credentials WHERE user_id = ?').run(userId);
  },
};
