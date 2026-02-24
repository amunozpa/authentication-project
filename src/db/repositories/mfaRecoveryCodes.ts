import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { MfaRecoveryCodeRecord } from '../../types';

export const mfaRecoveryCodesRepository = {
  /** Devuelve todos los códigos no usados — para verificar contra el OTP de recuperación */
  findUnusedByUserId(userId: string): MfaRecoveryCodeRecord[] {
    return db
      .prepare('SELECT * FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL')
      .all(userId) as MfaRecoveryCodeRecord[];
  },

  /** Inserta varios códigos en una sola transacción (se llaman desde transactions.ts) */
  createBatch(userId: string, codeHashes: string[]): void {
    const insert = db.prepare(
      'INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)',
    );
    const now = Date.now();
    for (const hash of codeHashes) {
      insert.run(uuidv4(), userId, hash, now);
    }
  },

  markUsed(id: string): void {
    db.prepare('UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?').run(Date.now(), id);
  },

  /** Elimina todos los códigos de un usuario (al resetear MFA o al eliminar la cuenta) */
  deleteAllForUser(userId: string): void {
    db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(userId);
  },
};
