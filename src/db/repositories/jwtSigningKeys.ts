import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import type { JwtSigningKeyRecord } from '../../types';

export const jwtSigningKeysRepository = {
  /** Obtiene la clave activa actual (solo debe existir una a la vez) */
  findActive(): JwtSigningKeyRecord | null {
    return (
      (db
        .prepare('SELECT * FROM jwt_signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1')
        .get() as JwtSigningKeyRecord | undefined) ?? null
    );
  },

  /** Busca cualquier clave por kid — activa o retirada (para verificar tokens viejos) */
  findByKid(kid: string): JwtSigningKeyRecord | null {
    return (
      (db
        .prepare('SELECT * FROM jwt_signing_keys WHERE id = ?')
        .get(kid) as JwtSigningKeyRecord | undefined) ?? null
    );
  },

  /** Lista todas las claves (activas y retiradas) — para panel de administración */
  findAll(): JwtSigningKeyRecord[] {
    return db
      .prepare('SELECT * FROM jwt_signing_keys ORDER BY created_at DESC')
      .all() as JwtSigningKeyRecord[];
  },

  create(secret: string): JwtSigningKeyRecord {
    // El kid es un UUID corto (primeros 8 chars) — legible en el header JWT
    const kid = uuidv4().replace(/-/g, '').slice(0, 12);
    const now = Date.now();

    db.prepare(
      'INSERT INTO jwt_signing_keys (id, secret, active, created_at) VALUES (?, ?, 1, ?)',
    ).run(kid, secret, now);

    return db.prepare('SELECT * FROM jwt_signing_keys WHERE id = ?').get(kid) as JwtSigningKeyRecord;
  },

  /** Retira una clave: deja de firmar pero sigue verificando tokens existentes hasta que expiren */
  retire(kid: string): void {
    db.prepare(
      'UPDATE jwt_signing_keys SET active = 0, retired_at = ? WHERE id = ?',
    ).run(Date.now(), kid);
  },
};
