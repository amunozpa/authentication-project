import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import { buildPage, decodeCursor, parseLimit } from '../../utils/pagination';
import type { UserRecord, UserRole, PaginatedResponse } from '../../types';

type CreateUserInput = {
  email: string;
  password_hash?: string | null;
  roles?: UserRole[];
  email_verified?: 0 | 1;
};

export const usersRepository = {
  findById(id: string): UserRecord | null {
    return (
      (db.prepare('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL').get(id) as
        | UserRecord
        | undefined) ?? null
    );
  },

  findByEmail(email: string): UserRecord | null {
    return (
      (db
        .prepare('SELECT * FROM users WHERE email = ? AND deleted_at IS NULL')
        .get(email) as UserRecord | undefined) ?? null
    );
  },

  /** Incluye usuarios eliminados (soft delete) — para comprobaciones internas */
  findByEmailIncludingDeleted(email: string): UserRecord | null {
    return (
      (db.prepare('SELECT * FROM users WHERE email = ?').get(email) as
        | UserRecord
        | undefined) ?? null
    );
  },

  create(data: CreateUserInput): UserRecord {
    const id = uuidv4();
    const now = Date.now();
    const roles = JSON.stringify(data.roles ?? ['user']);

    db.prepare(
      `INSERT INTO users (id, email, password_hash, roles, email_verified, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(id, data.email, data.password_hash ?? null, roles, data.email_verified ?? 0, now);

    return this.findById(id) as UserRecord;
  },

  setEmailVerified(id: string): void {
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(id);
  },

  setLocked(id: string, lockedUntil: number): void {
    db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockedUntil, id);
  },

  unlock(id: string): void {
    db.prepare('UPDATE users SET locked_until = NULL WHERE id = ?').run(id);
  },

  setMfa(id: string, secret: string): void {
    db.prepare('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?').run(secret, id);
  },

  disableMfa(id: string): void {
    db.prepare('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?').run(id);
  },

  updatePasswordHash(id: string, hash: string): void {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);
  },

  updateRoles(id: string, roles: UserRole[]): void {
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run(JSON.stringify(roles), id);
  },

  softDelete(id: string): void {
    db.prepare('UPDATE users SET deleted_at = ? WHERE id = ?').run(Date.now(), id);
  },

  /** Lista paginada — solo usuarios activos */
  list(options: {
    cursor?: string;
    limit?: number;
    role?: UserRole;
  }): PaginatedResponse<UserRecord> {
    const limit = parseLimit(options.limit);
    let query: string;
    let params: unknown[];

    if (options.cursor) {
      const { createdAt, id } = decodeCursor(options.cursor);
      if (options.role) {
        query = `SELECT * FROM users
                 WHERE deleted_at IS NULL AND roles LIKE ?
                   AND (created_at > ? OR (created_at = ? AND id > ?))
                 ORDER BY created_at ASC, id ASC LIMIT ?`;
        params = [`%"${options.role}"%`, createdAt, createdAt, id, limit + 1];
      } else {
        query = `SELECT * FROM users
                 WHERE deleted_at IS NULL
                   AND (created_at > ? OR (created_at = ? AND id > ?))
                 ORDER BY created_at ASC, id ASC LIMIT ?`;
        params = [createdAt, createdAt, id, limit + 1];
      }
    } else {
      if (options.role) {
        query = `SELECT * FROM users
                 WHERE deleted_at IS NULL AND roles LIKE ?
                 ORDER BY created_at ASC, id ASC LIMIT ?`;
        params = [`%"${options.role}"%`, limit + 1];
      } else {
        query = `SELECT * FROM users
                 WHERE deleted_at IS NULL
                 ORDER BY created_at ASC, id ASC LIMIT ?`;
        params = [limit + 1];
      }
    }

    const rows = db.prepare(query).all(...params) as UserRecord[];
    return buildPage(rows, limit);
  },
};
