import { v4 as uuidv4 } from 'uuid';
import { db } from '../index';
import { buildPage, decodeCursor, parseLimit } from '../../utils/pagination';
import type { AuditLogRecord, AuditEventType, PaginatedResponse } from '../../types';

type CreateAuditLogInput = {
  user_id?: string | null;
  event_type: AuditEventType;
  ip_hash?: string | null;
  user_agent?: string | null;
  correlation_id?: string | null;
  metadata?: Record<string, unknown> | null;
};

export const auditLogsRepository = {
  create(data: CreateAuditLogInput): AuditLogRecord {
    const id = uuidv4();
    const now = Date.now();

    db.prepare(
      `INSERT INTO audit_logs (id, user_id, event_type, ip_hash, user_agent, correlation_id, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      data.user_id ?? null,
      data.event_type,
      data.ip_hash ?? null,
      data.user_agent ?? null,
      data.correlation_id ?? null,
      data.metadata ? JSON.stringify(data.metadata) : null,
      now,
    );

    return db.prepare('SELECT * FROM audit_logs WHERE id = ?').get(id) as AuditLogRecord;
  },

  findByUserId(
    userId: string,
    options: { cursor?: string; limit?: number },
  ): PaginatedResponse<AuditLogRecord> {
    const limit = parseLimit(options.limit);

    if (options.cursor) {
      const { createdAt, id } = decodeCursor(options.cursor);
      const rows = db
        .prepare(
          `SELECT * FROM audit_logs
           WHERE user_id = ?
             AND (created_at > ? OR (created_at = ? AND id > ?))
           ORDER BY created_at ASC, id ASC LIMIT ?`,
        )
        .all(userId, createdAt, createdAt, id, limit + 1) as AuditLogRecord[];
      return buildPage(rows, limit);
    }

    const rows = db
      .prepare(
        'SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at ASC, id ASC LIMIT ?',
      )
      .all(userId, limit + 1) as AuditLogRecord[];
    return buildPage(rows, limit);
  },

  findByEventType(
    eventType: AuditEventType,
    options: { cursor?: string; limit?: number; userId?: string },
  ): PaginatedResponse<AuditLogRecord> {
    const limit = parseLimit(options.limit);
    const cursor = options.cursor ? decodeCursor(options.cursor) : null;

    const userFilter = options.userId ? 'AND user_id = ?' : '';
    const userParam = options.userId ? [options.userId] : [];

    if (cursor) {
      const rows = db
        .prepare(
          `SELECT * FROM audit_logs
           WHERE event_type = ? ${userFilter}
             AND (created_at > ? OR (created_at = ? AND id > ?))
           ORDER BY created_at ASC, id ASC LIMIT ?`,
        )
        .all(eventType, ...userParam, cursor.createdAt, cursor.createdAt, cursor.id, limit + 1) as AuditLogRecord[];
      return buildPage(rows, limit);
    }

    const rows = db
      .prepare(
        `SELECT * FROM audit_logs
         WHERE event_type = ? ${userFilter}
         ORDER BY created_at ASC, id ASC LIMIT ?`,
      )
      .all(eventType, ...userParam, limit + 1) as AuditLogRecord[];
    return buildPage(rows, limit);
  },

  /** GDPR: anonimiza registros más antiguos de N días (no eliminar — conservar estadísticas) */
  anonymizeOlderThan(cutoffTimestamp: number): number {
    const result = db
      .prepare(
        `UPDATE audit_logs
         SET user_id = NULL, ip_hash = NULL, user_agent = NULL
         WHERE created_at < ? AND user_id IS NOT NULL`,
      )
      .run(cutoffTimestamp);
    return result.changes;
  },

  /** Cuenta eventos recientes de un tipo para detección de anomalías */
  countRecentByType(
    eventType: AuditEventType,
    sinceTimestamp: number,
    userId?: string,
  ): number {
    if (userId) {
      const row = db
        .prepare(
          'SELECT COUNT(*) as count FROM audit_logs WHERE event_type = ? AND user_id = ? AND created_at > ?',
        )
        .get(eventType, userId, sinceTimestamp) as { count: number };
      return row.count;
    }
    const row = db
      .prepare(
        'SELECT COUNT(*) as count FROM audit_logs WHERE event_type = ? AND created_at > ?',
      )
      .get(eventType, sinceTimestamp) as { count: number };
    return row.count;
  },

  /** Cuenta IPs únicas que tuvieron un tipo de evento en un período — detección credential stuffing */
  countDistinctIpsByType(eventType: AuditEventType, sinceTimestamp: number): number {
    const row = db
      .prepare(
        'SELECT COUNT(DISTINCT ip_hash) as count FROM audit_logs WHERE event_type = ? AND created_at > ?',
      )
      .get(eventType, sinceTimestamp) as { count: number };
    return row.count;
  },

  /** Cuenta IPs únicas de una familia de tokens — detección de sesión inusual */
  countDistinctIpsByFamily(familyId: string, sinceTimestamp: number): number {
    const row = db
      .prepare(
        `SELECT COUNT(DISTINCT ip_hash) as count FROM audit_logs
         WHERE JSON_EXTRACT(metadata, '$.familyId') = ? AND created_at > ?`,
      )
      .get(familyId, sinceTimestamp) as { count: number };
    return row.count;
  },

  /** Lista paginada de eventos de anomalía de seguridad — para el panel admin (Fase 7) */
  findAnomalies(options: {
    typeParam?: string;
    cursor?: string;
    limit?: number;
    since?: number;
    until?: number;
  }): PaginatedResponse<AuditLogRecord> {
    const limit = parseLimit(options.limit);

    // Mapear tipo corto → event_type completo
    const eventTypeMap: Record<string, AuditEventType> = {
      credential_stuffing: 'ANOMALIA_CREDENTIAL_STUFFING',
      brute_force: 'ANOMALIA_FUERZA_BRUTA',
      unusual_session: 'ANOMALIA_SESION_INUSUAL',
    };
    const eventTypeFilter = options.typeParam
      ? (eventTypeMap[options.typeParam] ?? null)
      : null;

    const anomalyTypes = eventTypeFilter
      ? [eventTypeFilter]
      : (['ANOMALIA_CREDENTIAL_STUFFING', 'ANOMALIA_FUERZA_BRUTA', 'ANOMALIA_SESION_INUSUAL'] as AuditEventType[]);

    const placeholders = anomalyTypes.map(() => '?').join(', ');
    const sinceFilter = options.since ? 'AND created_at >= ?' : '';
    const untilFilter = options.until ? 'AND created_at <= ?' : '';

    const sinceParam = options.since ? [options.since] : [];
    const untilParam = options.until ? [options.until] : [];

    if (options.cursor) {
      const { createdAt, id } = decodeCursor(options.cursor);
      const rows = db
        .prepare(
          `SELECT * FROM audit_logs
           WHERE event_type IN (${placeholders})
             ${sinceFilter} ${untilFilter}
             AND (created_at > ? OR (created_at = ? AND id > ?))
           ORDER BY created_at DESC, id DESC LIMIT ?`,
        )
        .all(...anomalyTypes, ...sinceParam, ...untilParam, createdAt, createdAt, id, limit + 1) as AuditLogRecord[];
      return buildPage(rows, limit);
    }

    const rows = db
      .prepare(
        `SELECT * FROM audit_logs
         WHERE event_type IN (${placeholders})
           ${sinceFilter} ${untilFilter}
         ORDER BY created_at DESC, id DESC LIMIT ?`,
      )
      .all(...anomalyTypes, ...sinceParam, ...untilParam, limit + 1) as AuditLogRecord[];
    return buildPage(rows, limit);
  },
};
