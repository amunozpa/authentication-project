/**
 * Job de purga automática — Fase 2
 * Limpia registros expirados cada hora para mantener la BD liviana.
 *
 * 7 targets:
 * 1. webauthn_challenges expirados (TTL 5min — se acumulan si el usuario abandona el flujo)
 * 2. email_tokens expirados o usados
 * 3. oauth_states expirados
 * 4. device_codes expirados
 * 5. sessions expiradas
 * 6. refresh_token_families expiradas o revocadas hace > 7 días
 * 7. audit_logs > 90 días → anonimizar (no eliminar — conservar para estadísticas)
 */
import { db } from './index';
import { logger } from '../logger';

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

function runPurge(): void {
  const now = Date.now();

  try {
    // 1. webauthn_challenges expirados (TTL 5min)
    const wc = db
      .prepare('DELETE FROM webauthn_challenges WHERE expires_at < ?')
      .run(now);

    // 2. email_tokens expirados o ya usados
    const et = db
      .prepare('DELETE FROM email_tokens WHERE expires_at < ? OR used_at IS NOT NULL')
      .run(now);

    // 3. oauth_states expirados
    const os = db
      .prepare('DELETE FROM oauth_states WHERE expires_at < ?')
      .run(now);

    // 4. device_codes expirados
    const dc = db
      .prepare('DELETE FROM device_codes WHERE expires_at < ?')
      .run(now);

    // 5. sessions expiradas
    const s = db
      .prepare('DELETE FROM sessions WHERE expires_at < ?')
      .run(now);

    // 6. refresh_token_families: expiradas O revocadas hace > 7 días
    const rtf = db
      .prepare(
        `DELETE FROM refresh_token_families
         WHERE expires_at < ?
            OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
      )
      .run(now, now - SEVEN_DAYS_MS);

    // 7. audit_logs > 90 días → anonimizar PII (conservar el evento)
    const al = db
      .prepare(
        `UPDATE audit_logs
         SET user_id = NULL, ip_hash = NULL, user_agent = NULL
         WHERE created_at < ? AND user_id IS NOT NULL`,
      )
      .run(now - NINETY_DAYS_MS);

    const totalEliminados =
      wc.changes + et.changes + os.changes + dc.changes + s.changes + rtf.changes;

    if (totalEliminados > 0 || al.changes > 0) {
      logger.info(
        {
          webauthnChallenges: wc.changes,
          emailTokens: et.changes,
          oauthStates: os.changes,
          deviceCodes: dc.changes,
          sesiones: s.changes,
          familias: rtf.changes,
          logsAnonimizados: al.changes,
        },
        'Purga automática completada',
      );
    }
  } catch (err) {
    logger.error({ err }, 'Error en el job de purga automática');
  }
}

/**
 * Inicia el job de purga en un interval.
 * Ejecuta una purga inmediata al arrancar y luego cada hora.
 *
 * @param intervalMs - Intervalo entre purgas (default: 1 hora)
 */
export function startPurgeJob(intervalMs = 60 * 60 * 1000): void {
  // Purga inicial al arrancar (limpia residuos de arranques anteriores)
  runPurge();

  const interval = setInterval(runPurge, intervalMs);
  // .unref() permite que el proceso termine normalmente aunque el interval esté activo
  interval.unref();

  logger.info(`Job de purga automática iniciado — intervalo: ${intervalMs / 1000 / 60} minutos`);
}
