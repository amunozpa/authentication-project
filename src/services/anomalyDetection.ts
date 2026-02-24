/**
 * Servicio de Detección de Anomalías — Fase 7
 *
 * Analiza audit_logs en tiempo real para detectar patrones de ataque.
 * Se ejecuta sincrónicamente en cada login fallido o refresh de token.
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ ANOMALÍAS DETECTADAS                                                      │
 * │                                                                           │
 * │  credential_stuffing  > 10 LOGIN_FALLIDO desde IPs distintas en 5 min    │
 * │  brute_force          > 5  LOGIN_FALLIDO del mismo usuario en 10 min     │
 * │  unusual_session      mismo family_id desde > 2 IPs distintas en 1h      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * En producción multi-réplica este servicio debería usar Redis para compartir
 * estado entre réplicas. Aquí usa SQLite directamente (apropiado para demo).
 */
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { logger } from '../logger';

// Ventanas de tiempo para cada tipo de anomalía
const CREDENTIAL_STUFFING_WINDOW_MS = 5 * 60 * 1000;   // 5 minutos
const CREDENTIAL_STUFFING_THRESHOLD = 10;                // IPs distintas

const BRUTE_FORCE_WINDOW_MS = 10 * 60 * 1000;           // 10 minutos
const BRUTE_FORCE_THRESHOLD = 5;                         // intentos

const UNUSUAL_SESSION_WINDOW_MS = 60 * 60 * 1000;       // 1 hora
const UNUSUAL_SESSION_THRESHOLD = 2;                     // IPs distintas

// ── Credential Stuffing ───────────────────────────────────────────────────────

/**
 * Detecta credential stuffing: > N logins fallidos desde IPs distintas en 5 min.
 * Se llama tras cada LOGIN_FALLIDO, independientemente del usuario.
 *
 * @returns true si se detectó y registró una anomalía
 */
export function checkCredentialStuffing(correlationId: string | null): boolean {
  const since = Date.now() - CREDENTIAL_STUFFING_WINDOW_MS;
  const distinctIps = auditLogsRepository.countDistinctIpsByType('LOGIN_FALLIDO', since);

  if (distinctIps > CREDENTIAL_STUFFING_THRESHOLD) {
    auditLogsRepository.create({
      user_id: null,
      event_type: 'ANOMALIA_CREDENTIAL_STUFFING',
      ip_hash: null,
      correlation_id: correlationId,
      metadata: {
        distinct_ips: distinctIps,
        window_ms: CREDENTIAL_STUFFING_WINDOW_MS,
        threshold: CREDENTIAL_STUFFING_THRESHOLD,
      },
    });

    logger.warn(
      { anomaly: 'CREDENTIAL_STUFFING', distinct_ips: distinctIps },
      `[ANOMALÍA] Credential stuffing detectado: ${distinctIps} IPs distintas en 5 minutos`,
    );

    return true;
  }
  return false;
}

// ── Brute Force ───────────────────────────────────────────────────────────────

/**
 * Detecta fuerza bruta: > N logins fallidos del mismo usuario en 10 min.
 * Se llama tras cada LOGIN_FALLIDO de un usuario conocido.
 *
 * Complementa el account lockout — registra el evento de anomalía antes de
 * que el lockout actúe, y puede detectar patrones distribuidos más sutiles.
 *
 * @returns true si se detectó y registró una anomalía
 */
export function checkBruteForce(
  userId: string,
  ipHash: string,
  correlationId: string | null,
): boolean {
  const since = Date.now() - BRUTE_FORCE_WINDOW_MS;
  const recentFailures = auditLogsRepository.countRecentByType('LOGIN_FALLIDO', since, userId);

  if (recentFailures > BRUTE_FORCE_THRESHOLD) {
    auditLogsRepository.create({
      user_id: userId,
      event_type: 'ANOMALIA_FUERZA_BRUTA',
      ip_hash: ipHash,
      correlation_id: correlationId,
      metadata: {
        failures: recentFailures,
        window_ms: BRUTE_FORCE_WINDOW_MS,
        threshold: BRUTE_FORCE_THRESHOLD,
      },
    });

    logger.warn(
      { anomaly: 'BRUTE_FORCE', userId, failures: recentFailures },
      `[ANOMALÍA] Fuerza bruta detectada para usuario ${userId}: ${recentFailures} intentos en 10 minutos`,
    );

    return true;
  }
  return false;
}

// ── Sesión Inusual ────────────────────────────────────────────────────────────

/**
 * Detecta sesión inusual: mismo family_id usado desde > N IPs distintas en 1h.
 * Se llama tras cada TOKEN_RENOVADO exitoso.
 *
 * Indicador de posible robo de Refresh Token compartido entre múltiples clientes.
 *
 * @returns true si se detectó y registró una anomalía
 */
export function checkUnusualSession(
  familyId: string,
  ipHash: string,
  userId: string,
  correlationId: string | null,
): boolean {
  const since = Date.now() - UNUSUAL_SESSION_WINDOW_MS;
  const distinctIps = auditLogsRepository.countDistinctIpsByFamily(familyId, since);

  if (distinctIps > UNUSUAL_SESSION_THRESHOLD) {
    auditLogsRepository.create({
      user_id: userId,
      event_type: 'ANOMALIA_SESION_INUSUAL',
      ip_hash: ipHash,
      correlation_id: correlationId,
      metadata: {
        family_id: familyId,
        distinct_ips: distinctIps,
        window_ms: UNUSUAL_SESSION_WINDOW_MS,
        threshold: UNUSUAL_SESSION_THRESHOLD,
      },
    });

    logger.warn(
      { anomaly: 'UNUSUAL_SESSION', familyId, distinct_ips: distinctIps },
      `[ANOMALÍA] Sesión inusual detectada: family ${familyId} usado desde ${distinctIps} IPs distintas en 1h`,
    );

    return true;
  }
  return false;
}
