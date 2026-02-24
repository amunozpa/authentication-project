/**
 * DPoP Replay Protection Cache — Fase 2
 * Implementación: Map<jti, expiresAt> en memoria del proceso.
 *
 * RFC 9449 §11.1: el servidor DEBE rechazar proofs con jti ya visto.
 * El proof DPoP tiene un TTL de 60 segundos (iat ± 30s + margen).
 *
 * ⚠️  Limitación documentada:
 * Este cache es local al proceso. En un despliegue con múltiples réplicas,
 * un attacker podría reusar el mismo proof en una réplica distinta.
 * Solución para producción real: Redis con TTL (mismo patrón que rate limiter).
 * Para este laboratorio (single-instance) es suficiente.
 */

const cache = new Map<string, number>(); // jti → expiresAt (timestamp ms)

/**
 * Comprueba si un jti de proof DPoP ya fue visto (posible replay attack).
 * También limpia el entry si ya expiró (lazy cleanup).
 *
 * @returns true si el jti YA fue procesado (rechazar el request)
 */
export function isDpopJtiSeen(jti: string): boolean {
  const expiresAt = cache.get(jti);
  if (expiresAt === undefined) return false;

  if (Date.now() > expiresAt) {
    cache.delete(jti);
    return false; // expiró → ya no es válido como replay
  }

  return true; // visto y aún dentro del TTL → replay detectado
}

/**
 * Registra un jti de proof DPoP como procesado.
 * Se llama después de verificar y aceptar el proof.
 *
 * @param jti - Identificador único del proof DPoP
 * @param ttlSeconds - Tiempo de vida en segundos (default: 60s)
 */
export function markDpopJtiSeen(jti: string, ttlSeconds = 60): void {
  cache.set(jti, Date.now() + ttlSeconds * 1000);
}

/**
 * Limpieza periódica del cache.
 * Elimina entradas expiradas para evitar crecimiento ilimitado.
 * .unref() permite que el proceso termine aunque el interval esté activo.
 */
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [jti, expiresAt] of cache.entries()) {
    if (now > expiresAt) cache.delete(jti);
  }
}, 60_000);

// En tests, evitar que el interval bloquee el proceso
cleanupInterval.unref();

/** Solo para tests — permite inspeccionar el estado del cache */
export function _getCacheSize(): number {
  return cache.size;
}
