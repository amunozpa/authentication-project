/**
 * Utilidades de hashing — Fase 2
 * SHA-256 para IPs (GDPR) y tokens de sesión.
 * bcrypt está en las capas de usuario y API keys (importado directamente donde se usa).
 */
import { createHash } from 'crypto';
import { config } from '../config/env';

/**
 * Hashea una IP con SHA-256 + salt configurable.
 * La IP nunca se almacena en claro en ninguna tabla — cumplimiento GDPR.
 *
 * @param ip - Dirección IP del cliente (IPv4 o IPv6)
 * @returns Hash hexadecimal de 64 chars
 */
export function hashIp(ip: string): string {
  return createHash('sha256')
    .update(ip + config.IP_HASH_SALT)
    .digest('hex');
}

/**
 * Hashea un token con SHA-256 para almacenamiento seguro.
 * Úsalo para session tokens y email tokens (no contraseñas — esas usan bcrypt).
 *
 * @param token - Token en texto plano
 * @returns Hash hexadecimal de 64 chars
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
