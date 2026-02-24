/**
 * Middleware API Key — Fase 3
 * Verifica API Keys tipo Stripe: sk_live_<64 hex chars>
 *
 * Proceso:
 * 1. Extraer los primeros 16 chars (prefijo) para buscar candidatos en BD
 * 2. bcrypt.compare de la key completa contra cada hash candidato
 * 3. Si coincide: adjuntar req.user con los scopes de la key
 *
 * Por qué prefijo + hash:
 * - No se puede buscar directamente por hash (el hash de bcrypt no es determinista)
 * - El prefijo permite filtrar en BD antes de la comparación bcrypt
 * - La key completa nunca se almacena en claro
 */
import type { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { apiKeysRepository } from '../db/repositories/apiKeys';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { hashIp } from '../utils/hash';
import { AppError } from './errorHandler';
import type { UserRole } from '../types';

const API_KEY_PREFIX = 'sk_live_';
const PREFIX_LENGTH = 16; // 'sk_live_' (8) + 8 chars random = 16

export async function apiKeyAuthMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith(`Bearer ${API_KEY_PREFIX}`)) {
      throw new AppError(
        401,
        'Se requiere API Key válida en Authorization: Bearer sk_live_...',
        'NO_AUTENTICADO',
      );
    }

    const fullKey = authHeader.slice(7); // quitar 'Bearer '
    const prefix = fullKey.slice(0, PREFIX_LENGTH); // 'sk_live_xxxxxxxx'

    // Buscar candidatos por prefijo (lookup rápido antes de bcrypt)
    const candidates = apiKeysRepository.findActiveByPrefix(prefix);

    if (candidates.length === 0) {
      throw new AppError(401, 'API Key inválida', 'API_KEY_INVALIDA');
    }

    // Comparar con bcrypt contra cada candidato (normalmente solo hay uno por prefijo)
    let matchedKey: (typeof candidates)[0] | null = null;
    for (const candidate of candidates) {
      const match = await bcrypt.compare(fullKey, candidate.key_hash);
      if (match) {
        matchedKey = candidate;
        break;
      }
    }

    if (!matchedKey) {
      auditLogsRepository.create({
        user_id: null,
        event_type: 'LOGIN_FALLIDO',
        ip_hash: hashIp(req.ip ?? ''),
        user_agent: req.headers['user-agent'] ?? null,
        correlation_id: req.correlationId,
        metadata: { metodo: 'api_key', prefijo: prefix },
      });
      throw new AppError(401, 'API Key inválida', 'API_KEY_INVALIDA');
    }

    // Actualizar last_used_at de forma asíncrona (no bloquear el request)
    setImmediate(() => apiKeysRepository.updateLastUsed(matchedKey!.id));

    req.user = {
      userId: matchedKey.user_id,
      roles: [] as UserRole[], // Las API Keys no tienen roles de usuario — usan scopes
      scopes: JSON.parse(matchedKey.scopes) as string[],
    };

    next();
  } catch (err) {
    next(err);
  }
}
