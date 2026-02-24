/**
 * Middleware de control de acceso por scopes — Fase 3
 * Úsalo con API Keys y OAuth tokens que llevan scopes granulares.
 * Uso: router.get('/data', apiKeyAuth, requireScope('read:data'), handler)
 */
import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';

/**
 * Exige que req.user.scopes contenga TODOS los scopes especificados.
 * Debe usarse DESPUÉS del middleware apiKeyAuth() u oauthAuth().
 */
export function requireScope(...scopes: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError(401, 'No autenticado', 'NO_AUTENTICADO'));
    }

    const userScopes = req.user.scopes ?? [];
    const missing = scopes.filter((s) => !userScopes.includes(s));

    if (missing.length > 0) {
      return next(
        new AppError(
          403,
          `Scope insuficiente — se requiere: ${missing.join(', ')}`,
          'SIN_SCOPE',
        ),
      );
    }

    next();
  };
}
