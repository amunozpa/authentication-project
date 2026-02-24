/**
 * Middleware de control de acceso por roles (RBAC) — Fase 3
 * Uso: router.get('/admin', authenticate, requireRole('admin'), handler)
 *
 * Diferencia semántica:
 * - 401 Unauthorized: no autenticado (falta token o es inválido)
 * - 403 Forbidden: autenticado pero sin permiso para este recurso
 */
import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import type { UserRole } from '../types';

/**
 * Exige que req.user tenga al menos uno de los roles especificados.
 * Debe usarse DESPUÉS del middleware authenticate().
 */
export function requireRole(...roles: UserRole[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError(401, 'No autenticado', 'NO_AUTENTICADO'));
    }

    const hasRole = roles.some((r) => req.user!.roles.includes(r));

    if (!hasRole) {
      return next(
        new AppError(
          403,
          `No tienes permiso para esta acción — se requiere: ${roles.join(' o ')}`,
          'SIN_PERMISO',
        ),
      );
    }

    next();
  };
}
