/**
 * Middleware de permisos RBAC — Fase 5.12
 *
 * Alternativa a requireRole que trabaja con permisos granulares en lugar
 * de roles concretos. La ruta declara QUÉ necesita hacer; el sistema
 * resuelve qué roles lo permiten.
 *
 * Uso:
 *   router.post('/content', authenticate, requirePermission('write:content'), handler)
 *   router.get('/admin/users', authenticate, requirePermission('read:users'), handler)
 *
 * Ventaja sobre requireRole:
 *   Si en el futuro se añade un rol 'moderator' con 'publish:content', solo
 *   hay que actualizar ROLE_PERMISSIONS — las rutas no cambian.
 */
import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { hasPermission, ROLE_PERMISSIONS } from '../config/permissions';
import type { Permission } from '../config/permissions';
import type { UserRole } from '../types';

/**
 * Exige que el usuario autenticado tenga el permiso especificado
 * (resuelto a partir de sus roles).
 *
 * Debe usarse DESPUÉS del middleware authenticate() o equivalente.
 */
export function requirePermission(permission: Permission) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      return next(new AppError(401, 'No autenticado', 'NO_AUTENTICADO'));
    }

    if (!hasPermission(req.user.roles as UserRole[], permission)) {
      // Calcular qué roles tendrían este permiso (para el mensaje de error)
      const rolesConPermiso = (Object.entries(ROLE_PERMISSIONS) as [UserRole, Permission[]][])
        .filter(([, perms]) => perms.includes(permission))
        .map(([role]) => role);

      return next(
        new AppError(
          403,
          `Permiso insuficiente — se requiere '${permission}' (roles: ${rolesConPermiso.join(', ')})`,
          'SIN_PERMISO',
        ),
      );
    }

    next();
  };
}
