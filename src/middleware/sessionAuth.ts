/**
 * Middleware Session Token — Fase 3
 * Verifica tokens opacos almacenados en BD (distinto de JWT).
 * El token es un random de 32 bytes; se almacena su SHA-256 hash.
 */
import type { Request, Response, NextFunction } from 'express';
import { sessionsRepository } from '../db/repositories/sessions';
import { usersRepository } from '../db/repositories/users';
import { hashToken } from '../utils/hash';
import { AppError } from './errorHandler';
import type { UserRole } from '../types';

export function sessionAuthMiddleware(req: Request, _res: Response, next: NextFunction): void {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(401, 'Se requiere token de sesión en Authorization: Bearer', 'NO_AUTENTICADO');
    }

    const token = authHeader.slice(7);
    const tokenHash = hashToken(token);

    // Buscar sesión por hash (incluye verificación de expiración en la query)
    const session = sessionsRepository.findByHash(tokenHash);

    if (!session) {
      throw new AppError(401, 'Sesión inválida o expirada', 'SESION_INVALIDA');
    }

    // Cargar datos del usuario
    const user = usersRepository.findById(session.user_id);
    if (!user) {
      throw new AppError(401, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');
    }

    req.user = {
      userId: user.id,
      roles: JSON.parse(user.roles) as UserRole[],
    };

    next();
  } catch (err) {
    next(err);
  }
}
