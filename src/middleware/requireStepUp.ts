/**
 * Middleware Step-up Authentication — Fase 5.6
 *
 * Verifica que el request incluye un step_up_token válido en el header X-Step-Up-Token.
 * Debe usarse DESPUÉS de authenticate (necesita req.user).
 *
 * Flujo:
 *   1. POST /mfa/step-up  → TOTP válido → step_up_token (10 min, firmado con JWT)
 *   2. Ruta sensible      → authenticate + requireStepUp → acceso concedido
 */
import type { Request, Response, NextFunction } from 'express';
import { verifyTemporaryToken } from '../services/jwtService';
import { AppError } from './errorHandler';

export function requireStepUp(req: Request, _res: Response, next: NextFunction): void {
  const stepUpToken = req.headers['x-step-up-token'];

  if (!stepUpToken || typeof stepUpToken !== 'string') {
    throw new AppError(
      403,
      'Se requiere autenticación Step-Up — llama a POST /api/v1/mfa/step-up con tu código TOTP',
      'STEP_UP_REQUERIDO',
    );
  }

  try {
    const payload = verifyTemporaryToken(stepUpToken, 'step_up');

    // El step_up token debe pertenecer al mismo usuario del AT
    if (payload.sub !== req.user!.userId) {
      throw new AppError(
        403,
        'El Step-Up token no corresponde al usuario autenticado',
        'STEP_UP_INVALIDO',
      );
    }

    next();
  } catch (err) {
    if (err instanceof AppError) {
      next(err);
      return;
    }
    next(new AppError(403, 'Step-Up token inválido o expirado', 'STEP_UP_INVALIDO'));
  }
}
