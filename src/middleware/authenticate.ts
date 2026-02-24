/**
 * Middleware de autenticación JWT — Fase 3
 * Verifica el Access Token del header Authorization: Bearer <token>.
 * Adjunta req.user con userId y roles para uso en rutas protegidas.
 */
import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/jwtService';
import { AppError } from './errorHandler';

/**
 * Middleware que exige un JWT válido.
 * Rechaza tokens expirados, con alg:none, algoritmo incorrecto o kid desconocido.
 */
export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError(
        401,
        'Se requiere autenticación — incluye Authorization: Bearer <token>',
        'NO_AUTENTICADO',
      );
    }

    const token = authHeader.slice(7);

    // Prevenir que API Keys pasen por aquí accidentalmente
    if (token.startsWith('sk_live_')) {
      throw new AppError(
        401,
        'Las API Keys no son tokens JWT — usa el middleware de API Keys',
        'TOKEN_INVALIDO',
      );
    }

    const payload = verifyAccessToken(token);

    req.user = {
      userId: payload.sub,
      roles: payload.roles,
      jti: payload.jti,
      scopes: payload.scopes,   // presente en tokens M2M y Client Credentials
    };

    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Versión opcional: adjunta req.user si hay token válido, pero no bloquea si no hay.
 * Útil para rutas que tienen comportamiento diferente si el usuario está autenticado.
 */
export function optionalAuthenticate(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ') || authHeader.slice(7).startsWith('sk_live_')) {
    return next();
  }

  try {
    const payload = verifyAccessToken(authHeader.slice(7));
    req.user = { userId: payload.sub, roles: payload.roles, jti: payload.jti, scopes: payload.scopes };
  } catch {
    // Token inválido pero opcional — continuar sin req.user
  }

  next();
}
