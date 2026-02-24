/**
 * Error Handler Centralizado — Fase 1
 * Captura todos los errores no manejados de Express y responde
 * con un formato JSON consistente en español.
 *
 * Formato de respuesta de error:
 * { "error": "Mensaje en español", "code": "CODIGO_ERROR", "correlationId": "uuid" }
 */
import { Request, Response, NextFunction } from 'express';
import { logger } from '../logger';
import type { ApiError } from '../types';

/**
 * Error operacional de la aplicación.
 * Úsalo para errores esperados (validación, autenticación, permisos).
 * Los errores NO operacionales (bugs) se manejan como 500 genérico.
 */
export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'AppError';
    // Necesario para que instanceof funcione correctamente con TypeScript
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

/**
 * Middleware de Express para manejo centralizado de errores.
 * DEBE ser el último middleware registrado (4 parámetros obligatorios).
 */
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  const correlationId = req.correlationId ?? 'desconocido';

  if (err instanceof AppError) {
    logger.warn(
      { correlationId, code: err.code, statusCode: err.statusCode },
      err.message,
    );
    const body: ApiError = {
      error: err.message,
      code: err.code,
      correlationId,
    };
    res.status(err.statusCode).json(body);
    return;
  }

  // Error de body-parser (JSON malformado) — body-parser asigna status=400
  const errWithStatus = err as { status?: number; statusCode?: number; expose?: boolean };
  if ((errWithStatus.status === 400 || errWithStatus.statusCode === 400) && errWithStatus.expose === true) {
    logger.warn({ correlationId, code: 'CUERPO_INVALIDO' }, 'Cuerpo de la petición inválido');
    const body: ApiError = {
      error: 'Cuerpo de la petición inválido — verifica el formato JSON',
      code: 'CUERPO_INVALIDO',
      correlationId,
    };
    res.status(400).json(body);
    return;
  }

  // Error inesperado — no exponer detalles internos al cliente
  logger.error({ correlationId, err }, 'Error interno no controlado');
  const body: ApiError = {
    error: 'Error interno del servidor',
    code: 'ERROR_INTERNO',
    correlationId,
  };
  res.status(500).json(body);
}
