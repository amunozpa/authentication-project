/**
 * Correlation ID Middleware — Fase 1
 * Genera un UUID v4 por request, lo adjunta a req.correlationId
 * y lo propaga en el header X-Correlation-ID de la respuesta.
 * Permite trazar cualquier error hasta su request de origen.
 */
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
// Importar tipos para activar la augmentación de Express.Request
import type {} from '../types';

export function correlationIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Respetar el ID si ya viene del cliente (ej: microservicios internos)
  const incoming = req.headers['x-correlation-id'];
  const correlationId = typeof incoming === 'string' ? incoming : uuidv4();

  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);
  next();
}
