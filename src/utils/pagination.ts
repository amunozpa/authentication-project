/**
 * Utilidades de paginación con cursor — Fase 2
 * El cursor codifica (createdAt, id) para paginación estable.
 * Evita el problema de offset-based pagination cuando hay inserciones concurrentes.
 */
import type { PaginatedResponse } from '../types';

export interface CursorData {
  createdAt: number;
  id: string;
}

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;

/**
 * Codifica un cursor para el cliente.
 * El cliente lo devuelve opaco — no necesita conocer su estructura interna.
 */
export function encodeCursor(data: CursorData): string {
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

/**
 * Decodifica un cursor recibido del cliente.
 * Si el cursor es inválido lanza un error (se captura en el error handler).
 */
export function decodeCursor(cursor: string): CursorData {
  try {
    const decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString()) as unknown;
    if (
      typeof decoded !== 'object' ||
      decoded === null ||
      typeof (decoded as CursorData).createdAt !== 'number' ||
      typeof (decoded as CursorData).id !== 'string'
    ) {
      throw new Error('Estructura de cursor inválida');
    }
    return decoded as CursorData;
  } catch {
    throw new Error('Cursor de paginación inválido');
  }
}

/**
 * Construye la respuesta paginada a partir de una lista de registros.
 * Pide un registro extra (limit + 1) para saber si hay más páginas.
 *
 * @param rows - Registros obtenidos de BD (limit + 1 filas solicitadas)
 * @param limit - Límite real de la página
 * @returns PaginatedResponse con cursor para la siguiente página
 */
export function buildPage<T extends { id: string; created_at: number }>(
  rows: T[],
  limit: number,
): PaginatedResponse<T> {
  const hasMore = rows.length > limit;
  const data = hasMore ? rows.slice(0, limit) : rows;
  const lastRow = data[data.length - 1];

  return {
    data,
    cursor:
      hasMore && lastRow
        ? encodeCursor({ createdAt: lastRow.created_at, id: lastRow.id })
        : null,
    hasMore,
  };
}

/**
 * Valida y normaliza el límite de página recibido del cliente.
 */
export function parseLimit(limit: unknown): number {
  const n = Number(limit);
  if (!Number.isInteger(n) || n < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(n, MAX_PAGE_SIZE);
}
