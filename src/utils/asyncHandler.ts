/**
 * Wrapper para route handlers async en Express 4.
 * Express 4 no captura errores de Promises automáticamente — se necesita
 * pasarlos manualmente a next(). Express 5 lo haría solo.
 */
import type { Request, Response, NextFunction } from 'express';

export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
}
