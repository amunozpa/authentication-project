/**
 * GET /api/v1/health
 * Endpoint de salud para Docker health check y monitoreo externo.
 * No requiere autenticación.
 */
import { Router } from 'express';

const router = Router();

router.get('/', (_req, res) => {
  res.json({
    estado: 'activo',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version ?? '1.0.0',
  });
});

export default router;
