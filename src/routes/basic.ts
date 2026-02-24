/**
 * Rutas Basic Auth — Fase 3 (demostración educativa)
 * GET /api/v1/basic/protected
 *
 * Muestra cómo funciona RFC 7617 y sus limitaciones:
 * - Credenciales en cada request (sin estado)
 * - Base64 no es cifrado — solo codificación
 * - Requiere HTTPS para ser seguro (en HTTP las credenciales van en claro)
 */
import { Router } from 'express';
import { basicAuthMiddleware } from '../middleware/basicAuth';

const router = Router();

router.get('/protected', basicAuthMiddleware, (req, res) => {
  res.json({
    mensaje: 'Acceso concedido con Basic Auth',
    usuario: req.user?.userId,
    roles: req.user?.roles,
    advertencias: [
      'Basic Auth envía credenciales en CADA request',
      'Base64 no es cifrado — las credenciales son visibles en texto plano',
      'SIEMPRE requiere HTTPS en producción',
      'No tiene concepto de sesión ni revocación',
      'Para APIs modernas usa JWT o API Keys en su lugar',
    ],
    demo_ataque: {
      header_recibido: req.headers.authorization,
      decodificado: Buffer.from(
        (req.headers.authorization ?? '').slice(6),
        'base64',
      ).toString('utf-8'),
      conclusion: 'Cualquier intermediario con acceso al tráfico HTTP puede leer esto',
    },
  });
});

export default router;
