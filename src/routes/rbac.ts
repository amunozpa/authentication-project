/**
 * Rutas RBAC — Fase 5.12 (demo educativo)
 *
 * Demuestra Role-Based Access Control con dos capas:
 *   · requireRole('admin')          — control por rol directo
 *   · requirePermission('perm')     — control por permiso granular
 *
 *   GET  /api/v1/rbac/info               → explicación educativa del sistema
 *   GET  /api/v1/rbac/my-permissions     → introspección: permisos del usuario actual
 *   GET  /api/v1/rbac/content            → read:content  (viewer, user, editor, admin)
 *   POST /api/v1/rbac/content            → write:content (user, editor, admin)
 *   PUT  /api/v1/rbac/content/:id        → publish:content (editor, admin)
 *   GET  /api/v1/rbac/users              → read:users (editor, admin)
 *   DELETE /api/v1/rbac/users/:id        → delete:users (admin)
 *   GET  /api/v1/rbac/audit              → read:audit-logs (admin)
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ DIFERENCIA requireRole vs requirePermission                              │
 * │                                                                          │
 * │  requireRole('admin', 'editor')                                          │
 * │    → la ruta conoce los roles exactos; hay que actualizar la ruta       │
 * │      cada vez que se añade un rol nuevo.                                 │
 * │                                                                          │
 * │  requirePermission('publish:content')                                    │
 * │    → la ruta declara QUÉ necesita; basta actualizar ROLE_PERMISSIONS    │
 * │      cuando se añade un rol nuevo con ese permiso.                       │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import { Router } from 'express';
import { authenticate } from '../middleware/authenticate';
import { requirePermission } from '../middleware/requirePermission';
import { resolvePermissions, ROLE_PERMISSIONS } from '../config/permissions';
import type { UserRole } from '../types';

const router = Router();

// ── GET /info ─────────────────────────────────────────────────────────────────

router.get('/info', (_req, res) => {
  res.json({
    sistema: 'RBAC — Role-Based Access Control',
    descripcion:
      'Control de acceso en dos capas: roles (gruesos, en JWT) y permisos (finos, resueltos en runtime).',
    roles: Object.fromEntries(
      Object.entries(ROLE_PERMISSIONS).map(([role, perms]) => [role, perms]),
    ),
    ventaja_de_permisos: [
      'Las rutas declaran QUÉ necesitan hacer, no quién puede hacerlo.',
      'Añadir un rol nuevo solo requiere actualizar ROLE_PERMISSIONS.',
      'Los tests se escriben sobre permisos, no sobre roles específicos.',
    ],
    endpoints: {
      'GET /rbac/info':             'este endpoint (público)',
      'GET /rbac/my-permissions':   'permisos del usuario actual (autenticado)',
      'GET /rbac/content':          'read:content  → viewer, user, editor, admin',
      'POST /rbac/content':         'write:content → user, editor, admin',
      'PUT /rbac/content/:id':      'publish:content → editor, admin',
      'GET /rbac/users':            'read:users → editor, admin',
      'DELETE /rbac/users/:id':     'delete:users → admin',
      'GET /rbac/audit':            'read:audit-logs → admin',
    },
  });
});

// ── GET /my-permissions ───────────────────────────────────────────────────────

/**
 * Introspección: devuelve los permisos efectivos del usuario autenticado.
 * Útil para que el frontend adapte la UI (ocultar botones sin permiso).
 */
router.get('/my-permissions', authenticate, (req, res) => {
  const roles = req.user!.roles as UserRole[];
  const perms = [...resolvePermissions(roles)];

  res.json({
    userId: req.user!.userId,
    roles,
    permisos: perms,
    total: perms.length,
    nota: 'Estos permisos se derivan de tus roles en runtime — no se almacenan en el JWT.',
  });
});

// ── GET /content — read:content (viewer+) ─────────────────────────────────────

router.get('/content', authenticate, requirePermission('read:content'), (req, res) => {
  res.json({
    acceso: 'concedido',
    permiso: 'read:content',
    recurso: 'Lista de artículos publicados',
    userId: req.user!.userId,
    roles: req.user!.roles,
    articulos: [
      { id: 1, titulo: 'Introducción a RBAC', estado: 'publicado' },
      { id: 2, titulo: 'OAuth 2.0 explicado', estado: 'publicado' },
      { id: 3, titulo: 'DPoP: sender-constrained tokens', estado: 'publicado' },
    ],
  });
});

// ── POST /content — write:content (user+) ────────────────────────────────────

router.post('/content', authenticate, requirePermission('write:content'), (req, res) => {
  res.status(201).json({
    acceso: 'concedido',
    permiso: 'write:content',
    accion: 'Artículo creado (simulado)',
    userId: req.user!.userId,
    roles: req.user!.roles,
    nota: 'En producción, un "user" solo puede editar su propio contenido (resource ownership check adicional).',
  });
});

// ── PUT /content/:id — publish:content (editor+) ─────────────────────────────

router.put('/content/:id', authenticate, requirePermission('publish:content'), (req, res) => {
  res.json({
    acceso: 'concedido',
    permiso: 'publish:content',
    accion: `Artículo ${req.params.id} publicado (simulado)`,
    userId: req.user!.userId,
    roles: req.user!.roles,
  });
});

// ── GET /users — read:users (editor+) ────────────────────────────────────────

router.get('/users', authenticate, requirePermission('read:users'), (req, res) => {
  res.json({
    acceso: 'concedido',
    permiso: 'read:users',
    recurso: 'Lista de usuarios del sistema',
    userId: req.user!.userId,
    roles: req.user!.roles,
    nota: 'En producción conectaría con usersRepository.findAll() con paginación.',
  });
});

// ── DELETE /users/:id — delete:users (admin) ─────────────────────────────────

router.delete('/users/:id', authenticate, requirePermission('delete:users'), (req, res) => {
  res.json({
    acceso: 'concedido',
    permiso: 'delete:users',
    accion: `Usuario ${req.params.id} eliminado (simulado)`,
    userId: req.user!.userId,
    roles: req.user!.roles,
    advertencia: 'Solo admin puede llegar aquí — ni editor ni user tienen delete:users.',
  });
});

// ── GET /audit — read:audit-logs (admin) ─────────────────────────────────────

router.get('/audit', authenticate, requirePermission('read:audit-logs'), (req, res) => {
  res.json({
    acceso: 'concedido',
    permiso: 'read:audit-logs',
    recurso: 'Log de auditoría del sistema',
    userId: req.user!.userId,
    roles: req.user!.roles,
    nota: 'En producción conectaría con auditLogsRepository.findRecent() con paginación.',
  });
});

export default router;
