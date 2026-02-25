import { z } from 'zod';
import { registry, ErrorSchema } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/rbac/info',
  tags: ['RBAC'],
  summary: 'Información sobre RBAC y jerarquía de roles',
  description: 'Documenta la jerarquía de roles y permisos del sistema.',
  responses: {
    200: {
      description: 'Info RBAC',
      content: {
        'application/json': {
          schema: z.object({
            hierarchy: z.string().openapi({ example: 'admin ⊃ editor ⊃ user ⊃ viewer' }),
            roles: z.record(z.string(), z.array(z.string())).openapi({
              example: {
                admin: ['read:content', 'write:content', 'delete:content', 'read:users', 'delete:users', 'read:audit'],
                editor: ['read:content', 'write:content'],
                user: ['read:content'],
                viewer: ['read:content'],
              },
            }),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/rbac/content',
  tags: ['RBAC'],
  summary: 'Leer contenido (requiere read:content)',
  description: 'Accesible para todos los roles autenticados (viewer, user, editor, admin).',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Contenido accesible', content: { 'application/json': { schema: z.object({ data: z.array(z.object({ id: z.string(), title: z.string() })) }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Sin permiso', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/rbac/content',
  tags: ['RBAC'],
  summary: 'Crear contenido (requiere write:content)',
  description: 'Solo accesible para editor y admin.',
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: { 'application/json': { schema: z.object({ title: z.string(), body: z.string() }) } },
      required: true,
    },
  },
  responses: {
    201: { description: 'Contenido creado', content: { 'application/json': { schema: z.object({ id: z.string(), title: z.string() }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Sin permiso (viewer o user)', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'put',
  path: '/api/v1/rbac/content/{id}',
  tags: ['RBAC'],
  summary: 'Actualizar contenido (requiere write:content)',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({ id: z.string().openapi({ example: 'content-id-123' }) }),
    body: { content: { 'application/json': { schema: z.object({ title: z.string().optional(), body: z.string().optional() }) } }, required: true },
  },
  responses: {
    200: { description: 'Contenido actualizado', content: { 'application/json': { schema: z.object({ mensaje: z.string() }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Sin permiso', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/rbac/users',
  tags: ['RBAC'],
  summary: 'Listar usuarios (requiere read:users)',
  description: 'Solo accesible para admin.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Lista de usuarios', content: { 'application/json': { schema: z.object({ users: z.array(z.object({ id: z.string(), email: z.string(), roles: z.array(z.string()) })) }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Sin permiso (no es admin)', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/v1/rbac/users/{id}',
  tags: ['RBAC'],
  summary: 'Eliminar usuario (requiere delete:users)',
  description: 'Solo accesible para admin.',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid().openapi({ example: 'f47ac10b-...' }) }),
  },
  responses: {
    200: { description: 'Usuario eliminado', content: { 'application/json': { schema: z.object({ mensaje: z.string() }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Sin permiso', content: { 'application/json': { schema: ErrorSchema } } },
  },
});
