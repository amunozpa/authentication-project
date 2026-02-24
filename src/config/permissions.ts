/**
 * Mapa de permisos RBAC — Fase 5.12
 *
 * El RBAC de este sistema tiene dos capas:
 *
 *  1. Roles (gruesos)  — 'admin' | 'editor' | 'user' | 'viewer'
 *     Asignados al usuario en la BD; incluidos en el JWT como `roles`.
 *
 *  2. Permisos (finos) — strings 'recurso:acción'
 *     Derivados de los roles en runtime; NO se almacenan ni se incluyen en el JWT.
 *     El middleware `requirePermission` resuelve permisos a partir de `req.user.roles`.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ JERARQUÍA DE ROLES                                                       │
 * │                                                                          │
 * │  admin ⊃ editor ⊃ user ⊃ viewer                                          │
 * │                                                                          │
 * │  viewer : solo lectura de contenido público                              │
 * │  user   : viewer + puede crear/editar su propio contenido               │
 * │  editor : user + puede publicar y gestionar todo el contenido           │
 * │  admin  : editor + gestión de usuarios, auditoría y claves              │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
import type { UserRole } from '../types';

// ── Catálogo de permisos ──────────────────────────────────────────────────────

export type Permission =
  // Contenido
  | 'read:content'       // leer contenido publicado
  | 'write:content'      // crear y editar contenido propio
  | 'publish:content'    // publicar, despublicar o eliminar cualquier contenido
  // Usuarios
  | 'read:own-profile'   // leer el perfil propio
  | 'read:users'         // listar / ver cualquier usuario (panel admin)
  | 'write:users'        // crear o editar cualquier usuario
  | 'delete:users'       // eliminar usuarios
  | 'manage:roles'       // asignar y revocar roles
  // Sistema
  | 'read:audit-logs'    // ver el log de auditoría
  | 'manage:keys';       // rotar claves JWT

// ── Mapa Role → Permisos ──────────────────────────────────────────────────────

export const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  viewer: [
    'read:content',
    'read:own-profile',
  ],

  user: [
    'read:content',
    'write:content',
    'read:own-profile',
  ],

  editor: [
    'read:content',
    'write:content',
    'publish:content',
    'read:own-profile',
    'read:users',        // puede ver lista de usuarios para asignar autoría
  ],

  admin: [
    'read:content',
    'write:content',
    'publish:content',
    'read:own-profile',
    'read:users',
    'write:users',
    'delete:users',
    'manage:roles',
    'read:audit-logs',
    'manage:keys',
  ],
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Devuelve el conjunto de permisos efectivos de un usuario dado sus roles.
 * Un usuario puede tener múltiples roles; los permisos se unen (OR).
 */
export function resolvePermissions(roles: UserRole[]): Set<Permission> {
  const perms = new Set<Permission>();
  for (const role of roles) {
    for (const perm of ROLE_PERMISSIONS[role] ?? []) {
      perms.add(perm);
    }
  }
  return perms;
}

/**
 * Devuelve true si el usuario tiene el permiso requerido dados sus roles.
 */
export function hasPermission(roles: UserRole[], permission: Permission): boolean {
  return resolvePermissions(roles).has(permission);
}
