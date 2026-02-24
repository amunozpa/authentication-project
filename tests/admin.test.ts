/**
 * Tests de administración — Fase 8
 *
 * Cubre:
 *   · GET  /admin/keys          (lista claves JWT)
 *   · POST /admin/keys/rotate   (rota clave JWT — solo dev)
 *   · GET  /admin/users         (lista paginada de usuarios)
 *   · POST /admin/users/:id/unlock   (desbloquea cuenta)
 *   · DELETE /admin/users/:id        (elimina cuenta — GDPR)
 */
import request from 'supertest';
import { app } from '../src/app';
import { db } from '../src/db/index';

// ── Helpers ───────────────────────────────────────────────────────────────────

async function createVerifiedUser(email: string) {
  await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  return user.id;
}

async function loginForToken(email: string, password = 'password123'): Promise<string> {
  const res = await request(app).post('/api/v1/auth/login').send({ email, password });
  return res.body.accessToken as string;
}

async function createAdmin(): Promise<{ adminId: string; adminToken: string }> {
  const email = `admin-${Date.now()}@example.com`;
  const adminId = await createVerifiedUser(email);
  db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
  const adminToken = await loginForToken(email);
  return { adminId, adminToken };
}

// ── GET /admin/keys ───────────────────────────────────────────────────────────

describe('GET /api/v1/admin/keys', () => {
  it('lista las claves JWT activas — no expone el secret', async () => {
    const { adminToken } = await createAdmin();

    const res = await request(app)
      .get('/api/v1/admin/keys')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    res.body.data.forEach((k: Record<string, unknown>) => {
      expect(k).not.toHaveProperty('secret');
      expect(k).toHaveProperty('kid');
      expect(k).toHaveProperty('active');
    });
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .get('/api/v1/admin/keys')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });

  it('→ 401 sin autenticación', async () => {
    const res = await request(app).get('/api/v1/admin/keys');
    expect(res.status).toBe(401);
  });
});

// ── POST /admin/keys/rotate ───────────────────────────────────────────────────

describe('POST /api/v1/admin/keys/rotate', () => {
  it('rota la clave JWT y devuelve nuevo kid — solo admin en no-prod', async () => {
    const { adminToken } = await createAdmin();

    const res = await request(app)
      .post('/api/v1/admin/keys/rotate')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
    expect(res.body).toHaveProperty('nuevo_kid');
    expect(res.body).toHaveProperty('todas_las_claves');
    expect(Array.isArray(res.body.todas_las_claves)).toBe(true);
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-rot-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .post('/api/v1/admin/keys/rotate')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });

  it('→ 401 sin autenticación', async () => {
    const res = await request(app).post('/api/v1/admin/keys/rotate');
    expect(res.status).toBe(401);
  });
});

// ── GET /admin/users ──────────────────────────────────────────────────────────

describe('GET /api/v1/admin/users', () => {
  let adminToken: string;

  beforeAll(async () => {
    const result = await createAdmin();
    adminToken = result.adminToken;

    // Crear algunos usuarios para listar
    await createVerifiedUser(`list-user1-${Date.now()}@example.com`);
    await createVerifiedUser(`list-user2-${Date.now()}@example.com`);
  });

  it('lista usuarios con paginación — muestra campos correctos', async () => {
    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    res.body.data.forEach((u: Record<string, unknown>) => {
      expect(u).toHaveProperty('id');
      expect(u).toHaveProperty('email');
      expect(u).toHaveProperty('roles');
      expect(u).toHaveProperty('email_verified');
      expect(u).not.toHaveProperty('password_hash'); // no exponer hash
    });
  });

  it('filtra por rol admin', async () => {
    const res = await request(app)
      .get('/api/v1/admin/users?role=admin')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    // Todos los devueltos deben tener rol admin
    res.body.data.forEach((u: { roles: string[] }) => {
      expect(u.roles).toContain('admin');
    });
  });

  it('filtra por rol user', async () => {
    const res = await request(app)
      .get('/api/v1/admin/users?role=user')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  it('respeta limit de paginación', async () => {
    const res = await request(app)
      .get('/api/v1/admin/users?limit=2')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeLessThanOrEqual(2);
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-list-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });
});

// ── POST /admin/users/:id/unlock ──────────────────────────────────────────────

describe('POST /api/v1/admin/users/:id/unlock', () => {
  let adminToken: string;

  beforeAll(async () => {
    const result = await createAdmin();
    adminToken = result.adminToken;
  });

  it('→ 404 para usuario inexistente', async () => {
    const res = await request(app)
      .post('/api/v1/admin/users/nonexistent-id/unlock')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('USUARIO_NO_ENCONTRADO');
  });

  it('→ 409 para usuario que no está bloqueado', async () => {
    const email = `unlock-nolocked-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const res = await request(app)
      .post(`/api/v1/admin/users/${userId}/unlock`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('CUENTA_NO_BLOQUEADA');
  });

  it('→ 200 al desbloquear cuenta bloqueada', async () => {
    const email = `unlock-locked-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    // Bloquear el usuario manualmente (lockout futuro)
    db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(
      Date.now() + 30 * 60 * 1000,
      userId,
    );

    const res = await request(app)
      .post(`/api/v1/admin/users/${userId}/unlock`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');

    // Verificar que el usuario ya no está bloqueado en BD
    const user = db.prepare('SELECT locked_until FROM users WHERE id = ?').get(userId) as { locked_until: number | null };
    expect(user.locked_until).toBeNull();
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-unlock-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .post('/api/v1/admin/users/some-id/unlock')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });
});

// ── DELETE /admin/users/:id ───────────────────────────────────────────────────

describe('DELETE /api/v1/admin/users/:id', () => {
  let adminToken: string;
  let adminId: string;

  beforeAll(async () => {
    const result = await createAdmin();
    adminToken = result.adminToken;
    adminId = result.adminId;
  });

  it('→ 404 para usuario inexistente', async () => {
    const res = await request(app)
      .delete('/api/v1/admin/users/nonexistent-id')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(404);
    expect(res.body.code).toBe('USUARIO_NO_ENCONTRADO');
  });

  it('→ 409 al intentar eliminar su propia cuenta', async () => {
    const res = await request(app)
      .delete(`/api/v1/admin/users/${adminId}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('OPERACION_NO_PERMITIDA');
  });

  it('→ 200 al eliminar cuenta de otro usuario', async () => {
    const email = `to-delete-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const res = await request(app)
      .delete(`/api/v1/admin/users/${userId}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-del-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .delete('/api/v1/admin/users/some-id')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });
});

// ── GET /admin/anomalies ──────────────────────────────────────────────────────

describe('GET /api/v1/admin/anomalies', () => {
  let adminToken: string;

  beforeAll(async () => {
    const result = await createAdmin();
    adminToken = result.adminToken;
  });

  it('→ 200 con lista de anomalías y mapa de severidad', async () => {
    const res = await request(app)
      .get('/api/v1/admin/anomalies')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body).toHaveProperty('severidad');
    expect(res.body.severidad).toHaveProperty('ANOMALIA_CREDENTIAL_STUFFING', 'alta');
  });

  it('respeta filtro ?type con paginación', async () => {
    const res = await request(app)
      .get('/api/v1/admin/anomalies?type=brute_force&limit=10')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  it('→ 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-anom-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .get('/api/v1/admin/anomalies')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });
});
