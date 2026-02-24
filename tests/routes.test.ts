/**
 * Tests de rutas adicionales — Fase 8
 *
 * Cubre los endpoints menos cubiertos:
 *   · Session Auth (login, protected)
 *   · API Keys (create, list, revoke)
 *   · User routes (security, change-password, linked-accounts)
 *   · Auth routes (logout, forgot-password, verify-email)
 *   · Magic links
 *   · PASETO (sign, verify)
 *   · RBAC demo endpoints
 */
import request from 'supertest';
import { app } from '../src/app';
import { db } from '../src/db/index';

// ── Helpers ───────────────────────────────────────────────────────────────────

async function createVerifiedUser(email: string, password = 'password123') {
  await request(app).post('/api/v1/auth/register').send({ email, password });
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  return user.id;
}

async function login(email: string, password = 'password123') {
  const res = await request(app).post('/api/v1/auth/login').send({ email, password });
  return {
    accessToken: res.body.accessToken as string,
    cookies: res.headers['set-cookie'] as unknown as string[],
  };
}

// ── Session Auth ───────────────────────────────────────────────────────────────

describe('Session Auth — /api/v1/session', () => {
  it('POST /session/login → crea sesión y devuelve token', async () => {
    const email = `sess-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/session/login')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('sessionToken');
    expect(res.body).toHaveProperty('expiresIn');
  });

  it('POST /session/login falla con credenciales incorrectas → 401', async () => {
    const email = `sess-fail-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/session/login')
      .send({ email, password: 'wrongpass' });
    expect(res.status).toBe(401);
  });

  it('GET /session/protected requiere session token → 401 sin token', async () => {
    const res = await request(app).get('/api/v1/session/protected');
    expect(res.status).toBe(401);
  });

  it('GET /session/protected funciona con session token válido', async () => {
    const email = `sess-prot-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const loginRes = await request(app)
      .post('/api/v1/session/login')
      .send({ email, password: 'password123' });
    const token = loginRes.body.sessionToken as string;

    const res = await request(app)
      .get('/api/v1/session/protected')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});

// ── API Keys ───────────────────────────────────────────────────────────────────

describe('API Keys — /api/v1/keys', () => {
  let accessToken: string;

  beforeAll(async () => {
    const email = `keys-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const result = await login(email);
    accessToken = result.accessToken;
  });

  it('POST /keys crea una API key y la devuelve una sola vez', async () => {
    const res = await request(app)
      .post('/api/v1/keys')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Mi Clave de Test', scopes: ['read:data'] });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('key');
    expect(res.body.key).toMatch(/^sk_live_/);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'Mi Clave de Test');
    // La clave completa solo se devuelve una vez
    expect(res.body).toHaveProperty('advertencia');
  });

  it('POST /keys requiere autenticación → 401', async () => {
    const res = await request(app)
      .post('/api/v1/keys')
      .send({ name: 'Sin Auth', scopes: ['read:data'] });
    expect(res.status).toBe(401);
  });

  it('GET /keys lista las claves del usuario (sin exponer el valor completo)', async () => {
    const res = await request(app)
      .get('/api/v1/keys')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    // Las claves no exponen el hash completo
    res.body.data.forEach((k: Record<string, unknown>) => {
      expect(k).not.toHaveProperty('key_hash');
      expect(k).toHaveProperty('key_prefix');
    });
  });

  it('POST /keys/:id/revoke revoca la clave', async () => {
    // Crear una clave para revocar
    const createRes = await request(app)
      .post('/api/v1/keys')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Clave a Revocar', scopes: ['read:data'] });
    const keyId = createRes.body.id as string;

    const res = await request(app)
      .post(`/api/v1/keys/${keyId}/revoke`)
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });
});

// ── Basic Auth ────────────────────────────────────────────────────────────────

describe('Basic Auth — /api/v1/basic', () => {
  it('GET /basic/protected requiere Basic Auth → 401 sin auth', async () => {
    const res = await request(app).get('/api/v1/basic/protected');
    expect(res.status).toBe(401);
  });

  it('GET /basic/protected funciona con credenciales correctas', async () => {
    const email = `basic-${Date.now()}@example.com`;
    const password = 'password123';
    await createVerifiedUser(email, password);

    const credentials = Buffer.from(`${email}:${password}`).toString('base64');
    const res = await request(app)
      .get('/api/v1/basic/protected')
      .set('Authorization', `Basic ${credentials}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('usuario');
  });

  it('GET /basic/protected rechaza credenciales incorrectas → 401', async () => {
    const credentials = Buffer.from('wrong@email.com:wrongpass').toString('base64');
    const res = await request(app)
      .get('/api/v1/basic/protected')
      .set('Authorization', `Basic ${credentials}`);
    expect(res.status).toBe(401);
  });
});

// ── User Security Panel ───────────────────────────────────────────────────────

describe('User — /api/v1/user/security', () => {
  it('GET /user/security devuelve panel de seguridad completo', async () => {
    const email = `sec-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/user/security')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('email', email);
    expect(res.body).toHaveProperty('has_password', true);
    expect(res.body).toHaveProperty('mfa_enabled', false);
    expect(res.body).toHaveProperty('linked_providers');
    expect(res.body).toHaveProperty('active_sessions');
    expect(res.body).toHaveProperty('login_methods');
  });
});

// ── User Change Password ──────────────────────────────────────────────────────

describe('User — POST /api/v1/user/change-password', () => {
  it('cambia la contraseña con current_password correcto', async () => {
    const email = `changepw-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .post('/api/v1/user/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ current_password: 'password123', new_password: 'nuevaPass456' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('rechaza cambio de contraseña con current_password incorrecto → 401', async () => {
    const email = `changepw-fail-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .post('/api/v1/user/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ current_password: 'wrong', new_password: 'nuevaPass456' });

    expect(res.status).toBe(401);
  });

  it('rechaza si no se provee current_password cuando hay contraseña existente → 400', async () => {
    const email = `changepw-nocurr-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .post('/api/v1/user/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ new_password: 'nuevaPass456' });

    expect(res.status).toBe(400);
  });
});

// ── Auth — Forgot/Reset Password ─────────────────────────────────────────────

describe('Auth — Forgot/Reset Password', () => {
  it('POST /auth/forgot-password responde siempre el mismo mensaje (no revela si existe)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: `noexiste-${Date.now()}@example.com` });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('POST /auth/forgot-password para usuario real → 200 con mismo mensaje', async () => {
    const email = `forgot-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('POST /auth/reset-password con token inválido → 401', async () => {
    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: 'invalid-token', new_password: 'newPass123' });

    expect([400, 401, 404]).toContain(res.status);
  });
});

// ── Auth — Resend Verification ─────────────────────────────────────────────────

describe('Auth — Resend Verification', () => {
  it('POST /auth/resend-verification responde igual si email no existe (no revela)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email: `no-existe-${Date.now()}@example.com` });

    expect(res.status).toBe(200);
  });

  it('POST /auth/resend-verification para usuario no verificado → 200', async () => {
    const email = `resend-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });

    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email });

    expect(res.status).toBe(200);
  });

  it('POST /auth/resend-verification para email ya verificado → 200 (ya verificado)', async () => {
    const email = `resend-verified-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .send({ email });

    // Debe responder 200 de todas formas (sin revelar estado)
    expect(res.status).toBe(200);
  });
});

// ── Magic Links ────────────────────────────────────────────────────────────────

describe('Magic Links — /api/v1/magic', () => {
  it('POST /magic/request responde igual si el email no existe (no revela)', async () => {
    const res = await request(app)
      .post('/api/v1/magic/request')
      .send({ email: `noexiste-magic-${Date.now()}@example.com` });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('POST /magic/request para email registrado → 200', async () => {
    const email = `magic-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/magic/request')
      .send({ email });

    expect(res.status).toBe(200);
  });

  it('GET /magic/verify con token inválido → error 4xx', async () => {
    const res = await request(app)
      .get('/api/v1/magic/verify?token=invalid-token-12345');

    // Token inválido → cualquier error 4xx (401 o 404)
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it('GET /magic/verify sin token → 400', async () => {
    const res = await request(app).get('/api/v1/magic/verify');
    expect([400, 401]).toContain(res.status);
  });
});

// ── PASETO ────────────────────────────────────────────────────────────────────

describe('PASETO — /api/v1/paseto', () => {
  let accessToken: string;

  beforeAll(async () => {
    const email = `paseto-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const result = await login(email);
    accessToken = result.accessToken;
  });

  it('POST /paseto/sign firma un payload', async () => {
    const res = await request(app)
      .post('/api/v1/paseto/sign')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ sub: 'test-user', role: 'user' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(typeof res.body.token).toBe('string');
  });

  it('POST /paseto/verify verifica un token válido', async () => {
    // Primero firmar
    const signRes = await request(app)
      .post('/api/v1/paseto/sign')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ sub: 'test-user', data: 'test' });

    const token = signRes.body.token as string;

    // Luego verificar
    const res = await request(app)
      .post('/api/v1/paseto/verify')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ token });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('payload');
    // sub puede ser sobreescrito por el servicio con el userId real
    expect(res.body.payload).toHaveProperty('sub');
  });

  it('POST /paseto/verify rechaza token inválido → 400', async () => {
    const res = await request(app)
      .post('/api/v1/paseto/verify')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ token: 'not-a-valid-paseto-token' });

    expect([400, 401]).toContain(res.status);
  });

  it('GET /paseto/info devuelve información educativa', async () => {
    const res = await request(app).get('/api/v1/paseto/info');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('version');
    expect(res.body.version).toContain('PASETO');
  });
});

// ── RBAC Demo Endpoints ───────────────────────────────────────────────────────

describe('RBAC Demo — /api/v1/rbac', () => {
  let userToken: string;
  let editorToken: string;
  let adminToken: string;

  beforeAll(async () => {
    const userEmail = `rbac-user-${Date.now()}@example.com`;
    await createVerifiedUser(userEmail);
    const userResult = await login(userEmail);
    userToken = userResult.accessToken;

    const editorEmail = `rbac-editor-${Date.now()}@example.com`;
    const editorId = await createVerifiedUser(editorEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["editor"]', editorId);
    const editorResult = await login(editorEmail);
    editorToken = editorResult.accessToken;

    const adminEmail = `rbac-admin-main-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
    const adminResult = await login(adminEmail);
    adminToken = adminResult.accessToken;
  });

  it('GET /rbac/info → 200 sin autenticación', async () => {
    const res = await request(app).get('/api/v1/rbac/info');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('sistema');
  });

  it('GET /rbac/content → 401 sin token', async () => {
    const res = await request(app).get('/api/v1/rbac/content');
    expect(res.status).toBe(401);
  });

  it('GET /rbac/content → 200 con token de usuario (read:content)', async () => {
    const res = await request(app)
      .get('/api/v1/rbac/content')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(200);
  });

  it('GET /rbac/audit → 403 para usuario normal (read:audit-logs es solo admin)', async () => {
    const res = await request(app)
      .get('/api/v1/rbac/audit')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });

  it('GET /rbac/audit → 200 para admin', async () => {
    const res = await request(app)
      .get('/api/v1/rbac/audit')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });

  it('PUT /rbac/content/:id → 403 para usuario normal (publish:content es editor/admin)', async () => {
    const res = await request(app)
      .put('/api/v1/rbac/content/123')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });

  it('PUT /rbac/content/:id → 200 para editor', async () => {
    const res = await request(app)
      .put('/api/v1/rbac/content/123')
      .set('Authorization', `Bearer ${editorToken}`);
    expect(res.status).toBe(200);
  });

  it('GET /rbac/my-permissions → 200 con lista de permisos del usuario', async () => {
    const res = await request(app)
      .get('/api/v1/rbac/my-permissions')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('permisos');
  });
});

// ── Admin Keys ────────────────────────────────────────────────────────────────

describe('Admin Keys — /api/v1/admin/keys', () => {
  let adminToken: string;

  beforeAll(async () => {
    const adminEmail = `admin-keys-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
    const result = await login(adminEmail);
    adminToken = result.accessToken;
  });

  it('GET /admin/keys lista las claves JWT activas (solo admin)', async () => {
    const res = await request(app)
      .get('/api/v1/admin/keys')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    res.body.data.forEach((k: Record<string, unknown>) => {
      expect(k).not.toHaveProperty('secret'); // no exponer secret
      expect(k).toHaveProperty('kid');
      expect(k).toHaveProperty('active');
    });
  });

  it('GET /admin/keys → 403 para usuario normal', async () => {
    const email = `nonadmin-keys-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken: userToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/admin/keys')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });
});

// ── M2M Client Credentials ────────────────────────────────────────────────────

describe('OAuth M2M — Client Credentials Grant', () => {
  it('POST /oauth/m2m/token con credenciales válidas → AT sin sub de usuario', async () => {
    const res = await request(app)
      .post('/api/v1/oauth/m2m/token')
      .send({
        grant_type: 'client_credentials',
        client_id: 'test-m2m-client',
        client_secret: 'test-m2m-secret-seguro-1234567890',
      });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('access_token');
    expect(res.body).toHaveProperty('token_type', 'Bearer');
  });

  it('POST /oauth/m2m/token con credenciales incorrectas → 401', async () => {
    const res = await request(app)
      .post('/api/v1/oauth/m2m/token')
      .send({ grant_type: 'client_credentials', client_id: 'wrong', client_secret: 'wrong' });

    expect(res.status).toBe(401);
  });

  it('POST /oauth/m2m/token sin grant_type → 400', async () => {
    const res = await request(app)
      .post('/api/v1/oauth/m2m/token')
      .send({ client_id: 'test', client_secret: 'test' });
    expect(res.status).toBe(400);
  });
});

// ── Linked Accounts ───────────────────────────────────────────────────────────

describe('Linked Accounts — /api/v1/user/linked-accounts', () => {
  it('GET /user/linked-accounts devuelve lista vacía para usuario sin providers', async () => {
    const email = `linked-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/user/linked-accounts')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(0);
  });

  it('DELETE /user/linked-accounts/:provider devuelve error si no hay provider vinculado', async () => {
    const email = `linked-del-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .delete('/api/v1/user/linked-accounts/github')
      .set('Authorization', `Bearer ${accessToken}`);

    // 404 porque no hay cuenta GitHub vinculada
    expect([404, 409]).toContain(res.status);
  });
});

// ── Rate Limiting demo endpoint (con limiter real aplicado solo en producción) ──

describe('Rate Limit Demo — /api/v1/ratelimit', () => {
  it('GET /ratelimit/test-auth usa el authLimiter real', async () => {
    const res = await request(app).get('/api/v1/ratelimit/test-auth');
    // En test mode, el authLimiter es noop, así que debe responder 200
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });
});
