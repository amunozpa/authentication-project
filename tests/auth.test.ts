/**
 * Tests de autenticación — Fase 8
 *
 * Cubre:
 *   · Registro, verificación de email, login, logout
 *   · Account lockout (5 fallos → 423)
 *   · Login sin verificar email → 403 EMAIL_NO_VERIFICADO
 *   · JWT Family Tracking — reutilización de RT → TOKEN_ROBO_DETECTADO
 *   · Paginación de sesiones activas
 */
import request from 'supertest';
import { app } from '../src/app';
import { db } from '../src/db/index';
import { usersRepository } from '../src/db/repositories/users';
import { auditLogsRepository } from '../src/db/repositories/auditLogs';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Registra un usuario en la BD directamente para tests que necesitan un usuario ya creado */
async function createVerifiedUser(email: string, password = 'password123') {
  const res = await request(app)
    .post('/api/v1/auth/register')
    .send({ email, password });
  expect(res.status).toBe(201);

  // Verificar email directamente (sin necesidad de email real)
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as { id: string } | null;
  expect(user).not.toBeNull();
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user!.id);
  return user!.id;
}

/** Inicia sesión y devuelve el Access Token */
async function login(email: string, password = 'password123') {
  const res = await request(app)
    .post('/api/v1/auth/login')
    .send({ email, password });
  expect(res.status).toBe(200);
  return {
    accessToken: res.body.accessToken as string,
    cookies: res.headers['set-cookie'] as unknown as string[] | string,
  };
}

// ── Health check ──────────────────────────────────────────────────────────────

describe('GET /api/v1/health', () => {
  it('devuelve estado activo', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('estado', 'activo');
    expect(res.body).toHaveProperty('timestamp');
  });
});

// ── Registro ──────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/register', () => {
  it('crea un usuario con email_verified=0', async () => {
    const email = `test-reg-${Date.now()}@example.com`;
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('mensaje');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as { email_verified: number } | null;
    expect(user).not.toBeNull();
    expect(user!.email_verified).toBe(0);
  });

  it('responde 200 si el email ya existe (prevención de enumeración)', async () => {
    const email = `test-exists-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
    const res = await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
    expect(res.status).toBe(200); // mismo mensaje — no revela si existe
  });

  it('rechaza email inválido', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'no-es-un-email', password: 'password123' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDACION_FALLIDA');
  });

  it('rechaza contraseña corta (< 8 chars)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: `short-${Date.now()}@example.com`, password: '123' });
    expect(res.status).toBe(400);
  });
});

// ── Login ─────────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/login', () => {
  it('falla si el email no está verificado → 403 EMAIL_NO_VERIFICADO', async () => {
    const email = `test-unverified-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('EMAIL_NO_VERIFICADO');
  });

  it('login exitoso devuelve AT + cookie RT', async () => {
    const email = `test-login-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('tokenType', 'Bearer');
    expect(res.body).toHaveProperty('expiresIn', 900); // 15 min en segundos
    // Cookie RT debe estar presente
    const cookies = res.headers['set-cookie'] as unknown as string[] | string;
    const cookieStr = Array.isArray(cookies) ? cookies.join(';') : String(cookies ?? '');
    expect(cookieStr).toContain('refreshToken=');
    expect(cookieStr).toContain('HttpOnly');
  });

  it('credenciales incorrectas → 401 CREDENCIALES_INVALIDAS', async () => {
    const email = `test-wrongpass-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'wrong-password' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('CREDENCIALES_INVALIDAS');
  });

  it('email desconocido → 401 (mismo mensaje, no revela si existe)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('CREDENCIALES_INVALIDAS');
  });
});

// ── Account Lockout ───────────────────────────────────────────────────────────

describe('Account Lockout', () => {
  it('bloquea la cuenta tras 5 fallos consecutivos → 423', async () => {
    const email = `test-lockout-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    // 5 intentos fallidos
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/v1/auth/login')
        .send({ email, password: 'wrong' });
    }

    // El 6° intento (incluso con contraseña correcta) → 423
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(423);
    expect(res.body.code).toBe('CUENTA_BLOQUEADA');
  });

  it('admin puede desbloquear una cuenta → login funciona después', async () => {
    const email = `test-unlock-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    // Bloquear manualmente
    usersRepository.setLocked(userId, Date.now() + 60 * 60 * 1000);

    // Crear admin
    const adminEmail = `admin-unlock-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);

    const { accessToken: adminToken } = await login(adminEmail);

    // Desbloquear
    const unlockRes = await request(app)
      .post(`/api/v1/admin/users/${userId}/unlock`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(unlockRes.status).toBe(200);

    // Verificar que puede hacer login
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    expect(loginRes.status).toBe(200);
  });
});

// ── JWT Refresh + Family Tracking ─────────────────────────────────────────────

describe('JWT Refresh — Family Tracking', () => {
  it('refresh exitoso devuelve nuevo AT + rota cookie RT', async () => {
    const email = `test-refresh-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    const cookies = loginRes.headers['set-cookie'] as unknown as string[];
    const res = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', cookies);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    const newCookies = res.headers['set-cookie'] as unknown as string[];
    expect(newCookies.join(';')).toContain('refreshToken=');
  });

  it('reutilización de RT → 401 TOKEN_ROBO_DETECTADO (Family Tracking)', async () => {
    const email = `test-family-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    const originalCookies = loginRes.headers['set-cookie'] as unknown as string[];

    // Primer refresh — consume el RT original
    const firstRefresh = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', originalCookies);
    expect(firstRefresh.status).toBe(200);

    // Segundo refresh con el RT ORIGINAL (ya consumido) → TOKEN_ROBO_DETECTADO
    const stolenRefresh = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', originalCookies);

    expect(stolenRefresh.status).toBe(401);
    expect(stolenRefresh.body.code).toBe('TOKEN_ROBO_DETECTADO');

    // La familia debe estar revocada — el nuevo RT tampoco funciona
    const newCookies = firstRefresh.headers['set-cookie'] as unknown as string[];
    const afterRevokeRefresh = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', newCookies);
    expect(afterRevokeRefresh.status).toBe(401);
  });

  it('logout-all revoca todas las sesiones', async () => {
    const email = `test-logout-all-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken, cookies } = await login(email);

    const res = await request(app)
      .post('/api/v1/jwt/logout-all')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);

    // RT ya no funciona
    const cookieStr = Array.isArray(cookies) ? cookies : [cookies];
    const refresh = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', cookieStr);
    expect(refresh.status).toBe(401);
  });
});

// ── JWT Security — Ataques ────────────────────────────────────────────────────

describe('JWT Security — Ataques', () => {
  it('alg:none → 401 TOKEN_INVALIDO', async () => {
    // Construir token con alg:none manualmente (base64url)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'fake', roles: ['admin'], iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 900 })).toString('base64url');
    const fakeToken = `${header}.${payload}.`;

    const res = await request(app)
      .get('/api/v1/user/me')
      .set('Authorization', `Bearer ${fakeToken}`);

    expect(res.status).toBe(401);
  });

  it('token manipulado (payload alterado) → 401', async () => {
    const email = `test-tamper-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    // Decodificar y alterar el payload
    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    payload.roles = ['admin']; // escalada de privilegios
    const tamperedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const res = await request(app)
      .get('/api/v1/user/me')
      .set('Authorization', `Bearer ${tamperedToken}`);

    expect(res.status).toBe(401);
  });

  it('token expirado → 401', async () => {
    const expiredToken = require('jsonwebtoken').sign(
      { sub: 'test', jti: 'test-jti', kid: 'test-kid', roles: ['user'], iat: 1000, exp: 1001 },
      process.env['JWT_SECRET']!,
      { algorithm: 'HS256' }
    );

    const res = await request(app)
      .get('/api/v1/user/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
  });

  it('token sin Authorization header → 401', async () => {
    const res = await request(app).get('/api/v1/user/me');
    expect(res.status).toBe(401);
  });
});

// ── Sesiones activas ──────────────────────────────────────────────────────────

describe('GET /api/v1/jwt/sessions', () => {
  it('lista las sesiones activas del usuario', async () => {
    const email = `test-sessions-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/jwt/sessions')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('data');
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
    // Campos esperados en cada sesión
    const session = res.body.data[0];
    expect(session).toHaveProperty('id');
    expect(session).toHaveProperty('ip_hash');
    expect(session).toHaveProperty('created_at');
    expect(session).not.toHaveProperty('current_jti'); // No exponer jti
  });
});

// ── Logout ────────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/logout', () => {
  it('revoca la familia del RT actual', async () => {
    const email = `test-logout-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    const cookies = loginRes.headers['set-cookie'] as unknown as string[];
    const at = loginRes.body.accessToken as string;

    const logoutRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${at}`)
      .set('Cookie', cookies);
    expect(logoutRes.status).toBe(200);

    // RT ya no funciona
    const refresh = await request(app)
      .post('/api/v1/jwt/refresh')
      .set('Cookie', cookies);
    expect(refresh.status).toBe(401);
  });
});

// ── Verificación de email ─────────────────────────────────────────────────────

describe('Verificación de email', () => {
  it('usuario verifica email → puede hacer login', async () => {
    const email = `test-verify-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });

    // En tests, verificamos directamente desde la BD (sin servidor de email real)
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);

    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    expect(loginRes.status).toBe(200);
  });
});

// ── GET /me ───────────────────────────────────────────────────────────────────

describe('GET /api/v1/user/me', () => {
  it('devuelve el perfil del usuario autenticado', async () => {
    const email = `test-me-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/user/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('email', email);
    expect(res.body).toHaveProperty('roles');
    expect(res.body).not.toHaveProperty('password_hash'); // no exponer hash
    expect(res.body).not.toHaveProperty('mfa_secret');    // no exponer secret TOTP
  });
});

// ── GDPR — DELETE /me ─────────────────────────────────────────────────────────

describe('DELETE /api/v1/user/me — GDPR', () => {
  it('elimina la cuenta y todos los datos asociados', async () => {
    const email = `test-gdpr-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .delete('/api/v1/user/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('gdpr');

    // Usuario debe estar soft-deleted
    const deletedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as { deleted_at: number | null } | null;
    expect(deletedUser!.deleted_at).not.toBeNull();

    // Sessions debe estar vacío
    const sessions = db.prepare('SELECT COUNT(*) as c FROM sessions WHERE user_id = ?').get(userId) as { c: number };
    expect(sessions.c).toBe(0);

    // audit_logs deben estar anonimizados
    const auditLogs = db.prepare('SELECT * FROM audit_logs WHERE JSON_EXTRACT(metadata, \'$.deletedUserId\') = ?').all(userId) as { user_id: null }[];
    // Al menos el evento CUENTA_ELIMINADA existe y está anonimizado
    expect(auditLogs.length).toBeGreaterThan(0);
    // El user_id en el log del evento debe ser NULL (anonimizado)
    expect(auditLogs[0]!.user_id).toBeNull();
  });

  it('la cuenta eliminada no puede hacer login', async () => {
    const email = `test-gdpr-login-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    await request(app)
      .delete('/api/v1/user/me')
      .set('Authorization', `Bearer ${accessToken}`);

    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    expect(loginRes.status).toBe(401);
  });
});

// ── Admin — Gestión de usuarios ───────────────────────────────────────────────

describe('Admin — /api/v1/admin', () => {
  let adminToken: string;

  beforeAll(async () => {
    const adminEmail = `super-admin-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
    const result = await login(adminEmail);
    adminToken = result.accessToken;
  });

  it('GET /admin/users requiere rol admin', async () => {
    const userEmail = `nonAdmin-${Date.now()}@example.com`;
    await createVerifiedUser(userEmail);
    const { accessToken: userToken } = await login(userEmail);

    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });

  it('GET /admin/users devuelve lista paginada para admin', async () => {
    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body).toHaveProperty('hasMore');
    // No exponer password_hash
    res.body.data.forEach((u: Record<string, unknown>) => {
      expect(u).not.toHaveProperty('password_hash');
      expect(u).not.toHaveProperty('mfa_secret');
    });
  });

  it('GET /admin/anomalies devuelve lista de eventos de anomalía', async () => {
    // Insertar un evento de anomalía directamente para el test
    auditLogsRepository.create({
      event_type: 'ANOMALIA_CREDENTIAL_STUFFING',
      metadata: { test: true, distinct_ips: 15 },
    });

    const res = await request(app)
      .get('/api/v1/admin/anomalies')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body).toHaveProperty('severidad');
  });

  it('GET /admin/anomalies filtra por tipo', async () => {
    const res = await request(app)
      .get('/api/v1/admin/anomalies?type=credential_stuffing')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    res.body.data.forEach((e: { event_type: string }) => {
      expect(e.event_type).toBe('ANOMALIA_CREDENTIAL_STUFFING');
    });
  });
});

// ── RBAC ──────────────────────────────────────────────────────────────────────

describe('RBAC — Control de acceso basado en roles', () => {
  it('anónimo → 401 en rutas protegidas', async () => {
    const res = await request(app).get('/api/v1/user/me');
    expect(res.status).toBe(401);
  });

  it('usuario normal → 403 en /admin/*', async () => {
    const email = `test-rbac-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { accessToken } = await login(email);

    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it('admin → 200 en /admin/*', async () => {
    const adminEmail = `rbac-admin-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
    const { accessToken: adminToken } = await login(adminEmail);

    const res = await request(app)
      .get('/api/v1/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
  });
});

// ── Paginación ────────────────────────────────────────────────────────────────

describe('Paginación — cursor correcto, hasMore correcto', () => {
  it('GET /admin/users respeta el límite y devuelve cursor', async () => {
    const adminEmail = `pagination-admin-${Date.now()}@example.com`;
    const adminId = await createVerifiedUser(adminEmail);
    db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
    const { accessToken: adminToken } = await login(adminEmail);

    // Crear varios usuarios para la paginación
    for (let i = 0; i < 3; i++) {
      await createVerifiedUser(`page-user-${Date.now()}-${i}@example.com`);
    }

    const res = await request(app)
      .get('/api/v1/admin/users?limit=2')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeLessThanOrEqual(2);
    // Si hay más de 2 usuarios, debe haber cursor
    if (res.body.hasMore) {
      expect(res.body.cursor).not.toBeNull();
    }
  });
});
