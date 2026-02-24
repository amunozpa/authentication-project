/**
 * Tests de cobertura específica — Fase 8
 *
 * Cubre las ramas que no se alcanzan con los otros test files:
 *   · GET  /auth/verify-email con token válido / expirado / ya usado
 *   · POST /auth/logout sin RT cookie
 *   · POST /auth/forgot-password con email inválido
 *   · POST /keys con body inválido → validación
 *   · GET  /keys/protected con API Key (requireScope happy + missing)
 *   · POST /session/logout
 *   · authenticate.ts — rechazo de API Key como Bearer JWT
 *   · optionalAuthenticate — llamada directa con token inválido
 */
import request from 'supertest';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import type { Request, Response } from 'express';
import { app } from '../src/app';
import { db } from '../src/db/index';
import { optionalAuthenticate } from '../src/middleware/authenticate';

// ── Helpers ───────────────────────────────────────────────────────────────────

async function createVerifiedUser(email: string) {
  await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  return user.id;
}

async function loginForToken(email: string, password = 'password123'): Promise<{ token: string; cookies: string[] }> {
  const res = await request(app).post('/api/v1/auth/login').send({ email, password });
  return {
    token: res.body.accessToken as string,
    cookies: (res.headers['set-cookie'] as unknown as string[]) ?? [],
  };
}

function insertEmailToken(
  userId: string,
  rawToken: string,
  type: string,
  options: { expiresAt?: number; usedAt?: number } = {},
) {
  const tokenHash = createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = options.expiresAt ?? Date.now() + 24 * 3600 * 1000;
  const usedAt = options.usedAt ?? null;
  db.prepare(
    'INSERT INTO email_tokens (id, user_id, token_hash, type, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(uuidv4(), userId, tokenHash, type, expiresAt, usedAt, Date.now());
}

// ── GET /auth/verify-email ────────────────────────────────────────────────────

describe('GET /api/v1/auth/verify-email — todos los flujos', () => {
  it('token VERIFY_EMAIL válido → 200 — email queda verificado', async () => {
    const email = `veremail-ok-${Date.now()}@example.com`;
    // Registrar sin verificar
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };

    const rawToken = `verify-ok-${Date.now()}`;
    insertEmailToken(user.id, rawToken, 'VERIFY_EMAIL');

    const res = await request(app).get(`/api/v1/auth/verify-email?token=${rawToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');

    // El usuario ya debería poder iniciar sesión
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body).toHaveProperty('accessToken');
  });

  it('token expirado → 400 TOKEN_EXPIRADO', async () => {
    const email = `veremail-exp-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };

    const rawToken = `verify-exp-${Date.now()}`;
    insertEmailToken(user.id, rawToken, 'VERIFY_EMAIL', { expiresAt: Date.now() - 1000 });

    const res = await request(app).get(`/api/v1/auth/verify-email?token=${rawToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_EXPIRADO');
  });

  it('token ya usado → 400 TOKEN_YA_USADO', async () => {
    const email = `veremail-used-${Date.now()}@example.com`;
    await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };

    const rawToken = `verify-used-${Date.now()}`;
    insertEmailToken(user.id, rawToken, 'VERIFY_EMAIL', { usedAt: Date.now() - 1000 });

    const res = await request(app).get(`/api/v1/auth/verify-email?token=${rawToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_YA_USADO');
  });

  it('token no encontrado → 400 TOKEN_INVALIDO', async () => {
    const res = await request(app).get('/api/v1/auth/verify-email?token=nonexistent-token');
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_INVALIDO');
  });

  it('sin parámetro token → 400 VALIDACION_FALLIDA', async () => {
    const res = await request(app).get('/api/v1/auth/verify-email');
    expect(res.status).toBe(400);
  });
});

// ── POST /auth/logout sin RT cookie ──────────────────────────────────────────

describe('POST /api/v1/auth/logout sin RT cookie', () => {
  it('→ 200 aunque no haya cookie de RT (log LOGOUT sin_rt_cookie=true)', async () => {
    const email = `logout-nocookie-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { token } = await loginForToken(email);

    // Llamar logout sin pasar la cookie del refresh token
    const res = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${token}`);
    // No enviamos .set('Cookie', cookies) — sin RT cookie

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });
});

// ── POST /auth/forgot-password con email inválido ─────────────────────────────

describe('POST /api/v1/auth/forgot-password — validación', () => {
  it('email inválido → 400 VALIDACION_FALLIDA', async () => {
    const res = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: 'not-an-email' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDACION_FALLIDA');
  });
});

// ── POST /keys con body inválido ──────────────────────────────────────────────

describe('POST /api/v1/keys — validación de cuerpo', () => {
  it('body vacío → 400 VALIDACION_FALLIDA', async () => {
    const email = `keys-invalid-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { token } = await loginForToken(email);

    const res = await request(app)
      .post('/api/v1/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({}); // sin name ni scopes

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDACION_FALLIDA');
  });
});

// ── GET /keys/protected — requireScope ────────────────────────────────────────

describe('GET /api/v1/keys/protected — requireScope', () => {
  let apiKeyWithScope: string;
  let apiKeyWithoutScope: string;

  beforeAll(async () => {
    const email = `apikey-scope-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const { token } = await loginForToken(email);

    // API Key CON read:data scope
    const createRes1 = await request(app)
      .post('/api/v1/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Key con scope', scopes: ['read:data'] });
    apiKeyWithScope = createRes1.body.key as string;

    // API Key SIN read:data scope (otro scope)
    const createRes2 = await request(app)
      .post('/api/v1/keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Key sin scope correcto', scopes: ['write:data'] });
    apiKeyWithoutScope = createRes2.body.key as string;
  });

  it('→ 200 con API Key que tiene read:data scope', async () => {
    const res = await request(app)
      .get('/api/v1/keys/protected')
      .set('Authorization', `Bearer ${apiKeyWithScope}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('→ 403 SIN_SCOPE con API Key sin read:data', async () => {
    const res = await request(app)
      .get('/api/v1/keys/protected')
      .set('Authorization', `Bearer ${apiKeyWithoutScope}`);

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('SIN_SCOPE');
  });

  it('→ 401 sin Authorization header', async () => {
    const res = await request(app).get('/api/v1/keys/protected');
    expect(res.status).toBe(401);
  });

  it('→ 401 con API Key no reconocida', async () => {
    const res = await request(app)
      .get('/api/v1/keys/protected')
      .set('Authorization', 'Bearer sk_live_FAKE_TEST_KEY_NOT_REAL_0000');

    expect(res.status).toBe(401);
  });
});

// ── authenticate.ts — rechazo de API Key como Bearer JWT ─────────────────────

describe('authenticate.ts — rechaza sk_live_ como Bearer JWT', () => {
  it('→ 401 TOKEN_INVALIDO cuando se envía API Key a endpoint JWT-protected', async () => {
    const res = await request(app)
      .get('/api/v1/mfa/status')
      .set('Authorization', 'Bearer sk_live_some_fake_api_key_12345678');

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_INVALIDO');
  });
});

// ── POST /session/logout ──────────────────────────────────────────────────────

describe('POST /api/v1/session/logout', () => {
  it('→ 200 al cerrar sesión con session token válido', async () => {
    const email = `sess-logout-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const loginRes = await request(app)
      .post('/api/v1/session/login')
      .send({ email, password: 'password123' });
    const sessionToken = loginRes.body.sessionToken as string;

    const res = await request(app)
      .post('/api/v1/session/logout')
      .set('Authorization', `Bearer ${sessionToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');

    // El token ya no debería funcionar
    const protRes = await request(app)
      .get('/api/v1/session/protected')
      .set('Authorization', `Bearer ${sessionToken}`);
    expect(protRes.status).toBe(401);
  });

  it('→ 401 sin session token', async () => {
    const res = await request(app).post('/api/v1/session/logout');
    expect(res.status).toBe(401);
  });
});

// ── optionalAuthenticate unit tests ───────────────────────────────────────────

describe('optionalAuthenticate — middleware de autenticación opcional', () => {
  it('sin Authorization header → llama next() sin req.user', (done) => {
    const mockReq = { headers: {} } as unknown as Request;
    const mockRes = {} as Response;
    optionalAuthenticate(mockReq, mockRes, () => {
      expect((mockReq as unknown as { user?: unknown }).user).toBeUndefined();
      done();
    });
  });

  it('con Authorization: Bearer sk_live_xxx → llama next() sin req.user', (done) => {
    const mockReq = {
      headers: { authorization: 'Bearer sk_live_some_api_key_here' },
    } as unknown as Request;
    const mockRes = {} as Response;
    optionalAuthenticate(mockReq, mockRes, () => {
      expect((mockReq as unknown as { user?: unknown }).user).toBeUndefined();
      done();
    });
  });

  it('con JWT inválido → llama next() sin req.user (token inválido ignorado)', (done) => {
    const mockReq = {
      headers: { authorization: 'Bearer invalid-jwt-token-not-valid' },
    } as unknown as Request;
    const mockRes = {} as Response;
    optionalAuthenticate(mockReq, mockRes, () => {
      expect((mockReq as unknown as { user?: unknown }).user).toBeUndefined();
      done();
    });
  });

  it('sin Bearer prefix → llama next() sin req.user', (done) => {
    const mockReq = {
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    } as unknown as Request;
    const mockRes = {} as Response;
    optionalAuthenticate(mockReq, mockRes, () => {
      expect((mockReq as unknown as { user?: unknown }).user).toBeUndefined();
      done();
    });
  });
});

// ── apiKeyAuthMiddleware — cases no cubiertos ─────────────────────────────────

describe('apiKeyAuthMiddleware — edge cases', () => {
  it('→ 401 sin Authorization header', async () => {
    const res = await request(app).get('/api/v1/keys/protected');
    expect(res.status).toBe(401);
  });

  it('→ 401 con Authorization: Bearer (sin sk_live_ prefix)', async () => {
    const res = await request(app)
      .get('/api/v1/keys/protected')
      .set('Authorization', 'Bearer normal-jwt-token');

    expect(res.status).toBe(401);
  });
});
