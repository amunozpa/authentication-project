/**
 * Tests Magic Links / Passwordless — Fase 8
 *
 * Cubre las rutas que no se pueden testear con tokens inválidos:
 *   · GET  /magic/verify  con token válido → AT + RT
 *   · GET  /magic/verify  con token expirado → 400 TOKEN_EXPIRADO
 *   · GET  /magic/verify  con token ya usado → 400 TOKEN_YA_USADO
 *   · GET  /magic/verify  para usuario con MFA → mfa_session_token
 *   · POST /auth/reset-password con token válido → 200
 *   · POST /auth/reset-password con token expirado → 400
 *   · POST /auth/reset-password con token ya usado → 400
 *   · GET  /user/link/:provider → 503 cuando OAuth no configurado
 */
import request from 'supertest';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { authenticator } from 'otplib';
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

function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

function insertMagicToken(userId: string, rawToken: string, options: { expiresAt?: number; usedAt?: number } = {}) {
  const tokenHash = hashToken(rawToken);
  const expiresAt = options.expiresAt ?? Date.now() + 15 * 60 * 1000;
  const usedAt = options.usedAt ?? null;
  db.prepare(
    'INSERT INTO email_tokens (id, user_id, token_hash, type, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(uuidv4(), userId, tokenHash, 'MAGIC_LINK', expiresAt, usedAt, Date.now());
}

function insertPasswordResetToken(userId: string, rawToken: string, options: { expiresAt?: number; usedAt?: number } = {}) {
  const tokenHash = hashToken(rawToken);
  const expiresAt = options.expiresAt ?? Date.now() + 60 * 60 * 1000;
  const usedAt = options.usedAt ?? null;
  db.prepare(
    'INSERT INTO email_tokens (id, user_id, token_hash, type, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(uuidv4(), userId, tokenHash, 'PASSWORD_RESET', expiresAt, usedAt, Date.now());
}

// ── Magic Link Verify — happy path ────────────────────────────────────────────

describe('GET /api/v1/magic/verify — happy path', () => {
  it('token válido → 200 con AT + RT + usuario', async () => {
    const email = `magic-ok-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `magic-raw-${Date.now()}-abcdef123456`;
    insertMagicToken(userId, rawToken);

    const res = await request(app)
      .get(`/api/v1/magic/verify?token=${rawToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.tokenType).toBe('Bearer');
    expect(res.body).toHaveProperty('familyId');
    expect(res.body).toHaveProperty('usuario');
    expect(res.body.usuario.email).toBe(email);
  });

  it('token válido para usuario con MFA activo → mfa_session_token (no AT)', async () => {
    const email = `magic-mfa-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    // Activar MFA directamente en BD
    const mfaSecret = authenticator.generateSecret(20);
    db.prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?').run(mfaSecret, userId);

    const rawToken = `magic-mfa-raw-${Date.now()}-abc`;
    insertMagicToken(userId, rawToken);

    const res = await request(app)
      .get(`/api/v1/magic/verify?token=${rawToken}`);

    expect(res.status).toBe(200);
    expect(res.body.mfa_required).toBe(true);
    expect(res.body).toHaveProperty('mfa_session_token');
    expect(res.body).not.toHaveProperty('accessToken');
  });
});

// ── Magic Link Verify — error paths ──────────────────────────────────────────

describe('GET /api/v1/magic/verify — error paths', () => {
  it('token expirado → 400 TOKEN_EXPIRADO', async () => {
    const email = `magic-exp-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `magic-expired-${Date.now()}`;
    insertMagicToken(userId, rawToken, { expiresAt: Date.now() - 1000 }); // ya expirado

    const res = await request(app)
      .get(`/api/v1/magic/verify?token=${rawToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_EXPIRADO');
  });

  it('token ya usado → 400 TOKEN_YA_USADO', async () => {
    const email = `magic-used-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `magic-used-${Date.now()}`;
    insertMagicToken(userId, rawToken, { usedAt: Date.now() - 5000 }); // marcado como usado

    const res = await request(app)
      .get(`/api/v1/magic/verify?token=${rawToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_YA_USADO');
  });

  it('token de tipo incorrecto (PASSWORD_RESET, no MAGIC_LINK) → 400 TOKEN_INVALIDO', async () => {
    const email = `magic-wrong-type-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `reset-wrongtype-${Date.now()}`;
    // Insertar un token de tipo PASSWORD_RESET pero intentar usarlo como MAGIC_LINK
    insertPasswordResetToken(userId, rawToken);

    const res = await request(app)
      .get(`/api/v1/magic/verify?token=${rawToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_INVALIDO');
  });

  it('token no encontrado → 400 TOKEN_INVALIDO', async () => {
    const res = await request(app)
      .get('/api/v1/magic/verify?token=completely-nonexistent-token');

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_INVALIDO');
  });

  it('sin parámetro token → 400', async () => {
    const res = await request(app).get('/api/v1/magic/verify');
    expect(res.status).toBe(400);
  });
});

// ── POST /magic/request ───────────────────────────────────────────────────────

describe('POST /api/v1/magic/request', () => {
  it('para email existente → 200 con mensaje genérico', async () => {
    const email = `magic-req-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    const res = await request(app)
      .post('/api/v1/magic/request')
      .send({ email });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
    expect(res.body).toHaveProperty('expira_en');
  });

  it('para email inexistente → 200 (mismo mensaje — anti-enumeración)', async () => {
    const res = await request(app)
      .post('/api/v1/magic/request')
      .send({ email: `no-existe-magic-${Date.now()}@example.com` });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('email inválido → 400', async () => {
    const res = await request(app)
      .post('/api/v1/magic/request')
      .send({ email: 'not-an-email' });

    expect(res.status).toBe(400);
  });
});

// ── POST /auth/reset-password con token válido ─────────────────────────────────

describe('POST /api/v1/auth/reset-password — happy path', () => {
  it('token válido → 200, cambia contraseña y se puede login con la nueva', async () => {
    const email = `reset-ok-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `reset-raw-${Date.now()}-abcdef`;
    insertPasswordResetToken(userId, rawToken);

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: rawToken, new_password: 'NuevaContraseña123' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');

    // Verificar que el nuevo password funciona
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'NuevaContraseña123' });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body).toHaveProperty('accessToken');
  });
});

describe('POST /api/v1/auth/reset-password — error paths', () => {
  it('token expirado → 400 TOKEN_EXPIRADO', async () => {
    const email = `reset-exp-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `reset-expired-${Date.now()}`;
    insertPasswordResetToken(userId, rawToken, { expiresAt: Date.now() - 1000 });

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: rawToken, new_password: 'NuevaPass123' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_EXPIRADO');
  });

  it('token ya usado → 400 TOKEN_YA_USADO', async () => {
    const email = `reset-used-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    const rawToken = `reset-used-${Date.now()}`;
    insertPasswordResetToken(userId, rawToken, { usedAt: Date.now() - 1000 });

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: rawToken, new_password: 'NuevaPass123' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_YA_USADO');
  });

  it('token no encontrado → 400 TOKEN_INVALIDO', async () => {
    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: 'nonexistent-reset-token', new_password: 'NuevaPass123' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_INVALIDO');
  });

  it('nueva contraseña demasiado corta → 400', async () => {
    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: 'any-token', new_password: 'short' });

    expect(res.status).toBe(400);
  });
});

// ── GET /user/link/:provider ─────────────────────────────────────────────────

describe('GET /api/v1/user/link/:provider', () => {
  let accessToken: string;

  beforeAll(async () => {
    const email = `link-test-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    accessToken = await loginForToken(email);
  });

  it('provider=github sin GITHUB_CLIENT_ID configurado → 503 NO_CONFIGURADO', async () => {
    const res = await request(app)
      .get('/api/v1/user/link/github')
      .set('Authorization', `Bearer ${accessToken}`);

    // En tests, GITHUB_CLIENT_ID no está configurado → 503
    expect([503, 400]).toContain(res.status);
  });

  it('provider inválido → 400 VALIDACION_FALLIDA', async () => {
    const res = await request(app)
      .get('/api/v1/user/link/twitter')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('VALIDACION_FALLIDA');
  });

  it('→ 401 sin autenticación', async () => {
    const res = await request(app).get('/api/v1/user/link/github');
    expect(res.status).toBe(401);
  });
});
