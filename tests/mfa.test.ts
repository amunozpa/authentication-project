/**
 * Tests MFA / TOTP — Fase 8
 *
 * Cubre:
 *   · GET  /mfa/status
 *   · POST /mfa/setup
 *   · POST /mfa/enable (código correcto, incorrecto, double-enable)
 *   · DELETE /mfa/disable
 *   · POST /mfa/verify (login paso 2)
 *   · POST /mfa/recovery
 *   · POST /mfa/step-up
 *   · GET  /mfa/protected
 */
import request from 'supertest';
import { authenticator } from 'otplib';
import { app } from '../src/app';
import { db } from '../src/db/index';

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

// ── GET /mfa/status ───────────────────────────────────────────────────────────

describe('GET /api/v1/mfa/status', () => {
  it('devuelve mfa_enabled=false para usuario sin MFA', async () => {
    const email = `mfa-st-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .get('/api/v1/mfa/status')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.mfa_enabled).toBe(false);
    expect(res.body.recovery_codes_remaining).toBe(0);
    expect(res.body).toHaveProperty('siguiente_paso');
  });

  it('→ 401 sin autenticación', async () => {
    const res = await request(app).get('/api/v1/mfa/status');
    expect(res.status).toBe(401);
  });
});

// ── POST /mfa/setup ───────────────────────────────────────────────────────────

describe('POST /api/v1/mfa/setup', () => {
  it('devuelve secret, otpauth_uri y qr_code data URL', async () => {
    const email = `mfa-su-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .post('/api/v1/mfa/setup')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('secret');
    expect(res.body).toHaveProperty('otpauth_uri');
    expect(res.body).toHaveProperty('qr_code');
    expect(res.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect(res.body.qr_code).toMatch(/^data:image\/png;base64,/);
    expect(Array.isArray(res.body.instrucciones)).toBe(true);
  });

  it('→ 401 sin autenticación', async () => {
    const res = await request(app).post('/api/v1/mfa/setup');
    expect(res.status).toBe(401);
  });
});

// ── MFA — flujo completo: enable → verify → recovery → step-up → disable ──────

describe('MFA flujo completo (enable → verify → recovery → step-up → disable)', () => {
  let email: string;
  let accessToken: string; // obtenido ANTES de activar MFA (sigue siendo válido)
  let mfaSecret: string;
  let recoveryCodes: string[] = [];

  beforeAll(async () => {
    email = `mfa-flow-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    // Obtener AT antes de activar MFA — este AT sigue siendo válido tras activar MFA
    accessToken = await loginForToken(email);
    // Setup → obtener secret TOTP
    const setupRes = await request(app)
      .post('/api/v1/mfa/setup')
      .set('Authorization', `Bearer ${accessToken}`);
    mfaSecret = setupRes.body.secret as string;
  });

  // ── Enable ────────────────────────────────────────────────────────────────

  it('POST /mfa/enable → 400 con secret demasiado corto', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ secret: 'short', totp_code: '123456' });

    expect(res.status).toBe(400);
  });

  it('POST /mfa/enable → 401 con código TOTP incorrecto', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ secret: mfaSecret, totp_code: '000000' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOTP_INVALIDO');
  });

  it('POST /mfa/enable → 200 con código TOTP correcto — devuelve 8 recovery codes', async () => {
    const totpCode = authenticator.generate(mfaSecret);
    const res = await request(app)
      .post('/api/v1/mfa/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ secret: mfaSecret, totp_code: totpCode });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
    expect(res.body).toHaveProperty('recovery_codes');
    expect(Array.isArray(res.body.recovery_codes)).toBe(true);
    expect(res.body.recovery_codes.length).toBe(8);
    expect(Array.isArray(res.body.aviso)).toBe(true);
    recoveryCodes = res.body.recovery_codes as string[];
  });

  it('POST /mfa/enable → 409 cuando MFA ya está activo', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ secret: mfaSecret, totp_code: '123456' });

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('MFA_YA_ACTIVO');
  });

  it('POST /mfa/setup → 409 cuando MFA ya está activo', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/setup')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('MFA_YA_ACTIVO');
  });

  it('GET /mfa/status → mfa_enabled=true con 8 códigos restantes', async () => {
    const res = await request(app)
      .get('/api/v1/mfa/status')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.mfa_enabled).toBe(true);
    expect(res.body.recovery_codes_remaining).toBe(8);
  });

  // ── Login con MFA activo ──────────────────────────────────────────────────

  it('POST /auth/login con MFA activo → devuelve mfa_session_token (no accessToken)', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.mfa_required).toBe(true);
    expect(loginRes.body).toHaveProperty('mfa_session_token');
    expect(loginRes.body).not.toHaveProperty('accessToken');
  });

  // ── /mfa/verify ──────────────────────────────────────────────────────────

  it('POST /mfa/verify → 400 sin campos requeridos', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/verify')
      .send({});

    expect(res.status).toBe(400);
  });

  it('POST /mfa/verify → 401 con mfa_session_token inválido', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/verify')
      .send({ mfa_session_token: 'bad-token', totp_code: '123456' });

    expect(res.status).toBe(401);
  });

  it('POST /mfa/verify → 401 con TOTP incorrecto', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const mfaToken = loginRes.body.mfa_session_token as string;

    const res = await request(app)
      .post('/api/v1/mfa/verify')
      .send({ mfa_session_token: mfaToken, totp_code: '000000' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOTP_INVALIDO');
  });

  it('POST /mfa/verify → 200 con TOTP correcto — emite AT + RT', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const mfaToken = loginRes.body.mfa_session_token as string;

    const totpCode = authenticator.generate(mfaSecret);
    const res = await request(app)
      .post('/api/v1/mfa/verify')
      .send({ mfa_session_token: mfaToken, totp_code: totpCode });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.tokenType).toBe('Bearer');
    expect(typeof res.body.familyId).toBe('string');
  });

  // ── /mfa/recovery ─────────────────────────────────────────────────────────

  it('POST /mfa/recovery → 400 con formato de código inválido', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const mfaToken = loginRes.body.mfa_session_token as string;

    const res = await request(app)
      .post('/api/v1/mfa/recovery')
      .send({ mfa_session_token: mfaToken, recovery_code: 'bad-format' });

    expect(res.status).toBe(400);
  });

  it('POST /mfa/recovery → 401 con mfa_session_token inválido', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/recovery')
      .send({ mfa_session_token: 'bad-token', recovery_code: 'AAAA-BBBB' });

    expect(res.status).toBe(401);
  });

  it('POST /mfa/recovery → 200 con código de recuperación válido', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const mfaToken = loginRes.body.mfa_session_token as string;

    const res = await request(app)
      .post('/api/v1/mfa/recovery')
      .send({ mfa_session_token: mfaToken, recovery_code: recoveryCodes[0]! });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    // Con 7 restantes no debe haber aviso
    expect(res.body.aviso).toBeUndefined();
  });

  it('POST /mfa/recovery → 401 con código de recuperación ya usado', async () => {
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const mfaToken = loginRes.body.mfa_session_token as string;

    // El mismo código usado en el test anterior ya fue marcado como 'used'
    const res = await request(app)
      .post('/api/v1/mfa/recovery')
      .send({ mfa_session_token: mfaToken, recovery_code: recoveryCodes[0]! });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('CODIGO_INVALIDO');
  });

  // ── /mfa/step-up ──────────────────────────────────────────────────────────

  it('POST /mfa/step-up → 401 con TOTP incorrecto', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/step-up')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: '000000' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOTP_INVALIDO');
  });

  it('POST /mfa/step-up → 400 con código TOTP malformado', async () => {
    const res = await request(app)
      .post('/api/v1/mfa/step-up')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: 'abc' });

    expect(res.status).toBe(400);
  });

  it('POST /mfa/step-up → 200 con TOTP correcto — emite step_up_token de 10 min', async () => {
    const totpCode = authenticator.generate(mfaSecret);
    const res = await request(app)
      .post('/api/v1/mfa/step-up')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: totpCode });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('step_up_token');
    expect(res.body.expires_in).toBe(600);
    expect(res.body).toHaveProperty('uso');
  });

  // ── /mfa/protected ────────────────────────────────────────────────────────

  it('GET /mfa/protected → 403 sin X-Step-Up-Token (STEP_UP_REQUERIDO)', async () => {
    const res = await request(app)
      .get('/api/v1/mfa/protected')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('STEP_UP_REQUERIDO');
  });

  it('GET /mfa/protected → 401 sin Authorization', async () => {
    const res = await request(app).get('/api/v1/mfa/protected');
    expect(res.status).toBe(401);
  });

  it('GET /mfa/protected → 200 con AT + step_up_token válido', async () => {
    const totpCode = authenticator.generate(mfaSecret);
    const stepUpRes = await request(app)
      .post('/api/v1/mfa/step-up')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: totpCode });
    const stepUpToken = stepUpRes.body.step_up_token as string;

    const res = await request(app)
      .get('/api/v1/mfa/protected')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('X-Step-Up-Token', stepUpToken);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
    expect(res.body.userId).toBeTruthy();
    expect(Array.isArray(res.body.roles)).toBe(true);
  });

  // ── /mfa/disable ──────────────────────────────────────────────────────────

  it('DELETE /mfa/disable → 400 con código TOTP malformado', async () => {
    const res = await request(app)
      .delete('/api/v1/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: 'abc' });

    expect(res.status).toBe(400);
  });

  it('DELETE /mfa/disable → 401 con TOTP incorrecto', async () => {
    const res = await request(app)
      .delete('/api/v1/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: '000000' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOTP_INVALIDO');
  });

  it('DELETE /mfa/disable → 200 con TOTP correcto — desactiva MFA', async () => {
    const totpCode = authenticator.generate(mfaSecret);
    const res = await request(app)
      .delete('/api/v1/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: totpCode });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('DELETE /mfa/disable → 409 cuando MFA ya está desactivado', async () => {
    const res = await request(app)
      .delete('/api/v1/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totp_code: '123456' });

    expect(res.status).toBe(409);
    expect(res.body.code).toBe('MFA_NO_ACTIVO');
  });
});

// ── POST /mfa/step-up sin MFA activo ─────────────────────────────────────────

describe('POST /mfa/step-up cuando MFA no está activo', () => {
  it('→ 400 MFA_NO_ACTIVO', async () => {
    const email = `mfa-noa-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const token = await loginForToken(email);

    const res = await request(app)
      .post('/api/v1/mfa/step-up')
      .set('Authorization', `Bearer ${token}`)
      .send({ totp_code: '123456' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('MFA_NO_ACTIVO');
  });
});
