/**
 * Tests de Detección de Anomalías — Fase 8
 *
 * Cubre:
 *   · Credential stuffing: > 10 LOGIN_FALLIDO desde IPs distintas en 5 min
 *   · Brute force: > 5 LOGIN_FALLIDO del mismo usuario en 10 min
 *   · GET /admin/anomalies — lista y filtrado
 */
import request from 'supertest';
import { app } from '../src/app';
import { db } from '../src/db/index';
import { auditLogsRepository } from '../src/db/repositories/auditLogs';

async function createVerifiedUser(email: string) {
  await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  return user.id;
}

async function loginAsAdmin() {
  const adminEmail = `anom-admin-${Date.now()}@example.com`;
  const adminId = await createVerifiedUser(adminEmail);
  db.prepare('UPDATE users SET roles = ? WHERE id = ?').run('["admin"]', adminId);
  const res = await request(app)
    .post('/api/v1/auth/login')
    .send({ email: adminEmail, password: 'password123' });
  return res.body.accessToken as string;
}

// ── Credential Stuffing ───────────────────────────────────────────────────────

describe('Detección de Credential Stuffing', () => {
  it('registra ANOMALIA_CREDENTIAL_STUFFING tras > 10 IPs distintas con fallos', async () => {
    const email = `cs-target-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    // Insertar 11 LOGIN_FALLIDO con IPs distintas directamente en audit_logs
    for (let i = 0; i < 11; i++) {
      auditLogsRepository.create({
        user_id: null,
        event_type: 'LOGIN_FALLIDO',
        ip_hash: `fake-ip-hash-${i}-${Date.now()}`,
        metadata: { intento: 1 },
      });
    }

    // El siguiente login fallido debe activar la detección
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: `nonexistent-${Date.now()}@example.com`, password: 'wrong' });

    // Verificar que se generó el evento de anomalía
    const anomalies = db
      .prepare("SELECT * FROM audit_logs WHERE event_type = 'ANOMALIA_CREDENTIAL_STUFFING' ORDER BY created_at DESC LIMIT 1")
      .all() as { event_type: string }[];

    expect(anomalies.length).toBeGreaterThan(0);
    expect(anomalies[0]!.event_type).toBe('ANOMALIA_CREDENTIAL_STUFFING');
  });
});

// ── Brute Force ───────────────────────────────────────────────────────────────

describe('Detección de Brute Force', () => {
  it('registra ANOMALIA_FUERZA_BRUTA tras > 5 fallos del mismo usuario en 10 min', async () => {
    const email = `bf-target-${Date.now()}@example.com`;
    const userId = await createVerifiedUser(email);

    // Insertar 6 LOGIN_FALLIDO para el mismo usuario directamente
    for (let i = 0; i < 6; i++) {
      auditLogsRepository.create({
        user_id: userId,
        event_type: 'LOGIN_FALLIDO',
        ip_hash: `test-ip-${i}`,
        metadata: { intento: i + 1 },
      });
    }

    // El siguiente intento fallido debe activar la detección
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'wrong' });

    // Verificar que se generó el evento ANOMALIA_FUERZA_BRUTA
    const anomalies = db
      .prepare(`SELECT * FROM audit_logs WHERE event_type = 'ANOMALIA_FUERZA_BRUTA' AND user_id = ? ORDER BY created_at DESC LIMIT 1`)
      .all(userId) as { event_type: string }[];

    expect(anomalies.length).toBeGreaterThan(0);
  });
});

// ── Admin Anomalies Endpoint ──────────────────────────────────────────────────

describe('GET /api/v1/admin/anomalies', () => {
  let adminToken: string;

  beforeAll(async () => {
    adminToken = await loginAsAdmin();
  });

  it('devuelve lista de anomalías', async () => {
    // Insertar anomalía de prueba
    auditLogsRepository.create({
      event_type: 'ANOMALIA_SESION_INUSUAL',
      metadata: { family_id: 'test-family', distinct_ips: 3 },
    });

    const res = await request(app)
      .get('/api/v1/admin/anomalies')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body).toHaveProperty('severidad');
    expect(res.body.severidad).toHaveProperty('ANOMALIA_CREDENTIAL_STUFFING', 'alta');
  });

  it('filtra por tipo unusual_session', async () => {
    auditLogsRepository.create({
      event_type: 'ANOMALIA_SESION_INUSUAL',
      metadata: { distinct_ips: 4 },
    });

    const res = await request(app)
      .get('/api/v1/admin/anomalies?type=unusual_session')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    res.body.data.forEach((e: { event_type: string }) => {
      expect(e.event_type).toBe('ANOMALIA_SESION_INUSUAL');
    });
  });

  it('filtra por tipo credential_stuffing', async () => {
    auditLogsRepository.create({
      event_type: 'ANOMALIA_CREDENTIAL_STUFFING',
      metadata: { distinct_ips: 12 },
    });

    const res = await request(app)
      .get('/api/v1/admin/anomalies?type=credential_stuffing')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    res.body.data.forEach((e: { event_type: string }) => {
      expect(e.event_type).toBe('ANOMALIA_CREDENTIAL_STUFFING');
    });
  });

  it('devuelve 401 sin token', async () => {
    const res = await request(app).get('/api/v1/admin/anomalies');
    expect(res.status).toBe(401);
  });

  it('devuelve 403 para usuario sin rol admin', async () => {
    const email = `nonadmin-anomaly-${Date.now()}@example.com`;
    await createVerifiedUser(email);
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    const userToken = loginRes.body.accessToken as string;

    const res = await request(app)
      .get('/api/v1/admin/anomalies')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(403);
  });
});
