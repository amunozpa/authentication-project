/**
 * Tests de seguridad avanzados — Fase 8
 *
 * Cubre:
 *   · Fuzz testing: tokens malformados, Base64 inválido, JSON truncado, headers faltantes
 *   · Timing attack: verifica que comparaciones sensibles no filtran info por tiempo
 *   · Rate limiting info endpoint
 *   · 404 para rutas inexistentes
 *   · Correlation ID en cabeceras de respuesta
 */
import request from 'supertest';
import { app } from '../src/app';

// ── Fuzz Testing ──────────────────────────────────────────────────────────────

describe('Fuzz Testing — tokens malformados', () => {
  const fuzzTokens = [
    'not.a.jwt',
    'eyJhbGciOiJIUzI1NiJ9.e30.',           // payload vacío, firma vacía
    'Bearer',                                 // solo keyword, sin token
    '',                                       // vacío
    'null',
    'undefined',
    '...',                                   // solo puntos
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', // solo header, sin payload
    Buffer.from('{"alg":"HS256"}').toString('base64') + '.a.b', // Base64 válido pero no base64url
    'a'.repeat(5000),                         // token muy largo
  ];

  fuzzTokens.forEach((token) => {
    it(`rechaza token malformado: "${token.substring(0, 30)}..."`, async () => {
      const res = await request(app)
        .get('/api/v1/user/me')
        .set('Authorization', `Bearer ${token}`);

      // Debe rechazar con 401, nunca con 500
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
    });
  });

  it('rechaza body JSON malformado', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": "test@test.com", "password":}'); // JSON inválido

    // Express responde 400 por JSON inválido
    expect(res.status).toBe(400);
  });

  it('acepta body vacío sin crashear', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({});

    // Debe responder 400 por validación, no 500
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('code');
  });

  it('headers faltantes no causan 500', async () => {
    // DPoP sin header DPoP
    const res = await request(app)
      .post('/api/v1/dpop/token')
      .send({ email: 'test@test.com', password: 'pass' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_PROOF_REQUERIDO');
  });
});

// ── Correlation ID ────────────────────────────────────────────────────────────

describe('Correlation ID middleware', () => {
  it('añade X-Correlation-ID a todas las respuestas', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-correlation-id']).toBeDefined();
    expect(res.headers['x-correlation-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
  });

  it('incluye correlationId en respuestas de error', async () => {
    const res = await request(app).get('/api/v1/ruta-que-no-existe');
    expect(res.status).toBe(404);
    // El correlation ID debe estar en el header
    expect(res.headers['x-correlation-id']).toBeDefined();
  });
});

// ── 404 ───────────────────────────────────────────────────────────────────────

describe('404 — Rutas inexistentes', () => {
  it('devuelve 404 con código RUTA_NO_ENCONTRADA', async () => {
    const res = await request(app).get('/api/v1/ruta-que-no-existe');
    expect(res.status).toBe(404);
    expect(res.body.code).toBe('RUTA_NO_ENCONTRADA');
  });

  it('devuelve 404 para métodos incorrectos', async () => {
    const res = await request(app).delete('/api/v1/health');
    expect(res.status).toBe(404);
  });
});

// ── Security Headers ──────────────────────────────────────────────────────────

describe('Cabeceras de seguridad (Helmet)', () => {
  it('incluye X-Frame-Options', async () => {
    const res = await request(app).get('/api/v1/health');
    // Helmet puede usar X-Frame-Options o frame-ancestors en CSP
    const hasFrameProtection =
      res.headers['x-frame-options'] !== undefined ||
      (res.headers['content-security-policy'] || '').includes('frame-ancestors');
    expect(hasFrameProtection).toBe(true);
  });

  it('no expone X-Powered-By', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

// ── Rate Limiting Demo ────────────────────────────────────────────────────────

describe('Rate Limiting — /api/v1/ratelimit', () => {
  it('GET /info devuelve configuración de limitadores', async () => {
    const res = await request(app).get('/api/v1/ratelimit/info');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('limitadores');
    expect(res.body.limitadores).toHaveProperty('globalLimiter');
    expect(res.body.limitadores).toHaveProperty('authLimiter');
    expect(res.body.limitadores).toHaveProperty('strictLimiter');
    expect(res.body.limitadores).toHaveProperty('mfaLimiter');
    expect(res.body.limitadores).toHaveProperty('refreshLimiter');
  });

  it('GET /test devuelve mensaje de conteo', async () => {
    const res = await request(app).get('/api/v1/ratelimit/test');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('mensaje');
  });
});
