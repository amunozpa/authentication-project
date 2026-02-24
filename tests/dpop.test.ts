/**
 * Tests DPoP (RFC 9449) — Fase 8
 *
 * Cubre:
 *   · GET  /dpop/info
 *   · POST /dpop/token — éxito, credenciales inválidas, proof inválido, replay
 *   · GET  /dpop/protected — éxito, esquema incorrecto, replay, AT sin cnf.jkt
 *   · computeJwkThumbprint (EC, OKP, RSA, tipo no soportado)
 *   · dpopReplay cache — isDpopJtiSeen, markDpopJtiSeen, TTL vencido
 */
import request from 'supertest';
import { generateKeyPairSync, createHash } from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { app } from '../src/app';
import { db } from '../src/db/index';
import { computeJwkThumbprint } from '../src/services/dpopService';
import { isDpopJtiSeen, markDpopJtiSeen, _getCacheSize } from '../src/cache/dpopReplay';

// ── EC keypair para proofs en tests ──────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const ecJwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;

/**
 * Crea un DPoP proof JWT para usar en los tests.
 * Host fijo = 'localhost' → htu predecible.
 */
function createDpopProof(
  htm: string,
  htu: string,
  accessToken?: string,
  overrides: Record<string, unknown> = {},
): string {
  const ath = accessToken
    ? createHash('sha256').update(accessToken).digest('base64url')
    : undefined;

  return jwt.sign(
    {
      jti: uuidv4(),
      htm,
      htu,
      iat: Math.floor(Date.now() / 1000),
      ...(ath !== undefined ? { ath } : {}),
      ...overrides,
    },
    privateKeyPem,
    {
      algorithm: 'ES256',
      header: { alg: 'ES256', typ: 'dpop+jwt', jwk: ecJwk },
    } as unknown as jwt.SignOptions,
  );
}

/** Host fijo — el servidor construye htu como `${protocol}://${req.get('host')}${path}` */
const TEST_HOST = 'localhost';
const BASE_URL = `http://${TEST_HOST}/api/v1/dpop`;

async function createVerifiedUser(email: string) {
  await request(app).post('/api/v1/auth/register').send({ email, password: 'password123' });
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
  return user.id;
}

// ── GET /dpop/info ─────────────────────────────────────────────────────────────

describe('GET /api/v1/dpop/info', () => {
  it('devuelve descripción educativa del protocolo DPoP', async () => {
    const res = await request(app).get('/api/v1/dpop/info');

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('protocolo');
    expect(res.body).toHaveProperty('flujo');
    expect(res.body).toHaveProperty('proof_jwt');
    expect(res.body).toHaveProperty('endpoints');
    expect(Array.isArray(res.body.flujo)).toBe(true);
  });
});

// ── POST /dpop/token ───────────────────────────────────────────────────────────

describe('POST /api/v1/dpop/token', () => {
  let email: string;

  beforeAll(async () => {
    email = `dpop-tok-${Date.now()}@example.com`;
    await createVerifiedUser(email);
  });

  it('→ 401 sin header DPoP (DPOP_PROOF_REQUERIDO)', async () => {
    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .send({ email, password: 'password123' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_PROOF_REQUERIDO');
  });

  it('→ 400 con DPoP que no es un JWT válido', async () => {
    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', 'not-a-jwt-string')
      .send({ email, password: 'password123' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('DPOP_INVALIDO');
  });

  it('→ 400 con typ incorrecto en el proof header', async () => {
    const wrongTypProof = jwt.sign(
      { jti: uuidv4(), htm: 'POST', htu: `${BASE_URL}/token`, iat: Math.floor(Date.now() / 1000) },
      privateKeyPem,
      { algorithm: 'ES256', header: { alg: 'ES256', typ: 'JWT', jwk: ecJwk } } as unknown as jwt.SignOptions,
    );

    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', wrongTypProof)
      .send({ email, password: 'password123' });

    expect(res.status).toBe(400);
    expect(res.body.code).toBe('DPOP_INVALIDO');
  });

  it('→ 400 sin body válido (sin email)', async () => {
    const proof = createDpopProof('POST', `${BASE_URL}/token`);

    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ password: 'password123' });

    expect(res.status).toBe(400);
  });

  it('→ 401 con credenciales incorrectas', async () => {
    const proof = createDpopProof('POST', `${BASE_URL}/token`);

    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ email, password: 'wrong-password' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('CREDENCIALES_INVALIDAS');
  });

  it('→ 200 con proof válido y credenciales correctas — AT con cnf.jkt', async () => {
    const proof = createDpopProof('POST', `${BASE_URL}/token`);

    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ email, password: 'password123' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('access_token');
    expect(res.body.token_type).toBe('DPoP');
    expect(res.body.expires_in).toBe(15 * 60);
    expect(res.body).toHaveProperty('cnf');
    expect(res.body.cnf).toHaveProperty('jkt');
    expect(typeof res.body.cnf.jkt).toBe('string');
  });

  it('→ 401 DPOP_REPLAY al reusar el mismo jti', async () => {
    const fixedJti = `replay-${Date.now()}`;
    const iat = Math.floor(Date.now() / 1000);
    const proof = jwt.sign(
      { jti: fixedJti, htm: 'POST', htu: `${BASE_URL}/token`, iat },
      privateKeyPem,
      {
        algorithm: 'ES256',
        header: { alg: 'ES256', typ: 'dpop+jwt', jwk: ecJwk },
      } as unknown as jwt.SignOptions,
    );

    // Primer uso — debe funcionar (credenciales correctas)
    await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ email, password: 'password123' });

    // Segundo uso con el mismo proof → REPLAY
    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ email, password: 'password123' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_REPLAY');
  });

  it('→ 401 DPOP_HTM_INVALIDO con htm incorrecto en el proof', async () => {
    // htm = GET pero endpoint es POST
    const wrongHtmProof = createDpopProof('GET', `${BASE_URL}/token`);

    const res = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', wrongHtmProof)
      .send({ email, password: 'password123' });

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_HTM_INVALIDO');
  });
});

// ── GET /dpop/protected ────────────────────────────────────────────────────────

describe('GET /api/v1/dpop/protected', () => {
  let dpopAccessToken: string;
  let bearerAccessToken: string;

  beforeAll(async () => {
    const email = `dpop-prot-${Date.now()}@example.com`;
    await createVerifiedUser(email);

    // AT DPoP-bound
    const proof = createDpopProof('POST', `${BASE_URL}/token`);
    const tokenRes = await request(app)
      .post('/api/v1/dpop/token')
      .set('Host', TEST_HOST)
      .set('DPoP', proof)
      .send({ email, password: 'password123' });
    dpopAccessToken = tokenRes.body.access_token as string;

    // AT Bearer estándar (sin cnf.jkt) para probar TOKEN_NO_DPOP
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email, password: 'password123' });
    bearerAccessToken = loginRes.body.accessToken as string;
  });

  it('→ 401 DPOP_SCHEME_REQUERIDO sin Authorization header', async () => {
    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_SCHEME_REQUERIDO');
  });

  it('→ 401 DPOP_SCHEME_REQUERIDO con Authorization: Bearer (no DPoP scheme)', async () => {
    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `Bearer ${dpopAccessToken}`);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_SCHEME_REQUERIDO');
  });

  it('→ 401 DPOP_PROOF_REQUERIDO con Authorization: DPoP pero sin header DPoP', async () => {
    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${dpopAccessToken}`);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_PROOF_REQUERIDO');
  });

  it('→ 200 con AT DPoP-bound + proof válido', async () => {
    const proof = createDpopProof('GET', `${BASE_URL}/protected`, dpopAccessToken);

    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${dpopAccessToken}`)
      .set('DPoP', proof);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('acceso', 'concedido');
    expect(res.body).toHaveProperty('userId');
    expect(Array.isArray(res.body.roles)).toBe(true);
    expect(res.body).toHaveProperty('mensaje');
  });

  it('→ 401 DPOP_REPLAY al reusar el mismo proof en /protected', async () => {
    const proof = createDpopProof('GET', `${BASE_URL}/protected`, dpopAccessToken);

    // Primera vez
    await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${dpopAccessToken}`)
      .set('DPoP', proof);

    // Segunda vez con el mismo proof
    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${dpopAccessToken}`)
      .set('DPoP', proof);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_REPLAY');
  });

  it('→ 401 TOKEN_NO_DPOP con Bearer AT estándar (sin cnf.jkt)', async () => {
    const proof = createDpopProof('GET', `${BASE_URL}/protected`, bearerAccessToken);

    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${bearerAccessToken}`)
      .set('DPoP', proof);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('TOKEN_NO_DPOP');
  });

  it('→ 401 DPOP_HTU_INVALIDO cuando htu del proof no coincide', async () => {
    // Crear proof con htu incorrecto
    const wrongHtuProof = createDpopProof('GET', 'http://localhost/api/v1/dpop/wrong-path', dpopAccessToken);

    const res = await request(app)
      .get('/api/v1/dpop/protected')
      .set('Host', TEST_HOST)
      .set('Authorization', `DPoP ${dpopAccessToken}`)
      .set('DPoP', wrongHtuProof);

    expect(res.status).toBe(401);
    expect(res.body.code).toBe('DPOP_HTU_INVALIDO');
  });
});

// ── computeJwkThumbprint — tests unitarios ─────────────────────────────────────

describe('computeJwkThumbprint', () => {
  it('calcula thumbprint determinístico para clave EC P-256', () => {
    const jwkEc = {
      kty: 'EC' as const,
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };
    const t1 = computeJwkThumbprint(jwkEc);
    const t2 = computeJwkThumbprint(jwkEc);

    expect(typeof t1).toBe('string');
    expect(t1.length).toBeGreaterThan(10);
    expect(t1).toBe(t2); // determinístico
  });

  it('calcula thumbprint para clave OKP (Ed25519)', () => {
    const jwkOkp = {
      kty: 'OKP' as const,
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    };
    const result = computeJwkThumbprint(jwkOkp);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(10);
  });

  it('calcula thumbprint para clave RSA', () => {
    const jwkRsa = {
      kty: 'RSA' as const,
      e: 'AQAB',
      n: 'sA5FBe7TyEzaGDhFDLBimBjMJPzQBcM1P8mXMgvKVV9e7B3S5_3q8x_2a8b',
    };
    const result = computeJwkThumbprint(jwkRsa);
    expect(typeof result).toBe('string');
  });

  it('lanza error (AppError) para tipo de clave no soportado', () => {
    expect(() => {
      computeJwkThumbprint({ kty: 'UNSUPPORTED' } as never);
    }).toThrow();
  });
});

// ── dpopReplay cache — tests unitarios ─────────────────────────────────────────

describe('dpopReplay cache', () => {
  it('isDpopJtiSeen → false para jti nunca visto', () => {
    const jti = `fresh-${Date.now()}-${Math.random()}`;
    expect(isDpopJtiSeen(jti)).toBe(false);
  });

  it('isDpopJtiSeen → true después de markDpopJtiSeen con TTL activo', () => {
    const jti = `mark-${Date.now()}-${Math.random()}`;
    markDpopJtiSeen(jti, 60);
    expect(isDpopJtiSeen(jti)).toBe(true);
  });

  it('isDpopJtiSeen → false para jti con TTL ya vencido (limpieza lazy)', () => {
    const jti = `exp-${Date.now()}-${Math.random()}`;
    markDpopJtiSeen(jti, -1); // TTL negativo → ya expirado al instante
    expect(isDpopJtiSeen(jti)).toBe(false);
  });

  it('_getCacheSize → número no negativo', () => {
    expect(_getCacheSize()).toBeGreaterThanOrEqual(0);
  });
});
