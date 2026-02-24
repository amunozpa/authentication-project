/**
 * Rutas OAuth 2.0 — Fase 5
 *
 * Flujos implementados:
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ Authorization Code + PKCE  (GitHub, Google)                     │
 * │ Client Credentials Grant   (M2M — POST /m2m/token)              │
 * │ Device Authorization Grant (RFC 8628 — POST /device/code, etc.) │
 * │ Implicit Flow              (demo histórica — GET /implicit/*)    │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * PKCE — ¿por qué?
 * - Previene que un atacante que intercepta el code pueda usarlo
 * - El code_verifier nunca sale del cliente; solo se envía el challenge
 * - GitHub no soporta PKCE (usa client_secret); Google sí desde 2021
 * - Guardamos code_verifier para ambos (educativo), pero solo Google lo valida
 */
import { Router } from 'express';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { config } from '../config/env';
import { oauthStatesRepository } from '../db/repositories/oauthStates';
import { deviceCodesRepository } from '../db/repositories/deviceCodes';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import {
  generatePkce,
  generateState,
  exchangeGithubCode,
  getGithubProfile,
  exchangeGoogleCode,
  getGoogleProfile,
  processOAuthLogin,
} from '../services/oauthService';
import { signM2mToken, issueTokenPair } from '../services/jwtService';
import { authenticate } from '../middleware/authenticate';
import { usersRepository } from '../db/repositories/users';
import { linkedIdentitiesRepository } from '../db/repositories/linkedIdentities';
import { linkAccount } from '../db/transactions';
import { asyncHandler } from '../utils/asyncHandler';
import { hashIp } from '../utils/hash';
import { AppError } from '../middleware/errorHandler';
import type { UserRole } from '../types';

const router = Router();

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;  // 10 minutos
const DEVICE_CODE_TTL_MS = 5 * 60 * 1000;   // 5 minutos (RFC 8628)
const DEVICE_POLL_INTERVAL = 5;              // segundos entre polls

// Charset sin chars confusos: sin 0/O, 1/I/L — para device user codes (RFC 8628)
const USER_CODE_CHARSET = 'BCDFGHJKMNPQRSTVWXYZ23456789';

function generateUserCode(): string {
  const bytes = randomBytes(8);
  const chars = Array.from(
    { length: 8 },
    (_, i) => USER_CODE_CHARSET[bytes[i]! % USER_CODE_CHARSET.length]!,
  );
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

// ── Authorization Code + PKCE — GitHub ───────────────────────────────────────

router.get('/github', (_req, res) => {
  if (!config.GITHUB_CLIENT_ID) {
    throw new AppError(503, 'OAuth GitHub no configurado — añade GITHUB_CLIENT_ID al .env', 'NO_CONFIGURADO');
  }

  const { codeVerifier, codeChallenge } = generatePkce();
  const state = generateState();

  // Guardar state + code_verifier en BD (TTL 10min)
  oauthStatesRepository.create({
    state,
    code_verifier: codeVerifier,
    provider: 'github',
    expires_at: Date.now() + OAUTH_STATE_TTL_MS,
  });

  // Construir URL de autorización de GitHub
  // Nota: GitHub no soporta code_challenge — solo state para CSRF
  const params = new URLSearchParams({
    client_id: config.GITHUB_CLIENT_ID,
    redirect_uri: config.GITHUB_CALLBACK_URL,
    scope: 'user:email',
    state,
  });

  // Log educativo: mostramos code_challenge aunque GitHub lo ignore
  auditLogsRepository.create({
    event_type: 'OAUTH_INICIO',
    ip_hash: hashIp(_req.ip ?? ''),
    correlation_id: _req.correlationId,
    metadata: {
      provider: 'github',
      pkce_challenge: codeChallenge,
      nota: 'GitHub no valida PKCE — usamos state para CSRF. Google sí valida PKCE.',
    },
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

router.get(
  '/github/callback',
  asyncHandler(async (req, res) => {
    const { code, state, error } = req.query;

    // El usuario denegó el acceso
    if (error) {
      throw new AppError(400, `GitHub OAuth denegado: ${String(error)}`, 'OAUTH_DENEGADO');
    }

    if (typeof code !== 'string' || typeof state !== 'string') {
      throw new AppError(400, 'Parámetros de callback inválidos', 'VALIDACION_FALLIDA');
    }

    // ── Verificar state (anti-CSRF) ────────────────────────────────────────
    const stateRecord = oauthStatesRepository.findByState(state);
    if (!stateRecord || stateRecord.provider !== 'github') {
      throw new AppError(400, 'State inválido o expirado — posible ataque CSRF', 'CSRF_DETECTADO');
    }
    oauthStatesRepository.delete(stateRecord.id); // one-time use

    auditLogsRepository.create({
      event_type: 'OAUTH_CALLBACK',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: { provider: 'github' },
    });

    // ── Intercambiar code → access_token ──────────────────────────────────
    // code_verifier disponible en stateRecord pero GitHub no lo valida
    const ghToken = await exchangeGithubCode(code);
    const profile = await getGithubProfile(ghToken);

    const ipHash = hashIp(req.ip ?? '');

    // ── Flujo de vinculación (link_user_id presente en el state) ───────────
    if (stateRecord.link_user_id) {
      const targetUserId = stateRecord.link_user_id;

      const existingIdentity = linkedIdentitiesRepository.findByProvider('github', profile.id);
      if (existingIdentity && existingIdentity.user_id !== targetUserId) {
        throw new AppError(
          409,
          'Esta cuenta de GitHub ya está vinculada a otro usuario',
          'PROVIDER_YA_VINCULADO',
        );
      }
      if (existingIdentity && existingIdentity.user_id === targetUserId) {
        throw new AppError(409, 'Ya tienes vinculada esta cuenta de GitHub', 'YA_VINCULADO');
      }

      linkAccount({
        userId: targetUserId,
        provider: 'github',
        providerId: profile.id,
        providerEmail: profile.email,
        accessToken: ghToken,
        auditData: { ipHash, correlationId: req.correlationId },
      });

      res.redirect(`${config.FRONTEND_URL}?linked=true&provider=github`);
      return;
    }

    // ── Flujo normal: login / registro ─────────────────────────────────────
    const { accessToken, refreshToken, isNew } = processOAuthLogin(
      'github',
      profile.id,
      profile.email,
      ghToken,
      req,
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Redirigir al frontend con el AT en la URL (Fase 6: frontend Alpine.js)
    res.redirect(`${config.FRONTEND_URL}?at=${accessToken}&provider=github&nuevo=${isNew ? '1' : '0'}`);
  }),
);

// ── Authorization Code + PKCE — Google ───────────────────────────────────────

router.get('/google', (_req, res) => {
  if (!config.GOOGLE_CLIENT_ID) {
    throw new AppError(503, 'OAuth Google no configurado — añade GOOGLE_CLIENT_ID al .env', 'NO_CONFIGURADO');
  }

  const { codeVerifier, codeChallenge } = generatePkce();
  const state = generateState();

  oauthStatesRepository.create({
    state,
    code_verifier: codeVerifier,
    provider: 'google',
    expires_at: Date.now() + OAUTH_STATE_TTL_MS,
  });

  // Google SÍ soporta PKCE — incluir code_challenge y method
  const params = new URLSearchParams({
    client_id: config.GOOGLE_CLIENT_ID,
    redirect_uri: config.GOOGLE_CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'online',
  });

  auditLogsRepository.create({
    event_type: 'OAUTH_INICIO',
    ip_hash: hashIp(_req.ip ?? ''),
    correlation_id: _req.correlationId,
    metadata: { provider: 'google', pkce_method: 'S256' },
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

router.get(
  '/google/callback',
  asyncHandler(async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
      throw new AppError(400, `Google OAuth denegado: ${String(error)}`, 'OAUTH_DENEGADO');
    }

    if (typeof code !== 'string' || typeof state !== 'string') {
      throw new AppError(400, 'Parámetros de callback inválidos', 'VALIDACION_FALLIDA');
    }

    const stateRecord = oauthStatesRepository.findByState(state);
    if (!stateRecord || stateRecord.provider !== 'google') {
      throw new AppError(400, 'State inválido o expirado — posible ataque CSRF', 'CSRF_DETECTADO');
    }

    const { code_verifier: codeVerifier } = stateRecord;
    oauthStatesRepository.delete(stateRecord.id);

    auditLogsRepository.create({
      event_type: 'OAUTH_CALLBACK',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: { provider: 'google' },
    });

    // Google valida code_verifier en el intercambio (PKCE completo)
    const googleToken = await exchangeGoogleCode(code, codeVerifier);
    const profile = await getGoogleProfile(googleToken);

    const ipHash2 = hashIp(req.ip ?? '');

    // ── Flujo de vinculación (link_user_id presente en el state) ───────────
    if (stateRecord.link_user_id) {
      const targetUserId = stateRecord.link_user_id;

      const existingIdentity = linkedIdentitiesRepository.findByProvider('google', profile.id);
      if (existingIdentity && existingIdentity.user_id !== targetUserId) {
        throw new AppError(
          409,
          'Esta cuenta de Google ya está vinculada a otro usuario',
          'PROVIDER_YA_VINCULADO',
        );
      }
      if (existingIdentity && existingIdentity.user_id === targetUserId) {
        throw new AppError(409, 'Ya tienes vinculada esta cuenta de Google', 'YA_VINCULADO');
      }

      linkAccount({
        userId: targetUserId,
        provider: 'google',
        providerId: profile.id,
        providerEmail: profile.email,
        accessToken: googleToken,
        auditData: { ipHash: ipHash2, correlationId: req.correlationId },
      });

      res.redirect(`${config.FRONTEND_URL}?linked=true&provider=google`);
      return;
    }

    // ── Flujo normal: login / registro ─────────────────────────────────────
    const { accessToken, refreshToken, isNew } = processOAuthLogin(
      'google',
      profile.id,
      profile.email,
      googleToken,
      req,
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Redirigir al frontend con el AT en la URL (Fase 6: frontend Alpine.js)
    res.redirect(`${config.FRONTEND_URL}?at=${accessToken}&provider=google&nuevo=${isNew ? '1' : '0'}`);
  }),
);

// ── Client Credentials Grant — M2M ───────────────────────────────────────────

const m2mSchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  scope: z.string().optional(),
});

router.post(
  '/m2m/token',
  asyncHandler(async (req, res) => {
    if (!config.M2M_CLIENT_ID || !config.M2M_CLIENT_SECRET) {
      throw new AppError(503, 'M2M no configurado — añade M2M_CLIENT_ID y M2M_CLIENT_SECRET al .env', 'NO_CONFIGURADO');
    }

    // Soportar credenciales en Basic Auth header O en el body
    let clientId = '';
    let clientSecret = '';

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Basic ')) {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      const colonIdx = decoded.indexOf(':');
      clientId = colonIdx >= 0 ? decoded.slice(0, colonIdx) : decoded;
      clientSecret = colonIdx >= 0 ? decoded.slice(colonIdx + 1) : '';
    } else {
      const parsed = m2mSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new AppError(400, 'grant_type debe ser client_credentials', 'GRANT_TYPE_INVALIDO');
      }
      clientId = parsed.data.client_id ?? '';
      clientSecret = parsed.data.client_secret ?? '';
    }

    if (!clientId || !clientSecret) {
      throw new AppError(401, 'client_id y client_secret son requeridos', 'CREDENCIALES_INVALIDAS');
    }

    // Comparación timing-safe: hashear ambos para normalizar longitud a 32 bytes
    const hash = (s: string) => createHash('sha256').update(s).digest();
    const idMatch = timingSafeEqual(hash(clientId), hash(config.M2M_CLIENT_ID));
    const secretMatch = timingSafeEqual(hash(clientSecret), hash(config.M2M_CLIENT_SECRET));

    if (!idMatch || !secretMatch) {
      throw new AppError(401, 'Credenciales de cliente inválidas', 'CREDENCIALES_INVALIDAS');
    }

    // Emitir AT M2M (sin Refresh Token — el cliente solicita uno nuevo cuando expire)
    const scopes = ['read:data', 'write:data'];
    const accessToken = signM2mToken(clientId, scopes);

    auditLogsRepository.create({
      event_type: 'LOGIN_EXITOSO',
      ip_hash: hashIp(req.ip ?? ''),
      correlation_id: req.correlationId,
      metadata: { client_id: clientId, grant_type: 'client_credentials', scopes },
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: scopes.join(' '),
      nota: 'Token M2M — sin Refresh Token. Solicita uno nuevo cuando expire.',
      diferencia_con_usuario: {
        sin_sub_usuario: 'sub = client_id, no user_id',
        sin_refresh_token: 'Las máquinas re-autentican con client_credentials',
        sin_familia: 'No hay Family Tracking — el token es stateless',
      },
    });
  }),
);

// ── Device Authorization Grant — RFC 8628 ────────────────────────────────────

/**
 * Paso 1: El dispositivo solicita un código.
 * Devuelve device_code (para polling) y user_code (para el usuario).
 * El usuario va a verification_uri e introduce el user_code para aprobar.
 */
router.post('/device/code', (req, res) => {
  const deviceCode = randomBytes(32).toString('hex');
  const userCode = generateUserCode();
  const expiresAt = Date.now() + DEVICE_CODE_TTL_MS;

  deviceCodesRepository.create({
    device_code: deviceCode,
    user_code: userCode,
    expires_at: expiresAt,
  });

  auditLogsRepository.create({
    event_type: 'OAUTH_INICIO',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { grant_type: 'device_code', user_code: userCode },
  });

  const baseUrl = `${req.protocol}://${req.get('host')}`;

  res.status(200).json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl}/api/v1/oauth/device/verify`,
    verification_uri_complete: `${baseUrl}/api/v1/oauth/device/verify?user_code=${userCode}`,
    expires_in: DEVICE_CODE_TTL_MS / 1000,
    interval: DEVICE_POLL_INTERVAL,
    instrucciones: [
      `1. Abre ${baseUrl}/api/v1/oauth/device/verify en tu navegador`,
      `2. Introduce el código: ${userCode}`,
      `3. Aprueba el acceso`,
      `4. El dispositivo obtendrá un token automáticamente`,
    ],
  });
});

/**
 * Paso 2a: Página de aprobación — GET devuelve HTML interactivo.
 * El usuario introduce el user_code y aprueba/deniega con su JWT.
 */
router.get('/device/verify', (req, res) => {
  const userCode = typeof req.query['user_code'] === 'string' ? req.query['user_code'] : '';
  const safeUserCode = userCode.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AuthLab — Autorización de dispositivo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: white; border-radius: 12px; padding: 40px; max-width: 480px; width: 100%; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
    h1 { font-size: 1.5rem; margin-bottom: 8px; color: #111; }
    p { color: #6b7280; margin-bottom: 20px; line-height: 1.5; }
    label { font-size: 0.875rem; font-weight: 600; color: #374151; display: block; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 14px; border: 1.5px solid #d1d5db; border-radius: 8px; font-size: 1rem; margin-bottom: 16px; transition: border-color 0.2s; }
    input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.1); }
    #userCode { text-align: center; font-size: 1.5rem; letter-spacing: 6px; font-weight: 700; text-transform: uppercase; }
    .buttons { display: flex; gap: 10px; margin-top: 8px; }
    .btn { flex: 1; padding: 12px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
    .btn:hover { opacity: 0.85; }
    .approve { background: #22c55e; color: white; }
    .deny { background: #ef4444; color: white; }
    #result { margin-top: 20px; padding: 14px; border-radius: 8px; display: none; font-weight: 500; }
    .success { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
    .error { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    details { margin-top: 24px; }
    summary { cursor: pointer; color: #6366f1; font-size: 0.875rem; }
    pre { margin-top: 12px; background: #f8f9fa; padding: 12px; border-radius: 6px; font-size: 0.75rem; overflow-x: auto; color: #374151; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Autorización de dispositivo</h1>
    <p>Un dispositivo ha solicitado acceso a tu cuenta. Introduce el código que aparece en tu dispositivo y aprueba el acceso.</p>

    <label for="userCode">Código del dispositivo</label>
    <input type="text" id="userCode" value="${safeUserCode}" placeholder="XXXX-XXXX" maxlength="9" autocomplete="off" />

    <label for="accessToken">Tu Access Token (Bearer JWT)</label>
    <input type="password" id="accessToken" placeholder="eyJhbGciOiJIUzI1NiIsInR5c..." />
    <small style="color:#9ca3af;font-size:0.75rem">Obtén tu AT con POST /api/v1/auth/login</small>

    <div class="buttons" style="margin-top:16px">
      <button class="btn approve" onclick="submitApproval('approve')">✅ Aprobar acceso</button>
      <button class="btn deny" onclick="submitApproval('deny')">❌ Denegar acceso</button>
    </div>

    <div id="result"></div>

    <details>
      <summary>¿Cómo funciona el Device Authorization Grant? (RFC 8628)</summary>
      <pre>1. Dispositivo → POST /oauth/device/code
   ← device_code, user_code, verification_uri

2. Dispositivo muestra user_code al usuario
   Usuario va a verification_uri e introduce el código

3. Dispositivo hace polling → POST /oauth/device/token
   ← 'authorization_pending' hasta que el usuario apruebe

4. Usuario aprueba → dispositivo recibe access_token

Caso de uso: smart TVs, CLIs, IoT — sin navegador en el dispositivo</pre>
    </details>
  </div>

  <script>
    async function submitApproval(action) {
      const userCode = document.getElementById('userCode').value.trim().toUpperCase();
      const accessToken = document.getElementById('accessToken').value.trim();
      const resultEl = document.getElementById('result');

      if (!userCode.match(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)) {
        alert('El código debe tener el formato XXXX-XXXX'); return;
      }
      if (!accessToken) {
        alert('Introduce tu Access Token (obtenlo con POST /api/v1/auth/login)'); return;
      }

      try {
        const res = await fetch('/api/v1/oauth/device/verify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + accessToken,
          },
          body: JSON.stringify({ user_code: userCode, action }),
        });

        const data = await res.json();
        resultEl.style.display = 'block';

        if (res.ok) {
          resultEl.className = 'success';
          resultEl.textContent = action === 'approve'
            ? '✅ Acceso aprobado. El dispositivo recibirá un token en su próximo intento de polling.'
            : '❌ Acceso denegado. El dispositivo recibirá un error en su próximo polling.';
        } else {
          resultEl.className = 'error';
          resultEl.textContent = '❌ ' + (data.error || JSON.stringify(data));
        }
      } catch (e) {
        resultEl.style.display = 'block';
        resultEl.className = 'error';
        resultEl.textContent = '❌ Error de red: ' + String(e);
      }
    }
  </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

/**
 * Paso 2b: El usuario aprueba o deniega el acceso (POST).
 * Requiere Bearer JWT para identificar al usuario autenticado.
 */
const deviceVerifySchema = z.object({
  user_code: z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/i, 'Formato de código inválido — debe ser XXXX-XXXX'),
  action: z.enum(['approve', 'deny']),
});

router.post(
  '/device/verify',
  authenticate,
  (req, res) => {
    const parsed = deviceVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(400, parsed.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { user_code: userCode, action } = parsed.data;
    const deviceRecord = deviceCodesRepository.findByUserCode(userCode.toUpperCase());

    if (!deviceRecord) {
      throw new AppError(404, 'Código de dispositivo no encontrado o expirado', 'CODIGO_NO_ENCONTRADO');
    }

    if (deviceRecord.expires_at < Date.now()) {
      throw new AppError(400, 'El código ha expirado — el dispositivo debe solicitar uno nuevo', 'CODIGO_EXPIRADO');
    }

    if (action === 'approve') {
      deviceCodesRepository.approve(deviceRecord.id, req.user!.userId);
      res.json({ mensaje: 'Dispositivo autorizado correctamente' });
    } else {
      deviceCodesRepository.deny(deviceRecord.id);
      res.json({ mensaje: 'Acceso denegado al dispositivo' });
    }
  },
);

/**
 * Paso 3: Polling del dispositivo.
 * El dispositivo llama a este endpoint cada `interval` segundos.
 * Respuestas posibles: authorization_pending, access_denied, expired_token, AT.
 */
const deviceTokenSchema = z.object({
  grant_type: z.literal('urn:ietf:params:oauth:grant-type:device_code'),
  device_code: z.string().min(1),
});

router.post(
  '/device/token',
  asyncHandler(async (req, res) => {
    const parsed = deviceTokenSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'invalid_request',
        error_description: parsed.error.issues[0]?.message ?? 'grant_type inválido',
      });
      return;
    }

    const { device_code: deviceCode } = parsed.data;
    const record = deviceCodesRepository.findByDeviceCode(deviceCode);

    if (!record) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'device_code no encontrado' });
      return;
    }

    if (record.expires_at < Date.now()) {
      res.status(400).json({ error: 'expired_token', error_description: 'El device_code ha expirado' });
      return;
    }

    if (record.status === 'denied') {
      res.status(400).json({ error: 'access_denied', error_description: 'El usuario denegó el acceso' });
      return;
    }

    if (record.status === 'pending') {
      // RFC 8628: responder con 428 o 200 según la implementación
      res.status(428).json({
        error: 'authorization_pending',
        error_description: 'El usuario aún no ha aprobado el acceso — continúa haciendo polling',
        interval: DEVICE_POLL_INTERVAL,
      });
      return;
    }

    if (record.status === 'expired') {
      // device_code ya fue usado (single-use) — el dispositivo debe solicitar uno nuevo
      res.status(400).json({
        error: 'expired_token',
        error_description: 'El device_code ya fue canjeado — solicita uno nuevo con POST /device/code',
      });
      return;
    }

    // status === 'approved' — emitir AT
    const user = usersRepository.findById(record.user_id!);
    if (!user) {
      res.status(400).json({ error: 'server_error', error_description: 'Usuario no encontrado' });
      return;
    }

    const ipHash = hashIp(req.ip ?? '');
    const roles = JSON.parse(user.roles) as UserRole[];
    const { accessToken, refreshToken } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash,
      userAgent: req.headers['user-agent'] ?? null,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      correlation_id: req.correlationId,
      metadata: { grant_type: 'device_code', device_code: deviceCode.slice(0, 8) + '...' },
    });

    // El device_code es de un solo uso — marcarlo como expirado
    deviceCodesRepository.expire(record.id);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 15 * 60,
    });
  }),
);

// ── Implicit Flow — Demostración Histórica ────────────────────────────────────
// RFC 6749 §4.2 — eliminado en OAuth 2.1 por inseguro.
// El AT aparece en el URL fragment → historial del browser, logs del servidor de analytics.

router.get(
  '/implicit/authorize',
  authenticate,
  asyncHandler(async (req, res) => {
    const redirectUri = typeof req.query['redirect_uri'] === 'string' ? req.query['redirect_uri'] : null;
    const state = typeof req.query['state'] === 'string' ? req.query['state'] : '';

    if (!redirectUri) {
      throw new AppError(400, 'redirect_uri es requerido', 'VALIDACION_FALLIDA');
    }

    const user = usersRepository.findById(req.user!.userId);
    if (!user) throw new AppError(401, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    const roles = JSON.parse(user.roles) as UserRole[];
    // Emitir AT de corta duración (sin RT — el implicit flow no emite RT)
    const { accessToken } = issueTokenPair({
      userId: user.id,
      roles,
      ipHash: hashIp(req.ip ?? ''),
      userAgent: req.headers['user-agent'] ?? null,
    });

    // VULNERABLE: el token aparece en el fragment → historial del browser, logs de analytics
    const fragment = new URLSearchParams({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: String(15 * 60),
      state,
    });

    // Redirect con token en el FRAGMENT (no en query string ni body)
    res.redirect(`${redirectUri}#${fragment}`);
  }),
);

// ── GET /api/v1/oauth/m2m/protected ──────────────────────────────────────────
// Demostración: ruta accesible con token M2M (scopes read:data, write:data)

router.get(
  '/m2m/protected',
  authenticate,
  (req, res) => {
    if (req.user?.scopes?.includes('read:data') !== true) {
      throw new AppError(403, 'Token M2M requiere scope read:data', 'SCOPE_INSUFICIENTE');
    }

    res.json({
      mensaje: 'Acceso M2M concedido',
      client_id: req.user.userId,
      scopes: req.user.scopes,
      tipo: 'client_credentials',
      nota: 'Este endpoint demuestra la diferencia con tokens de usuario: sin sub de usuario, sin roles humanos',
    });
  },
);

export default router;
