/**
 * Servicio OAuth 2.0 — Fase 5
 * Helpers de PKCE, llamadas HTTP a proveedores (GitHub, Google)
 * y lógica de Account Linking.
 *
 * Account Linking — orden de resolución:
 * 1. (provider, provider_id) en linked_identities → usuario conocido → login
 * 2. provider_email en users → auto-vincular (el provider verificó el email)
 * 3. Nuevo usuario → crear + vincular
 */
import { randomBytes, createHash } from 'crypto';
import { config } from '../config/env';
import { usersRepository } from '../db/repositories/users';
import { linkedIdentitiesRepository } from '../db/repositories/linkedIdentities';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { linkAccount } from '../db/transactions';
import { issueTokenPair } from './jwtService';
import { hashIp } from '../utils/hash';
import { AppError } from '../middleware/errorHandler';
import type { OAuthProvider, UserRole } from '../types';
import type { Request } from 'express';

// ── PKCE (RFC 7636) ───────────────────────────────────────────────────────────

/**
 * Genera un par code_verifier / code_challenge para PKCE.
 * code_verifier: 43 chars URL-safe (base64url de 32 bytes aleatorios)
 * code_challenge: BASE64URL(SHA256(ASCII(code_verifier))) — método S256
 */
export function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString('base64url'); // 43 chars URL-safe
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

/** Genera un estado anti-CSRF de 32 chars hexadecimales */
export function generateState(): string {
  return randomBytes(16).toString('hex');
}

// ── GitHub OAuth ──────────────────────────────────────────────────────────────

/**
 * Intercambia el code de autorización por un access_token de GitHub.
 * Nota: GitHub no soporta PKCE — usa client_secret para autenticación confidencial.
 */
export async function exchangeGithubCode(code: string): Promise<string> {
  if (!config.GITHUB_CLIENT_ID || !config.GITHUB_CLIENT_SECRET) {
    throw new AppError(503, 'OAuth GitHub no configurado — añade GITHUB_CLIENT_ID y GITHUB_CLIENT_SECRET al .env', 'NO_CONFIGURADO');
  }

  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: config.GITHUB_CLIENT_ID,
      client_secret: config.GITHUB_CLIENT_SECRET,
      code,
    }),
  });

  if (!res.ok) {
    throw new AppError(502, 'Error al comunicarse con GitHub', 'OAUTH_ERROR');
  }

  const data = await res.json() as { access_token?: string; error?: string; error_description?: string };

  if (!data.access_token) {
    throw new AppError(400, data.error_description ?? data.error ?? 'GitHub rechazó el código', 'OAUTH_CODE_INVALIDO');
  }

  return data.access_token;
}

/** Obtiene el perfil del usuario de GitHub (id, email, name) */
export async function getGithubProfile(accessToken: string): Promise<{
  id: string;
  email: string | null;
  name: string | null;
}> {
  const headers = {
    'Authorization': `Bearer ${accessToken}`,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'AuthLab/1.0 (https://github.com)',
  };

  const [userRes, emailsRes] = await Promise.all([
    fetch('https://api.github.com/user', { headers }),
    fetch('https://api.github.com/user/emails', { headers }),
  ]);

  if (!userRes.ok) {
    throw new AppError(502, 'Error al obtener perfil de GitHub', 'OAUTH_PROFILE_ERROR');
  }

  const user = await userRes.json() as {
    id: number;
    login: string;
    name: string | null;
    email: string | null;
  };

  // Intentar obtener el email primario verificado si no está en el perfil público
  let primaryEmail = user.email;
  if (!primaryEmail && emailsRes.ok) {
    const emails = await emailsRes.json() as Array<{
      email: string;
      primary: boolean;
      verified: boolean;
    }>;
    const primary = emails.find((e) => e.primary && e.verified);
    primaryEmail = primary?.email ?? null;
  }

  return {
    id: String(user.id),
    email: primaryEmail,
    name: user.name ?? user.login,
  };
}

// ── Google OAuth ──────────────────────────────────────────────────────────────

/**
 * Intercambia el code por un access_token de Google.
 * Google SÍ soporta PKCE desde 2021 — enviamos code_verifier en el intercambio.
 */
export async function exchangeGoogleCode(code: string, codeVerifier: string): Promise<string> {
  if (!config.GOOGLE_CLIENT_ID || !config.GOOGLE_CLIENT_SECRET) {
    throw new AppError(503, 'OAuth Google no configurado — añade GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET al .env', 'NO_CONFIGURADO');
  }

  const params = new URLSearchParams({
    code,
    client_id: config.GOOGLE_CLIENT_ID,
    client_secret: config.GOOGLE_CLIENT_SECRET,
    redirect_uri: config.GOOGLE_CALLBACK_URL,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,   // PKCE: enviado solo a Google, no a GitHub
  });

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  const data = await res.json() as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };

  if (!res.ok || !data.access_token) {
    throw new AppError(400, data.error_description ?? data.error ?? 'Google rechazó el código', 'OAUTH_CODE_INVALIDO');
  }

  return data.access_token;
}

/** Obtiene el perfil del usuario de Google (id=sub, email, name) */
export async function getGoogleProfile(accessToken: string): Promise<{
  id: string;
  email: string;
  name: string | null;
}> {
  const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { 'Authorization': `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    throw new AppError(502, 'Error al obtener perfil de Google', 'OAUTH_PROFILE_ERROR');
  }

  const user = await res.json() as {
    sub: string;
    email: string;
    email_verified: boolean;
    name: string | null;
    given_name?: string;
  };

  return {
    id: user.sub,
    email: user.email,
    name: user.name ?? user.given_name ?? null,
  };
}

// ── Account Linking ───────────────────────────────────────────────────────────

type OAuthLoginResult = {
  accessToken: string;
  refreshToken: string;
  familyId: string;
  isNew: boolean;
};

/**
 * Implementa el flujo de Account Linking para OAuth.
 * Tres caminos posibles:
 * 1. Identidad conocida → login directo
 * 2. Email coincide con usuario existente → auto-vincular
 * 3. Email nuevo → crear usuario + vincular
 */
export function processOAuthLogin(
  provider: OAuthProvider,
  providerId: string,
  providerEmail: string | null,
  providerAccessToken: string,
  req: Request,
): OAuthLoginResult {
  const ipHash = hashIp(req.ip ?? '');
  const userAgent = req.headers['user-agent'] ?? null;

  // ── 1. Identidad ya vinculada ──────────────────────────────────────────────
  const identity = linkedIdentitiesRepository.findByProvider(provider, providerId);

  if (identity) {
    // Actualizar token del provider (puede haber expirado)
    linkedIdentitiesRepository.updateAccessToken(identity.id, providerAccessToken);

    const user = usersRepository.findById(identity.user_id);
    if (!user) throw new AppError(401, 'Usuario no encontrado', 'USUARIO_NO_ENCONTRADO');

    const roles = JSON.parse(user.roles) as UserRole[];
    const tokens = issueTokenPair({ userId: user.id, roles, ipHash, userAgent });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: `oauth_${provider}` },
    });

    return { ...tokens, isNew: false };
  }

  // ── 2. Email coincide con cuenta existente → auto-vincular ────────────────
  const existingUser = providerEmail ? usersRepository.findByEmail(providerEmail) : null;

  if (existingUser) {
    // El provider ya verificó el email → podemos vincular automáticamente
    linkAccount({
      userId: existingUser.id,
      provider,
      providerId,
      providerEmail,
      accessToken: providerAccessToken,
      auditData: { ipHash, correlationId: req.correlationId },
    });

    const roles = JSON.parse(existingUser.roles) as UserRole[];
    const tokens = issueTokenPair({ userId: existingUser.id, roles, ipHash, userAgent });

    auditLogsRepository.create({
      user_id: existingUser.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: `oauth_${provider}`, auto_vinculado: true },
    });

    return { ...tokens, isNew: false };
  }

  // ── 3. Nuevo usuario — crear + vincular ───────────────────────────────────
  // Si el provider no tiene email, usamos un placeholder (ej. GitHub con email privado)
  const email = providerEmail ?? `${provider}_${providerId}@noemail.local`;

  const newUser = usersRepository.create({
    email,
    password_hash: null,
    email_verified: 1,   // el provider ya verificó el email
  });

  linkAccount({
    userId: newUser.id,
    provider,
    providerId,
    providerEmail,
    accessToken: providerAccessToken,
    auditData: { ipHash, correlationId: req.correlationId },
  });

  auditLogsRepository.create({
    user_id: newUser.id,
    event_type: 'REGISTRO_VERIFICADO',
    ip_hash: ipHash,
    user_agent: userAgent,
    correlation_id: req.correlationId,
    metadata: { metodo: `oauth_${provider}` },
  });

  const roles = JSON.parse(newUser.roles) as UserRole[];
  const tokens = issueTokenPair({ userId: newUser.id, roles, ipHash, userAgent });

  return { ...tokens, isNew: true };
}
