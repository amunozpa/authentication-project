/**
 * Tipos TypeScript base del proyecto de autenticación.
 * Todos los contratos de datos del sistema están definidos aquí.
 */

// ============================================================
// ENUMS Y UNION TYPES
// ============================================================

/** Roles disponibles en el sistema RBAC */
export type UserRole = 'admin' | 'editor' | 'user' | 'viewer';

/** Proveedores OAuth soportados */
export type OAuthProvider = 'github' | 'google';

/** Tipos de tokens de email — todos comparten la tabla email_tokens */
export type EmailTokenType = 'VERIFY_EMAIL' | 'PASSWORD_RESET' | 'MAGIC_LINK';

/** Estados posibles de un Device Code (RFC 8628) */
export type DeviceCodeStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** Algoritmos JWT permitidos — whitelist estricta, prohíbe alg:none */
export type AllowedJwtAlgorithm = 'HS256';

// ============================================================
// PAYLOADS JWT
// ============================================================

/** Payload del Access Token — sin PII, solo identificadores */
export interface JWTAccessPayload {
  sub: string;           // user_id (UUID) — o client_id para tokens M2M
  jti: string;           // ID único del token (UUID v4) — para revocación
  kid: string;           // ID de la clave de firma — para rotación sin logout masivo
  roles: UserRole[];     // Roles del usuario — sin email ni nombre (minimización)
  scopes?: string[];     // Scopes OAuth/API Key — para tokens M2M y Client Credentials
  type?: 'm2m';          // Discriminador para tokens de máquina a máquina
  /** Fase 5.11: binding DPoP — contiene el JWK thumbprint del cliente (RFC 9449 §6) */
  cnf?: { jkt: string }; // confirmation claim — sender-constrained token
  iat: number;           // Issued At (timestamp UNIX)
  exp: number;           // Expiration (timestamp UNIX)
}

/** Payload del Refresh Token — incluye familyId para Family Tracking */
export interface JWTRefreshPayload {
  sub: string;        // user_id (UUID)
  jti: string;        // ID único de este RT — se compara con current_jti en BD
  kid: string;        // ID de la clave de firma
  familyId: string;   // ID de la familia de tokens — detecta reutilización (robo)
  iat: number;
  exp: number;
}

/** Token temporal para el paso intermedio de MFA en login de dos pasos */
export interface MfaSessionPayload {
  sub: string;               // user_id
  type: 'mfa_session';       // discriminador — solo válido en /mfa/verify
  iat: number;
  exp: number;               // 5 minutos
}

/** Token temporal emitido tras Step-up Authentication */
export interface StepUpPayload {
  sub: string;               // user_id
  type: 'step_up';           // discriminador — solo válido en rutas sensibles
  iat: number;
  exp: number;               // 10 minutos
}

// ============================================================
// REGISTROS DE BASE DE DATOS (better-sqlite3)
// SQLite mapea: INTEGER→number, TEXT→string, REAL→number, NULL→null
// ============================================================

/** Registro de usuario en tabla `users` */
export interface UserRecord {
  id: string;                  // UUID v4
  email: string;
  password_hash: string | null; // NULL si solo usa OAuth
  roles: string;               // JSON array: '["user"]'
  email_verified: 0 | 1;       // 0=pendiente, 1=verificado
  mfa_enabled: 0 | 1;
  mfa_secret: string | null;   // secret TOTP
  locked_until: number | null;  // timestamp UNIX — account lockout
  created_at: number;           // timestamp UNIX
  deleted_at: number | null;    // soft delete GDPR
}

/** Registro de identidad vinculada en tabla `linked_identities` */
export interface LinkedIdentityRecord {
  id: string;
  user_id: string;
  provider: OAuthProvider;
  provider_id: string;          // ID del usuario en el provider externo
  provider_email: string | null;
  access_token: string | null;  // token del provider (para llamadas a su API)
  created_at: number;
}

/** Registro de token de email en tabla `email_tokens` */
export interface EmailTokenRecord {
  id: string;
  user_id: string;
  token_hash: string;           // SHA-256 del token — nunca guardar el token en claro
  type: EmailTokenType;
  expires_at: number;
  used_at: number | null;       // NULL = no usado
  created_at: number;
}

/** Código de recuperación MFA en tabla `mfa_recovery_codes` */
export interface MfaRecoveryCodeRecord {
  id: string;
  user_id: string;
  code_hash: string;            // bcrypt del código
  used_at: number | null;
  created_at: number;
}

/** Registro de sesión clásica en tabla `sessions` */
export interface SessionRecord {
  id: string;
  user_id: string;
  token_hash: string;           // SHA-256 del session token
  ip_hash: string;              // SHA-256(ip + IP_HASH_SALT) — GDPR
  user_agent: string | null;
  expires_at: number;
  created_at: number;
}

/** Familia de Refresh Tokens en tabla `refresh_token_families` */
export interface RefreshTokenFamilyRecord {
  id: string;                   // familyId
  user_id: string;
  current_jti: string;          // jti del RT válido actualmente
  access_jti: string | null;    // jti del AT emitido con el último refresh
  kid: string;                  // clave de firma usada
  ip_hash: string;
  user_agent: string | null;
  revoked_at: number | null;
  revoked_reason: string | null; // 'logout' | 'stolen' | 'global_logout' | 'password_reset'
  created_at: number;
  expires_at: number;
}

/** Clave de firma JWT en tabla `jwt_signing_keys` */
export interface JwtSigningKeyRecord {
  id: string;                   // kid (UUID corto)
  secret: string;               // el secreto en sí (en prod debería estar en vault)
  active: 0 | 1;               // 0 = retirada (solo verifica), 1 = activa (firma + verifica)
  created_at: number;
  retired_at: number | null;
}

/** API Key en tabla `api_keys` */
export interface ApiKeyRecord {
  id: string;
  user_id: string;
  name: string;
  key_prefix: string;           // primeros 8 chars en claro: 'sk_live_'
  key_hash: string;             // bcrypt del token completo
  scopes: string;               // JSON array: '["read:data","write:data"]'
  last_used_at: number | null;
  revoked_at: number | null;
  created_at: number;
}

/** Estado PKCE en tabla `oauth_states` */
export interface OAuthStateRecord {
  id: string;
  state: string;                // valor aleatorio anti-CSRF
  code_verifier: string;        // PKCE verifier
  provider: OAuthProvider;
  expires_at: number;           // TTL 10 minutos
  created_at: number;
  /** Fase 5.9: si está presente → flujo de vinculación (usuario ya autenticado) */
  link_user_id: string | null;
}

/** Device Code en tabla `device_codes` (RFC 8628) */
export interface DeviceCodeRecord {
  id: string;
  device_code: string;          // UUID largo — usado por el dispositivo para polling
  user_code: string;            // 8 chars legibles: 'ABCD-1234' — ingresado por el usuario
  user_id: string | null;       // NULL hasta que el usuario aprueba
  status: DeviceCodeStatus;
  expires_at: number;           // TTL 5 minutos
  created_at: number;
}

/** Challenge temporal WebAuthn en tabla `webauthn_challenges` */
export interface WebAuthnChallengeRecord {
  id: string;
  user_id: string;
  challenge: string;            // base64url del challenge
  type: 'registration' | 'authentication';
  expires_at: number;           // TTL 5 minutos
  created_at: number;
}

/** Credencial WebAuthn/Passkey en tabla `webauthn_credentials` */
export interface WebAuthnCredentialRecord {
  id: string;
  user_id: string;
  credential_id: string;        // base64url — identificador del authenticator
  public_key: string;           // base64url — clave pública COSE
  counter: number;              // contador de uso — detecta clonación si decrece
  device_name: string | null;   // nombre descriptivo del dispositivo
  created_at: number;
  last_used_at: number | null;
}

/** Evento de auditoría en tabla `audit_logs` */
export interface AuditLogRecord {
  id: string;
  user_id: string | null;       // NULL si el evento es anónimo o anonimizado (GDPR)
  event_type: AuditEventType;
  ip_hash: string | null;       // SHA-256(ip + salt) — nunca IP en claro
  user_agent: string | null;
  correlation_id: string | null; // UUID del request — para trazabilidad
  metadata: string | null;       // JSON con datos adicionales del evento
  created_at: number;
}

// ============================================================
// CATÁLOGO DE EVENTOS DE AUDITORÍA
// 35 eventos cubriendo todo el ciclo de vida de autenticación
// ============================================================
export type AuditEventType =
  // Registro y verificación de email
  | 'REGISTRO_EXITOSO'
  | 'REGISTRO_VERIFICADO'
  | 'VERIFICACION_ENVIADA'
  | 'VERIFICACION_COMPLETADA'
  | 'VERIFICACION_REENVIADA'
  // Autenticación básica y sesiones
  | 'LOGIN_EXITOSO'
  | 'LOGIN_FALLIDO'
  | 'LOGOUT'
  | 'SESION_GLOBAL_CERRADA'
  // Account Lockout
  | 'CUENTA_BLOQUEADA'
  | 'CUENTA_DESBLOQUEADA'
  // JWT y tokens
  | 'TOKEN_RENOVADO'
  | 'TOKEN_ROBO_DETECTADO'
  | 'CLAVE_JWT_ROTADA'
  // Contraseñas
  | 'RESET_SOLICITADO'
  | 'RESET_COMPLETADO'
  | 'PASSWORD_CAMBIADO'
  // Magic Links
  | 'MAGIC_LINK_ENVIADO'
  | 'MAGIC_LINK_VERIFICADO'
  | 'MAGIC_LINK_EXPIRADO'
  // OAuth
  | 'OAUTH_INICIO'
  | 'OAUTH_CALLBACK'
  | 'CUENTA_VINCULADA'
  | 'CUENTA_DESVINCULADA'
  // WebAuthn / Passkeys
  | 'PASSKEY_REGISTRADA'
  | 'PASSKEY_LOGIN'
  // MFA / TOTP
  | 'MFA_ACTIVADO'
  | 'MFA_DESACTIVADO'
  | 'MFA_VERIFICADO'
  | 'MFA_FALLIDO'
  | 'MFA_RECUPERACION_USADA'
  // API Keys
  | 'API_KEY_CREADA'
  | 'API_KEY_REVOCADA'
  // GDPR
  | 'CUENTA_ELIMINADA'
  // Anomalías de seguridad
  | 'ANOMALIA_CREDENTIAL_STUFFING'
  | 'ANOMALIA_FUERZA_BRUTA'
  | 'ANOMALIA_SESION_INUSUAL'
  // DPoP — Fase 5.11
  | 'DPOP_TOKEN_EMITIDO'
  | 'DPOP_VERIFICADO';

// ============================================================
// TIPOS DE RESPUESTA DE LA API
// ============================================================

/** Formato estándar de error de la API */
export interface ApiError {
  error: string;         // Mensaje en español
  code: string;          // Código de error en MAYUSCULAS_CON_GUION_BAJO
  correlationId: string; // UUID del request para trazabilidad
}

/** Respuesta de tokens emitidos (AT en body, RT en cookie HttpOnly) */
export interface TokenResponse {
  accessToken: string;
  expiresIn: number;     // segundos hasta expiración del AT
  tokenType: 'Bearer';
}

/** Estructura de paginación con cursor */
export interface PaginatedResponse<T> {
  data: T[];
  cursor: string | null; // cursor para la siguiente página (NULL = última página)
  hasMore: boolean;
}

// ============================================================
// TIPOS DE REQUEST (Express augmentados)
// ============================================================

/** Datos del usuario autenticado adjuntados por los middlewares de auth */
export interface AuthenticatedUser {
  userId: string;
  roles: UserRole[];
  jti?: string;          // jti del AT — para algunos middlewares especializados
  scopes?: string[];     // scopes del API Key u OAuth token
}

// Augmentación del tipo Request de Express
declare global {
  namespace Express {
    interface Request {
      correlationId: string;         // UUID generado por el Correlation ID middleware
      user?: AuthenticatedUser;      // adjuntado por middlewares de autenticación
    }
  }
}
