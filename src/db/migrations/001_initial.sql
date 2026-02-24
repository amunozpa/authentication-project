-- ============================================================
-- Migración 001 — Schema completo del proyecto de autenticación
-- 13 tablas con índices optimizados
-- ============================================================

-- ── USUARIOS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,                       -- UUID v4
  email          TEXT UNIQUE NOT NULL COLLATE NOCASE,    -- case-insensitive
  password_hash  TEXT,                                   -- NULL si solo usa OAuth
  roles          TEXT NOT NULL DEFAULT '["user"]',       -- JSON array
  email_verified INTEGER NOT NULL DEFAULT 0,             -- 0=pendiente 1=verificado
  mfa_enabled    INTEGER NOT NULL DEFAULT 0,
  mfa_secret     TEXT,                                   -- secret TOTP
  locked_until   INTEGER,                                -- timestamp UNIX — account lockout
  created_at     INTEGER NOT NULL,
  deleted_at     INTEGER                                 -- soft delete GDPR (NULL=activo)
);

CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- ── IDENTIDADES VINCULADAS (Account Linking) ─────────────────
CREATE TABLE IF NOT EXISTS linked_identities (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider       TEXT NOT NULL CHECK(provider IN ('github', 'google')),
  provider_id    TEXT NOT NULL,
  provider_email TEXT,
  access_token   TEXT,
  created_at     INTEGER NOT NULL,
  UNIQUE(provider, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_linked_identities_user_id ON linked_identities(user_id);

-- ── TOKENS DE EMAIL (verificación / reset / magic link) ──────
CREATE TABLE IF NOT EXISTS email_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  type       TEXT NOT NULL CHECK(type IN ('VERIFY_EMAIL', 'PASSWORD_RESET', 'MAGIC_LINK')),
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_tokens_user_id    ON email_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_tokens_token_hash ON email_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_email_tokens_expires_at ON email_tokens(expires_at);

-- ── CÓDIGOS DE RECUPERACIÓN MFA ───────────────────────────────
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  used_at    INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);

-- ── SESIONES CLÁSICAS ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  ip_hash    TEXT NOT NULL,
  user_agent TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ── FAMILIAS DE REFRESH TOKENS (JWT Family Tracking) ─────────
CREATE TABLE IF NOT EXISTS refresh_token_families (
  id             TEXT PRIMARY KEY,                -- familyId
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  current_jti    TEXT NOT NULL,                   -- jti del RT válido actualmente
  access_jti     TEXT,                            -- jti del AT emitido con el último refresh
  kid            TEXT NOT NULL,                   -- clave de firma usada
  ip_hash        TEXT NOT NULL,
  user_agent     TEXT,
  revoked_at     INTEGER,
  revoked_reason TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rtf_user_id      ON refresh_token_families(user_id);
CREATE INDEX IF NOT EXISTS idx_rtf_current_jti  ON refresh_token_families(current_jti);
CREATE INDEX IF NOT EXISTS idx_rtf_expires_at   ON refresh_token_families(expires_at);
CREATE INDEX IF NOT EXISTS idx_rtf_revoked_at   ON refresh_token_families(revoked_at);

-- ── CLAVES DE FIRMA JWT ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS jwt_signing_keys (
  id         TEXT PRIMARY KEY,             -- kid (UUID corto)
  secret     TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1,   -- 0=retirada (solo verifica) 1=activa
  created_at INTEGER NOT NULL,
  retired_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_jwt_signing_keys_active ON jwt_signing_keys(active);

-- ── API KEYS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  key_prefix   TEXT NOT NULL,              -- primeros 8 chars: 'sk_live_'
  key_hash     TEXT NOT NULL,              -- bcrypt del token completo
  scopes       TEXT NOT NULL DEFAULT '[]', -- JSON array
  last_used_at INTEGER,
  revoked_at   INTEGER,
  created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id    ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);

-- ── OAUTH STATES (PKCE) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS oauth_states (
  id            TEXT PRIMARY KEY,
  state         TEXT UNIQUE NOT NULL,
  code_verifier TEXT NOT NULL,
  provider      TEXT NOT NULL CHECK(provider IN ('github', 'google')),
  expires_at    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_state      ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

-- ── DEVICE CODES (RFC 8628) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS device_codes (
  id          TEXT PRIMARY KEY,
  device_code TEXT UNIQUE NOT NULL,
  user_code   TEXT UNIQUE NOT NULL,     -- 8 chars legibles: 'ABCD-1234'
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
  status      TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending', 'approved', 'denied', 'expired')),
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code   ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at  ON device_codes(expires_at);

-- ── WEBAUTHN CHALLENGES (temporal entre /options y /verify) ───
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenge  TEXT NOT NULL,
  type       TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_id   ON webauthn_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires_at ON webauthn_challenges(expires_at);

-- ── WEBAUTHN CREDENTIALS / PASSKEYS ──────────────────────────
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT UNIQUE NOT NULL,
  public_key    TEXT NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,  -- detecta clonación si decrece
  device_name   TEXT,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id       ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);

-- ── AUDIT LOGS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
  id             TEXT PRIMARY KEY,
  user_id        TEXT,              -- NULL si es anónimo o anonimizado (GDPR)
  event_type     TEXT NOT NULL,
  ip_hash        TEXT,              -- SHA-256(ip + IP_HASH_SALT) — nunca IP en claro
  user_agent     TEXT,
  correlation_id TEXT,
  metadata       TEXT,              -- JSON con datos adicionales
  created_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
