/**
 * Fail-Fast Config — Fase 1
 * Valida todas las variables de entorno al arrancar con Zod.
 * Si algo falta o es inválido → log en español + process.exit(1)
 */
import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  // ── Servidor ────────────────────────────────────────────────
  PORT: z.coerce.number().int().positive().default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  FRONTEND_URL: z.string().min(1).default('http://localhost:3000'),

  // ── JWT ─────────────────────────────────────────────────────
  JWT_SECRET: z
    .string()
    .min(32, 'JWT_SECRET debe tener mínimo 32 caracteres — generalo con: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'),
  JWT_EXPIRY_ACCESS: z.string().default('15m'),
  JWT_EXPIRY_REFRESH: z.string().default('7d'),

  // ── Privacidad / GDPR ───────────────────────────────────────
  IP_HASH_SALT: z
    .string()
    .min(16, 'IP_HASH_SALT debe tener mínimo 16 caracteres — generalo con: node -e "console.log(require(\'crypto\').randomBytes(16).toString(\'hex\'))"'),

  // ── OAuth — GitHub (requerido en Fase 5) ────────────────────
  GITHUB_CLIENT_ID: z.string().default(''),
  GITHUB_CLIENT_SECRET: z.string().default(''),
  GITHUB_CALLBACK_URL: z.string().default('http://localhost:3000/api/v1/auth/oauth/github/callback'),

  // ── OAuth — Google (requerido en Fase 5) ────────────────────
  GOOGLE_CLIENT_ID: z.string().default(''),
  GOOGLE_CLIENT_SECRET: z.string().default(''),
  GOOGLE_CALLBACK_URL: z.string().default('http://localhost:3000/api/v1/auth/oauth/google/callback'),

  // ── Client Credentials M2M (requerido en Fase 5) ────────────
  M2M_CLIENT_ID: z.string().default(''),
  M2M_CLIENT_SECRET: z.string().default(''),

  // ── Email — Gmail SMTP (requerido en Fase 5.7) ──────────────
  GMAIL_USER: z.string().default(''),
  GMAIL_APP_PASSWORD: z.string().default(''),

  // ── PASETO v4 — Ed25519 (generadas en Fase 5.10) ────────────
  PASETO_PRIVATE_KEY: z.string().default(''),
  PASETO_PUBLIC_KEY: z.string().default(''),
});

const result = envSchema.safeParse(process.env);

if (!result.success) {
  console.error('\n❌ Error de configuración — el servidor no puede arrancar:\n');
  result.error.issues.forEach((issue) => {
    const campo = issue.path.join('.') || 'desconocido';
    console.error(`   • ${campo}: ${issue.message}`);
  });
  console.error('\n💡 Copia .env.example a .env y completa las variables marcadas.\n');
  process.exit(1);
}

export const config = result.data;
export type Config = typeof config;
