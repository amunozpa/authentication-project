/**
 * Rutas Session Token — Fase 3
 * POST /api/v1/session/login
 * GET  /api/v1/session/protected
 * POST /api/v1/session/logout
 *
 * Session tokens vs JWT:
 * - Stateful: el servidor guarda cada sesión en BD
 * - Revocación instantánea (borra el registro)
 * - Ideal para aplicaciones web tradicionales
 * - Escala peor que JWT (lookup en BD por request)
 */
import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { usersRepository } from '../db/repositories/users';
import { sessionsRepository } from '../db/repositories/sessions';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { hashToken, hashIp } from '../utils/hash';
import { sessionAuthMiddleware } from '../middleware/sessionAuth';
import { asyncHandler } from '../utils/asyncHandler';
import { AppError } from '../middleware/errorHandler';

const router = Router();

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 horas

const loginSchema = z.object({
  email: z.string().email('Email inválido'),
  password: z.string().min(1, 'Contraseña requerida'),
});

// ── POST /api/v1/session/login ────────────────────────────────────────────────

router.post(
  '/login',
  asyncHandler(async (req, res) => {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      throw new AppError(400, result.error.issues[0]?.message ?? 'Datos inválidos', 'VALIDACION_FALLIDA');
    }

    const { email, password } = result.data;
    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    const user = usersRepository.findByEmail(email);
    const hashToCompare = user?.password_hash ?? await bcrypt.hash('dummy', 12);
    const match = await bcrypt.compare(password, hashToCompare);

    if (!match || !user) {
      throw new AppError(401, 'Email o contraseña incorrectos', 'CREDENCIALES_INVALIDAS');
    }

    if (!user.email_verified) {
      throw new AppError(403, 'Debes verificar tu email primero', 'EMAIL_NO_VERIFICADO');
    }

    if (user.locked_until && user.locked_until > Date.now()) {
      throw new AppError(423, 'Cuenta bloqueada temporalmente', 'CUENTA_BLOQUEADA');
    }

    // Generar session token: 32 bytes aleatorios
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);

    sessionsRepository.create({
      user_id: user.id,
      token_hash: tokenHash,
      ip_hash: ipHash,
      user_agent: userAgent,
      expires_at: Date.now() + SESSION_TTL_MS,
    });

    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: 'session_token' },
    });

    res.json({
      sessionToken: rawToken, // Solo visible aquí — el cliente debe guardarlo
      expiresIn: SESSION_TTL_MS / 1000,
      advertencia: 'Guarda este token de forma segura. No se puede recuperar después.',
      comparativa: {
        jwt: 'Stateless — el servidor no guarda nada. Revocación difícil.',
        session: 'Stateful — el servidor guarda en BD. Revocación inmediata.',
      },
    });
  }),
);

// ── GET /api/v1/session/protected ─────────────────────────────────────────────

router.get('/protected', sessionAuthMiddleware, (req, res) => {
  res.json({
    mensaje: 'Acceso concedido con Session Token',
    usuario: req.user?.userId,
    tipo_auth: 'session_token',
  });
});

// ── POST /api/v1/session/logout ───────────────────────────────────────────────

router.post('/logout', sessionAuthMiddleware, (req, res) => {
  const authHeader = req.headers.authorization ?? '';
  const token = authHeader.slice(7);
  const tokenHash = hashToken(token);

  sessionsRepository.deleteByTokenHash(tokenHash);

  auditLogsRepository.create({
    user_id: req.user?.userId ?? null,
    event_type: 'LOGOUT',
    ip_hash: hashIp(req.ip ?? ''),
    correlation_id: req.correlationId,
    metadata: { metodo: 'session_token' },
  });

  res.json({ mensaje: 'Sesión cerrada correctamente' });
});

export default router;
