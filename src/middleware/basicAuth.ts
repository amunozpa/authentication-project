/**
 * Middleware Basic Auth — Fase 3 (demostración educativa)
 *
 * RFC 7617: Authorization: Basic base64(username:password)
 *
 * Defensas implementadas:
 * - timingSafeEqual para comparación de hashes (no ===)
 * - bcrypt.compare siempre se ejecuta, incluso si el usuario no existe
 *   (previene enumeración de usuarios por diferencia de tiempo)
 * - Contraseña nunca se almacena en claro
 */
import type { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { timingSafeEqual } from 'crypto';
import { usersRepository } from '../db/repositories/users';
import { auditLogsRepository } from '../db/repositories/auditLogs';
import { hashIp } from '../utils/hash';
import { AppError } from './errorHandler';

// Hash dummy para comparar cuando el usuario no existe (previene timing attack)
// Calculado una sola vez al cargar el módulo para no añadir latencia al primer request
const DUMMY_HASH = bcrypt.hashSync('timing_protection_dummy_hash_authlab', 12);

export async function basicAuthMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Basic ')) {
      _res.setHeader('WWW-Authenticate', 'Basic realm="Auth Lab"');
      throw new AppError(401, 'Se requiere autenticación Basic', 'NO_AUTENTICADO');
    }

    // Decodificar base64 → "email:password"
    const base64 = authHeader.slice(6);
    const decoded = Buffer.from(base64, 'base64').toString('utf-8');
    const colonIndex = decoded.indexOf(':');

    if (colonIndex === -1) {
      throw new AppError(401, 'Formato Basic Auth inválido — se espera email:password', 'TOKEN_INVALIDO');
    }

    const email = decoded.slice(0, colonIndex);
    const password = decoded.slice(colonIndex + 1);

    if (!email || !password) {
      throw new AppError(401, 'Email o contraseña vacíos', 'TOKEN_INVALIDO');
    }

    // Buscar usuario (la comparación bcrypt siempre ocurre para prevenir timing attacks)
    const user = usersRepository.findByEmail(email);
    const hashToCompare = user?.password_hash ?? DUMMY_HASH;

    // bcrypt.compare es la comparación constante en tiempo para contraseñas
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    const ipHash = hashIp(req.ip ?? '');
    const userAgent = req.headers['user-agent'] ?? null;

    if (!passwordMatch || !user) {
      auditLogsRepository.create({
        user_id: user?.id ?? null,
        event_type: 'LOGIN_FALLIDO',
        ip_hash: ipHash,
        user_agent: userAgent,
        correlation_id: req.correlationId,
        metadata: { metodo: 'basic_auth', razon: !user ? 'usuario_no_encontrado' : 'password_incorrecto' },
      });
      throw new AppError(401, 'Credenciales incorrectas', 'CREDENCIALES_INVALIDAS');
    }

    // Comparación adicional con timingSafeEqual para el email (previene enumeración por timing)
    const emailBuffer = Buffer.from(email.toLowerCase());
    const storedEmailBuffer = Buffer.from(user.email.toLowerCase());
    const emailsMatch =
      emailBuffer.length === storedEmailBuffer.length &&
      timingSafeEqual(emailBuffer, storedEmailBuffer);

    if (!emailsMatch) {
      throw new AppError(401, 'Credenciales incorrectas', 'CREDENCIALES_INVALIDAS');
    }

    // Éxito
    auditLogsRepository.create({
      user_id: user.id,
      event_type: 'LOGIN_EXITOSO',
      ip_hash: ipHash,
      user_agent: userAgent,
      correlation_id: req.correlationId,
      metadata: { metodo: 'basic_auth' },
    });

    req.user = {
      userId: user.id,
      roles: JSON.parse(user.roles) as import('../types').UserRole[],
    };

    next();
  } catch (err) {
    next(err);
  }
}
