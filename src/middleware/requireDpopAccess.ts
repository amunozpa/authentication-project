/**
 * Middleware DPoP Access — Fase 5.11
 *
 * Verifica que el request incluye:
 *   1. `Authorization: DPoP <access_token>` (no Bearer)
 *   2. `DPoP: <proof_jwt>` — proof generado para este request específico
 *
 * Valida:
 *   · AT firmado con clave del servidor + no expirado
 *   · AT contiene `cnf.jkt` (JWK thumbprint del cliente)
 *   · Proof DPoP válido: firma, htm, htu, iat, jti no replayed, ath correcto
 *   · jkt del proof == cnf.jkt del AT (mismo cliente que obtuvo el token)
 */
import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/jwtService';
import { verifyDpopProof, computeJwkThumbprint } from '../services/dpopService';
import { AppError } from './errorHandler';

export function requireDpopAccess(req: Request, _res: Response, next: NextFunction): void {
  // ── Extraer AT del header Authorization: DPoP <token> ────────────────────
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('DPoP ')) {
    throw new AppError(
      401,
      'Se requiere Authorization: DPoP <token> — los recursos DPoP no aceptan Bearer',
      'DPOP_SCHEME_REQUERIDO',
    );
  }
  const accessToken = authHeader.slice(5).trim(); // quitar 'DPoP '

  // ── Extraer DPoP proof del header ─────────────────────────────────────────
  const proofJwt = req.headers['dpop'];
  if (!proofJwt || typeof proofJwt !== 'string') {
    throw new AppError(
      401,
      'Header DPoP requerido — incluye un proof JWT firmado con tu clave privada',
      'DPOP_PROOF_REQUERIDO',
    );
  }

  // ── Verificar el AT con las claves del servidor (misma lógica que Bearer) ─
  let atPayload: ReturnType<typeof verifyAccessToken>;
  try {
    atPayload = verifyAccessToken(accessToken);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(401, 'Access Token DPoP inválido o expirado', 'TOKEN_INVALIDO');
  }

  // ── El AT debe tener cnf.jkt (solo los tokens DPoP-bound lo tienen) ───────
  const jkt = atPayload.cnf?.jkt;
  if (!jkt) {
    throw new AppError(
      401,
      'Este Access Token no está vinculado a DPoP (sin cnf.jkt) — usa POST /dpop/token para obtener uno',
      'TOKEN_NO_DPOP',
    );
  }

  // ── Construir htu esperado (scheme + authority + path, sin query) ─────────
  // req.originalUrl incluye el prefijo completo (/api/v1/dpop/protected)
  const expectedHtu = `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;

  // ── Verificar el DPoP proof ───────────────────────────────────────────────
  const { jwk } = verifyDpopProof({
    proofJwt,
    htm: req.method,
    htu: expectedHtu,
    accessToken, // activa verificación del claim ath
  });

  // ── Verificar que el proof pertenece al mismo cliente que tiene el AT ─────
  const proofJkt = computeJwkThumbprint(jwk as Parameters<typeof computeJwkThumbprint>[0]);
  if (proofJkt !== jkt) {
    throw new AppError(
      401,
      'DPoP: el JWK del proof no coincide con la clave que obtuvo el Access Token (cnf.jkt)',
      'DPOP_CLAVE_INCORRECTA',
    );
  }

  // ── Inyectar usuario en req (igual que authenticate) ─────────────────────
  req.user = { userId: atPayload.sub, roles: atPayload.roles };
  next();
}
