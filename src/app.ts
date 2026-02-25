/**
 * Configuración de la aplicación Express — separada del arranque del servidor.
 * Exportar `app` permite que los tests creen su propia instancia sin iniciar
 * el servidor en un puerto real.
 */
import express, { Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import pinoHttp from 'pino-http';
import swaggerUi from 'swagger-ui-express';
import { openApiDocument } from './openapi/index';
import { config } from './config/env';
import { logger } from './logger';
import { correlationIdMiddleware } from './middleware/correlationId';
import { errorHandler } from './middleware/errorHandler';
import healthRouter from './routes/health';
import authRouter from './routes/auth';
import basicRouter from './routes/basic';
import sessionRouter from './routes/session';
import keysRouter from './routes/keys';
import jwtRouter from './routes/jwt';
import adminRouter from './routes/admin';
import oauthRouter from './routes/oauth';
import userRouter from './routes/user';
import webauthnRouter from './routes/webauthn';
import mfaRouter from './routes/mfa';
import magicRouter from './routes/magic';
import pasetoRouter from './routes/paseto';
import dpopRouter from './routes/dpop';
import rbacRouter from './routes/rbac';
import ratelimitRouter from './routes/ratelimit';
import { globalLimiter } from './middleware/rateLimiter';

// Inicializar BD (ejecuta migraciones)
import './db/index';
import { initializeJwtKeys } from './services/jwtService';
import { initializePasetoKeys } from './services/pasetoService';

// Inicializar servicios
initializeJwtKeys();
void initializePasetoKeys();

export const app = express();

// ── Seguridad ────────────────────────────────────────────────────────────────
app.use(helmet());

app.use(
  cors({
    origin: config.FRONTEND_URL,
    credentials: true,
  }),
);

// ── Frontend estático ─────────────────────────────────────────────────────────
app.use(express.static('public'));

// ── Parsers ──────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Correlation ID ───────────────────────────────────────────────────────────
app.use(correlationIdMiddleware);

// ── Logging HTTP ─────────────────────────────────────────────────────────────
// En tests se silencia el logger para evitar ruido
if (config.NODE_ENV !== 'test') {
  app.use(
    pinoHttp({
      logger,
      customProps: (req: Request) => ({ correlationId: req.correlationId }),
      customSuccessMessage: (_req: Request, res: Response) =>
        `Respuesta enviada — ${res.statusCode}`,
      customErrorMessage: (_req: Request, res: Response) =>
        `Error en respuesta — ${res.statusCode}`,
      serializers: {
        req: (req) => ({
          method: req.method,
          url: req.url,
          userAgent: req.headers['user-agent'],
        }),
        res: (res) => ({ statusCode: res.statusCode }),
      },
    }),
  );
}

// ── Rate Limiting global ──────────────────────────────────────────────────────
// En tests se desactiva el rate limiting para no interferir con los tests de carga
if (config.NODE_ENV !== 'test') {
  app.use('/api/v1', globalLimiter);
}

// ── Rutas ─────────────────────────────────────────────────────────────────────
app.use('/api/v1/health', healthRouter);
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/basic', basicRouter);
app.use('/api/v1/session', sessionRouter);
app.use('/api/v1/keys', keysRouter);
app.use('/api/v1/jwt', jwtRouter);
app.use('/api/v1/admin', adminRouter);
app.use('/api/v1/oauth', oauthRouter);
app.use('/api/v1/user', userRouter);
app.use('/api/v1/webauthn', webauthnRouter);
app.use('/api/v1/mfa', mfaRouter);
app.use('/api/v1/magic', magicRouter);
app.use('/api/v1/paseto', pasetoRouter);
app.use('/api/v1/dpop', dpopRouter);
app.use('/api/v1/rbac', rbacRouter);
app.use('/api/v1/ratelimit', ratelimitRouter);

// ── Swagger UI ────────────────────────────────────────────────────────────────
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openApiDocument, {
  customSiteTitle: 'Auth Lab — API Docs',
  swaggerOptions: { persistAuthorization: true },
}));
app.get('/api/docs.json', (_req: Request, res: Response) => res.json(openApiDocument));

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Ruta no encontrada',
    code: 'RUTA_NO_ENCONTRADA',
  });
});

// ── Error handler centralizado ────────────────────────────────────────────────
app.use(errorHandler);
