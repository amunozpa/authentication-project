/**
 * Punto de entrada del servidor — Fase 1/4
 * Importa la app configurada y arranca el servidor HTTP.
 */
import { app } from './app';
import { config } from './config/env';
import { logger } from './logger';
import { startPurgeJob } from './db/purgeJob';

const server = app.listen(config.PORT, () => {
  logger.info(`Servidor activo en http://localhost:${config.PORT}`);
  logger.info(`Ambiente: ${config.NODE_ENV}`);
  logger.info(`CORS permitido para: ${config.FRONTEND_URL}`);
  startPurgeJob();
});

// Manejo limpio de señales de apagado (Docker, PM2)
process.on('SIGTERM', () => {
  logger.info('SIGTERM recibido — cerrando servidor...');
  server.close(() => {
    logger.info('Servidor cerrado correctamente');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT recibido — cerrando servidor...');
  server.close(() => {
    logger.info('Servidor cerrado correctamente');
    process.exit(0);
  });
});

export default server;
