/**
 * Logger global con Pino.
 * Dev: pino-pretty (legible, con colores).
 * Prod: JSON estructurado (para ingestión en sistemas de logs).
 * Todos los mensajes en español.
 */
import pino from 'pino';
import { config } from './config/env';

const isDev = config.NODE_ENV === 'development';

export const logger = pino(
  {
    level: isDev ? 'debug' : 'info',
    // Serializa errores correctamente
    serializers: {
      err: pino.stdSerializers.err,
    },
  },
  isDev
    ? pino.transport({
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:dd/mm/yyyy HH:MM:ss',
          ignore: 'pid,hostname',
          messageFormat: '{msg}',
        },
      })
    : undefined,
);
