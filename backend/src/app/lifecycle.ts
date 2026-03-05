import type { FastifyInstance } from 'fastify';
import { captureException, flushSentry } from '../lib/sentry.js';
import { closeDatabase } from '../database/connection.js';
import { getScheduler } from '../lib/scheduler.js';
import { getSecurityCleanupService } from '../lib/security-cleanup.js';

export function registerProcessHandlers(fastify: FastifyInstance): void {
  const gracefulShutdown = async (signal: string) => {
    fastify.log.info(`Received ${signal}, starting graceful shutdown...`);

    try {
      const scheduler = getScheduler();
      scheduler.stop();
      getSecurityCleanupService().stop();

      await closeDatabase();
      await fastify.close();
      await flushSentry();

      fastify.log.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      fastify.log.error({ error }, 'Error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => void gracefulShutdown('SIGINT'));

  process.on('uncaughtException', (error) => {
    captureException(error, { context: 'uncaughtException' });
    fastify.log.fatal({ error }, 'Uncaught Exception');
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    captureException(reason, { context: 'unhandledRejection' });
    fastify.log.fatal({ reason }, 'Unhandled Rejection');
    process.exit(1);
  });
}
