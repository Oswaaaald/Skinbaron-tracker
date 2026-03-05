import type { FastifyInstance } from 'fastify';
import { registerWebhookReadRoutes } from './webhooks/read-routes.js';
import { registerWebhookWriteRoutes } from './webhooks/write-routes.js';
import { registerWebhookBatchRoutes } from './webhooks/batch-routes.js';

export default async function webhooksRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  const writeRateLimit = {
    max: 10,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many webhook changes. Please try again in 1 minute.',
    }),
  };

  const batchRateLimit = {
    max: 5,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many batch operations. Please try again in 1 minute.',
    }),
  };

  registerWebhookReadRoutes(fastify);
  registerWebhookWriteRoutes(fastify, { writeRateLimit });
  registerWebhookBatchRoutes(fastify, { batchRateLimit });
}
