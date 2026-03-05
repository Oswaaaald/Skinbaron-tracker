import type { FastifyInstance } from 'fastify';
import { registerWebhookReadRoutes } from './webhooks/read-routes.js';
import { registerWebhookWriteRoutes } from './webhooks/write-routes.js';
import { registerWebhookBatchRoutes } from './webhooks/batch-routes.js';
import { webhooksWriteRateLimit, batchWriteRateLimit } from '../lib/rate-limit.js';

export default async function webhooksRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  const writeRateLimit = webhooksWriteRateLimit;
  const batchRateLimit = batchWriteRateLimit;

  registerWebhookReadRoutes(fastify);
  registerWebhookWriteRoutes(fastify, { writeRateLimit });
  registerWebhookBatchRoutes(fastify, { batchRateLimit });
}
