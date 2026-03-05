import type { FastifyInstance } from 'fastify';
import { registerRuleReadRoutes } from './rules/read-routes.js';
import { registerRuleWriteRoutes } from './rules/write-routes.js';
import { registerRuleBatchRoutes } from './rules/batch-routes.js';

export default async function rulesRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  const writeRateLimit = {
    max: 15,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many rule changes. Please try again in 1 minute.',
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

  registerRuleReadRoutes(fastify);
  registerRuleWriteRoutes(fastify, { writeRateLimit });
  registerRuleBatchRoutes(fastify, { batchRateLimit });
}
