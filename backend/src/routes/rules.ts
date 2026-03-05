import type { FastifyInstance } from 'fastify';
import { registerRuleReadRoutes } from './rules/read-routes.js';
import { registerRuleWriteRoutes } from './rules/write-routes.js';
import { registerRuleBatchRoutes } from './rules/batch-routes.js';
import { rulesWriteRateLimit, batchWriteRateLimit } from '../lib/rate-limit.js';

export default async function rulesRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  const writeRateLimit = rulesWriteRateLimit;
  const batchRateLimit = batchWriteRateLimit;

  registerRuleReadRoutes(fastify);
  registerRuleWriteRoutes(fastify, { writeRateLimit });
  registerRuleBatchRoutes(fastify, { batchRateLimit });
}
