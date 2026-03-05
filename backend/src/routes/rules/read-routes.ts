import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getAuthUser } from '../../lib/middleware.js';
import { handleRouteError } from '../../lib/validation-handler.js';

export function registerRuleReadRoutes(fastify: FastifyInstance): void {
  fastify.get('/', {
    schema: {
      description: 'Get all alert rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  user_id: { type: 'number' },
                  search_item: { type: 'string' },
                  min_price: { type: 'number', nullable: true },
                  max_price: { type: 'number', nullable: true },
                  min_wear: { type: 'number', nullable: true },
                  max_wear: { type: 'number', nullable: true },
                  stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                  souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                  sticker_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                  webhook_ids: { type: 'array', items: { type: 'number' } },
                  enabled: { type: 'boolean' },
                  created_at: { type: 'string' },
                  updated_at: { type: 'string' },
                },
              },
            },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const rules = await store.rules.findByUserId(getAuthUser(request).id);

      return reply.status(200).send({
        success: true,
        data: rules,
        count: rules.length,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get rules');
    }
  });
}
