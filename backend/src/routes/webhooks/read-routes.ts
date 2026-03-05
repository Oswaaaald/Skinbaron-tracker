import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { getAuthUser } from '../../lib/middleware.js';
import { WebhookQuerySchema } from './shared.js';

export function registerWebhookReadRoutes(fastify: FastifyInstance): void {
  fastify.get('/', {
    schema: {
      description: 'Get all webhooks for the authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          decrypt: { type: 'string', enum: ['true', 'false'], default: 'false' },
        },
      },
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
                  name: { type: 'string' },
                  webhook_url: { type: 'string' },
                  webhook_type: { type: 'string' },
                  notification_style: { type: 'string' },
                  is_active: { type: 'boolean' },
                  created_at: { type: 'string' },
                  updated_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { decrypt } = validateWithZod(WebhookQuerySchema, request.query);
      const webhooks = await store.webhooks.findByUserId(getAuthUser(request).id, decrypt);

      const safeWebhooks = webhooks.map(webhook => {
        const { webhook_url_encrypted: _, ...safe } = webhook;
        return safe;
      });

      return reply.status(200).send({
        success: true,
        data: safeWebhooks,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get webhooks');
    }
  });
}
