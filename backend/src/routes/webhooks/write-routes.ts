import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { CreateUserWebhookSchema } from '../../database/validation-schemas.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { validateWebhookUrl } from '../../lib/webhook-validator.js';
import { getAuthUser } from '../../lib/middleware.js';
import { MAX_WEBHOOKS_PER_USER } from '../../lib/config.js';
import { WebhookParamsSchema } from './shared.js';

type RegisterWebhookWriteRoutesOptions = {
  writeRateLimit: {
    max: number;
    timeWindow: string;
    errorResponseBuilder: () => {
      statusCode: number;
      success: boolean;
      error: string;
      message: string;
    };
  };
};

export function registerWebhookWriteRoutes(
  fastify: FastifyInstance,
  { writeRateLimit }: RegisterWebhookWriteRoutesOptions,
): void {
  fastify.post('/', {
    config: { rateLimit: writeRateLimit },
    schema: {
      description: 'Create a new webhook for the authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 50 },
          webhook_url: { type: 'string', format: 'uri' },
          webhook_type: { type: 'string', enum: ['discord'] },
          notification_style: { type: 'string', enum: ['compact', 'detailed'] },
          is_active: { type: 'boolean' },
        },
        required: ['name', 'webhook_url'],
      },
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                user_id: { type: 'number' },
                name: { type: 'string' },
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
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const webhookData = validateWithZod(CreateUserWebhookSchema, request.body);

      const webhookCount = await store.webhooks.count(userId);
      if (webhookCount >= MAX_WEBHOOKS_PER_USER) {
        throw new AppError(400, `You have reached the maximum limit of ${MAX_WEBHOOKS_PER_USER} webhooks. Please delete some webhooks before creating new ones.`, 'MAX_WEBHOOKS_REACHED');
      }

      const urlValidation = await validateWebhookUrl(webhookData.webhook_url);
      if (!urlValidation.valid) {
        throw new AppError(400, urlValidation.error || 'Invalid webhook URL', 'INVALID_WEBHOOK_URL');
      }

      const webhook = await store.webhooks.create(userId, webhookData);
      const { webhook_url_encrypted: _, ...safeWebhook } = webhook;

      return reply.status(201).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Create webhook');
    }
  });

  fastify.patch('/:id', {
    config: { rateLimit: writeRateLimit },
    schema: {
      description: 'Update a webhook for the authenticated user (partial update)',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 50 },
          webhook_url: { type: 'string', format: 'uri' },
          webhook_type: { type: 'string', enum: ['discord'] },
          notification_style: { type: 'string', enum: ['compact', 'detailed'] },
          is_active: { type: 'boolean' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                user_id: { type: 'number' },
                name: { type: 'string' },
                webhook_type: { type: 'string' },
                notification_style: { type: 'string' },
                is_active: { type: 'boolean' },
                created_at: { type: 'string' },
                updated_at: { type: 'string' },
              },
            },
          },
        },
        404: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id } = validateWithZod(WebhookParamsSchema, request.params);
      const updates = validateWithZod(CreateUserWebhookSchema.partial(), request.body);

      const existingWebhook = await store.webhooks.findById(id, userId);
      if (!existingWebhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      if (updates.webhook_url) {
        const urlValidation = await validateWebhookUrl(updates.webhook_url);
        if (!urlValidation.valid) {
          throw new AppError(400, urlValidation.error || 'Invalid webhook URL', 'INVALID_WEBHOOK_URL');
        }
      }

      const webhook = await store.webhooks.update(id, userId, updates);
      if (!webhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      const { webhook_url_encrypted: _, ...safeWebhook } = webhook;

      return reply.status(200).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Update webhook');
    }
  });

  fastify.delete('/:id', {
    config: { rateLimit: writeRateLimit },
    schema: {
      description: 'Delete a webhook for the authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
        404: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id } = validateWithZod(WebhookParamsSchema, request.params);

      const existingWebhook = await store.webhooks.findById(id, userId);
      if (!existingWebhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      const deleted = await store.webhooks.delete(id, userId);
      if (!deleted) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      return reply.status(200).send({
        success: true,
        message: 'Webhook deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete webhook');
    }
  });
}
