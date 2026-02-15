import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { store } from '../database/index.js';
import { CreateUserWebhookSchema } from '../database/schemas.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { validateWebhookUrl } from '../lib/webhook-validator.js';
import { getAuthUser } from '../lib/middleware.js';
import { MAX_WEBHOOKS_PER_USER } from '../lib/config.js';

// Query parameters schemas
const WebhookParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

const WebhookQuerySchema = z.object({
  decrypt: z.string().default('false').transform(val => val === 'true'),
});

// Route handlers
export default async function webhooksRoutes(fastify: FastifyInstance) {
  // Local hook for defense in depth - ensures all routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);

  /**
   * POST /webhooks - Create a new webhook for the authenticated user
   */
  fastify.post('/', {
    schema: {
      description: 'Create a new webhook for the authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
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
      const webhookData = validateWithZod(CreateUserWebhookSchema, request.body);
      
      // Check max webhooks limit
      const webhookCount = await store.webhooks.count(getAuthUser(request).id);
      if (webhookCount >= MAX_WEBHOOKS_PER_USER) {
        throw new AppError(400, `You have reached the maximum limit of ${MAX_WEBHOOKS_PER_USER} webhooks. Please delete some webhooks before creating new ones.`, 'MAX_WEBHOOKS_REACHED');
      }

      // SECURITY: Validate webhook URL against SSRF attacks
      const urlValidation = await validateWebhookUrl(webhookData.webhook_url);
      if (!urlValidation.valid) {
        throw new AppError(400, urlValidation.error || 'Invalid webhook URL', 'INVALID_WEBHOOK_URL');
      }
      
      const webhook = await store.createUserWebhook(getAuthUser(request).id, webhookData);
      
      // Don't return encrypted URL in response
      const { webhook_url_encrypted: _, ...safeWebhook } = webhook;
      
      return reply.status(201).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Create webhook');
    }
  });

  /**
   * GET /webhooks - Get all webhooks for the authenticated user
   */
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
      const webhooks = await store.getUserWebhooksByUserId(getAuthUser(request).id, decrypt);
      
      // Remove encrypted field from response
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

  /**
   * PATCH /webhooks/:id - Update a webhook for the authenticated user
   */
  fastify.patch('/:id', {
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
      const { id } = validateWithZod(WebhookParamsSchema, request.params);
      const updates = validateWithZod(CreateUserWebhookSchema.partial(), request.body);
      
      // Check if webhook exists and user owns it
      const existingWebhook = await store.getUserWebhookById(id);
      if (!existingWebhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      if (existingWebhook.user_id !== getAuthUser(request).id) {
        throw new AppError(403, 'You can only update your own webhooks', 'ACCESS_DENIED');
      }
      
      // SECURITY: Validate webhook URL against SSRF attacks if URL is being updated
      if (updates.webhook_url) {
        const urlValidation = await validateWebhookUrl(updates.webhook_url);
        if (!urlValidation.valid) {
          throw new AppError(400, urlValidation.error || 'Invalid webhook URL', 'INVALID_WEBHOOK_URL');
        }
      }
      
      const webhook = await store.updateUserWebhook(id, getAuthUser(request).id, updates);
      
      if (!webhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }
      
      // Remove encrypted field from response
      const { webhook_url_encrypted: _, ...safeWebhook } = webhook;
      
      return reply.status(200).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Update webhook');
    }
  });

  /**
   * DELETE /webhooks/:id - Delete a webhook for the authenticated user
   */
  fastify.delete('/:id', {
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
      const { id } = validateWithZod(WebhookParamsSchema, request.params);
      
      // Check if webhook exists and user owns it
      const existingWebhook = await store.getUserWebhookById(id);
      if (!existingWebhook) {
        throw new AppError(404, 'Webhook not found', 'WEBHOOK_NOT_FOUND');
      }

      if (existingWebhook.user_id !== getAuthUser(request).id) {
        throw new AppError(403, 'You can only delete your own webhooks', 'ACCESS_DENIED');
      }
      
      const deleted = await store.deleteUserWebhook(id, getAuthUser(request).id);
      
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

  /**
   * POST /webhooks/batch/enable - Enable multiple or all webhooks
   */
  fastify.post('/batch/enable', {
    schema: {
      description: 'Enable multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          webhook_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of webhook IDs to enable. If empty or not provided, enables all webhooks'
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { webhook_ids } = request.body as { webhook_ids?: number[] };
      const userId = getAuthUser(request).id;

      let updated = 0;
      
      if (!webhook_ids || webhook_ids.length === 0) {
        // Enable all webhooks for this user
        const allWebhooks = await store.getUserWebhooks(userId);
        const allIds = allWebhooks.filter(w => !w.is_active).map(w => w.id);
        updated = await store.enableWebhooksBatch(allIds, userId);
      } else {
        // Validate ownership of all webhooks
        for (const webhookId of webhook_ids) {
          const webhook = await store.getUserWebhookById(webhookId);
          if (!webhook) {
            throw new AppError(404, `Webhook ${webhookId} not found`, 'WEBHOOK_NOT_FOUND');
          }
          if (webhook.user_id !== userId) {
            throw new AppError(403, 'You can only enable your own webhooks', 'ACCESS_DENIED');
          }
        }
        // Enable specific webhooks (optimized batch operation)
        updated = await store.enableWebhooksBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully enabled ${updated} webhook(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Enable webhooks');
    }
  });

  /**
   * POST /webhooks/batch/disable - Disable multiple or all webhooks
   */
  fastify.post('/batch/disable', {
    schema: {
      description: 'Disable multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          webhook_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of webhook IDs to disable. If empty or not provided, disables all webhooks'
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { webhook_ids } = request.body as { webhook_ids?: number[] };
      const userId = getAuthUser(request).id;

      let updated = 0;
      
      if (!webhook_ids || webhook_ids.length === 0) {
        // Disable all webhooks for this user
        const allWebhooks = await store.getUserWebhooks(userId);
        const allIds = allWebhooks.filter(w => w.is_active).map(w => w.id);
        updated = await store.disableWebhooksBatch(allIds, userId);
      } else {
        // Validate ownership of all webhooks
        for (const webhookId of webhook_ids) {
          const webhook = await store.getUserWebhookById(webhookId);
          if (!webhook) {
            throw new AppError(404, `Webhook ${webhookId} not found`, 'WEBHOOK_NOT_FOUND');
          }
          if (webhook.user_id !== userId) {
            throw new AppError(403, 'You can only disable your own webhooks', 'ACCESS_DENIED');
          }
        }
        // Disable specific webhooks (optimized batch operation)
        updated = await store.disableWebhooksBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully disabled ${updated} webhook(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Disable webhooks');
    }
  });

  /**
   * POST /webhooks/batch/delete - Delete multiple or all webhooks
   */
  fastify.post('/batch/delete', {
    schema: {
      description: 'Delete multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          webhook_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of webhook IDs to delete. If empty, deletes all webhooks (requires confirm_all)'
          },
          confirm_all: {
            type: 'boolean',
            description: 'Must be true to delete all webhooks',
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { webhook_ids, confirm_all } = request.body as { webhook_ids?: number[]; confirm_all?: boolean };
      const userId = getAuthUser(request).id;

      let deleted = 0;
      
      if (!webhook_ids || webhook_ids.length === 0) {
        // Delete all webhooks - requires confirmation
        if (!confirm_all) {
          throw new AppError(400, 'Set confirm_all to true to delete all webhooks', 'CONFIRMATION_REQUIRED');
        }
        
        const allWebhooks = await store.getUserWebhooks(userId);
        const allIds = allWebhooks.map(w => w.id);
        deleted = await store.deleteWebhooksBatch(allIds, userId);
      } else {
        // Validate ownership of all webhooks
        for (const webhookId of webhook_ids) {
          const webhook = await store.getUserWebhookById(webhookId);
          if (!webhook) {
            throw new AppError(404, `Webhook ${webhookId} not found`, 'WEBHOOK_NOT_FOUND');
          }
          if (webhook.user_id !== userId) {
            throw new AppError(403, 'You can only delete your own webhooks', 'ACCESS_DENIED');
          }
        }
        // Delete specific webhooks (optimized batch operation)
        deleted = await store.deleteWebhooksBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully deleted ${deleted} webhook(s)`,
        count: deleted,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete webhooks');
    }
  });
}